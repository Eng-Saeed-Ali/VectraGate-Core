"""Layer 2 deterministic OT firewall: Nygard breaker, fencing, rate limit & audit chain."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from vectragate.dag_engine import evaluate_dag, validate_and_sort_dag
from vectragate.models import (
    GENESIS_HASH_U64,
    MAX_PACKETS,
    MAX_REG_VAL,
    MAX_REGISTERS,
    MAX_SOURCES,
    MIN_REG_VAL,
    BreakerState,
    DagNode,
    FirewallPolicy,
    FirewallRunResult,
    PacketVerdict,
    RawPacket,
    SourceSecurityState,
    VerdictCode,
    compute_verdict_hash,
)
from vectragate.protocol import decode_wire_packet

_DEFAULT_POLICY: FirewallPolicy = FirewallPolicy()


@dataclass(slots=True)
class _MutableSource:
    """Internal per-source mutable state updated strictly in run-to-completion."""

    source_id: str
    last_seq_no: int
    breaker_state: BreakerState
    consecutive_failures: int
    total_violations: int
    opened_at_ms: int
    window_timestamps: list[int]


def _init_registers(initial_registers: Sequence[int] | None) -> list[int]:
    """Create validated MAX_REGISTERS integer bank from optional initial state."""
    assert MAX_REGISTERS == 256
    if initial_registers is None:
        regs = [0] * MAX_REGISTERS
        assert len(regs) == MAX_REGISTERS
        return regs
    if len(initial_registers) != MAX_REGISTERS:
        raise ValueError(f"initial_registers must have length {MAX_REGISTERS}")
    regs: list[int] = []
    for val in initial_registers:
        if type(val) is not int:
            raise TypeError("initial_registers entries must be exact int")
        if not (MIN_REG_VAL <= val <= MAX_REG_VAL):
            raise ValueError(f"register value {val} out of bounds")
        regs.append(val)
    assert len(regs) == MAX_REGISTERS
    return regs


def _get_or_create_source(
    sources: dict[str, _MutableSource],
    source_id: str,
) -> _MutableSource:
    """Fetch existing source security state or allocate within MAX_SOURCES."""
    assert isinstance(sources, dict)
    assert isinstance(source_id, str)
    if source_id in sources:
        return sources[source_id]
    if len(sources) >= MAX_SOURCES:
        raise ValueError(f"Distinct sources exceed MAX_SOURCES={MAX_SOURCES}")
    state = _MutableSource(
        source_id=source_id,
        last_seq_no=0,
        breaker_state=BreakerState.CLOSED,
        consecutive_failures=0,
        total_violations=0,
        opened_at_ms=-1,
        window_timestamps=[],
    )
    sources[source_id] = state
    return state


def _apply_step6_accounting(
    src: _MutableSource,
    verdict_code: VerdictCode,
    timestamp_ms: int,
    policy: FirewallPolicy,
) -> bool:
    """Apply Step 6 violation accounting and Nygard state transitions."""
    assert isinstance(src, _MutableSource)
    assert isinstance(verdict_code, VerdictCode)
    allowed = verdict_code in (VerdictCode.ALLOW_READ, VerdictCode.ALLOW_WRITE)
    if allowed:
        src.consecutive_failures = 0
        if src.breaker_state == BreakerState.HALF_OPEN:
            src.breaker_state = BreakerState.CLOSED
        return True
    src.consecutive_failures += 1
    src.total_violations += 1
    if (
        src.breaker_state == BreakerState.HALF_OPEN
        or src.consecutive_failures >= policy.trip_threshold
    ):
        src.breaker_state = BreakerState.OPEN
        src.opened_at_ms = timestamp_ms
    return False


def _run_security_and_interlock(
    pkt: RawPacket,
    src: _MutableSource,
    policy: FirewallPolicy,
    nodes_by_id: dict[int, DagNode],
    topo_order: tuple[int, ...],
    live_regs: list[int],
) -> tuple[VerdictCode, int]:
    """Execute Steps 2–5: fencing, sliding window, decode, and trial-write DAG."""
    assert isinstance(pkt, RawPacket)
    assert len(live_regs) == MAX_REGISTERS
    if pkt.seq_no <= src.last_seq_no:
        return VerdictCode.REPLAY_ATTACK_BLOCKED, -1
    src.last_seq_no = pkt.seq_no
    cutoff = pkt.timestamp_ms - policy.window_ms
    src.window_timestamps = [t for t in src.window_timestamps if t >= cutoff]
    if len(src.window_timestamps) >= policy.max_requests_per_window:
        return VerdictCode.RATE_LIMIT_EXCEEDED, -1
    src.window_timestamps.append(pkt.timestamp_ms)
    err, op = decode_wire_packet(pkt.protocol, pkt.payload_hex)
    if err is not None or op is None:
        return (err if err is not None else VerdictCode.MODBUS_UNAUTHORIZED_FC), -1
    if not op.is_write:
        return VerdictCode.ALLOW_READ, -1
    scratch = list(live_regs)
    for reg_addr, reg_val in op.writes:
        scratch[reg_addr] = reg_val
    tripped, trip_id, _ = evaluate_dag(nodes_by_id, topo_order, scratch)
    if tripped:
        return VerdictCode.INTERLOCK_TRIPPED, trip_id
    live_regs[:] = scratch
    return VerdictCode.ALLOW_WRITE, -1


def _evaluate_single_packet(
    seq_index: int,
    pkt: RawPacket,
    src: _MutableSource,
    policy: FirewallPolicy,
    nodes_by_id: dict[int, DagNode],
    topo_order: tuple[int, ...],
    live_regs: list[int],
    prev_hash_u64: int,
) -> PacketVerdict:
    """Evaluate one packet across Steps 1–6 and seal into BLAKE2b-64 chain."""
    assert seq_index >= 0
    assert isinstance(src, _MutableSource)
    if (
        src.breaker_state == BreakerState.OPEN
        and pkt.timestamp_ms - src.opened_at_ms < policy.cooldown_ms
    ):
        verdict_code = VerdictCode.CIRCUIT_BREAKER_OPEN
        tripped_id = -1
        is_allowed = False
    else:
        if src.breaker_state == BreakerState.OPEN:
            src.breaker_state = BreakerState.HALF_OPEN
        verdict_code, tripped_id = _run_security_and_interlock(
            pkt, src, policy, nodes_by_id, topo_order, live_regs
        )
        is_allowed = _apply_step6_accounting(
            src, verdict_code, pkt.timestamp_ms, policy
        )
    chain_hash = compute_verdict_hash(
        prev_hash_u64,
        pkt.packet_id,
        pkt.seq_no,
        pkt.timestamp_ms,
        pkt.source_id,
        pkt.protocol,
        verdict_code,
        tripped_id,
        src.breaker_state,
    )
    return PacketVerdict(
        seq_index=seq_index,
        packet_id=pkt.packet_id,
        source_id=pkt.source_id,
        seq_no=pkt.seq_no,
        timestamp_ms=pkt.timestamp_ms,
        protocol=pkt.protocol,
        verdict_code=verdict_code,
        is_allowed=is_allowed,
        tripped_node_id=tripped_id,
        breaker_state_after=src.breaker_state,
        prev_hash_u64=prev_hash_u64,
        chain_hash_u64=chain_hash,
    )


def evaluate_packet_stream(
    packets: Sequence[RawPacket],
    dag_nodes: Sequence[DagNode],
    initial_registers: Sequence[int] | None = None,
    policy: FirewallPolicy = _DEFAULT_POLICY,
) -> FirewallRunResult:
    """Evaluate bounded packet stream deterministically against DAG & firewall policy."""
    if len(packets) > MAX_PACKETS:
        raise ValueError(f"Packet count {len(packets)} exceeds MAX_PACKETS={MAX_PACKETS}")
    if not isinstance(policy, FirewallPolicy):
        raise TypeError("policy must be FirewallPolicy")
    live_regs = _init_registers(initial_registers)
    topo_order = validate_and_sort_dag(dag_nodes)
    nodes_by_id = {n.node_id: n for n in dag_nodes}
    assert len(topo_order) == len(nodes_by_id)
    assert len(live_regs) == MAX_REGISTERS
    sources: dict[str, _MutableSource] = {}
    verdicts: list[PacketVerdict] = []
    prev_hash = GENESIS_HASH_U64
    allowed_count = 0
    for idx, pkt in enumerate(packets):
        src = _get_or_create_source(sources, pkt.source_id)
        verdict = _evaluate_single_packet(
            idx, pkt, src, policy, nodes_by_id, topo_order, live_regs, prev_hash
        )
        verdicts.append(verdict)
        prev_hash = verdict.chain_hash_u64
        allowed_count += 1 if verdict.is_allowed else 0
    frozen_sources = tuple(
        SourceSecurityState(
            source_id=s.source_id,
            last_seq_no=s.last_seq_no,
            breaker_state=s.breaker_state,
            consecutive_failures=s.consecutive_failures,
            total_violations=s.total_violations,
            opened_at_ms=s.opened_at_ms,
            window_timestamps=tuple(s.window_timestamps),
        )
        for s in (sources[k] for k in sorted(sources))
    )
    return FirewallRunResult(
        verdicts=tuple(verdicts),
        final_registers=tuple(live_regs),
        source_states=frozen_sources,
        topological_order=topo_order,
        final_chain_hash_u64=prev_hash,
        allowed_count=allowed_count,
        blocked_count=len(verdicts) - allowed_count,
    )


def verify_verdict_chain(verdicts: Sequence[PacketVerdict]) -> bool:
    """Recompute and verify every link of a BLAKE2b-64 verdict audit chain."""
    assert verdicts is not None
    expected_prev = GENESIS_HASH_U64
    assert expected_prev == 0x5645435452413236
    for verdict in verdicts:
        if verdict.prev_hash_u64 != expected_prev:
            return False
        expected_hash = compute_verdict_hash(
            verdict.prev_hash_u64,
            verdict.packet_id,
            verdict.seq_no,
            verdict.timestamp_ms,
            verdict.source_id,
            verdict.protocol,
            verdict.verdict_code,
            verdict.tripped_node_id,
            verdict.breaker_state_after,
        )
        if verdict.chain_hash_u64 != expected_hash:
            return False
        expected_prev = verdict.chain_hash_u64
    return True

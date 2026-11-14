"""Layer 3 subprocess bridge and compiler driver for native vectragate_cli.exe."""

from __future__ import annotations

import pathlib
import subprocess
from collections.abc import Sequence

from vectragate.firewall import verify_verdict_chain
from vectragate.models import (
    GENESIS_HASH_U64,
    MAX_DAG_NODES,
    MAX_PACKETS,
    MAX_REG_VAL,
    MAX_REGISTERS,
    MIN_REG_VAL,
    BreakerState,
    DagNode,
    FirewallPolicy,
    FirewallRunResult,
    PacketVerdict,
    ProtocolType,
    RawPacket,
    SourceSecurityState,
    VerdictCode,
)

_DEFAULT_POLICY: FirewallPolicy = FirewallPolicy()


def _repo_root() -> pathlib.Path:
    """Resolve repository root directory from this module path."""
    root = pathlib.Path(__file__).resolve().parent.parent.parent
    assert root.exists()
    assert root.is_dir()
    return root


def compile_cpp_engine(
    binary_path: str | pathlib.Path | None = None,
) -> pathlib.Path:
    """Compile vectragate_cli.cpp with pedantic flags if binary is missing or stale."""
    root = _repo_root()
    target = (
        pathlib.Path(binary_path)
        if binary_path is not None
        else root.joinpath("vectragate_cli.exe")
    )
    cpp_dir = root.joinpath("src", "cpp")
    hpp_path = cpp_dir.joinpath("vectragate_core.hpp")
    cpp_path = cpp_dir.joinpath("vectragate_cli.cpp")
    assert hpp_path.exists()
    assert cpp_path.exists()
    if target.exists():
        bin_mtime = target.stat().st_mtime_ns
        src_mtime = max(hpp_path.stat().st_mtime_ns, cpp_path.stat().st_mtime_ns)
        if bin_mtime >= src_mtime:
            return target
    target.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "g++",
        "-std=c++17",
        "-O3",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-Werror",
        str(cpp_path),
        "-o",
        str(target),
    ]
    proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "C++ engine compilation failed")
    return target


def _serialize_cpp_input(
    packets: Sequence[RawPacket],
    dag_nodes: Sequence[DagNode],
    initial_registers: Sequence[int] | None,
    policy: FirewallPolicy,
) -> str:
    """Serialize policy, initial registers, DAG nodes, and packets to wire stdin."""
    assert len(packets) <= MAX_PACKETS
    assert len(dag_nodes) <= MAX_DAG_NODES
    if initial_registers is not None:
        if len(initial_registers) != MAX_REGISTERS:
            raise ValueError(f"initial_registers must have length {MAX_REGISTERS}")
        for val in initial_registers:
            if type(val) is not int or not (MIN_REG_VAL <= val <= MAX_REG_VAL):
                raise ValueError("invalid initial register entry")
    lines = [
        (
            f"POLICY {policy.window_ms} {policy.max_requests_per_window} "
            f"{policy.trip_threshold} {policy.cooldown_ms}"
        )
    ]
    if initial_registers is not None:
        for addr, val in enumerate(initial_registers):
            if val != 0:
                lines.append(f"REG {addr} {val}")
    for node in dag_nodes:
        in_tail = (" " + " ".join(str(i) for i in node.inputs)) if node.inputs else ""
        lines.append(
            f"NODE {node.node_id} {node.tag} {node.op.value} {node.target_reg} "
            f"{node.threshold} {1 if node.is_hazard_output else 0} "
            f"{len(node.inputs)}{in_tail}"
        )
    for pkt in packets:
        lines.append(
            f"PKT {pkt.packet_id} {pkt.source_id} {pkt.seq_no} {pkt.timestamp_ms} "
            f"{pkt.protocol.value} {pkt.payload_hex}"
        )
    lines.append("END")
    return "\n".join(lines) + "\n"


def _parse_verdict_line(parts: list[str]) -> PacketVerdict:
    """Decode one VERDICT stdout record into PacketVerdict."""
    assert parts[0] == "VERDICT"
    assert len(parts) == 13
    return PacketVerdict(
        seq_index=int(parts[1]),
        packet_id=parts[2],
        source_id=parts[3],
        seq_no=int(parts[4]),
        timestamp_ms=int(parts[5]),
        protocol=ProtocolType(parts[6]),
        verdict_code=VerdictCode(parts[7]),
        is_allowed=(parts[8] == "1"),
        tripped_node_id=int(parts[9]),
        breaker_state_after=BreakerState(parts[10]),
        prev_hash_u64=int(parts[11], 16),
        chain_hash_u64=int(parts[12], 16),
    )


def _parse_source_line(parts: list[str]) -> SourceSecurityState:
    """Decode one SOURCE stdout record into SourceSecurityState."""
    assert parts[0] == "SOURCE"
    assert len(parts) >= 8
    win_cnt = int(parts[7])
    if len(parts) != 8 + win_cnt:
        raise RuntimeError(f"Malformed SOURCE line token count: {len(parts)}")
    return SourceSecurityState(
        source_id=parts[1],
        last_seq_no=int(parts[2]),
        breaker_state=BreakerState(parts[3]),
        consecutive_failures=int(parts[4]),
        total_violations=int(parts[5]),
        opened_at_ms=int(parts[6]),
        window_timestamps=tuple(int(x) for x in parts[8:]),
    )


def _parse_cpp_stdout(stdout_text: str) -> FirewallRunResult:
    """Parse vectragate_cli.exe wire stdout into a verified FirewallRunResult."""
    lines = [ln.strip() for ln in stdout_text.splitlines() if ln.strip()]
    assert len(lines) >= 3
    topo: tuple[int, ...] = ()
    verdicts: list[PacketVerdict] = []
    sources: list[SourceSecurityState] = []
    regs: tuple[int, ...] = ()
    allowed = 0
    blocked = 0
    final_hash = GENESIS_HASH_U64
    for ln in lines:
        parts = ln.split()
        tag = parts[0]
        if tag == "TOPO":
            topo = tuple(int(x) for x in parts[1:])
        elif tag == "VERDICT":
            verdicts.append(_parse_verdict_line(parts))
        elif tag == "SOURCE":
            sources.append(_parse_source_line(parts))
        elif tag == "REGS":
            regs = tuple(int(x) for x in parts[1:])
        elif tag == "SUMMARY":
            allowed = int(parts[1])
            blocked = int(parts[2])
            final_hash = int(parts[3], 16)
    assert len(regs) == MAX_REGISTERS
    if not verify_verdict_chain(verdicts):
        raise RuntimeError("C++ verdict audit chain failed local verification")
    return FirewallRunResult(
        verdicts=tuple(verdicts),
        final_registers=regs,
        source_states=tuple(sources),
        topological_order=topo,
        final_chain_hash_u64=final_hash,
        allowed_count=allowed,
        blocked_count=blocked,
    )


def run_cpp_engine(
    packets: Sequence[RawPacket],
    dag_nodes: Sequence[DagNode],
    initial_registers: Sequence[int] | None = None,
    policy: FirewallPolicy = _DEFAULT_POLICY,
    binary_path: pathlib.Path | None = None,
) -> FirewallRunResult:
    """Execute native C++ vectragate_cli.exe and parse deterministic output."""
    if len(packets) > MAX_PACKETS:
        raise ValueError(f"Packet count {len(packets)} exceeds MAX_PACKETS={MAX_PACKETS}")
    if len(dag_nodes) > MAX_DAG_NODES:
        raise ValueError(f"DAG node count {len(dag_nodes)} exceeds {MAX_DAG_NODES}")
    if not isinstance(policy, FirewallPolicy):
        raise TypeError("policy must be FirewallPolicy")
    exe_path = compile_cpp_engine(binary_path)
    stdin_payload = _serialize_cpp_input(packets, dag_nodes, initial_registers, policy)
    proc = subprocess.run(
        [str(exe_path)],
        input=stdin_payload,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise ValueError(proc.stderr.strip() or f"vectragate_cli exited {proc.returncode}")
    result = _parse_cpp_stdout(proc.stdout)
    assert len(result.verdicts) == len(packets)
    assert result.allowed_count + result.blocked_count == len(packets)
    return result

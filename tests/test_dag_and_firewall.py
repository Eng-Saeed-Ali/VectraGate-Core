"""Unit tests for DAG engine, firewall policies, BLAKE2b chain, and C++ CLI parity."""

from __future__ import annotations

import pathlib
import struct
import subprocess

import pytest

from vectragate.dag_engine import evaluate_dag, validate_and_sort_dag
from vectragate.firewall import evaluate_packet_stream, verify_verdict_chain
from vectragate.models import (
    MAX_REGISTERS,
    BreakerState,
    DagNode,
    FirewallPolicy,
    NodeOp,
    PacketVerdict,
    ProtocolType,
    RawPacket,
    VerdictCode,
)


def _mb_write_single(reg: int, val: int, tx_id: int = 1) -> str:
    """Build valid Modbus FC 0x06 Write Single Register hex payload."""
    return struct.pack("!HHHBBHH", tx_id, 0, 6, 1, 0x06, reg, val).hex()


def _mb_write_multi(start: int, values: list[int], tx_id: int = 1) -> str:
    """Build valid Modbus FC 0x10 Write Multiple Registers hex payload."""
    cnt = len(values)
    bc = 2 * cnt
    hdr = struct.pack("!HHHBBHHB", tx_id, 0, 7 + bc, 1, 0x10, start, cnt, bc)
    body = b"".join(struct.pack("!H", v) for v in values)
    return (hdr + body).hex()


def _mb_read(start: int, cnt: int, tx_id: int = 1) -> str:
    """Build valid Modbus FC 0x03 Read Holding Registers hex payload."""
    return struct.pack("!HHHBBHH", tx_id, 0, 6, 1, 0x03, start, cnt).hex()


def _mqtt_ascii(topic: str, cmd: str) -> str:
    """Build valid QoS 0 MQTT PUBLISH hex payload."""
    t_bytes = topic.encode("utf-8")
    p_bytes = cmd.encode("ascii")
    body = struct.pack("!H", len(t_bytes)) + t_bytes + p_bytes
    return (bytes([0x30, len(body)]) + body).hex()


def test_f4_all_12_node_ops_kahn_tiebreak_and_cycle_rejection() -> None:
    """Verify all 12 comparator/gate ops, deterministic Kahn order, and cycle EC-C."""
    nodes = [
        DagNode(10, "N_GT", NodeOp.CMP_GT, target_reg=0, threshold=100),
        DagNode(2, "N_GE", NodeOp.CMP_GE, target_reg=1, threshold=50),
        DagNode(3, "N_LT", NodeOp.CMP_LT, target_reg=2, threshold=10),
        DagNode(4, "N_LE", NodeOp.CMP_LE, target_reg=3, threshold=20),
        DagNode(5, "N_EQ", NodeOp.CMP_EQ, target_reg=4, threshold=7),
        DagNode(6, "N_NE", NodeOp.CMP_NE, target_reg=5, threshold=0),
        DagNode(7, "G_AND", NodeOp.AND, inputs=(10, 2)),
        DagNode(8, "G_OR", NodeOp.OR, inputs=(3, 4)),
        DagNode(9, "G_XOR", NodeOp.XOR, inputs=(7, 8)),
        DagNode(11, "G_NOT", NodeOp.NOT, inputs=(5,)),
        DagNode(12, "G_NAND", NodeOp.NAND, inputs=(6, 9)),
        DagNode(13, "G_NOR", NodeOp.NOR, inputs=(11, 12), is_hazard_output=True),
    ]
    topo = validate_and_sort_dag(nodes)
    assert topo == (2, 3, 4, 5, 6, 8, 10, 7, 9, 11, 12, 13)
    regs = [0] * MAX_REGISTERS
    regs[0] = 101
    regs[1] = 50
    regs[2] = 5
    regs[3] = 20
    regs[4] = 8
    regs[5] = 0
    tripped, trip_id, _ = evaluate_dag({n.node_id: n for n in nodes}, topo, regs)
    assert not tripped and trip_id == -1

    regs[2] = 15
    regs[3] = 25
    regs[4] = 7
    regs[5] = 1
    tripped, trip_id, _ = evaluate_dag({n.node_id: n for n in nodes}, topo, regs)
    assert tripped and trip_id == 13

    cyclic = [
        DagNode(0, "A", NodeOp.NOT, inputs=(1,)),
        DagNode(1, "B", NodeOp.NOT, inputs=(0,)),
    ]
    with pytest.raises(ValueError, match="Cyclic"):
        validate_and_sort_dag(cyclic)


@pytest.mark.parametrize(
    ("op", "reg_val", "threshold", "expected_bit"),
    [
        (NodeOp.CMP_GT, 101, 100, 1),
        (NodeOp.CMP_GT, 100, 100, 0),
        (NodeOp.CMP_GE, 100, 100, 1),
        (NodeOp.CMP_GE, 99, 100, 0),
        (NodeOp.CMP_LT, -5, 0, 1),
        (NodeOp.CMP_LT, 0, 0, 0),
        (NodeOp.CMP_LE, 0, 0, 1),
        (NodeOp.CMP_LE, 1, 0, 0),
        (NodeOp.CMP_EQ, 42, 42, 1),
        (NodeOp.CMP_EQ, 41, 42, 0),
        (NodeOp.CMP_NE, 41, 42, 1),
        (NodeOp.CMP_NE, 42, 42, 0),
    ],
)
def test_f4_individual_comparator_ops(
    op: NodeOp,
    reg_val: int,
    threshold: int,
    expected_bit: int,
) -> None:
    """Verify each of the 6 comparator operations on true and false boundaries."""
    node = DagNode(0, "CMP", op, target_reg=3, threshold=threshold, is_hazard_output=True)
    regs = [0] * MAX_REGISTERS
    regs[3] = reg_val
    tripped, trip_id, bits = evaluate_dag({0: node}, (0,), regs)
    assert bits == (expected_bit,)
    assert tripped is (expected_bit == 1)
    assert trip_id == (0 if expected_bit == 1 else -1)


@pytest.mark.parametrize(
    ("op", "in_bits", "expected_bit"),
    [
        (NodeOp.AND, (1, 1), 1),
        (NodeOp.AND, (1, 0), 0),
        (NodeOp.OR, (0, 1), 1),
        (NodeOp.OR, (0, 0), 0),
        (NodeOp.XOR, (1, 0), 1),
        (NodeOp.XOR, (1, 1), 0),
        (NodeOp.NOT, (0,), 1),
        (NodeOp.NOT, (1,), 0),
        (NodeOp.NAND, (1, 0), 1),
        (NodeOp.NAND, (1, 1), 0),
        (NodeOp.NOR, (0, 0), 1),
        (NodeOp.NOR, (0, 1), 0),
    ],
)
def test_f4_individual_logic_gate_ops(
    op: NodeOp,
    in_bits: tuple[int, ...],
    expected_bit: int,
) -> None:
    """Verify each of the 6 combinational logic gates across bit combinations."""
    regs = [0] * MAX_REGISTERS
    nodes: list[DagNode] = []
    for idx, b in enumerate(in_bits):
        regs[idx] = b
        nodes.append(DagNode(idx, f"IN_{idx}", NodeOp.CMP_EQ, target_reg=idx, threshold=1))
    gate_id = len(in_bits)
    nodes.append(
        DagNode(
            gate_id,
            "GATE",
            op,
            inputs=tuple(range(len(in_bits))),
            is_hazard_output=True,
        )
    )
    topo = validate_and_sort_dag(nodes)
    tripped, trip_id, bits = evaluate_dag({n.node_id: n for n in nodes}, topo, regs)
    assert bits[-1] == expected_bit
    assert tripped is (expected_bit == 1)
    assert trip_id == (gate_id if expected_bit == 1 else -1)


def test_f4_trial_write_atomic_rollback_on_interlock_trip() -> None:
    """Multi-register write tripping interlock on reg 1 leaves reg 0 unmodified."""
    nodes = [
        DagNode(0, "OVER_TEMP", NodeOp.CMP_GT, target_reg=1, threshold=500, is_hazard_output=True),
    ]
    packets = [
        RawPacket("PKT1", "PLC_A", 1, 100, ProtocolType.MODBUS_TCP, _mb_write_single(0, 77)),
        RawPacket(
            "PKT2",
            "PLC_A",
            2,
            200,
            ProtocolType.MODBUS_TCP,
            _mb_write_multi(0, [999, 600]),
        ),
    ]
    res = evaluate_packet_stream(packets, nodes)
    assert res.verdicts[0].verdict_code == VerdictCode.ALLOW_WRITE
    assert res.verdicts[1].verdict_code == VerdictCode.INTERLOCK_TRIPPED
    assert res.verdicts[1].tripped_node_id == 0
    assert res.final_registers[0] == 77
    assert res.final_registers[1] == 0


def test_f5_ecd_nygard_breaker_fencing_rate_limit_and_chain_verification() -> None:
    """Exercise replay defense, rate limit, breaker OPEN fast-fail, and HALF_OPEN probe."""
    nodes = [
        DagNode(0, "HI_PRESS", NodeOp.CMP_GT, target_reg=0, threshold=100, is_hazard_output=True),
    ]
    policy = FirewallPolicy(
        window_ms=1_000, max_requests_per_window=3, trip_threshold=2, cooldown_ms=5_000
    )
    packets = [
        RawPacket("P1", "PLC1", 10, 1_000, ProtocolType.MODBUS_TCP, _mb_write_single(0, 50)),
        RawPacket("P2", "PLC1", 10, 1_100, ProtocolType.MODBUS_TCP, _mb_read(0, 1)),
        RawPacket("P3", "PLC1", 11, 1_200, ProtocolType.MODBUS_TCP, _mb_write_single(0, 200)),
        RawPacket("P4", "PLC1", 12, 2_000, ProtocolType.MODBUS_TCP, _mb_read(0, 1)),
        RawPacket("P5", "PLC1", 13, 6_200, ProtocolType.MODBUS_TCP, _mb_write_single(0, 200)),
        RawPacket("P6", "PLC1", 14, 12_000, ProtocolType.MODBUS_TCP, _mb_read(0, 1)),
        RawPacket("P7", "PLC1", 15, 12_100, ProtocolType.MODBUS_TCP, _mb_read(0, 1)),
        RawPacket("P8", "PLC1", 16, 12_200, ProtocolType.MODBUS_TCP, _mb_read(0, 1)),
        RawPacket("P9", "PLC1", 17, 12_300, ProtocolType.MODBUS_TCP, _mb_read(0, 1)),
    ]
    res = evaluate_packet_stream(packets, nodes, policy=policy)
    codes = [v.verdict_code for v in res.verdicts]
    assert codes == [
        VerdictCode.ALLOW_WRITE,
        VerdictCode.REPLAY_ATTACK_BLOCKED,
        VerdictCode.INTERLOCK_TRIPPED,
        VerdictCode.CIRCUIT_BREAKER_OPEN,
        VerdictCode.INTERLOCK_TRIPPED,
        VerdictCode.ALLOW_READ,
        VerdictCode.ALLOW_READ,
        VerdictCode.ALLOW_READ,
        VerdictCode.RATE_LIMIT_EXCEEDED,
    ]
    assert res.verdicts[2].breaker_state_after == BreakerState.OPEN
    assert res.verdicts[3].breaker_state_after == BreakerState.OPEN
    assert res.verdicts[4].breaker_state_after == BreakerState.OPEN
    assert res.verdicts[5].breaker_state_after == BreakerState.CLOSED
    assert res.final_registers[0] == 50
    assert verify_verdict_chain(res.verdicts)

    tampered = res.verdicts[0]
    bad_verdict = PacketVerdict(
        seq_index=tampered.seq_index,
        packet_id=tampered.packet_id,
        source_id=tampered.source_id,
        seq_no=tampered.seq_no,
        timestamp_ms=tampered.timestamp_ms,
        protocol=tampered.protocol,
        verdict_code=tampered.verdict_code,
        is_allowed=tampered.is_allowed,
        tripped_node_id=tampered.tripped_node_id,
        breaker_state_after=tampered.breaker_state_after,
        prev_hash_u64=tampered.prev_hash_u64,
        chain_hash_u64=tampered.chain_hash_u64 ^ 1,
    )
    assert not verify_verdict_chain((bad_verdict,) + res.verdicts[1:])


def test_r04_r05_cpp_cli_parity_including_multiblock_blake2b() -> None:
    """Verify bit-for-bit parity between vectragate_cli.exe and Python firewall core."""
    root = pathlib.Path(__file__).resolve().parent.parent
    exe_path = root.joinpath("vectragate_cli.exe")
    assert exe_path.exists()

    nodes = [
        DagNode(0, "PRESS_HI", NodeOp.CMP_GT, target_reg=10, threshold=1000),
        DagNode(1, "VALVE_OPEN", NodeOp.CMP_EQ, target_reg=11, threshold=1),
        DagNode(2, "HAZARD_AND", NodeOp.AND, inputs=(0, 1), is_hazard_output=True),
    ]
    policy = FirewallPolicy(
        window_ms=2_000, max_requests_per_window=4, trip_threshold=2, cooldown_ms=5_000
    )
    init_regs = [0] * MAX_REGISTERS
    init_regs[10] = 500
    long_pkt = "PKT_" + ("A" * 28)
    long_src = "SRC_" + ("B" * 28)
    mb_pkt = "PKT_LONG_" + ("D" * 23)
    mb_src = "SRC_LONG_" + ("C" * 23)
    packets = [
        RawPacket(long_pkt, long_src, 1, 100, ProtocolType.MODBUS_TCP, _mb_write_single(11, 1)),
        RawPacket(
            "P2", long_src, 2, 200, ProtocolType.MQTT, _mqtt_ascii("boiler/pressure", "SET 10 1200")
        ),
        RawPacket(
            "P3", long_src, 3, 300, ProtocolType.MQTT, _mqtt_ascii("boiler/pressure", "SET 10 900")
        ),
        RawPacket("P4", long_src, 2, 400, ProtocolType.MODBUS_TCP, _mb_read(10, 2)),
        RawPacket("P5", "PLC_Z", 1, 450, ProtocolType.MODBUS_TCP, "0001000000ff0103"),
        RawPacket(
            mb_pkt, mb_src, 123_456_789, 9_999_999_999, ProtocolType.MODBUS_TCP, "0001000000ff0103"
        ),
    ]
    py_res = evaluate_packet_stream(packets, nodes, initial_registers=init_regs, policy=policy)
    last_v = py_res.verdicts[-1]
    last_preimage = (
        f"{last_v.prev_hash_u64:016x}|{last_v.packet_id}|{last_v.seq_no}|"
        f"{last_v.timestamp_ms}|{last_v.source_id}|{last_v.protocol.value}|"
        f"{last_v.verdict_code.value}|{last_v.tripped_node_id}|{last_v.breaker_state_after.value}"
    )
    assert len(last_preimage.encode("ascii")) > 128

    lines = [
        (f"POLICY {policy.window_ms} {policy.max_requests_per_window} "
         f"{policy.trip_threshold} {policy.cooldown_ms}"),
        "REG 10 500",
    ]
    for n in nodes:
        in_part = (" " + " ".join(str(x) for x in n.inputs)) if n.inputs else ""
        lines.append(
            f"NODE {n.node_id} {n.tag} {n.op.value} {n.target_reg} {n.threshold} "
            f"{1 if n.is_hazard_output else 0} {len(n.inputs)}{in_part}"
        )
    for p in packets:
        lines.append(
            f"PKT {p.packet_id} {p.source_id} {p.seq_no} {p.timestamp_ms} "
            f"{p.protocol.value} {p.payload_hex}"
        )
    lines.append("END")

    proc = subprocess.run(
        [str(exe_path)],
        input="\n".join(lines) + "\n",
        text=True,
        capture_output=True,
        check=True,
    )
    out_lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
    topo_tokens = out_lines[0].split()
    assert tuple(int(x) for x in topo_tokens[1:]) == py_res.topological_order

    verdict_lines = [ln for ln in out_lines if ln.startswith("VERDICT ")]
    assert len(verdict_lines) == len(py_res.verdicts)
    for v_py, ln in zip(py_res.verdicts, verdict_lines, strict=True):
        parts = ln.split()
        assert int(parts[1]) == v_py.seq_index
        assert parts[2] == v_py.packet_id
        assert parts[3] == v_py.source_id
        assert int(parts[4]) == v_py.seq_no
        assert int(parts[5]) == v_py.timestamp_ms
        assert parts[6] == v_py.protocol.value
        assert parts[7] == v_py.verdict_code.value
        assert (parts[8] == "1") == v_py.is_allowed
        assert int(parts[9]) == v_py.tripped_node_id
        assert parts[10] == v_py.breaker_state_after.value
        assert int(parts[11], 16) == v_py.prev_hash_u64
        assert int(parts[12], 16) == v_py.chain_hash_u64

    regs_line = next(ln for ln in out_lines if ln.startswith("REGS ")).split()
    assert tuple(int(x) for x in regs_line[1:]) == py_res.final_registers

    sum_parts = next(ln for ln in out_lines if ln.startswith("SUMMARY ")).split()
    assert int(sum_parts[1]) == py_res.allowed_count
    assert int(sum_parts[2]) == py_res.blocked_count
    assert int(sum_parts[3], 16) == py_res.final_chain_hash_u64


def test_f04_cpp_spsc_ring_buffer_selftest_saturation_and_wraparound() -> None:
    """Verify C++ 256-slot SPSC ring buffer full saturation and wrap-around (F-04)."""
    root = pathlib.Path(__file__).resolve().parent.parent
    exe_path = root.joinpath("vectragate_cli.exe")
    proc = subprocess.run(
        [str(exe_path), "--selftest-spsc"],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stdout.strip() == "SPSC_SELFTEST_OK"


@pytest.mark.parametrize(
    "bad_stdin",
    [
        "POLICY 1000 65 3 5000\nEND\n",
        "REG 256 10\nEND\n",
        "REG 0 99999\nEND\n",
        "NODE 0 BAD_REG CMP_GT 256 100 1 0\nEND\n",
        "NODE 0 BAD_ARITY AND 0 0 1 0\nEND\n",
        "PKT P1 S1 0 100 MODBUS_TCP 000100000006010300000001\nEND\n",
    ],
)
def test_f03_cpp_cli_rejects_malformed_directives_and_oob_bounds(bad_stdin: str) -> None:
    """Verify C++ CLI rejects out-of-bounds POLICY, REG, NODE, and PKT directives (F-03)."""
    root = pathlib.Path(__file__).resolve().parent.parent
    exe_path = root.joinpath("vectragate_cli.exe")
    proc = subprocess.run(
        [str(exe_path)],
        input=bad_stdin,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode != 0

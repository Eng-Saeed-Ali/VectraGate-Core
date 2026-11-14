"""Layer 4 Rich Unicode SIEM dashboard and CLI entrypoint for VectraGate-Core."""

from __future__ import annotations

import argparse
import pathlib
from collections.abc import Sequence

from vectragate.cpp_bridge import run_cpp_engine
from vectragate.exporters import export_xlsx_atomic, query_duckdb_siem_summary
from vectragate.firewall import evaluate_packet_stream, verify_verdict_chain
from vectragate.intake_gate import ingest_json_bundle
from vectragate.models import (
    MAX_REGISTERS,
    DagNode,
    FirewallPolicy,
    FirewallRunResult,
    NodeOp,
    ProtocolType,
    RawPacket,
)


def _mb_frame_hex(fc: int, addr: int, val_or_cnt: int) -> str:
    """Build valid 12-byte Modbus TCP FC 0x03/0x05/0x06 frame as hex."""
    assert fc in (0x03, 0x05, 0x06)
    assert 0 <= addr < MAX_REGISTERS
    frame = (
        (1).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + (6).to_bytes(2, "big")
        + bytes((1, fc))
        + addr.to_bytes(2, "big")
        + (val_or_cnt & 0xFFFF).to_bytes(2, "big")
    )
    return frame.hex()


def _mqtt_set_hex(topic: str, cmd: str) -> str:
    """Build valid QoS 0 MQTT PUBLISH frame with ASCII SET command as hex."""
    assert len(topic) > 0
    assert cmd.startswith("SET ")
    topic_b = topic.encode("utf-8")
    body = len(topic_b).to_bytes(2, "big") + topic_b + cmd.encode("ascii")
    assert len(body) < 128
    return (bytes((0x30, len(body))) + body).hex()


def _demo_dag_and_policy() -> tuple[
    tuple[DagNode, ...], tuple[int, ...], FirewallPolicy
]:
    """Construct industrial thermal-gas safety interlock DAG, registers, and policy."""
    nodes = (
        DagNode(0, "TEMP_HIGH", NodeOp.CMP_GT, target_reg=0, threshold=800),
        DagNode(1, "PUMP_OFF", NodeOp.CMP_EQ, target_reg=1, threshold=0),
        DagNode(2, "GAS_VALVE_OPEN", NodeOp.CMP_EQ, target_reg=2, threshold=1),
        DagNode(3, "OVERHEAT_NO_COOL", NodeOp.AND, inputs=(0, 1)),
        DagNode(
            4,
            "THERMAL_GAS_HAZARD",
            NodeOp.AND,
            inputs=(3, 2),
            is_hazard_output=True,
        ),
    )
    regs = [0] * MAX_REGISTERS
    regs[0] = 600
    regs[1] = 1
    regs[2] = 0
    policy = FirewallPolicy(
        window_ms=1_000, max_requests_per_window=4, trip_threshold=3, cooldown_ms=5_000
    )
    assert len(nodes) == 5
    assert len(regs) == MAX_REGISTERS
    return nodes, tuple(regs), policy


def build_demo_scenario() -> tuple[
    tuple[RawPacket, ...], tuple[DagNode, ...], tuple[int, ...], FirewallPolicy
]:
    """Build deterministic 14-packet OT/ICS demo covering all firewall mechanisms."""
    nodes, init_regs, policy = _demo_dag_and_policy()
    bad_mb_bc = "00010000000b0110000a00020500010002"
    mqtt_varint_ovf = "30ffffffff01"
    packets = (
        RawPacket("PKT_01", "PLC_MAIN", 1, 100, ProtocolType.MODBUS_TCP, _mb_frame_hex(0x06, 0, 850)),
        RawPacket("PKT_02", "PLC_MAIN", 2, 200, ProtocolType.MODBUS_TCP, _mb_frame_hex(0x03, 0, 3)),
        RawPacket("PKT_03", "PLC_MAIN", 3, 300, ProtocolType.MQTT, _mqtt_set_hex("plant/cooling", "SET 1 0")),
        RawPacket("PKT_04", "PLC_MAIN", 4, 400, ProtocolType.MODBUS_TCP, _mb_frame_hex(0x05, 2, 0xFF00)),
        RawPacket("PKT_05", "PLC_MAIN", 4, 450, ProtocolType.MODBUS_TCP, _mb_frame_hex(0x03, 0, 1)),
        RawPacket("PKT_06", "PLC_MAIN", 5, 1500, ProtocolType.MODBUS_TCP, bad_mb_bc),
        RawPacket("PKT_07", "PLC_MAIN", 6, 2000, ProtocolType.MODBUS_TCP, _mb_frame_hex(0x03, 0, 1)),
        RawPacket("PKT_08", "PLC_MAIN", 6, 7000, ProtocolType.MQTT, _mqtt_set_hex("plant/cooling", "SET 1 1")),
        RawPacket("PKT_09", "PLC_MAIN", 7, 7100, ProtocolType.MODBUS_TCP, _mb_frame_hex(0x05, 2, 0xFF00)),
        RawPacket("PKT_10", "EDGE_GW", 1, 7200, ProtocolType.MQTT, _mqtt_set_hex("sensors/aux", "SET 5 42")),
        RawPacket("PKT_11", "EDGE_GW", 2, 7300, ProtocolType.MQTT, mqtt_varint_ovf),
        RawPacket("PKT_12", "EDGE_GW", 3, 7400, ProtocolType.MODBUS_TCP, _mb_frame_hex(0x03, 5, 1)),
        RawPacket("PKT_13", "EDGE_GW", 4, 7500, ProtocolType.MODBUS_TCP, _mb_frame_hex(0x03, 5, 1)),
        RawPacket("PKT_14", "EDGE_GW", 5, 7600, ProtocolType.MODBUS_TCP, _mb_frame_hex(0x03, 5, 1)),
    )
    assert len(packets) == 14
    assert len(init_regs) == MAX_REGISTERS
    return packets, nodes, init_regs, policy


def _format_verdict_rows(result: FirewallRunResult) -> list[str]:
    """Format packet verdict rows for the ASCII/Unicode SIEM console report."""
    assert isinstance(result, FirewallRunResult)
    lines = [
        "  Seq PacketID   SourceID   SeqNo   TimeMs Protocol    Status   Trip Breaker    VerdictCode",
        "  --- ---------- ---------- ----- -------- ----------- -------- ---- ---------- --------------------------",
    ]
    for v in result.verdicts:
        status = "ALLOW" if v.is_allowed else "BLOCK"
        lines.append(
            f"  {v.seq_index:>3} {v.packet_id:<10} {v.source_id:<10} {v.seq_no:>5} "
            f"{v.timestamp_ms:>8} {v.protocol.value:<11} {status:<8} "
            f"{v.tripped_node_id:>4} {v.breaker_state_after.value:<10} {v.verdict_code.value}"
        )
    assert len(lines) == 2 + len(result.verdicts)
    return lines


def _format_source_rows(result: FirewallRunResult) -> list[str]:
    """Format per-source Nygard circuit-breaker and Kleppmann fencing summary."""
    assert isinstance(result, FirewallRunResult)
    lines = [
        "  SourceID   LastSeq Breaker    Fail Viol OpenedMs WinLen",
        "  ---------- ------- ---------- ---- ---- -------- ------",
    ]
    for s in result.source_states:
        lines.append(
            f"  {s.source_id:<10} {s.last_seq_no:>7} {s.breaker_state.value:<10} "
            f"{s.consecutive_failures:>4} {s.total_violations:>4} "
            f"{s.opened_at_ms:>8} {len(s.window_timestamps):>6}"
        )
    assert len(lines) == 2 + len(result.source_states)
    return lines


def render_firewall_report(result: FirewallRunResult) -> str:
    """Render deterministic Unicode SIEM firewall report and DuckDB 2.0 summary."""
    if not isinstance(result, FirewallRunResult):
        raise TypeError("result must be FirewallRunResult")
    chain_ok = verify_verdict_chain(result.verdicts)
    siem = query_duckdb_siem_summary(result)
    assert len(siem) == 9
    assert len(result.final_registers) == MAX_REGISTERS
    topo_text = " -> ".join(str(n) for n in result.topological_order) or "(empty)"
    chain_lbl = "VALID" if chain_ok else "BROKEN"
    out = [
        "╔════════════════════════════════════════════════════════════════════════════╗",
        "║               VectraGate-Core (بَرْزَخ) OT/ICS Firewall Report              ║",
        "╚════════════════════════════════════════════════════════════════════════════╝",
        f"  Topological Order : {topo_text}",
        f"  BLAKE2b-64 Chain  : {chain_lbl} | Final = 0x{result.final_chain_hash_u64:016x}",
        (
            f"  SIEM DuckDB 2.0   : total={siem['total_packets']} allow={siem['allowed_packets']} "
            f"block={siem['blocked_packets']} interlock={siem['interlock_trips']} "
            f"replay={siem['replay_blocks']} rate={siem['rate_limit_blocks']} "
            f"breaker={siem['breaker_blocks']} proto={siem['protocol_errors']} "
            f"open={siem['open_breakers']}"
        ),
        "",
        "── Packet Verdicts ───────────────────────────────────────────────────────────",
        *_format_verdict_rows(result),
        "",
        "── Source Security States ────────────────────────────────────────────────────",
        *_format_source_rows(result),
    ]
    return "\n".join(out)


def _build_arg_parser() -> argparse.ArgumentParser:
    """Construct CLI parser supporting --demo, --bundle, --export-xlsx, --verify-cpp."""
    parser = argparse.ArgumentParser(
        prog="vectragate.cli_visualizer",
        description="VectraGate-Core OT/ICS Firewall Evaluator & SIEM Audit Tool",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--demo", action="store_true", help="Run built-in 14-packet demo")
    group.add_argument("--bundle", type=str, help="Path to vectragate.bundle/v1 JSON")
    parser.add_argument("--export-xlsx", type=str, help="Write styled 4-sheet .xlsx")
    parser.add_argument("--verify-cpp", action="store_true", help="Verify C++ parity")
    assert parser.prog == "vectragate.cli_visualizer"
    assert isinstance(parser, argparse.ArgumentParser)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for evaluating bundles, exporting Excel, and checking C++ parity."""
    parser = _build_arg_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.bundle:
        raw_bytes = pathlib.Path(args.bundle).read_bytes()
        packets, nodes, init_regs, policy = ingest_json_bundle(raw_bytes)
    else:
        packets, nodes, init_regs, policy = build_demo_scenario()
    py_res = evaluate_packet_stream(
        packets, nodes, initial_registers=init_regs, policy=policy
    )
    assert verify_verdict_chain(py_res.verdicts)
    report = render_firewall_report(py_res)
    if args.verify_cpp:
        cpp_res = run_cpp_engine(
            packets, nodes, initial_registers=init_regs, policy=policy
        )
        if cpp_res != py_res:
            print("ERROR: C++ native engine diverged from Python reference!")
            return 2
        report = (
            f"{report}\n\n[C++ NATIVE PARITY VERIFIED: vectragate_cli.exe == "
            f"Python Core | Final Chain 0x{cpp_res.final_chain_hash_u64:016x}]"
        )
    if args.export_xlsx:
        export_xlsx_atomic(py_res, args.export_xlsx)
        report = f"{report}\n[XLSX EXPORTED ATOMICALLY: {args.export_xlsx}]"
    assert len(report) > 0
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Integration tests for intake_gate, cpp_bridge, exporters, and cli_visualizer."""

from __future__ import annotations

import json
import pathlib

import pytest
from openpyxl import load_workbook

from vectragate import (
    MAX_PAYLOAD_BYTES,
    MAX_REGISTERS,
    BreakerState,
    IntakeError,
    ProtocolType,
    RawPacket,
    VerdictCode,
    build_demo_scenario,
    compile_cpp_engine,
    evaluate_packet_stream,
    export_xlsx_atomic,
    ingest_json_bundle,
    ingest_json_bundle_report,
    main,
    neutralize_formula_cell,
    query_duckdb_siem_summary,
    render_firewall_report,
    run_cpp_engine,
    verify_verdict_chain,
)
from vectragate.models import DagNode, NodeOp


def _sample_bundle_dict() -> dict[str, object]:
    """Construct a minimal valid vectragate.bundle/v1 payload dictionary."""
    return {
        "schema_version": "vectragate.bundle/v1",
        "policy": {
            "window_ms": 2_000,
            "max_requests_per_window": 4,
            "trip_threshold": 2,
            "cooldown_ms": 5_000,
        },
        "initial_registers": {"0": 700, "1": 1},
        "dag_nodes": [
            {
                "node_id": 0,
                "tag": "OVER_TEMP",
                "op": "CMP_GT",
                "target_reg": 0,
                "threshold": 800,
                "is_hazard_output": True,
            }
        ],
        "packets": [
            {
                "packet_id": "PKT_1",
                "source_id": "-PLC_HAZ",
                "seq_no": 1,
                "timestamp_ms": 100,
                "protocol": "MODBUS_TCP",
                "payload_hex": "0001000000060106000002ee",
            },
            {
                "packet_id": "PKT_2",
                "source_id": "PLC_B",
                "seq_no": 1,
                "timestamp_ms": 200,
                "protocol": "MODBUS_TCP",
                "payload_hex": "000100000006010300000002",
            },
        ],
    }


def _bundle_with_override(key: str, val: object) -> str:
    """Return JSON bundle string with one root key overridden."""
    base = _sample_bundle_dict()
    base[key] = val
    return json.dumps(base)


def _intake_defense_payload(case_name: str) -> str | bytes:
    """Return the adversarial payload corresponding to case_name."""
    if case_name == "oversized_4mib":
        return b"{" + (b" " * MAX_PAYLOAD_BYTES) + b"}"
    cases: dict[str, str | bytes] = {
        "invalid_utf8_bytes": b"\xff\xfe",
        "raw_nul_byte": b'{"a": "\x00"}',
        "lone_surrogate_str": "\ud800",
        "escaped_surrogate_json": '{"schema_version": "\\uD800"}',
        "escaped_nul_json": '{"schema_version": "\\u0000"}',
        "depth_exceeds_8": '{"a":' + ("[" * 8) + "1" + ("]" * 8) + "}",
        "float_literal_rejected": '{"threshold": 1.5}',
        "nan_constant_rejected": '{"threshold": NaN}',
        "unsupported_schema_version": _bundle_with_override(
            "schema_version", "vectragate.bundle/v0"
        ),
        "unknown_root_key": _bundle_with_override("extra_field", 1),
        "cyclic_dag_in_bundle": _bundle_with_override(
            "dag_nodes",
            [
                {"node_id": 0, "tag": "A", "op": "NOT", "inputs": [1]},
                {"node_id": 1, "tag": "B", "op": "NOT", "inputs": [0]},
            ],
        ),
    }
    return cases[case_name]


@pytest.mark.parametrize(
    ("case_name", "expected_match"),
    [
        ("oversized_4mib", "PAYLOAD_TOO_LARGE"),
        ("invalid_utf8_bytes", "INVALID_UTF8"),
        ("raw_nul_byte", "NUL_BYTE_FORBIDDEN"),
        ("lone_surrogate_str", "INVALID_STRING"),
        ("escaped_surrogate_json", "INVALID_STRING_TOKEN"),
        ("escaped_nul_json", "INVALID_STRING_TOKEN"),
        ("depth_exceeds_8", "JSON_DEPTH_EXCEEDED"),
        ("float_literal_rejected", "FLOAT_FORBIDDEN"),
        ("nan_constant_rejected", "FLOAT_FORBIDDEN"),
        ("unsupported_schema_version", "UNSUPPORTED_SCHEMA_VERSION"),
        ("unknown_root_key", "UNKNOWN_ROOT_KEYS"),
        ("cyclic_dag_in_bundle", "INVALID_DAG_GRAPH"),
    ],
)
def test_f7_intake_gate_stage1_to_stage3_individual_defenses(
    case_name: str,
    expected_match: str,
) -> None:
    """Enforce 4 MiB limit, UTF-8/NUL/surrogate checks, depth <= 8, and zero floats."""
    assert len(case_name) > 0
    with pytest.raises(IntakeError, match=expected_match):
        ingest_json_bundle(_intake_defense_payload(case_name))


def test_f7_stage4_packet_quarantine_and_sparse_registers() -> None:
    """Quarantine invalid packets in report mode while rejecting in strict mode."""
    bundle = _sample_bundle_dict()
    raw_pkts = bundle["packets"]
    assert isinstance(raw_pkts, list)
    raw_pkts.append(
        {
            "packet_id": "BAD_SEQ",
            "source_id": "PLC_C",
            "seq_no": 0,
            "timestamp_ms": 300,
            "protocol": "MODBUS_TCP",
            "payload_hex": "000100000006010300000001",
        }
    )
    raw_pkts.append("NOT_AN_OBJECT")
    text = json.dumps(bundle)

    pkts, nodes, init_regs, policy, rejections = ingest_json_bundle_report(text)
    assert len(pkts) == 2
    assert len(nodes) == 1
    assert len(init_regs) == MAX_REGISTERS
    assert init_regs[0] == 700 and init_regs[1] == 1
    assert policy.trip_threshold == 2
    assert len(rejections) == 2
    assert rejections[0].packet_index == 2 and rejections[0].packet_id == "BAD_SEQ"
    assert rejections[1].packet_index == 3 and rejections[1].packet_id is None

    with pytest.raises(IntakeError, match="PACKET_QUARANTINED"):
        ingest_json_bundle(text)


@pytest.mark.parametrize(
    "sample",
    [
        "=CMD|'/C calc'!A0",
        "＝SUM(1)",
        " =1+1",
        " \t=1+1",
        "\n=1+1",
        "\r+1",
        "|calc",
        "%0A",
        "@SUM(A1)",
        "+1",
        "-EVIL",
    ],
)
def test_f8_cwe1236_individual_trigger_neutralization(sample: str) -> None:
    """Verify each OWASP 2026 CWE-1236 trigger and NFKC homoglyph is prefixed with '."""
    assert neutralize_formula_cell(sample) == "'" + sample


def test_f8_atomic_xlsx_all_4_sheets_zero_none_cells_and_live_sum_formulas(
    tmp_path: pathlib.Path,
) -> None:
    """Verify full CWE-1236 shielding, 0 None cells, and live =SUM across all 4 sheets."""
    assert neutralize_formula_cell("") == "\u2014"
    assert neutralize_formula_cell("PLC_MAIN") == "PLC_MAIN"

    packets = (
        RawPacket("P1", "-EVIL_SRC", 1, 100, ProtocolType.MODBUS_TCP, "000100000006010600000064"),
        RawPacket("P2", "SAFE_SRC", 1, 200, ProtocolType.MODBUS_TCP, "000100000006010300000001"),
    )
    nodes = (DagNode(0, "HI", NodeOp.CMP_GT, target_reg=0, threshold=500, is_hazard_output=True),)
    res = evaluate_packet_stream(packets, nodes)

    xlsx_path = tmp_path.joinpath("siem_audit.xlsx")
    export_xlsx_atomic(res, xlsx_path)
    assert xlsx_path.exists()
    leftover_tmp = [p for p in tmp_path.iterdir() if p.name.startswith(".tmp_")]
    assert leftover_tmp == []

    wb = load_workbook(xlsx_path, data_only=False)
    assert wb.sheetnames == [
        "PacketVerdicts",
        "RegisterSnapshot",
        "SourceSecurityState",
        "SIEMSummary",
    ]
    for sheet_name in wb.sheetnames:
        ws = wb[sheet_name]
        for r in range(1, ws.max_row + 1):
            for c in range(1, ws.max_column + 1):
                assert ws.cell(row=r, column=c).value is not None

    ws_verdicts = wb["PacketVerdicts"]
    assert ws_verdicts["A1"].fill.fgColor.rgb == "000F172A"
    assert ws_verdicts["C2"].value == "'-EVIL_SRC"
    assert ws_verdicts["C2"].data_type == "s"
    assert ws_verdicts["K2"].data_type == "s"
    assert ws_verdicts["L2"].data_type == "s"
    assert ws_verdicts["A4"].value == "TOTAL"
    assert ws_verdicts["H4"].value == "=SUM(H2:H3)"
    assert ws_verdicts["H4"].data_type == "f"

    ws_regs = wb["RegisterSnapshot"]
    assert ws_regs["A258"].value == "TOTAL"
    assert ws_regs["B258"].value == "=SUM(B2:B257)"
    assert ws_regs["B258"].data_type == "f"

    ws_sources = wb["SourceSecurityState"]
    assert ws_sources["A2"].value == "'-EVIL_SRC"
    assert ws_sources["A2"].data_type == "s"
    assert ws_sources["A4"].value == "TOTAL"
    assert ws_sources["D4"].fill.fgColor.rgb == "00D1FAE5"
    assert ws_sources["D4"].value == "=SUM(D2:D3)"
    assert ws_sources["E4"].value == "=SUM(E2:E3)"
    assert ws_sources["G4"].value == "=SUM(G2:G3)"

    ws_summary = wb["SIEMSummary"]
    assert ws_summary["A9"].value == "TOTAL"
    assert ws_summary["B9"].fill.fgColor.rgb == "00D1FAE5"
    assert ws_summary["B9"].value == "=SUM(B2:B8)"
    assert ws_summary["A10"].value == "OPEN_BREAKERS"
    assert ws_summary["A11"].value == "FINAL_CHAIN_HASH_HEX"
    assert ws_summary["B11"].data_type == "s"

    empty_res = evaluate_packet_stream((), ())
    empty_xlsx = tmp_path.joinpath("empty_audit.xlsx")
    export_xlsx_atomic(empty_res, empty_xlsx)
    wb_empty = load_workbook(empty_xlsx, data_only=False)
    for sheet_name in wb_empty.sheetnames:
        ws_e = wb_empty[sheet_name]
        for r in range(1, ws_e.max_row + 1):
            for c in range(1, ws_e.max_column + 1):
                assert ws_e.cell(row=r, column=c).value is not None


def test_demo_scenario_duckdb_siem_cpp_parity_and_cli(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify demo scenario, DuckDB 2.0 views, C++ bridge parity, and CLI flags."""
    exe_path = compile_cpp_engine()
    assert exe_path.exists()

    packets, nodes, init_regs, policy = build_demo_scenario()
    py_res = evaluate_packet_stream(
        packets, nodes, initial_registers=init_regs, policy=policy
    )
    cpp_res = run_cpp_engine(
        packets, nodes, initial_registers=init_regs, policy=policy
    )
    assert cpp_res == py_res
    assert verify_verdict_chain(py_res.verdicts)

    verdict_set = {v.verdict_code for v in py_res.verdicts}
    assert VerdictCode.ALLOW_READ in verdict_set
    assert VerdictCode.ALLOW_WRITE in verdict_set
    assert VerdictCode.INTERLOCK_TRIPPED in verdict_set
    assert VerdictCode.REPLAY_ATTACK_BLOCKED in verdict_set
    assert VerdictCode.MODBUS_BYTE_COUNT_MISMATCH in verdict_set
    assert VerdictCode.CIRCUIT_BREAKER_OPEN in verdict_set
    assert VerdictCode.MQTT_VARINT_OVERFLOW in verdict_set
    assert VerdictCode.RATE_LIMIT_EXCEEDED in verdict_set

    plc_main = next(s for s in py_res.source_states if s.source_id == "PLC_MAIN")
    assert plc_main.breaker_state == BreakerState.CLOSED

    siem = query_duckdb_siem_summary(py_res)
    assert siem == {
        "total_packets": 14,
        "allowed_packets": 8,
        "blocked_packets": 6,
        "interlock_trips": 1,
        "replay_blocks": 1,
        "rate_limit_blocks": 1,
        "breaker_blocks": 1,
        "protocol_errors": 2,
        "open_breakers": 0,
    }
    report = render_firewall_report(py_res)
    assert "BLAKE2b-64 Chain  : VALID" in report

    xlsx_out = tmp_path.joinpath("cli_out.xlsx")
    rc_demo = main(["--demo", "--verify-cpp", "--export-xlsx", str(xlsx_out)])
    assert rc_demo == 0
    assert xlsx_out.exists()
    out_demo = capsys.readouterr().out
    assert "C++ NATIVE PARITY VERIFIED" in out_demo

    bundle_path = tmp_path.joinpath("bundle.json")
    bundle_path.write_text(json.dumps(_sample_bundle_dict()), encoding="utf-8")
    rc_bundle = main(["--bundle", str(bundle_path), "--verify-cpp"])
    assert rc_bundle == 0
    out_bundle = capsys.readouterr().out
    assert "C++ NATIVE PARITY VERIFIED" in out_bundle

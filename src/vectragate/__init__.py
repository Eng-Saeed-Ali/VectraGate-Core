"""VectraGate-Core (بَرْزَخ) deterministic OT/ICS protocol firewall package."""

from __future__ import annotations

from vectragate.cpp_bridge import compile_cpp_engine, run_cpp_engine
from vectragate.dag_engine import evaluate_dag, validate_and_sort_dag
from vectragate.exporters import (
    export_xlsx_atomic,
    neutralize_formula_cell,
    query_duckdb_siem_summary,
)
from vectragate.firewall import evaluate_packet_stream, verify_verdict_chain
from vectragate.intake_gate import (
    IntakeError,
    ingest_json_bundle,
    ingest_json_bundle_report,
)
from vectragate.models import (
    GENESIS_HASH_U64,
    MAX_DAG_NODES,
    MAX_JSON_DEPTH,
    MAX_PACKETS,
    MAX_PAYLOAD_BYTES,
    MAX_REG_VAL,
    MAX_REGISTERS,
    MAX_SOURCES,
    MAX_WINDOW_TIMESTAMPS,
    MIN_REG_VAL,
    SPSC_RING_SLOTS,
    BreakerState,
    DagNode,
    DecodedOperation,
    FirewallPolicy,
    FirewallRunResult,
    NodeOp,
    PacketRejection,
    PacketVerdict,
    ProtocolType,
    RawPacket,
    SourceSecurityState,
    VerdictCode,
    blake2b_u64,
    ceil_div,
    compute_verdict_hash,
)
from vectragate.protocol import (
    decode_modbus_tcp,
    decode_mqtt_publish,
    decode_wire_packet,
)

__all__ = [
    "GENESIS_HASH_U64",
    "MAX_DAG_NODES",
    "MAX_JSON_DEPTH",
    "MAX_PACKETS",
    "MAX_PAYLOAD_BYTES",
    "MAX_REGISTERS",
    "MAX_REG_VAL",
    "MAX_SOURCES",
    "MAX_WINDOW_TIMESTAMPS",
    "MIN_REG_VAL",
    "SPSC_RING_SLOTS",
    "BreakerState",
    "DagNode",
    "DecodedOperation",
    "FirewallPolicy",
    "FirewallRunResult",
    "IntakeError",
    "NodeOp",
    "PacketRejection",
    "PacketVerdict",
    "ProtocolType",
    "RawPacket",
    "SourceSecurityState",
    "VerdictCode",
    "blake2b_u64",
    "build_demo_scenario",
    "ceil_div",
    "compile_cpp_engine",
    "compute_verdict_hash",
    "decode_modbus_tcp",
    "decode_mqtt_publish",
    "decode_wire_packet",
    "evaluate_dag",
    "evaluate_packet_stream",
    "export_xlsx_atomic",
    "ingest_json_bundle",
    "ingest_json_bundle_report",
    "main",
    "neutralize_formula_cell",
    "query_duckdb_siem_summary",
    "render_firewall_report",
    "run_cpp_engine",
    "validate_and_sort_dag",
    "verify_verdict_chain",
]


def __getattr__(name: str) -> object:
    """Lazy PEP 562 loader for CLI visualizer exports avoiding runpy warnings."""
    assert isinstance(name, str)
    assert len(name) > 0
    if name in ("build_demo_scenario", "main", "render_firewall_report"):
        from vectragate import cli_visualizer

        return getattr(cli_visualizer, name)
    raise AttributeError(f"module 'vectragate' has no attribute {name!r}")

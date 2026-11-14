"""Layer 3 CWE-1236-shielded .xlsx exporter and DuckDB 2.0 SIEM analytics."""

from __future__ import annotations

import os
import pathlib
import unicodedata
from collections.abc import Sequence

import duckdb
from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.worksheet import Worksheet

from vectragate.firewall import verify_verdict_chain
from vectragate.models import MAX_REGISTERS, FirewallRunResult

_FORMULA_TRIGGERS: tuple[str, ...] = ("=", "+", "-", "@", "|", "%", "\t", "\r", "\n")
_HEADER_FILL: PatternFill = PatternFill(fill_type="solid", fgColor="0F172A")
_TOTAL_FILL: PatternFill = PatternFill(fill_type="solid", fgColor="D1FAE5")
_HEADER_FONT: Font = Font(name="Arial", size=10, bold=True, color="FFFFFF")
_BODY_FONT: Font = Font(name="Arial", size=10, bold=False, color="0F172A")
_TOTAL_FONT: Font = Font(name="Arial", size=10, bold=True, color="064E3B")
_THIN_SIDE: Side = Side(border_style="thin", color="CBD5E1")
_CELL_BORDER: Border = Border(
    left=_THIN_SIDE, right=_THIN_SIDE, top=_THIN_SIDE, bottom=_THIN_SIDE
)


def neutralize_formula_cell(val: str) -> str:
    """Apply full OWASP 2026 CWE-1236 formula injection neutralization."""
    if type(val) is not str:
        raise TypeError("neutralize_formula_cell requires str input")
    assert len(_FORMULA_TRIGGERS) == 9
    if val == "":
        return "\u2014"
    normalized = unicodedata.normalize("NFKC", val).lstrip()
    starts_raw = val[0] in _FORMULA_TRIGGERS
    starts_norm = bool(normalized) and (normalized[0] in _FORMULA_TRIGGERS)
    assert type(starts_raw) is bool
    if starts_raw or starts_norm:
        return "'" + val
    return val


def _write_header_row(ws: Worksheet, headers: Sequence[str]) -> None:
    """Write dark-navy #0F172A styled header row at row 1."""
    assert len(headers) >= 1
    assert isinstance(ws, Worksheet)
    for col_idx, heading in enumerate(headers, start=1):
        cell = ws.cell(row=1, column=col_idx)
        cell.value = neutralize_formula_cell(heading)
        cell.data_type = "s"
        cell.fill = _HEADER_FILL
        cell.font = _HEADER_FONT
        cell.border = _CELL_BORDER
        cell.alignment = Alignment(horizontal="center", vertical="center")


def _write_data_row(ws: Worksheet, row_idx: int, values: Sequence[int | str]) -> None:
    """Write one styled body row enforcing integer format and CWE-1236 text safety."""
    assert row_idx >= 2
    assert len(values) >= 1
    for col_idx, val in enumerate(values, start=1):
        cell = ws.cell(row=row_idx, column=col_idx)
        cell.font = _BODY_FONT
        cell.border = _CELL_BORDER
        if type(val) is int:
            cell.value = val
            cell.number_format = "#,##0"
            cell.alignment = Alignment(horizontal="right", vertical="center")
        elif type(val) is str:
            cell.value = neutralize_formula_cell(val)
            cell.data_type = "s"
            cell.alignment = Alignment(horizontal="left", vertical="center")
        else:
            raise TypeError(f"Unsupported Excel cell value type: {type(val).__name__}")


def _write_total_cell(
    ws: Worksheet, row_idx: int, col_idx: int, val: str, is_formula: bool
) -> None:
    """Write an emerald-highlighted total label or live =SUM(...) formula cell."""
    assert row_idx >= 2
    assert col_idx >= 1
    cell = ws.cell(row=row_idx, column=col_idx)
    cell.fill = _TOTAL_FILL
    cell.font = _TOTAL_FONT
    cell.border = _CELL_BORDER
    if is_formula:
        cell.value = val
        cell.number_format = "#,##0"
        cell.alignment = Alignment(horizontal="right", vertical="center")
    else:
        cell.value = neutralize_formula_cell(val)
        cell.data_type = "s"
        cell.alignment = Alignment(horizontal="left", vertical="center")


def _auto_fit_columns(ws: Worksheet) -> None:
    """Size worksheet columns deterministically from character lengths."""
    assert isinstance(ws, Worksheet)
    assert ws.max_column >= 1
    for col_idx in range(1, ws.max_column + 1):
        width = 14
        for row_idx in range(1, ws.max_row + 1):
            raw_val = ws.cell(row=row_idx, column=col_idx).value
            if raw_val is not None:
                width = max(width, min(len(str(raw_val)) + 4, 48))
        ws.column_dimensions[get_column_letter(col_idx)].width = width


def _build_verdicts_sheet(wb: Workbook, result: FirewallRunResult) -> None:
    """Populate PacketVerdicts sheet with neutralized text, hex digests, and =SUM row."""
    ws = wb.active
    assert ws is not None
    assert len(result.final_registers) == MAX_REGISTERS
    ws.title = "PacketVerdicts"
    headers = (
        "SeqIndex", "PacketID", "SourceID", "SeqNo", "TimestampMs", "Protocol",
        "VerdictCode", "IsAllowed", "TrippedNodeID", "BreakerStateAfter",
        "PrevHashHex", "ChainHashHex",
    )
    _write_header_row(ws, headers)
    if not result.verdicts:
        _write_data_row(
            ws, 2, (0, "\u2014", "\u2014", 0, 0, "\u2014", "\u2014", 0, -1, "\u2014", "\u2014", "\u2014")
        )
    for row_idx, v in enumerate(result.verdicts, start=2):
        _write_data_row(
            ws,
            row_idx,
            (
                v.seq_index, v.packet_id, v.source_id, v.seq_no, v.timestamp_ms,
                v.protocol.value, v.verdict_code.value, 1 if v.is_allowed else 0,
                v.tripped_node_id, v.breaker_state_after.value,
                f"0x{v.prev_hash_u64:016x}", f"0x{v.chain_hash_u64:016x}",
            ),
        )
    last_row = max(2, 1 + len(result.verdicts))
    tot_row = last_row + 1
    _write_total_cell(ws, tot_row, 1, "TOTAL", False)
    for col_idx in range(2, 13):
        if col_idx == 8:
            _write_total_cell(ws, tot_row, col_idx, f"=SUM(H2:H{last_row})", True)
        else:
            _write_total_cell(ws, tot_row, col_idx, "\u2014", False)
    _auto_fit_columns(ws)


def _build_registers_sheet(wb: Workbook, result: FirewallRunResult) -> None:
    """Populate RegisterSnapshot sheet across all 256 PLC registers with =SUM row."""
    ws = wb.create_sheet("RegisterSnapshot")
    assert len(result.final_registers) == MAX_REGISTERS
    assert isinstance(ws, Worksheet)
    _write_header_row(ws, ("RegAddr", "RegValue", "HexU16"))
    for addr, reg_val in enumerate(result.final_registers):
        _write_data_row(ws, addr + 2, (addr, reg_val, f"0x{reg_val & 0xFFFF:04x}"))
    tot_row = MAX_REGISTERS + 2
    _write_total_cell(ws, tot_row, 1, "TOTAL", False)
    _write_total_cell(ws, tot_row, 2, f"=SUM(B2:B{MAX_REGISTERS + 1})", True)
    _write_total_cell(ws, tot_row, 3, "\u2014", False)
    _auto_fit_columns(ws)


def _build_sources_sheet(wb: Workbook, result: FirewallRunResult) -> None:
    """Populate SourceSecurityState sheet with emerald live =SUM(...) total row."""
    ws = wb.create_sheet("SourceSecurityState")
    assert isinstance(ws, Worksheet)
    assert isinstance(result, FirewallRunResult)
    headers = (
        "SourceID",
        "LastSeqNo",
        "BreakerState",
        "ConsecutiveFailures",
        "TotalViolations",
        "OpenedAtMs",
        "WindowCount",
    )
    _write_header_row(ws, headers)
    if not result.source_states:
        _write_data_row(ws, 2, ("\u2014", 0, "\u2014", 0, 0, -1, 0))
    for row_idx, s in enumerate(result.source_states, start=2):
        _write_data_row(
            ws,
            row_idx,
            (
                s.source_id,
                s.last_seq_no,
                s.breaker_state.value,
                s.consecutive_failures,
                s.total_violations,
                s.opened_at_ms,
                len(s.window_timestamps),
            ),
        )
    last_row = max(2, 1 + len(result.source_states))
    tot_row = last_row + 1
    _write_total_cell(ws, tot_row, 1, "TOTAL", False)
    _write_total_cell(ws, tot_row, 2, "\u2014", False)
    _write_total_cell(ws, tot_row, 3, "\u2014", False)
    _write_total_cell(ws, tot_row, 4, f"=SUM(D2:D{last_row})", True)
    _write_total_cell(ws, tot_row, 5, f"=SUM(E2:E{last_row})", True)
    _write_total_cell(ws, tot_row, 6, "\u2014", False)
    _write_total_cell(ws, tot_row, 7, f"=SUM(G2:G{last_row})", True)
    _auto_fit_columns(ws)


def _build_summary_sheet(
    wb: Workbook, result: FirewallRunResult, summary: dict[str, int]
) -> None:
    """Populate SIEMSummary sheet with live =SUM(B2:B8) total verification row."""
    ws = wb.create_sheet("SIEMSummary")
    assert len(summary) == 9
    assert isinstance(ws, Worksheet)
    _write_header_row(ws, ("MetricCategory", "CountOrDigest"))
    allow_reads = sum(1 for v in result.verdicts if v.verdict_code.value == "ALLOW_READ")
    allow_writes = sum(1 for v in result.verdicts if v.verdict_code.value == "ALLOW_WRITE")
    rows: tuple[tuple[str, int], ...] = (
        ("ALLOW_READ", allow_reads),
        ("ALLOW_WRITE", allow_writes),
        ("INTERLOCK_TRIPPED", summary["interlock_trips"]),
        ("REPLAY_ATTACK_BLOCKED", summary["replay_blocks"]),
        ("RATE_LIMIT_EXCEEDED", summary["rate_limit_blocks"]),
        ("CIRCUIT_BREAKER_OPEN", summary["breaker_blocks"]),
        ("PROTOCOL_ERRORS", summary["protocol_errors"]),
    )
    for row_idx, pair in enumerate(rows, start=2):
        _write_data_row(ws, row_idx, pair)
    _write_total_cell(ws, 9, 1, "TOTAL", False)
    _write_total_cell(ws, 9, 2, "=SUM(B2:B8)", True)
    _write_data_row(ws, 10, ("OPEN_BREAKERS", summary["open_breakers"]))
    _write_data_row(
        ws, 11, ("FINAL_CHAIN_HASH_HEX", f"0x{result.final_chain_hash_u64:016x}")
    )
    _auto_fit_columns(ws)


def export_xlsx_atomic(
    result: FirewallRunResult, target_path: str | os.PathLike[str]
) -> None:
    """Write 4-sheet styled workbook atomically via .tmp_ + os.fsync + os.replace."""
    if not isinstance(result, FirewallRunResult):
        raise TypeError("result must be FirewallRunResult")
    assert verify_verdict_chain(result.verdicts)
    assert len(result.final_registers) == MAX_REGISTERS
    summary = query_duckdb_siem_summary(result)
    wb = Workbook()
    _build_verdicts_sheet(wb, result)
    _build_registers_sheet(wb, result)
    _build_sources_sheet(wb, result)
    _build_summary_sheet(wb, result, summary)
    target = pathlib.Path(target_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = target.with_name(f".tmp_{target.name}.{os.getpid()}")
    try:
        wb.save(str(tmp_path))
        fd = os.open(str(tmp_path), os.O_RDWR)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp_path, target)
    except BaseException:
        if tmp_path.exists():
            tmp_path.unlink()
        raise


def _load_duckdb_tables(
    con: duckdb.DuckDBPyConnection, result: FirewallRunResult
) -> None:
    """Create and populate DuckDB 2.0 BIGINT/VARCHAR SIEM tables and SQL views."""
    assert isinstance(con, duckdb.DuckDBPyConnection)
    assert len(result.final_registers) == MAX_REGISTERS
    con.execute(
        "CREATE TABLE packet_verdicts ("
        "seq_index BIGINT, packet_id VARCHAR, source_id VARCHAR, seq_no BIGINT, "
        "timestamp_ms BIGINT, protocol VARCHAR, verdict_code VARCHAR, "
        "is_allowed BOOLEAN, tripped_node_id BIGINT, breaker_state_after VARCHAR, "
        "prev_hash_hex VARCHAR, chain_hash_hex VARCHAR)"
    )
    con.execute("CREATE TABLE register_snapshot (reg_addr BIGINT, reg_value BIGINT)")
    con.execute(
        "CREATE TABLE source_security_state ("
        "source_id VARCHAR, last_seq_no BIGINT, breaker_state VARCHAR, "
        "consecutive_failures BIGINT, total_violations BIGINT, opened_at_ms BIGINT)"
    )
    verdict_rows = [
        (
            v.seq_index,
            v.packet_id,
            v.source_id,
            v.seq_no,
            v.timestamp_ms,
            v.protocol.value,
            v.verdict_code.value,
            v.is_allowed,
            v.tripped_node_id,
            v.breaker_state_after.value,
            f"0x{v.prev_hash_u64:016x}",
            f"0x{v.chain_hash_u64:016x}",
        )
        for v in result.verdicts
    ]
    if verdict_rows:
        con.executemany(
            "INSERT INTO packet_verdicts VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", verdict_rows
        )
    reg_rows = list(enumerate(result.final_registers))
    con.executemany("INSERT INTO register_snapshot VALUES (?,?)", reg_rows)
    src_rows = [
        (
            s.source_id,
            s.last_seq_no,
            s.breaker_state.value,
            s.consecutive_failures,
            s.total_violations,
            s.opened_at_ms,
        )
        for s in result.source_states
    ]
    if src_rows:
        con.executemany("INSERT INTO source_security_state VALUES (?,?,?,?,?,?)", src_rows)


def _create_siem_views(con: duckdb.DuckDBPyConnection) -> None:
    """Create analytical SIEM views over DuckDB packet and breaker tables."""
    assert isinstance(con, duckdb.DuckDBPyConnection)
    con.execute(
        "CREATE VIEW v_interlock_trips AS "
        "SELECT seq_index, packet_id, source_id, tripped_node_id, timestamp_ms "
        "FROM packet_verdicts WHERE verdict_code = 'INTERLOCK_TRIPPED'"
    )
    con.execute(
        "CREATE VIEW v_siem_threat_summary AS SELECT "
        "CAST(COUNT(*) AS BIGINT) AS total_packets, "
        "CAST(COALESCE(SUM(CASE WHEN is_allowed THEN 1 ELSE 0 END), 0) AS BIGINT) "
        "AS allowed_packets, "
        "CAST(COALESCE(SUM(CASE WHEN NOT is_allowed THEN 1 ELSE 0 END), 0) AS BIGINT) "
        "AS blocked_packets, "
        "CAST(COALESCE(SUM(CASE WHEN verdict_code = 'INTERLOCK_TRIPPED' THEN 1 ELSE 0 END), 0) "
        "AS BIGINT) AS interlock_trips, "
        "CAST(COALESCE(SUM(CASE WHEN verdict_code = 'REPLAY_ATTACK_BLOCKED' THEN 1 ELSE 0 END), 0) "
        "AS BIGINT) AS replay_blocks, "
        "CAST(COALESCE(SUM(CASE WHEN verdict_code = 'RATE_LIMIT_EXCEEDED' THEN 1 ELSE 0 END), 0) "
        "AS BIGINT) AS rate_limit_blocks, "
        "CAST(COALESCE(SUM(CASE WHEN verdict_code = 'CIRCUIT_BREAKER_OPEN' THEN 1 ELSE 0 END), 0) "
        "AS BIGINT) AS breaker_blocks, "
        "CAST(COALESCE(SUM(CASE WHEN verdict_code LIKE 'MODBUS_%' "
        "OR verdict_code LIKE 'MQTT_%' THEN 1 ELSE 0 END), 0) AS BIGINT) AS protocol_errors, "
        "CAST((SELECT COUNT(*) FROM source_security_state WHERE breaker_state = 'OPEN') "
        "AS BIGINT) AS open_breakers "
        "FROM packet_verdicts"
    )
    view_cnt = con.execute(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_type = 'VIEW'"
    ).fetchone()
    assert view_cnt is not None and int(view_cnt[0]) == 2


def query_duckdb_siem_summary(result: FirewallRunResult) -> dict[str, int]:
    """Query in-memory DuckDB 2.0 SIEM SQL views and return exact int counts."""
    if not isinstance(result, FirewallRunResult):
        raise TypeError("result must be FirewallRunResult")
    con = duckdb.connect(":memory:")
    try:
        _load_duckdb_tables(con, result)
        _create_siem_views(con)
        row = con.execute("SELECT * FROM v_siem_threat_summary").fetchone()
    finally:
        con.close()
    assert row is not None
    assert len(row) == 9
    return {
        "total_packets": int(row[0]),
        "allowed_packets": int(row[1]),
        "blocked_packets": int(row[2]),
        "interlock_trips": int(row[3]),
        "replay_blocks": int(row[4]),
        "rate_limit_blocks": int(row[5]),
        "breaker_blocks": int(row[6]),
        "protocol_errors": int(row[7]),
        "open_breakers": int(row[8]),
    }

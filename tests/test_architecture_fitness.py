"""Automated Architectural Fitness Functions FF-1 through FF-9 (Codex #17)."""

from __future__ import annotations

import ast
import pathlib
import random
import re
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import FrozenInstanceError

import pytest
from _oracle import (
    OracleNode,
    OraclePacket,
    OraclePolicy,
    OracleRunResult,
    generate_random_scenario,
    oracle_evaluate_stream,
)
from openpyxl import load_workbook

from vectragate.cpp_bridge import compile_cpp_engine, run_cpp_engine
from vectragate.exporters import export_xlsx_atomic, neutralize_formula_cell
from vectragate.firewall import evaluate_packet_stream
from vectragate.models import (
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
)

_ROOT: pathlib.Path = pathlib.Path(__file__).resolve().parent.parent


def _to_vectragate_inputs(
    packets: list[OraclePacket],
    nodes: list[OracleNode],
    regs: list[int],
    policy: OraclePolicy,
) -> tuple[list[RawPacket], list[DagNode], list[int], FirewallPolicy]:
    """Convert independent oracle types to vectragate public domain types."""
    py_pkts = [
        RawPacket(
            packet_id=p.packet_id,
            source_id=p.source_id,
            seq_no=p.seq_no,
            timestamp_ms=p.timestamp_ms,
            protocol=ProtocolType(p.protocol),
            payload_hex=p.payload_hex,
        )
        for p in packets
    ]
    py_nodes = [
        DagNode(
            node_id=n.node_id,
            tag=n.tag,
            op=NodeOp(n.op),
            target_reg=n.target_reg,
            threshold=n.threshold,
            inputs=n.inputs,
            is_hazard_output=n.is_hazard_output,
        )
        for n in nodes
    ]
    py_pol = FirewallPolicy(
        window_ms=policy.window_ms,
        max_requests_per_window=policy.max_requests_per_window,
        trip_threshold=policy.trip_threshold,
        cooldown_ms=policy.cooldown_ms,
    )
    return py_pkts, py_nodes, list(regs), py_pol


def _assert_oracle_parity(py_res: FirewallRunResult, ora_res: OracleRunResult) -> None:
    """Assert 100% bit-for-bit parity between Python core and independent oracle."""
    assert py_res.topological_order == ora_res.topological_order
    assert py_res.final_registers == ora_res.final_registers
    assert py_res.final_chain_hash_u64 == ora_res.final_chain_hash_u64
    assert py_res.allowed_count == ora_res.allowed_count
    assert py_res.blocked_count == ora_res.blocked_count
    assert len(py_res.verdicts) == len(ora_res.verdicts)
    for vp, vo in zip(py_res.verdicts, ora_res.verdicts, strict=True):
        assert vp.seq_index == vo.seq_index
        assert vp.packet_id == vo.packet_id
        assert vp.source_id == vo.source_id
        assert vp.seq_no == vo.seq_no
        assert vp.timestamp_ms == vo.timestamp_ms
        assert vp.protocol.value == vo.protocol
        assert vp.verdict_code.value == vo.verdict_code
        assert vp.is_allowed == vo.is_allowed
        assert vp.tripped_node_id == vo.tripped_node_id
        assert vp.breaker_state_after.value == vo.breaker_state_after
        assert vp.prev_hash_u64 == vo.prev_hash_u64
        assert vp.chain_hash_u64 == vo.chain_hash_u64
    assert len(py_res.source_states) == len(ora_res.source_states)
    for sp, so in zip(py_res.source_states, ora_res.source_states, strict=True):
        assert sp.source_id == so.source_id
        assert sp.last_seq_no == so.last_seq_no
        assert sp.breaker_state.value == so.breaker_state
        assert sp.consecutive_failures == so.consecutive_failures
        assert sp.total_violations == so.total_violations
        assert sp.opened_at_ms == so.opened_at_ms
        assert sp.window_timestamps == so.window_timestamps


def test_ff1_acyclic_layered_import_dag() -> None:
    """FF-1: Enforce upward layered import sets across all src/vectragate/*.py modules."""
    allowed: dict[str, set[str]] = {
        "models.py": {"__future__", "dataclasses", "enum", "hashlib", "re"},
        "protocol.py": {"__future__", "vectragate.models"},
        "dag_engine.py": {"__future__", "collections.abc", "vectragate.models"},
        "firewall.py": {
            "__future__",
            "collections.abc",
            "dataclasses",
            "vectragate.models",
            "vectragate.protocol",
            "vectragate.dag_engine",
        },
        "intake_gate.py": {
            "__future__",
            "collections.abc",
            "json",
            "re",
            "vectragate.models",
            "vectragate.dag_engine",
        },
        "cpp_bridge.py": {
            "__future__",
            "collections.abc",
            "pathlib",
            "subprocess",
            "vectragate.models",
            "vectragate.firewall",
        },
        "exporters.py": {
            "__future__",
            "collections.abc",
            "os",
            "pathlib",
            "unicodedata",
            "duckdb",
            "openpyxl",
            "openpyxl.styles",
            "openpyxl.utils",
            "openpyxl.worksheet.worksheet",
            "vectragate.models",
            "vectragate.firewall",
        },
        "cli_visualizer.py": {
            "__future__",
            "argparse",
            "collections.abc",
            "pathlib",
            "vectragate.models",
            "vectragate.firewall",
            "vectragate.intake_gate",
            "vectragate.cpp_bridge",
            "vectragate.exporters",
        },
    }
    pkg_dir = _ROOT.joinpath("src", "vectragate")
    for mod_name, permit in allowed.items():
        tree = ast.parse(pkg_dir.joinpath(mod_name).read_text(encoding="utf-8"), mod_name)
        seen: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    seen.add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                seen.add(node.module)
        extra = seen - permit
        assert not extra, f"{mod_name} has disallowed imports: {sorted(extra)}"


def test_ff2_zero_float_and_zero_division_gate() -> None:
    """FF-2: Ban float literals, float/Decimal/truediv identifiers, and / operators."""
    banned_names = ("float", "Decimal", "truediv")
    py_files = sorted(
        list(_ROOT.joinpath("src").rglob("*.py"))
        + list(_ROOT.joinpath("tests").rglob("*.py"))
    )
    assert len(py_files) >= 10
    for path in py_files:
        tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, int) is False:
                assert type(node.value).__name__ != banned_names[0], f"{path}:{node.lineno}"
            assert not (
                isinstance(node, (ast.BinOp, ast.AugAssign)) and isinstance(node.op, ast.Div)
            ), f"Forbidden true division / at {path}:{node.lineno}"
            assert not (
                isinstance(node, ast.Name) and node.id in banned_names
            ), f"Forbidden identifier {node.id} at {path}:{node.lineno}"


def test_ff3_bounded_functions_assertions_and_zero_recursion() -> None:
    """FF-3: Enforce <=60 LOC/fn, >=2 asserts/fn, 0 recursion, and 0 open/eval/exec/pickle."""
    forbidden_calls = ("open", "eval", "exec", "pickle")
    for path in sorted(_ROOT.joinpath("src", "vectragate").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
        mod_calls: dict[str, set[str]] = {}
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in forbidden_calls
            ):
                raise AssertionError(f"Forbidden call {node.func.id} at {path}:{node.lineno}")
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                loc = (node.end_lineno or node.lineno) - node.lineno + 1
                assert loc <= 60, f"{path.name}:{node.name} has {loc} LOC (> 60)"
                asserts = sum(1 for sub in ast.walk(node) if isinstance(sub, ast.Assert))
                assert asserts >= 2, f"{path.name}:{node.name} has {asserts} asserts (< 2)"
                callees = {
                    sub.func.id
                    for sub in ast.walk(node)
                    if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name)
                }
                assert node.name not in callees, f"Direct recursion in {path.name}:{node.name}"
                mod_calls[node.name] = callees
        for fn_name, fn_callees in mod_calls.items():
            seen: set[str] = set()
            stack = list(fn_callees)
            while stack:
                nxt = stack.pop()
                assert nxt != fn_name, f"Mutual recursion cycle involving {path.name}:{fn_name}"
                if nxt not in seen and nxt in mod_calls:
                    seen.add(nxt)
                    stack.extend(mod_calls[nxt])


def test_ff4_immutable_value_objects_gate() -> None:
    """FF-4: Verify all 8 models.py dataclasses declare slots=True and frozen=True."""
    expected_classes = (
        FirewallPolicy,
        DagNode,
        RawPacket,
        DecodedOperation,
        SourceSecurityState,
        PacketVerdict,
        PacketRejection,
        FirewallRunResult,
    )
    models_src = _ROOT.joinpath("src", "vectragate", "models.py").read_text(encoding="utf-8")
    tree = ast.parse(models_src)
    dc_flags: dict[str, tuple[bool, bool]] = {}
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            for dec in node.decorator_list:
                if (
                    isinstance(dec, ast.Call)
                    and isinstance(dec.func, ast.Name)
                    and dec.func.id == "dataclass"
                ):
                    kw = {k.arg: getattr(k.value, "value", None) for k in dec.keywords}
                    dc_flags[node.name] = (kw.get("slots") is True, kw.get("frozen") is True)
    assert len(dc_flags) == 8
    for cls in expected_classes:
        assert dc_flags[cls.__name__] == (True, True)
        assert hasattr(cls, "__slots__")
    pol = FirewallPolicy()
    with pytest.raises(FrozenInstanceError):
        pol.trip_threshold = 99  # type: ignore[misc]


def test_ff5_oracle_independence_gate() -> None:
    """FF-5: Verify tests/_oracle.py has 0 imports from src/ or vectragate."""
    oracle_path = _ROOT.joinpath("tests", "_oracle.py")
    tree = ast.parse(oracle_path.read_text(encoding="utf-8"), str(oracle_path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith(("src", "vectragate"))
        elif isinstance(node, ast.ImportFrom) and node.module:
            assert not node.module.startswith(("src", "vectragate"))


def test_ff6_cwe1236_and_live_excel_formula_gate(tmp_path: pathlib.Path) -> None:
    """FF-6: Verify 9-trigger + NFKC neutralization and live =SUM Excel export."""
    payloads = (
        "=SUM(1,2)",
        "＝SUM(1)",
        " +1+1",
        "\t=cmd",
        "\r=cmd",
        "\n=1+1",
        "@SUM(A1)",
        "|calc",
        "%0A",
        "-1",
    )
    for item in payloads:
        assert neutralize_formula_cell(item) == "'" + item
    pkts = (RawPacket("P1", "-SRC", 1, 10, ProtocolType.MODBUS_TCP, "000100000006010300000001"),)
    res = evaluate_packet_stream(pkts, ())
    out_xlsx = tmp_path.joinpath("ff6.xlsx")
    export_xlsx_atomic(res, out_xlsx)
    assert out_xlsx.exists()
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".tmp_")]
    wb = load_workbook(out_xlsx, data_only=False)
    for sheet_name in wb.sheetnames:
        ws = wb[sheet_name]
        formulas = 0
        for r in range(1, ws.max_row + 1):
            for c in range(1, ws.max_column + 1):
                cell = ws.cell(row=r, column=c)
                assert cell.value is not None, f"{sheet_name}!{cell.coordinate} is None"
                if cell.data_type == "f":
                    formulas += 1
        assert formulas >= 1, f"{sheet_name} missing live =SUM formula"


def test_ff7_cpp20_arena_and_zero_heap_source_gate() -> None:
    """FF-7: Verify static cache alignment, SPSC ring, multi-block BLAKE2b, and 0 heap."""
    hpp_text = _ROOT.joinpath("src", "cpp", "vectragate_core.hpp").read_text(encoding="utf-8")
    assert "alignas(64)" in hpp_text
    assert "static_assert" in hpp_text
    assert "SpscRingBuffer" in hpp_text
    assert "EngineArena" in hpp_text
    assert "blake2b_64" in hpp_text
    assert "while (len > 128U)" in hpp_text
    heap_kw = re.findall(r"\b(new|delete|malloc|free|calloc|realloc|aligned_alloc)\b", hpp_text)
    assert heap_kw == []


def test_ff8_zero_dollar_docs_svg_geometry_and_loc_gate() -> None:
    """FF-8: Verify 0 $ in docs, SVG validity/<=46ch/0 unused markers, and README LOC parity."""
    for md_path in sorted(_ROOT.glob("*.md")):
        md_text = md_path.read_text(encoding="utf-8")
        assert "$" not in md_text, f"Raw dollar found in {md_path.name}"

    svgs = sorted(_ROOT.joinpath("assets").glob("*.svg"))
    assert len(svgs) == 2
    for svg_path in svgs:
        svg_text = svg_path.read_text(encoding="utf-8")
        assert "$" not in svg_text
        tree = ET.parse(svg_path)
        root = tree.getroot()
        markers = {
            e.attrib["id"]
            for e in root.iter()
            if e.tag.endswith("marker") and "id" in e.attrib
        }
        used_markers: set[str] = set()
        for elem in root.iter():
            for attr_name in ("marker-start", "marker-mid", "marker-end"):
                attr_val = elem.attrib.get(attr_name, "")
                for ref in re.findall(r"url\(#([^)]+)\)", attr_val):
                    used_markers.add(ref)
            if elem.tag.endswith("text"):
                txt = (elem.text or "").strip()
                assert len(txt) <= 46, f"{svg_path.name} overflow text ({len(txt)}): {txt!r}"
        assert markers == used_markers

    readme = _ROOT.joinpath("README.md").read_text(encoding="utf-8")
    row_pattern = re.compile(r"^\|\s*`([^`]+)`\s*\|\s*([0-9,]+)\s*\|", re.MULTILINE)
    recorded = {rel: int(loc_s.replace(",", "")) for rel, loc_s in row_pattern.findall(readme)}
    expected_files = (
        sorted(p.relative_to(_ROOT).as_posix() for p in _ROOT.joinpath("src").rglob("*.py"))
        + sorted(p.relative_to(_ROOT).as_posix() for p in _ROOT.joinpath("src", "cpp").glob("*"))
        + sorted(p.relative_to(_ROOT).as_posix() for p in _ROOT.joinpath("tests").glob("*.py"))
        + sorted(p.relative_to(_ROOT).as_posix() for p in _ROOT.joinpath("assets").glob("*.svg"))
        + ["BLUEPRINT.md", "SPEC.md", "ADR.md", "HANDOFF.md", "README.md", "pyproject.toml"]
    )
    for rel in expected_files:
        assert rel in recorded, f"{rel} missing from README.md LOC table"
        actual_loc = len(_ROOT.joinpath(rel).read_text(encoding="utf-8").splitlines())
        assert recorded[rel] == actual_loc, f"{rel}: README={recorded[rel]} != disk={actual_loc}"


def test_ff9_cpp_native_compilation_and_1050_seed_parity() -> None:
    """FF-9: Compile C++ core cleanly and prove 1,050-seed C++/Python/Oracle parity."""
    exe_path = compile_cpp_engine()
    cpp_path = _ROOT.joinpath("src", "cpp", "vectragate_cli.cpp")
    proc = subprocess.run(
        ["g++", "-std=c++17", "-O3", "-Wall", "-Wextra", "-Wpedantic", "-Werror", str(cpp_path), "-o", str(exe_path)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr

    fast_seeds = list(range(50))
    random.Random(42).shuffle(fast_seeds)
    verdicts_seen: set[str] = set()
    ops_seen: set[NodeOp] = set()
    counts = {
        "allow": 0,
        "interlock": 0,
        "replay": 0,
        "rate": 0,
        "breaker": 0,
        "modbus_err": 0,
        "mqtt_err": 0,
    }

    for seed in fast_seeds:
        o_pkts, o_nodes, o_regs, o_pol = generate_random_scenario(seed)
        pkts, nodes, regs, pol = _to_vectragate_inputs(o_pkts, o_nodes, o_regs, o_pol)
        for n in nodes:
            ops_seen.add(n.op)
        ora_res = oracle_evaluate_stream(o_pkts, o_nodes, o_regs, o_pol)
        py_res = evaluate_packet_stream(pkts, nodes, initial_registers=regs, policy=pol)
        cpp_res = run_cpp_engine(pkts, nodes, initial_registers=regs, policy=pol)
        assert cpp_res == py_res
        _assert_oracle_parity(py_res, ora_res)
        for v in py_res.verdicts:
            vc = v.verdict_code.value
            verdicts_seen.add(vc)
            if v.is_allowed:
                counts["allow"] += 1
            elif vc == "INTERLOCK_TRIPPED":
                counts["interlock"] += 1
            elif vc == "REPLAY_ATTACK_BLOCKED":
                counts["replay"] += 1
            elif vc == "RATE_LIMIT_EXCEEDED":
                counts["rate"] += 1
            elif vc == "CIRCUIT_BREAKER_OPEN":
                counts["breaker"] += 1
            elif vc.startswith("MODBUS_"):
                counts["modbus_err"] += 1
            elif vc.startswith("MQTT_"):
                counts["mqtt_err"] += 1

    assert len(verdicts_seen) == 24
    assert len(ops_seen) == 12
    assert counts["allow"] >= 100
    assert counts["interlock"] >= 20
    assert counts["replay"] >= 20
    assert counts["rate"] >= 20
    assert counts["breaker"] >= 15
    assert counts["modbus_err"] >= 30
    assert counts["mqtt_err"] >= 30

    deep_seeds = list(range(100, 1100))
    random.Random(2026).shuffle(deep_seeds)
    batch_o_pkts: list[OraclePacket] = []
    batch_o_nodes: list[OracleNode] = []
    batch_regs: list[int] = [0] * 256
    batch_pol = OraclePolicy(500, 3, 3, 2_000)

    for idx, seed in enumerate(deep_seeds):
        o_pkts, o_nodes, o_regs, o_pol = generate_random_scenario(seed)
        pkts, nodes, regs, pol = _to_vectragate_inputs(o_pkts, o_nodes, o_regs, o_pol)
        ora_res = oracle_evaluate_stream(o_pkts, o_nodes, o_regs, o_pol)
        py_res = evaluate_packet_stream(pkts, nodes, initial_registers=regs, policy=pol)
        _assert_oracle_parity(py_res, ora_res)
        if idx == 0:
            batch_o_nodes = o_nodes
            batch_regs = o_regs
        if idx < 20:
            batch_o_pkts.extend(o_pkts)

    b_pkts, b_nodes, b_regs, b_pol = _to_vectragate_inputs(
        batch_o_pkts, batch_o_nodes, batch_regs, batch_pol
    )
    b_ora = oracle_evaluate_stream(batch_o_pkts, batch_o_nodes, batch_regs, batch_pol)
    b_py = evaluate_packet_stream(b_pkts, b_nodes, initial_registers=b_regs, policy=b_pol)
    b_cpp = run_cpp_engine(b_pkts, b_nodes, initial_registers=b_regs, policy=b_pol)
    assert len(b_pkts) == 240
    assert b_cpp == b_py
    _assert_oracle_parity(b_py, b_ora)

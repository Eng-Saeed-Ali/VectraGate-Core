"""Layer 3 4-stage JSON boundary intake gate for vectragate.bundle/v1."""

from __future__ import annotations

import json
import re

from vectragate.dag_engine import validate_and_sort_dag
from vectragate.models import (
    MAX_DAG_NODES,
    MAX_JSON_DEPTH,
    MAX_PACKETS,
    MAX_PAYLOAD_BYTES,
    MAX_REG_VAL,
    MAX_REGISTERS,
    MIN_REG_VAL,
    DagNode,
    FirewallPolicy,
    NodeOp,
    PacketRejection,
    ProtocolType,
    RawPacket,
)

_ROOT_REQUIRED: frozenset[str] = frozenset({"schema_version", "dag_nodes", "packets"})
_ROOT_ALLOWED: frozenset[str] = frozenset(
    {"schema_version", "dag_nodes", "packets", "policy", "initial_registers"}
)
_POLICY_ALLOWED: frozenset[str] = frozenset(
    {"window_ms", "max_requests_per_window", "trip_threshold", "cooldown_ms"}
)
_NODE_REQUIRED: frozenset[str] = frozenset({"node_id", "tag", "op"})
_NODE_ALLOWED: frozenset[str] = frozenset(
    {"node_id", "tag", "op", "target_reg", "threshold", "inputs", "is_hazard_output"}
)
_PACKET_REQUIRED: frozenset[str] = frozenset(
    {"packet_id", "source_id", "seq_no", "timestamp_ms", "protocol", "payload_hex"}
)
_REG_KEY_RE: re.Pattern[str] = re.compile(r"^(0|[1-9][0-9]{0,2})\Z")


class IntakeError(ValueError):
    """Deterministic boundary intake validation failure."""


def _as_exact_int(val: object, name: str) -> int:
    """Validate and narrow exact integer (rejecting booleans)."""
    assert len(name) > 0
    if type(val) is not int or not isinstance(val, int):
        raise IntakeError(f"EXPECTED_INT: {name}")
    assert type(val) is int
    return val


def _as_exact_str(val: object, name: str) -> str:
    """Validate and narrow exact string."""
    assert len(name) > 0
    if type(val) is not str or not isinstance(val, str):
        raise IntakeError(f"EXPECTED_STR: {name}")
    assert type(val) is str
    return val


def _as_exact_bool(val: object, name: str) -> bool:
    """Validate and narrow exact boolean."""
    assert len(name) > 0
    if type(val) is not bool or not isinstance(val, bool):
        raise IntakeError(f"EXPECTED_BOOL: {name}")
    assert type(val) is bool
    return val


def _as_str_dict(val: object, code: str) -> dict[str, object]:
    """Validate and narrow JSON object dictionary with string keys."""
    assert len(code) > 0
    if type(val) is not dict or not isinstance(val, dict):
        raise IntakeError(code)
    out: dict[str, object] = {}
    for k, v in val.items():
        if type(k) is not str or not isinstance(k, str):
            raise IntakeError(code)
        out[k] = v
    assert len(out) == len(val)
    return out


def _has_surrogate_or_nul(text: str) -> bool:
    """Return True if text contains NUL or UTF-16 lone surrogate code points."""
    assert isinstance(text, str)
    found = "\x00" in text or any(0xD800 <= ord(ch) <= 0xDFFF for ch in text)
    assert isinstance(found, bool)
    return found


def _stage1_decode_utf8(raw: str | bytes) -> str:
    """Enforce 4 MiB byte ceiling, strict UTF-8 decoding, NUL and surrogate bans."""
    assert MAX_PAYLOAD_BYTES == 4_194_304
    if isinstance(raw, bytes):
        if len(raw) > MAX_PAYLOAD_BYTES:
            raise IntakeError("PAYLOAD_TOO_LARGE: exceeds 4 MiB limit")
        if b"\x00" in raw:
            raise IntakeError("NUL_BYTE_FORBIDDEN")
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise IntakeError("INVALID_UTF8") from exc
    elif isinstance(raw, str):
        if _has_surrogate_or_nul(raw):
            raise IntakeError("INVALID_STRING_INPUT: NUL or lone surrogate")
        encoded = raw.encode("utf-8", errors="strict")
        if len(encoded) > MAX_PAYLOAD_BYTES:
            raise IntakeError("PAYLOAD_TOO_LARGE: exceeds 4 MiB limit")
        text = raw
    else:
        raise IntakeError(f"INVALID_RAW_TYPE: {type(raw).__name__}")
    assert not _has_surrogate_or_nul(text)
    return text


def _stage2_check_depth(text: str) -> None:
    """Enforce iterative JSON bracket depth limit without recursion."""
    assert isinstance(text, str)
    assert MAX_JSON_DEPTH == 8
    depth = 0
    in_string = False
    escape = False
    for ch in text:
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "{[":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise IntakeError(f"JSON_DEPTH_EXCEEDED: max depth is {MAX_JSON_DEPTH}")
        elif ch in "}]":
            depth -= 1
            if depth < 0:
                raise IntakeError("MALFORMED_JSON_BRACKETS")


def _reject_fp_token(token: str) -> object:
    """Reject floating-point and non-finite JSON numeric tokens."""
    assert isinstance(token, str)
    assert len(token) > 0
    raise IntakeError(f"FLOAT_FORBIDDEN: {token}")


def _validate_parsed_strings(root: object) -> None:
    """Iteratively reject NUL bytes and lone surrogates inside decoded JSON strings."""
    stack: list[object] = [root]
    assert len(stack) == 1
    while stack:
        cur = stack.pop()
        if isinstance(cur, str):
            if _has_surrogate_or_nul(cur):
                raise IntakeError("INVALID_STRING_TOKEN: NUL or lone surrogate")
        elif isinstance(cur, dict):
            for key, val in cur.items():
                stack.append(key)
                stack.append(val)
        elif isinstance(cur, list):
            stack.extend(cur)
    assert len(stack) == 0


def _parse_json_object(text: str) -> dict[str, object]:
    """Run Stage 3 JSON parse, string scan, and closed-world root key validation."""
    assert isinstance(text, str)
    try:
        parsed: object = json.loads(
            text, parse_float=_reject_fp_token, parse_constant=_reject_fp_token
        )
    except json.JSONDecodeError as exc:
        raise IntakeError(f"INVALID_JSON: {exc}") from exc
    obj = _as_str_dict(parsed, "INVALID_BUNDLE_ROOT: expected JSON object")
    _validate_parsed_strings(obj)
    keys = set(obj.keys())
    if not _ROOT_REQUIRED.issubset(keys):
        missing = sorted(_ROOT_REQUIRED - keys)
        raise IntakeError(f"MISSING_ROOT_KEYS: {missing}")
    if not keys.issubset(_ROOT_ALLOWED):
        unknown = sorted(keys - _ROOT_ALLOWED)
        raise IntakeError(f"UNKNOWN_ROOT_KEYS: {unknown}")
    if obj["schema_version"] != "vectragate.bundle/v1":
        raise IntakeError("UNSUPPORTED_SCHEMA_VERSION")
    assert obj["schema_version"] == "vectragate.bundle/v1"
    return obj


def _parse_policy(raw_policy: object) -> FirewallPolicy:
    """Validate and construct FirewallPolicy from optional JSON object."""
    assert len(_POLICY_ALLOWED) == 4
    if raw_policy is None:
        return FirewallPolicy()
    obj = _as_str_dict(raw_policy, "INVALID_POLICY: expected object")
    keys = set(obj.keys())
    if not keys.issubset(_POLICY_ALLOWED):
        raise IntakeError(f"UNKNOWN_POLICY_KEYS: {sorted(keys - _POLICY_ALLOWED)}")
    try:
        policy = FirewallPolicy(
            window_ms=_as_exact_int(obj.get("window_ms", 10_000), "window_ms"),
            max_requests_per_window=_as_exact_int(
                obj.get("max_requests_per_window", 10), "max_requests_per_window"
            ),
            trip_threshold=_as_exact_int(
                obj.get("trip_threshold", 3), "trip_threshold"
            ),
            cooldown_ms=_as_exact_int(obj.get("cooldown_ms", 30_000), "cooldown_ms"),
        )
    except (TypeError, ValueError) as exc:
        raise IntakeError(f"INVALID_POLICY: {exc}") from exc
    assert isinstance(policy, FirewallPolicy)
    return policy


def _parse_initial_registers(raw_regs: object) -> tuple[int, ...]:
    """Validate optional 256-entry register list or sparse address map."""
    assert MAX_REGISTERS == 256
    if raw_regs is None:
        return (0,) * MAX_REGISTERS
    if type(raw_regs) is list and isinstance(raw_regs, list):
        if len(raw_regs) != MAX_REGISTERS:
            raise IntakeError(f"INVALID_REGISTERS: expected length {MAX_REGISTERS}")
        dense: list[int] = []
        for item in raw_regs:
            val = _as_exact_int(item, "register")
            if not (MIN_REG_VAL <= val <= MAX_REG_VAL):
                raise IntakeError("INVALID_REGISTER_VALUE")
            dense.append(val)
        assert len(dense) == MAX_REGISTERS
        return tuple(dense)
    sparse = _as_str_dict(raw_regs, "INVALID_REGISTERS: expected list or dict")
    regs = [0] * MAX_REGISTERS
    for key, raw_val in sparse.items():
        if not _REG_KEY_RE.fullmatch(key):
            raise IntakeError(f"INVALID_REGISTER_KEY: {key!r}")
        idx = int(key)
        if idx >= MAX_REGISTERS:
            raise IntakeError(f"REGISTER_INDEX_OOB: {idx}")
        val = _as_exact_int(raw_val, f"reg[{idx}]")
        if not (MIN_REG_VAL <= val <= MAX_REG_VAL):
            raise IntakeError("INVALID_REGISTER_VALUE")
        regs[idx] = val
    assert len(regs) == MAX_REGISTERS
    return tuple(regs)


def _parse_single_dag_node(item: object) -> DagNode:
    """Validate closed-world keys and construct one DagNode."""
    assert len(_NODE_REQUIRED) == 3
    obj = _as_str_dict(item, "INVALID_DAG_NODE: expected object")
    keys = set(obj.keys())
    if not _NODE_REQUIRED.issubset(keys) or not keys.issubset(_NODE_ALLOWED):
        raise IntakeError("INVALID_DAG_NODE_KEYS")
    raw_op = _as_exact_str(obj["op"], "op")
    try:
        op = NodeOp(raw_op)
    except ValueError as exc:
        raise IntakeError(f"UNKNOWN_NODE_OP: {raw_op}") from exc
    raw_inputs = obj.get("inputs", [])
    if type(raw_inputs) is not list or not isinstance(raw_inputs, list):
        raise IntakeError("INVALID_NODE_INPUTS: expected list")
    parsed_inputs = tuple(_as_exact_int(v, "inputs[]") for v in raw_inputs)
    try:
        node = DagNode(
            node_id=_as_exact_int(obj["node_id"], "node_id"),
            tag=_as_exact_str(obj["tag"], "tag"),
            op=op,
            target_reg=_as_exact_int(obj.get("target_reg", 0), "target_reg"),
            threshold=_as_exact_int(obj.get("threshold", 0), "threshold"),
            inputs=parsed_inputs,
            is_hazard_output=_as_exact_bool(
                obj.get("is_hazard_output", False), "is_hazard_output"
            ),
        )
    except (TypeError, ValueError) as exc:
        raise IntakeError(f"INVALID_DAG_NODE: {exc}") from exc
    assert isinstance(node, DagNode)
    return node


def _parse_dag_nodes(raw_nodes: object) -> tuple[DagNode, ...]:
    """Validate DAG node sequence bounds and topological acyclicity."""
    assert MAX_DAG_NODES == 128
    if type(raw_nodes) is not list or not isinstance(raw_nodes, list):
        raise IntakeError("INVALID_DAG_NODES: expected list")
    if len(raw_nodes) > MAX_DAG_NODES:
        raise IntakeError(f"DAG_NODE_LIMIT_EXCEEDED: max {MAX_DAG_NODES}")
    nodes = tuple(_parse_single_dag_node(item) for item in raw_nodes)
    try:
        topo = validate_and_sort_dag(nodes)
    except ValueError as exc:
        raise IntakeError(f"INVALID_DAG_GRAPH: {exc}") from exc
    assert len(topo) == len(nodes)
    return nodes


def _safe_packet_id(item: object) -> str | None:
    """Extract sanitized non-empty packet_id for rejection diagnostics."""
    assert len(_PACKET_REQUIRED) == 6
    if not isinstance(item, dict):
        return None
    raw_pid = item.get("packet_id")
    if not isinstance(raw_pid, str) or not raw_pid or _has_surrogate_or_nul(raw_pid):
        return None
    assert len(raw_pid) > 0
    return raw_pid


def _parse_single_packet(
    idx: int, item: object
) -> tuple[RawPacket | None, PacketRejection | None]:
    """Validate one packet entry or return a quarantined PacketRejection."""
    assert idx >= 0
    pid = _safe_packet_id(item)
    try:
        obj = _as_str_dict(item, "INVALID_PACKET_TYPE")
        if set(obj.keys()) != _PACKET_REQUIRED:
            return None, PacketRejection(
                idx, pid, "INVALID_PACKET_KEYS", f"expected {sorted(_PACKET_REQUIRED)}"
            )
        proto = ProtocolType(_as_exact_str(obj["protocol"], "protocol"))
        pkt = RawPacket(
            packet_id=_as_exact_str(obj["packet_id"], "packet_id"),
            source_id=_as_exact_str(obj["source_id"], "source_id"),
            seq_no=_as_exact_int(obj["seq_no"], "seq_no"),
            timestamp_ms=_as_exact_int(obj["timestamp_ms"], "timestamp_ms"),
            protocol=proto,
            payload_hex=_as_exact_str(obj["payload_hex"], "payload_hex"),
        )
    except (TypeError, ValueError) as exc:
        return None, PacketRejection(idx, pid, "INVALID_PACKET", str(exc))
    assert isinstance(pkt, RawPacket)
    return pkt, None


def _stage4_quarantine_packets(
    raw_packets: object,
) -> tuple[tuple[RawPacket, ...], tuple[PacketRejection, ...]]:
    """Validate packet list length and isolate malformed packet items."""
    assert MAX_PACKETS == 10_000
    if type(raw_packets) is not list or not isinstance(raw_packets, list):
        raise IntakeError("INVALID_PACKETS: expected list")
    if len(raw_packets) > MAX_PACKETS:
        raise IntakeError(f"PACKET_LIMIT_EXCEEDED: max {MAX_PACKETS}")
    valid: list[RawPacket] = []
    rejected: list[PacketRejection] = []
    for idx, item in enumerate(raw_packets):
        pkt, rej = _parse_single_packet(idx, item)
        if rej is not None:
            rejected.append(rej)
        elif pkt is not None:
            valid.append(pkt)
    assert len(valid) + len(rejected) == len(raw_packets)
    return tuple(valid), tuple(rejected)


def ingest_json_bundle_report(
    raw: str | bytes,
) -> tuple[
    tuple[RawPacket, ...],
    tuple[DagNode, ...],
    tuple[int, ...],
    FirewallPolicy,
    tuple[PacketRejection, ...],
]:
    """Execute Stages 1-4 on JSON bundle and return quarantined packet report."""
    text = _stage1_decode_utf8(raw)
    _stage2_check_depth(text)
    parsed = _parse_json_object(text)
    policy = _parse_policy(parsed.get("policy"))
    init_regs = _parse_initial_registers(parsed.get("initial_registers"))
    dag_nodes = _parse_dag_nodes(parsed["dag_nodes"])
    packets, rejections = _stage4_quarantine_packets(parsed["packets"])
    assert len(init_regs) == MAX_REGISTERS
    assert isinstance(policy, FirewallPolicy)
    return packets, dag_nodes, init_regs, policy, rejections


def ingest_json_bundle(
    raw: str | bytes,
) -> tuple[
    tuple[RawPacket, ...],
    tuple[DagNode, ...],
    tuple[int, ...],
    FirewallPolicy,
]:
    """Execute Stages 1-4 on JSON bundle and reject if any packet was quarantined."""
    packets, dag_nodes, init_regs, policy, rejections = ingest_json_bundle_report(raw)
    assert isinstance(rejections, tuple)
    if rejections:
        first = rejections[0]
        raise IntakeError(
            f"PACKET_QUARANTINED[{first.packet_index}]: {first.code}: {first.detail}"
        )
    assert len(init_regs) == MAX_REGISTERS
    return packets, dag_nodes, init_regs, policy

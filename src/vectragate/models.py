"""Layer 0 domain enums, immutable value objects, and cryptographic helpers."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum

MAX_REGISTERS: int = 256
MAX_DAG_NODES: int = 128
MAX_SOURCES: int = 64
MAX_WINDOW_TIMESTAMPS: int = 64
SPSC_RING_SLOTS: int = 256
MIN_REG_VAL: int = -32_768
MAX_REG_VAL: int = 65_535
GENESIS_HASH_U64: int = 0x5645435452413236
MAX_PAYLOAD_BYTES: int = 4_194_304
MAX_JSON_DEPTH: int = 8
MAX_PACKETS: int = 10_000
U64_LIMIT: int = 1 << 64

ID_PATTERN: re.Pattern[str] = re.compile(r"^[A-Z0-9_-]{1,32}\Z")
HEX_PATTERN: re.Pattern[str] = re.compile(r"^[0-9a-fA-F]{2,1024}\Z")


class ProtocolType(StrEnum):
    """Supported OT/ICS wire protocols."""

    MODBUS_TCP = "MODBUS_TCP"
    MQTT = "MQTT"


class NodeOp(StrEnum):
    """Combinational logic-gate and comparator operations."""

    CMP_GT = "CMP_GT"
    CMP_GE = "CMP_GE"
    CMP_LT = "CMP_LT"
    CMP_LE = "CMP_LE"
    CMP_EQ = "CMP_EQ"
    CMP_NE = "CMP_NE"
    AND = "AND"
    OR = "OR"
    XOR = "XOR"
    NOT = "NOT"
    NAND = "NAND"
    NOR = "NOR"


class BreakerState(StrEnum):
    """Nygard 3-state circuit breaker states."""

    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class VerdictCode(StrEnum):
    """Deterministic packet evaluation verdict codes."""

    ALLOW_READ = "ALLOW_READ"
    ALLOW_WRITE = "ALLOW_WRITE"
    CIRCUIT_BREAKER_OPEN = "CIRCUIT_BREAKER_OPEN"
    REPLAY_ATTACK_BLOCKED = "REPLAY_ATTACK_BLOCKED"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    INTERLOCK_TRIPPED = "INTERLOCK_TRIPPED"
    MODBUS_FRAME_TOO_SHORT = "MODBUS_FRAME_TOO_SHORT"
    MODBUS_INVALID_PROTOCOL = "MODBUS_INVALID_PROTOCOL"
    MODBUS_LENGTH_OUT_OF_BOUNDS = "MODBUS_LENGTH_OUT_OF_BOUNDS"
    MODBUS_MBAP_LEN_MISMATCH = "MODBUS_MBAP_LEN_MISMATCH"
    MODBUS_REGISTER_OOB = "MODBUS_REGISTER_OOB"
    MODBUS_INVALID_COIL_VALUE = "MODBUS_INVALID_COIL_VALUE"
    MODBUS_BYTE_COUNT_MISMATCH = "MODBUS_BYTE_COUNT_MISMATCH"
    MODBUS_UNAUTHORIZED_FC = "MODBUS_UNAUTHORIZED_FC"
    MQTT_FRAME_TOO_SHORT = "MQTT_FRAME_TOO_SHORT"
    MQTT_UNSUPPORTED_PACKET_TYPE = "MQTT_UNSUPPORTED_PACKET_TYPE"
    MQTT_INVALID_FLAGS = "MQTT_INVALID_FLAGS"
    MQTT_VARINT_OVERFLOW = "MQTT_VARINT_OVERFLOW"
    MQTT_OVERLONG_VARINT = "MQTT_OVERLONG_VARINT"
    MQTT_PACKET_LEN_MISMATCH = "MQTT_PACKET_LEN_MISMATCH"
    MQTT_TOPIC_OOB = "MQTT_TOPIC_OOB"
    MQTT_INVALID_TOPIC = "MQTT_INVALID_TOPIC"
    MQTT_INVALID_PAYLOAD = "MQTT_INVALID_PAYLOAD"
    MQTT_REGISTER_OOB = "MQTT_REGISTER_OOB"


_COMPARATOR_OPS: frozenset[NodeOp] = frozenset({
    NodeOp.CMP_GT,
    NodeOp.CMP_GE,
    NodeOp.CMP_LT,
    NodeOp.CMP_LE,
    NodeOp.CMP_EQ,
    NodeOp.CMP_NE,
})

_GATE_OPS: frozenset[NodeOp] = frozenset({
    NodeOp.AND,
    NodeOp.OR,
    NodeOp.XOR,
    NodeOp.NOT,
    NodeOp.NAND,
    NodeOp.NOR,
})


def _require_int(
    val: object,
    name: str,
    min_val: int | None = None,
    max_val: int | None = None,
) -> int:
    """Validate an exact integer (rejecting bool) within inclusive bounds."""
    assert isinstance(name, str)
    assert len(name) > 0
    if type(val) is not int:
        raise TypeError(f"{name} must be exact int, got {type(val).__name__}")
    if min_val is not None and val < min_val:
        raise ValueError(f"{name} must be >= {min_val}, got {val}")
    if max_val is not None and val > max_val:
        raise ValueError(f"{name} must be <= {max_val}, got {val}")
    return val


def _require_id(val: object, name: str) -> str:
    """Validate identifier format without NUL or control characters."""
    assert isinstance(name, str)
    assert len(name) > 0
    if type(val) is not str:
        raise TypeError(f"{name} must be str, got {type(val).__name__}")
    if "\x00" in val or any(ord(ch) < 32 for ch in val):
        raise ValueError(f"{name} contains forbidden control characters")
    if not ID_PATTERN.fullmatch(val):
        raise ValueError(f"{name} must match ^[A-Z0-9_-]{{1,32}}$")
    return val


def _require_bool(val: object, name: str) -> bool:
    """Validate an exact boolean value."""
    assert isinstance(name, str)
    assert len(name) > 0
    if type(val) is not bool:
        raise TypeError(f"{name} must be exact bool, got {type(val).__name__}")
    return val


def ceil_div(n: int, d: int) -> int:
    """Exact integer ceiling division for n >= 0 and d > 0."""
    if type(n) is not int or type(d) is not int:
        raise TypeError("ceil_div requires exact int operands")
    if n < 0 or d <= 0:
        raise ValueError("ceil_div requires n >= 0 and d > 0")
    result = (n + d - 1) // d
    assert result >= 0
    assert result * d >= n
    return result


def blake2b_u64(data: bytes) -> int:
    """Compute RFC 7693 BLAKE2b-64 digest interpreted as little-endian uint64."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")
    digest = hashlib.blake2b(data, digest_size=8).digest()
    assert len(digest) == 8
    value = int.from_bytes(digest, "little")
    assert 0 <= value < U64_LIMIT
    return value


def compute_verdict_hash(
    prev_hash_u64: int,
    packet_id: str,
    seq_no: int,
    timestamp_ms: int,
    source_id: str,
    protocol: ProtocolType,
    verdict_code: VerdictCode,
    tripped_node_id: int,
    breaker_state: BreakerState,
) -> int:
    """Seal verdict fields into the BLAKE2b-64 cryptographic hash chain."""
    _require_int(prev_hash_u64, "prev_hash_u64", 0, U64_LIMIT - 1)
    assert isinstance(protocol, ProtocolType)
    assert isinstance(verdict_code, VerdictCode)
    preimage = (
        f"{prev_hash_u64:016x}|{packet_id}|{seq_no}|{timestamp_ms}|"
        f"{source_id}|{protocol.value}|{verdict_code.value}|"
        f"{tripped_node_id}|{breaker_state.value}"
    ).encode("ascii")
    return blake2b_u64(preimage)


@dataclass(slots=True, frozen=True)
class FirewallPolicy:
    """Immutable per-source rate-limit and Nygard circuit-breaker policy."""

    window_ms: int = 10_000
    max_requests_per_window: int = 10
    trip_threshold: int = 3
    cooldown_ms: int = 30_000

    def __post_init__(self) -> None:
        """Validate policy integer domains."""
        _require_int(self.window_ms, "window_ms", 1, 86_400_000)
        _require_int(
            self.max_requests_per_window,
            "max_requests_per_window",
            1,
            MAX_WINDOW_TIMESTAMPS,
        )
        _require_int(self.trip_threshold, "trip_threshold", 1, 1_000)
        _require_int(self.cooldown_ms, "cooldown_ms", 1, 86_400_000)
        assert self.window_ms >= 1
        assert self.max_requests_per_window <= MAX_WINDOW_TIMESTAMPS


@dataclass(slots=True, frozen=True)
class DagNode:
    """Immutable combinational safety-interlock DAG vertex."""

    node_id: int
    tag: str
    op: NodeOp
    target_reg: int = 0
    threshold: int = 0
    inputs: tuple[int, ...] = ()
    is_hazard_output: bool = False

    def __post_init__(self) -> None:
        """Validate node operation, bounds, and input arity."""
        _require_int(self.node_id, "node_id", 0, MAX_DAG_NODES - 1)
        _require_id(self.tag, "tag")
        if not isinstance(self.op, NodeOp):
            raise TypeError("op must be NodeOp")
        _require_int(self.target_reg, "target_reg", 0, MAX_REGISTERS - 1)
        _require_int(self.threshold, "threshold", MIN_REG_VAL, MAX_REG_VAL)
        _require_bool(self.is_hazard_output, "is_hazard_output")
        if type(self.inputs) is not tuple:
            raise TypeError("inputs must be tuple[int, ...]")
        for inp in self.inputs:
            _require_int(inp, "inputs[]", 0, MAX_DAG_NODES - 1)
            if inp == self.node_id:
                raise ValueError("Self-loop detected in DagNode.inputs")
        if self.op in _COMPARATOR_OPS and len(self.inputs) != 0:
            raise ValueError("Comparator DagNode must have empty inputs")
        if self.op == NodeOp.NOT and len(self.inputs) != 1:
            raise ValueError("NOT gate requires exactly 1 input")
        if self.op in _GATE_OPS and not (1 <= len(self.inputs) <= 8):
            raise ValueError("Logic gate requires 1..8 inputs")
        assert 0 <= self.node_id < MAX_DAG_NODES
        assert 0 <= self.target_reg < MAX_REGISTERS


@dataclass(slots=True, frozen=True)
class RawPacket:
    """Immutable ingress OT/ICS packet envelope."""

    packet_id: str
    source_id: str
    seq_no: int
    timestamp_ms: int
    protocol: ProtocolType
    payload_hex: str

    def __post_init__(self) -> None:
        """Validate identifiers, integer fields, protocol, and hex payload."""
        _require_id(self.packet_id, "packet_id")
        _require_id(self.source_id, "source_id")
        _require_int(self.seq_no, "seq_no", 1)
        _require_int(self.timestamp_ms, "timestamp_ms", 0)
        if not isinstance(self.protocol, ProtocolType):
            raise TypeError("protocol must be ProtocolType")
        if type(self.payload_hex) is not str:
            raise TypeError("payload_hex must be str")
        if "\x00" in self.payload_hex or len(self.payload_hex) % 2 != 0:
            raise ValueError("payload_hex must be even-length without NUL")
        if not HEX_PATTERN.fullmatch(self.payload_hex):
            raise ValueError("payload_hex must be 2..1024 hex digits")
        assert self.seq_no >= 1
        assert len(self.payload_hex) % 2 == 0


@dataclass(slots=True, frozen=True)
class DecodedOperation:
    """Decoded wire-protocol register read or candidate write mutation."""

    protocol: ProtocolType
    is_write: bool
    writes: tuple[tuple[int, int], ...]
    read_start: int = 0
    read_count: int = 0
    topic: str = ""

    def __post_init__(self) -> None:
        """Validate decoded register mutations and topic hygiene."""
        if not isinstance(self.protocol, ProtocolType):
            raise TypeError("protocol must be ProtocolType")
        _require_bool(self.is_write, "is_write")
        if type(self.writes) is not tuple:
            raise TypeError("writes must be tuple")
        for pair in self.writes:
            if type(pair) is not tuple or len(pair) != 2:
                raise TypeError("each write must be (reg_addr, reg_val)")
            _require_int(pair[0], "reg_addr", 0, MAX_REGISTERS - 1)
            _require_int(pair[1], "reg_val", MIN_REG_VAL, MAX_REG_VAL)
        _require_int(self.read_start, "read_start", 0, MAX_REGISTERS - 1)
        _require_int(self.read_count, "read_count", 0, MAX_REGISTERS)
        if type(self.topic) is not str or "\x00" in self.topic:
            raise ValueError("topic must be NUL-free str")
        assert 0 <= self.read_start < MAX_REGISTERS
        assert 0 <= self.read_count <= MAX_REGISTERS


@dataclass(slots=True, frozen=True)
class SourceSecurityState:
    """Immutable snapshot of per-source fencing, rate-limit, and breaker state."""

    source_id: str
    last_seq_no: int
    breaker_state: BreakerState
    consecutive_failures: int
    total_violations: int
    opened_at_ms: int
    window_timestamps: tuple[int, ...]

    def __post_init__(self) -> None:
        """Validate per-source security invariants."""
        _require_id(self.source_id, "source_id")
        _require_int(self.last_seq_no, "last_seq_no", 0)
        if not isinstance(self.breaker_state, BreakerState):
            raise TypeError("breaker_state must be BreakerState")
        _require_int(self.consecutive_failures, "consecutive_failures", 0)
        _require_int(self.total_violations, "total_violations", 0)
        _require_int(self.opened_at_ms, "opened_at_ms", -1)
        if type(self.window_timestamps) is not tuple:
            raise TypeError("window_timestamps must be tuple")
        if len(self.window_timestamps) > MAX_WINDOW_TIMESTAMPS:
            raise ValueError("window_timestamps exceeds MAX_WINDOW_TIMESTAMPS")
        for ts in self.window_timestamps:
            _require_int(ts, "window_timestamp", 0)
        assert self.last_seq_no >= 0
        assert len(self.window_timestamps) <= MAX_WINDOW_TIMESTAMPS


@dataclass(slots=True, frozen=True)
class PacketVerdict:
    """Immutable cryptographically chained firewall verdict record."""

    seq_index: int
    packet_id: str
    source_id: str
    seq_no: int
    timestamp_ms: int
    protocol: ProtocolType
    verdict_code: VerdictCode
    is_allowed: bool
    tripped_node_id: int
    breaker_state_after: BreakerState
    prev_hash_u64: int
    chain_hash_u64: int

    def __post_init__(self) -> None:
        """Validate verdict fields and allow-flag consistency."""
        _require_int(self.seq_index, "seq_index", 0)
        _require_id(self.packet_id, "packet_id")
        _require_id(self.source_id, "source_id")
        _require_int(self.seq_no, "seq_no", 1)
        _require_int(self.timestamp_ms, "timestamp_ms", 0)
        if not isinstance(self.protocol, ProtocolType):
            raise TypeError("protocol must be ProtocolType")
        if not isinstance(self.verdict_code, VerdictCode):
            raise TypeError("verdict_code must be VerdictCode")
        _require_bool(self.is_allowed, "is_allowed")
        expected = self.verdict_code in (VerdictCode.ALLOW_READ, VerdictCode.ALLOW_WRITE)
        if self.is_allowed != expected:
            raise ValueError("is_allowed disagrees with verdict_code")
        _require_int(self.tripped_node_id, "tripped_node_id", -1, MAX_DAG_NODES - 1)
        if not isinstance(self.breaker_state_after, BreakerState):
            raise TypeError("breaker_state_after must be BreakerState")
        _require_int(self.prev_hash_u64, "prev_hash_u64", 0, U64_LIMIT - 1)
        _require_int(self.chain_hash_u64, "chain_hash_u64", 0, U64_LIMIT - 1)
        assert -1 <= self.tripped_node_id < MAX_DAG_NODES
        assert 0 <= self.chain_hash_u64 < U64_LIMIT


@dataclass(slots=True, frozen=True)
class PacketRejection:
    """Quarantined ingress packet error record from intake gate."""

    packet_index: int
    packet_id: str | None
    code: str
    detail: str

    def __post_init__(self) -> None:
        """Validate rejection metadata."""
        _require_int(self.packet_index, "packet_index", 0)
        if self.packet_id is not None and (
            type(self.packet_id) is not str or "\x00" in self.packet_id
        ):
            raise ValueError("packet_id must be None or NUL-free str")
        if type(self.code) is not str or not self.code or "\x00" in self.code:
            raise ValueError("code must be non-empty NUL-free str")
        if not self.code.isascii():
            raise ValueError("code must be ASCII")
        if type(self.detail) is not str or not self.detail or "\x00" in self.detail:
            raise ValueError("detail must be non-empty NUL-free str")
        assert self.packet_index >= 0
        assert len(self.code) > 0


@dataclass(slots=True, frozen=True)
class FirewallRunResult:
    """Complete deterministic output of evaluating a packet stream."""

    verdicts: tuple[PacketVerdict, ...]
    final_registers: tuple[int, ...]
    source_states: tuple[SourceSecurityState, ...]
    topological_order: tuple[int, ...]
    final_chain_hash_u64: int
    allowed_count: int
    blocked_count: int

    def __post_init__(self) -> None:
        """Validate run result dimensions and packet count accounting."""
        if (
            type(self.verdicts) is not tuple
            or type(self.final_registers) is not tuple
            or type(self.source_states) is not tuple
            or type(self.topological_order) is not tuple
        ):
            raise TypeError("FirewallRunResult collections must be tuple")
        if len(self.final_registers) != MAX_REGISTERS:
            raise ValueError("final_registers must have length MAX_REGISTERS")
        for reg_val in self.final_registers:
            _require_int(reg_val, "register", MIN_REG_VAL, MAX_REG_VAL)
        _require_int(self.final_chain_hash_u64, "final_chain_hash_u64", 0, U64_LIMIT - 1)
        _require_int(self.allowed_count, "allowed_count", 0)
        _require_int(self.blocked_count, "blocked_count", 0)
        if self.allowed_count + self.blocked_count != len(self.verdicts):
            raise ValueError("allowed_count + blocked_count != len(verdicts)")
        assert len(self.final_registers) == MAX_REGISTERS
        assert self.allowed_count + self.blocked_count == len(self.verdicts)

"""100% independent stdlib reference oracle and seeded scenario generator (FF-5)."""

from __future__ import annotations

import hashlib
import random
from collections.abc import Sequence
from dataclasses import dataclass

ORACLE_MAX_REGISTERS: int = 256
ORACLE_MAX_DAG_NODES: int = 128
ORACLE_MAX_SOURCES: int = 64
ORACLE_MAX_WINDOW_TIMESTAMPS: int = 64
ORACLE_MIN_REG_VAL: int = -32_768
ORACLE_MAX_REG_VAL: int = 65_535
ORACLE_GENESIS_HASH_U64: int = 0x5645435452413236


@dataclass(slots=True, frozen=True)
class OraclePolicy:
    """Reference policy parameters."""

    window_ms: int = 10_000
    max_requests_per_window: int = 10
    trip_threshold: int = 3
    cooldown_ms: int = 30_000


@dataclass(slots=True, frozen=True)
class OracleNode:
    """Reference DAG node."""

    node_id: int
    tag: str
    op: str
    target_reg: int = 0
    threshold: int = 0
    inputs: tuple[int, ...] = ()
    is_hazard_output: bool = False


@dataclass(slots=True, frozen=True)
class OraclePacket:
    """Reference input wire packet."""

    packet_id: str
    source_id: str
    seq_no: int
    timestamp_ms: int
    protocol: str
    payload_hex: str


@dataclass(slots=True, frozen=True)
class OracleVerdict:
    """Reference output packet verdict."""

    seq_index: int
    packet_id: str
    source_id: str
    seq_no: int
    timestamp_ms: int
    protocol: str
    verdict_code: str
    is_allowed: bool
    tripped_node_id: int
    breaker_state_after: str
    prev_hash_u64: int
    chain_hash_u64: int


@dataclass(slots=True, frozen=True)
class OracleSourceState:
    """Reference per-source security state."""

    source_id: str
    last_seq_no: int
    breaker_state: str
    consecutive_failures: int
    total_violations: int
    opened_at_ms: int
    window_timestamps: tuple[int, ...]


@dataclass(slots=True, frozen=True)
class OracleRunResult:
    """Reference stream evaluation output."""

    verdicts: tuple[OracleVerdict, ...]
    final_registers: tuple[int, ...]
    source_states: tuple[OracleSourceState, ...]
    topological_order: tuple[int, ...]
    final_chain_hash_u64: int
    allowed_count: int
    blocked_count: int


def oracle_blake2b_u64(data: bytes) -> int:
    """Independent RFC 7693 BLAKE2b-64 little-endian digest."""
    digest = hashlib.blake2b(data, digest_size=8).digest()
    return int.from_bytes(digest, "little")


def oracle_verdict_hash(
    prev_hash_u64: int,
    packet_id: str,
    seq_no: int,
    timestamp_ms: int,
    source_id: str,
    protocol: str,
    verdict_code: str,
    tripped_node_id: int,
    breaker_state: str,
) -> int:
    """Compute canonical ASCII verdict hash."""
    preimage = (
        f"{prev_hash_u64:016x}|{packet_id}|{seq_no}|{timestamp_ms}|"
        f"{source_id}|{protocol}|{verdict_code}|{tripped_node_id}|{breaker_state}"
    ).encode("ascii")
    return oracle_blake2b_u64(preimage)


def oracle_decode_modbus(
    raw: bytes,
) -> tuple[str | None, bool, tuple[tuple[int, int], ...]]:
    """Independent reference Modbus TCP wire decoder."""
    n = len(raw)
    if n < 8:
        return "MODBUS_FRAME_TOO_SHORT", False, ()
    proto_id = (raw[2] << 8) | raw[3]
    if proto_id != 0:
        return "MODBUS_INVALID_PROTOCOL", False, ()
    mbap_len = (raw[4] << 8) | raw[5]
    if mbap_len < 2 or mbap_len > 254:
        return "MODBUS_LENGTH_OUT_OF_BOUNDS", False, ()
    if n != 6 + mbap_len:
        return "MODBUS_MBAP_LEN_MISMATCH", False, ()
    fc = raw[7]
    if fc in (0x03, 0x05, 0x06):
        if mbap_len != 6:
            return "MODBUS_MBAP_LEN_MISMATCH", False, ()
        addr = (raw[8] << 8) | raw[9]
        val_u16 = (raw[10] << 8) | raw[11]
        if fc == 0x03:
            if val_u16 < 1 or val_u16 > 125 or addr + val_u16 > ORACLE_MAX_REGISTERS:
                return "MODBUS_REGISTER_OOB", False, ()
            return None, False, ()
        if addr >= ORACLE_MAX_REGISTERS:
            return "MODBUS_REGISTER_OOB", False, ()
        if fc == 0x05:
            if val_u16 not in (0x0000, 0xFF00):
                return "MODBUS_INVALID_COIL_VALUE", False, ()
            return None, True, ((addr, (val_u16 >> 8) & 1),)
        return None, True, ((addr, val_u16),)
    if fc == 0x10:
        if mbap_len < 9:
            return "MODBUS_MBAP_LEN_MISMATCH", False, ()
        addr = (raw[8] << 8) | raw[9]
        cnt = (raw[10] << 8) | raw[11]
        bc = raw[12]
        if cnt < 1 or cnt > 123 or addr + cnt > ORACLE_MAX_REGISTERS:
            return "MODBUS_REGISTER_OOB", False, ()
        if bc != 2 * cnt or mbap_len != 7 + bc:
            return "MODBUS_BYTE_COUNT_MISMATCH", False, ()
        writes = tuple(
            (addr + k, (raw[13 + 2 * k] << 8) | raw[14 + 2 * k]) for k in range(cnt)
        )
        return None, True, writes
    return "MODBUS_UNAUTHORIZED_FC", False, ()


def _parse_int_token(token: str) -> tuple[bool, int]:
    """Parse strict base-10 integer without whitespace or signs other than leading '-'."""
    if not token:
        return False, 0
    neg = token[0] == "-"
    digits = token[1:] if neg else token
    if not digits or len(digits) > 10 or any(c < "0" or c > "9" for c in digits):
        return False, 0
    val = int(digits)
    return True, (-val if neg else val)


def oracle_decode_mqtt(
    raw: bytes,
) -> tuple[str | None, bool, tuple[tuple[int, int], ...]]:
    """Independent reference MQTT v3.1.1 PUBLISH decoder."""
    n = len(raw)
    if n < 2:
        return "MQTT_FRAME_TOO_SHORT", False, ()
    ptype = (raw[0] >> 4) & 0x0F
    qos = ((raw[0] & 0x0F) >> 1) & 0x03
    if ptype != 3:
        return "MQTT_UNSUPPORTED_PACKET_TYPE", False, ()
    if qos == 3:
        return "MQTT_INVALID_FLAGS", False, ()
    rem_len = 0
    hdr_len = 0
    for idx in range(1, 5):
        digit = raw[idx]
        rem_len |= (digit & 0x7F) << (7 * (idx - 1))
        if (digit & 0x80) != 0:
            if idx == 4:
                return "MQTT_VARINT_OVERFLOW", False, ()
            if idx == n - 1:
                return "MQTT_FRAME_TOO_SHORT", False, ()
        else:
            if idx > 1 and digit == 0x00:
                return "MQTT_OVERLONG_VARINT", False, ()
            hdr_len = 1 + idx
            break
    if hdr_len + rem_len != n:
        return "MQTT_PACKET_LEN_MISMATCH", False, ()
    if rem_len < 2:
        return "MQTT_TOPIC_OOB", False, ()
    tlen = (raw[hdr_len] << 8) | raw[hdr_len + 1]
    vhdr = 2 + tlen + (2 if qos > 0 else 0)
    if tlen == 0 or vhdr > rem_len:
        return "MQTT_TOPIC_OOB", False, ()
    try:
        topic = raw[hdr_len + 2 : hdr_len + 2 + tlen].decode("utf-8")
    except UnicodeDecodeError:
        return "MQTT_INVALID_TOPIC", False, ()
    if "\x00" in topic or "+" in topic or "#" in topic:
        return "MQTT_INVALID_TOPIC", False, ()
    p = raw[hdr_len + vhdr :]
    if p.startswith(b"SET "):
        if not all(32 <= b < 128 for b in p):
            return "MQTT_INVALID_PAYLOAD", False, ()
        parts = p.decode("ascii").split(" ")
        if len(parts) != 3 or parts[0] != "SET":
            return "MQTT_INVALID_PAYLOAD", False, ()
        oka, addr = _parse_int_token(parts[1])
        okv, val = _parse_int_token(parts[2])
        if not oka or not okv:
            return "MQTT_INVALID_PAYLOAD", False, ()
    elif len(p) == 6:
        addr = (p[0] << 8) | p[1]
        raw_u32 = (p[2] << 24) | (p[3] << 16) | (p[4] << 8) | p[5]
        val = raw_u32 - 0x1_0000_0000 if (raw_u32 & 0x8000_0000) else raw_u32
    else:
        return "MQTT_INVALID_PAYLOAD", False, ()
    if not (0 <= addr < ORACLE_MAX_REGISTERS and ORACLE_MIN_REG_VAL <= val <= ORACLE_MAX_REG_VAL):
        return "MQTT_REGISTER_OOB", False, ()
    return None, True, ((addr, val),)


def oracle_kahn_sort(nodes: Sequence[OracleNode]) -> tuple[int, ...]:
    """Independent iterative Kahn topological sort with ascending node_id tie-break."""
    by_id: dict[int, OracleNode] = {}
    for n in nodes:
        if n.node_id in by_id:
            raise ValueError("Duplicate node_id")
        by_id[n.node_id] = n
    in_deg = {nid: len(n.inputs) for nid, n in by_id.items()}
    children: dict[int, list[int]] = {nid: [] for nid in by_id}
    for nid, n in by_id.items():
        for inp in n.inputs:
            if inp not in by_id:
                raise ValueError("Unknown input")
            children[inp].append(nid)
    ready = sorted(nid for nid, d in in_deg.items() if d == 0)
    topo: list[int] = []
    while ready:
        cur = ready.pop(0)
        topo.append(cur)
        for ch in children[cur]:
            in_deg[ch] -= 1
            if in_deg[ch] == 0:
                ready.append(ch)
        ready.sort()
    if len(topo) != len(by_id):
        raise ValueError("Cyclic DAG")
    return tuple(topo)


def oracle_eval_dag(
    nodes_by_id: dict[int, OracleNode], topo_order: tuple[int, ...], regs: Sequence[int]
) -> tuple[bool, int]:
    """Independent branchless DAG evaluation."""
    out: dict[int, int] = {}
    tripped_id = -1
    for nid in topo_order:
        n = nodes_by_id[nid]
        rv = regs[n.target_reg]
        th = n.threshold
        if n.op == "CMP_GT":
            bit = 1 if rv > th else 0
        elif n.op == "CMP_GE":
            bit = 1 if rv >= th else 0
        elif n.op == "CMP_LT":
            bit = 1 if rv < th else 0
        elif n.op == "CMP_LE":
            bit = 1 if rv <= th else 0
        elif n.op == "CMP_EQ":
            bit = 1 if rv == th else 0
        elif n.op == "CMP_NE":
            bit = 1 if rv != th else 0
        elif n.op == "NOT":
            bit = (out[n.inputs[0]] ^ 1) & 1
        elif n.op in ("AND", "NAND"):
            acc = 1
            for inp in n.inputs:
                acc &= out[inp] & 1
            bit = (acc ^ 1) & 1 if n.op == "NAND" else acc
        elif n.op in ("OR", "NOR"):
            acc = 0
            for inp in n.inputs:
                acc |= out[inp] & 1
            bit = (acc ^ 1) & 1 if n.op == "NOR" else acc
        else:
            acc = 0
            for inp in n.inputs:
                acc ^= out[inp] & 1
            bit = acc
        out[nid] = bit
        if n.is_hazard_output and bit == 1 and (tripped_id == -1 or nid < tripped_id):
            tripped_id = nid
    return tripped_id != -1, tripped_id


def oracle_evaluate_stream(
    packets: Sequence[OraclePacket],
    dag_nodes: Sequence[OracleNode],
    initial_registers: Sequence[int] | None = None,
    policy: OraclePolicy | None = None,
) -> OracleRunResult:
    """Independent reference implementation of Steps 1-6 OT firewall state machine."""
    pol = policy or OraclePolicy()
    regs = list(initial_registers) if initial_registers is not None else [0] * ORACLE_MAX_REGISTERS
    topo = oracle_kahn_sort(dag_nodes)
    by_id = {n.node_id: n for n in dag_nodes}
    sources: dict[str, dict[str, object]] = {}
    verdicts: list[OracleVerdict] = []
    prev_hash = ORACLE_GENESIS_HASH_U64
    allowed_cnt = 0
    for idx, pkt in enumerate(packets):
        if pkt.source_id not in sources:
            sources[pkt.source_id] = {
                "last_seq": 0,
                "state": "CLOSED",
                "fails": 0,
                "viols": 0,
                "opened": -1,
                "win": [],
            }
        st = sources[pkt.source_id]
        state_str = str(st["state"])
        opened = int(str(st["opened"]))
        if state_str == "OPEN" and pkt.timestamp_ms - opened < pol.cooldown_ms:
            vcode, trip_id, allowed = "CIRCUIT_BREAKER_OPEN", -1, False
        else:
            if state_str == "OPEN":
                st["state"] = "HALF_OPEN"
            last_seq = int(str(st["last_seq"]))
            if pkt.seq_no <= last_seq:
                vcode, trip_id = "REPLAY_ATTACK_BLOCKED", -1
            else:
                st["last_seq"] = pkt.seq_no
                win: list[int] = list(st["win"])  # type: ignore[arg-type]
                cutoff = pkt.timestamp_ms - pol.window_ms
                win = [t for t in win if t >= cutoff]
                if len(win) >= pol.max_requests_per_window:
                    st["win"] = win
                    vcode, trip_id = "RATE_LIMIT_EXCEEDED", -1
                else:
                    win.append(pkt.timestamp_ms)
                    st["win"] = win
                    raw = bytes.fromhex(pkt.payload_hex)
                    err, is_write, writes = (
                        oracle_decode_modbus(raw)
                        if pkt.protocol == "MODBUS_TCP"
                        else oracle_decode_mqtt(raw)
                    )
                    if err is not None:
                        vcode, trip_id = err, -1
                    elif not is_write:
                        vcode, trip_id = "ALLOW_READ", -1
                    else:
                        scratch = list(regs)
                        for addr, val in writes:
                            scratch[addr] = val
                        tripped, trip_id = oracle_eval_dag(by_id, topo, scratch)
                        if tripped:
                            vcode = "INTERLOCK_TRIPPED"
                        else:
                            regs[:] = scratch
                            vcode, trip_id = "ALLOW_WRITE", -1
            allowed = vcode in ("ALLOW_READ", "ALLOW_WRITE")
            if allowed:
                st["fails"] = 0
                if st["state"] == "HALF_OPEN":
                    st["state"] = "CLOSED"
            else:
                fails = int(str(st["fails"])) + 1
                st["fails"] = fails
                st["viols"] = int(str(st["viols"])) + 1
                if st["state"] == "HALF_OPEN" or fails >= pol.trip_threshold:
                    st["state"] = "OPEN"
                    st["opened"] = pkt.timestamp_ms
        cur_state = str(st["state"])
        ch = oracle_verdict_hash(
            prev_hash,
            pkt.packet_id,
            pkt.seq_no,
            pkt.timestamp_ms,
            pkt.source_id,
            pkt.protocol,
            vcode,
            trip_id,
            cur_state,
        )
        verdicts.append(
            OracleVerdict(
                seq_index=idx,
                packet_id=pkt.packet_id,
                source_id=pkt.source_id,
                seq_no=pkt.seq_no,
                timestamp_ms=pkt.timestamp_ms,
                protocol=pkt.protocol,
                verdict_code=vcode,
                is_allowed=allowed,
                tripped_node_id=trip_id,
                breaker_state_after=cur_state,
                prev_hash_u64=prev_hash,
                chain_hash_u64=ch,
            )
        )
        prev_hash = ch
        allowed_cnt += 1 if allowed else 0
    src_tuple = tuple(
        OracleSourceState(
            source_id=k,
            last_seq_no=int(str(sources[k]["last_seq"])),
            breaker_state=str(sources[k]["state"]),
            consecutive_failures=int(str(sources[k]["fails"])),
            total_violations=int(str(sources[k]["viols"])),
            opened_at_ms=int(str(sources[k]["opened"])),
            window_timestamps=tuple(sources[k]["win"]),  # type: ignore[arg-type]
        )
        for k in sorted(sources)
    )
    return OracleRunResult(
        verdicts=tuple(verdicts),
        final_registers=tuple(regs),
        source_states=src_tuple,
        topological_order=topo,
        final_chain_hash_u64=prev_hash,
        allowed_count=allowed_cnt,
        blocked_count=len(verdicts) - allowed_cnt,
    )


def _mb_hdr(tx: int, proto: int, mbap_len: int, unit: int, fc: int) -> bytes:
    """Build 8-byte MBAP + function code header."""
    return (
        tx.to_bytes(2, "big")
        + proto.to_bytes(2, "big")
        + mbap_len.to_bytes(2, "big")
        + bytes((unit, fc))
    )


def _bad_modbus_hex(kind: int) -> str:
    """Select one of all 8 Modbus rejection error frames deterministically."""
    idx = kind % 8
    if idx == 0:
        return (b"\x00" * 7).hex()
    if idx == 1:
        return _mb_hdr(1, 7, 2, 1, 0x03).hex()
    if idx == 2:
        return _mb_hdr(1, 0, 1, 1, 0x03).hex()
    if idx == 3:
        return (_mb_hdr(1, 0, 6, 1, 0x03) + b"\x00\x00").hex()
    if idx == 4:
        return (_mb_hdr(1, 0, 6, 1, 0x06) + (260).to_bytes(2, "big") + (10).to_bytes(2, "big")).hex()
    if idx == 5:
        return (_mb_hdr(1, 0, 6, 1, 0x05) + (2).to_bytes(2, "big") + (0x1234).to_bytes(2, "big")).hex()
    if idx == 6:
        return (
            _mb_hdr(1, 0, 11, 1, 0x10)
            + (10).to_bytes(2, "big")
            + (2).to_bytes(2, "big")
            + bytes((5,))
            + b"\x00\x01\x00\x02"
        ).hex()
    return (_mb_hdr(1, 0, 6, 1, 0x08) + b"\x00\x00\x00\x00").hex()


def _bad_mqtt_hex(kind: int) -> str:
    """Select one of all 10 MQTT rejection error frames deterministically."""
    idx = kind % 10
    if idx == 0:
        return "30"
    if idx == 1:
        return "1000"
    if idx == 2:
        return "3600"
    if idx == 3:
        return "30ffffffff01"
    if idx == 4:
        return "308000"
    if idx == 5:
        return "3005000161"
    if idx == 6:
        return "30020005"
    if idx == 7:
        body = (5).to_bytes(2, "big") + b"a/+/b" + b"SET 1 1"
        return (bytes((0x30, len(body))) + body).hex()
    if idx == 8:
        body = (3).to_bytes(2, "big") + b"a/b" + b"BAD"
        return (bytes((0x30, len(body))) + body).hex()
    body = (3).to_bytes(2, "big") + b"a/b" + b"SET 300 1"
    return (bytes((0x30, len(body))) + body).hex()


def _valid_mqtt_binary_hex(addr: int, val: int, qos: int = 0) -> str:
    """Build valid 6-byte big-endian signed MQTT binary command frame (QoS 0/1/2)."""
    topic = b"edge/telemetry"
    val_u32 = val & 0xFFFF_FFFF
    payload = addr.to_bytes(2, "big") + val_u32.to_bytes(4, "big")
    pkt_id = (1).to_bytes(2, "big") if qos > 0 else b""
    body = len(topic).to_bytes(2, "big") + topic + pkt_id + payload
    hdr_byte = 0x30 | ((qos & 0x03) << 1)
    return (bytes((hdr_byte, len(body))) + body).hex()


def _valid_mqtt_ascii_hex(addr: int, val: int, qos: int = 0) -> str:
    """Build valid ASCII SET MQTT frame (QoS 0/1/2)."""
    topic = b"plant/cmd"
    cmd = f"SET {addr} {val}".encode("ascii")
    pkt_id = (2).to_bytes(2, "big") if qos > 0 else b""
    body = len(topic).to_bytes(2, "big") + topic + pkt_id + cmd
    hdr_byte = 0x30 | ((qos & 0x03) << 1)
    return (bytes((hdr_byte, len(body))) + body).hex()


def _valid_modbus_fc16_hex(addr: int, values: list[int]) -> str:
    """Build valid Modbus FC 0x10 frame."""
    cnt = len(values)
    bc = 2 * cnt
    hdr = (
        _mb_hdr(2, 0, 7 + bc, 1, 0x10)
        + addr.to_bytes(2, "big")
        + cnt.to_bytes(2, "big")
        + bytes((bc,))
    )
    body = b"".join(v.to_bytes(2, "big") for v in values)
    return (hdr + body).hex()


def generate_random_scenario(
    seed: int,
) -> tuple[list[OraclePacket], list[OracleNode], list[int], OraclePolicy]:
    """Generate deterministic multi-protocol OT scenario covering all 24 codes & 12 ops."""
    rng = random.Random(seed)
    regs = [0] * ORACLE_MAX_REGISTERS
    regs[0] = rng.randint(100, 400)
    policy = OraclePolicy(
        window_ms=500,
        max_requests_per_window=3,
        trip_threshold=3,
        cooldown_ms=2_000,
    )
    all_cmp = ("CMP_GE", "CMP_LT", "CMP_LE", "CMP_EQ", "CMP_NE")
    all_gates = ("AND", "OR", "XOR", "NOT", "NAND", "NOR")
    cmp_a = all_cmp[seed % 5]
    cmp_b = all_cmp[(seed + 1) % 5]
    gate_a = all_gates[seed % 6]
    gate_b = all_gates[(seed + 3) % 6]
    nodes = [
        OracleNode(0, "HAZ_TEMP", "CMP_GT", target_reg=0, threshold=1000, is_hazard_output=True),
        OracleNode(10, "CMP_1", cmp_a, target_reg=2, threshold=50),
        OracleNode(3, "CMP_2", cmp_b, target_reg=3, threshold=0),
        OracleNode(
            7,
            "GATE_1",
            gate_a,
            inputs=(10,) if gate_a == "NOT" else (10, 3),
        ),
        OracleNode(
            5,
            "GATE_2",
            gate_b,
            inputs=(7,) if gate_b == "NOT" else (7, 3),
        ),
    ]
    mb_read = (_mb_hdr(1, 0, 6, 1, 0x03) + (0).to_bytes(2, "big") + (4).to_bytes(2, "big")).hex()
    mb_write_safe = (_mb_hdr(1, 0, 6, 1, 0x06) + (2).to_bytes(2, "big") + (rng.randint(10, 200)).to_bytes(2, "big")).hex()
    mb_write_haz = (_mb_hdr(1, 0, 6, 1, 0x06) + (0).to_bytes(2, "big") + (1500).to_bytes(2, "big")).hex()
    coil_val = 0xFF00 if (seed & 1) == 0 else 0x0000
    mb_coil = (_mb_hdr(3, 0, 6, 1, 0x05) + (6).to_bytes(2, "big") + coil_val.to_bytes(2, "big")).hex()
    bin_val = rng.randint(-10_000, 10_000)
    src_a = f"PLC_A_{seed}"
    src_b = f"EDGE_B_{seed}"
    src_c = f"COIL_C_{seed}"
    probe_pkt = (
        OraclePacket(
            "PKT_7", src_a, 5, 4_000, "MQTT", _valid_mqtt_ascii_hex(1, 77, qos=seed % 3)
        )
        if (seed & 1) == 0
        else OraclePacket("PKT_7", src_a, 4, 4_000, "MODBUS_TCP", mb_read)
    )
    packets = [
        OraclePacket("PKT_1", src_a, 1, 1_000, "MODBUS_TCP", mb_write_safe),
        OraclePacket("PKT_2", src_a, 2, 1_050, "MODBUS_TCP", mb_read),
        OraclePacket("PKT_3", src_a, 3, 1_100, "MODBUS_TCP", mb_write_haz),
        OraclePacket("PKT_4", src_a, 3, 1_150, "MODBUS_TCP", mb_read),
        OraclePacket("PKT_5", src_a, 4, 1_700, "MODBUS_TCP", _bad_modbus_hex(seed)),
        OraclePacket("PKT_6", src_a, 5, 2_000, "MODBUS_TCP", mb_read),
        probe_pkt,
        OraclePacket(
            "PKT_8",
            src_b,
            1,
            4_100,
            "MQTT",
            _valid_mqtt_binary_hex(3, bin_val, qos=(seed + 1) % 3),
        ),
        OraclePacket("PKT_9", src_b, 2, 4_150, "MQTT", _bad_mqtt_hex(seed)),
        OraclePacket("PKT_10", src_b, 3, 4_200, "MODBUS_TCP", _valid_modbus_fc16_hex(4, [11, 22])),
        OraclePacket("PKT_11", src_b, 4, 4_250, "MODBUS_TCP", mb_read),
        OraclePacket("PKT_12", src_c, 1, 4_300, "MODBUS_TCP", mb_coil),
    ]
    return packets, nodes, regs, policy

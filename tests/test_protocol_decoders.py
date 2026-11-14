"""Unit tests for Layer 0 models/hygiene and Layer 1 Modbus/MQTT wire decoders."""

from __future__ import annotations

import struct

import pytest

from vectragate.models import (
    MAX_REGISTERS,
    BreakerState,
    DagNode,
    FirewallPolicy,
    FirewallRunResult,
    NodeOp,
    ProtocolType,
    RawPacket,
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


def _mqtt_varint(length: int) -> bytes:
    """Encode MQTT v3.1.1 Remaining Length variable-byte integer."""
    out = bytearray()
    rem = length
    while True:
        encoded = rem & 0x7F
        rem >>= 7
        if rem > 0:
            encoded |= 0x80
        out.append(encoded)
        if rem == 0:
            break
    return bytes(out)


def _build_mqtt_publish(
    topic: bytes,
    payload: bytes,
    *,
    qos: int = 0,
    packet_id: int = 1,
    flags_extra: int = 0,
) -> bytes:
    """Construct raw MQTT v3.1.1 PUBLISH frame."""
    header_byte = 0x30 | ((qos & 0x03) << 1) | (flags_extra & 0x09)
    body = bytearray(struct.pack("!H", len(topic)) + topic)
    if qos > 0:
        body.extend(struct.pack("!H", packet_id))
    body.extend(payload)
    return bytes([header_byte]) + _mqtt_varint(len(body)) + bytes(body)


def test_f1_models_boundary_hygiene_and_helpers() -> None:
    """Reject bool masquerading as int, bad IDs, NUL bytes, and invalid ranges."""
    with pytest.raises(TypeError):
        FirewallPolicy(window_ms=True)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        RawPacket("PKT1", "PLC1", True, 0, ProtocolType.MODBUS_TCP, "00010000")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        RawPacket("pkt-lower", "PLC1", 1, 0, ProtocolType.MODBUS_TCP, "00010000")
    with pytest.raises(ValueError):
        RawPacket("PKT\x001", "PLC1", 1, 0, ProtocolType.MODBUS_TCP, "00010000")
    with pytest.raises(ValueError):
        RawPacket("PKT1", "PLC1", 1, 0, ProtocolType.MODBUS_TCP, "001")
    with pytest.raises(ValueError):
        DagNode(node_id=0, tag="SELF", op=NodeOp.NOT, inputs=(0,))
    with pytest.raises(ValueError):
        DagNode(node_id=1, tag="CMPBAD", op=NodeOp.CMP_GT, inputs=(0,))
    assert ceil_div(0, 8) == 0
    assert ceil_div(17, 8) == 3
    assert blake2b_u64(b"A" * 200) != blake2b_u64(b"A" * 199)
    h1 = compute_verdict_hash(
        0x5645435452413236,
        "A" * 32,
        1,
        100,
        "B" * 32,
        ProtocolType.MODBUS_TCP,
        VerdictCode.MODBUS_LENGTH_OUT_OF_BOUNDS,
        -1,
        BreakerState.HALF_OPEN,
    )
    assert 0 <= h1 < (1 << 64)


def test_f1_firewall_run_result_tuple_enforcement() -> None:
    """Reject non-tuple sequences in FirewallRunResult.__post_init__ (F-05)."""
    regs = (0,) * MAX_REGISTERS
    with pytest.raises(TypeError):
        FirewallRunResult([], regs, (), (), 0, 0, 0)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        FirewallRunResult((), regs, [], (), 0, 0, 0)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        FirewallRunResult((), regs, (), [], 0, 0, 0)  # type: ignore[arg-type]


def test_f2_modbus_valid_read_coil_single_and_multi_writes() -> None:
    """Decode valid Modbus FC 0x03, 0x05, 0x06, and 0x10 frames."""
    fc03 = struct.pack("!HHHBBHH", 1, 0, 6, 1, 0x03, 10, 4)
    err, op = decode_modbus_tcp(fc03)
    assert err is None and op is not None
    assert not op.is_write and op.read_start == 10 and op.read_count == 4

    fc05_on = struct.pack("!HHHBBHH", 2, 0, 6, 1, 0x05, 5, 0xFF00)
    err, op = decode_modbus_tcp(fc05_on)
    assert err is None and op is not None
    assert op.is_write and op.writes == ((5, 1),)

    fc05_off = struct.pack("!HHHBBHH", 3, 0, 6, 1, 0x05, 5, 0x0000)
    err, op = decode_modbus_tcp(fc05_off)
    assert err is None and op is not None and op.writes == ((5, 0),)

    fc06 = struct.pack("!HHHBBHH", 4, 0, 6, 1, 0x06, 20, 4200)
    err, op = decode_wire_packet(ProtocolType.MODBUS_TCP, fc06.hex())
    assert err is None and op is not None and op.writes == ((20, 4200),)

    fc10 = struct.pack("!HHHBBHHBHH", 5, 0, 11, 1, 0x10, 100, 2, 4, 500, 600)
    err, op = decode_modbus_tcp(fc10)
    assert err is None and op is not None
    assert op.writes == ((100, 500), (101, 600))


@pytest.mark.parametrize(
    ("case_name", "raw_frame", "expected_code"),
    [
        ("short_7b", b"\x00" * 7, VerdictCode.MODBUS_FRAME_TOO_SHORT),
        (
            "bad_protocol_id",
            struct.pack("!HHHBB", 1, 7, 2, 1, 0x03),
            VerdictCode.MODBUS_INVALID_PROTOCOL,
        ),
        (
            "ec_a_mbap_len_1_underflow",
            struct.pack("!HHHBB", 1, 0, 1, 1, 0x03),
            VerdictCode.MODBUS_LENGTH_OUT_OF_BOUNDS,
        ),
        (
            "cve_2026_54410_mbap_len_255",
            struct.pack("!HHHBB", 1, 0, 255, 1, 0x03) + (b"\x00" * 253),
            VerdictCode.MODBUS_LENGTH_OUT_OF_BOUNDS,
        ),
        (
            "mbap_len_mismatch_fc03",
            struct.pack("!HHHBBHH", 1, 0, 7, 1, 0x03, 0, 1),
            VerdictCode.MODBUS_MBAP_LEN_MISMATCH,
        ),
        (
            "fc03_register_oob",
            struct.pack("!HHHBBHH", 1, 0, 6, 1, 0x03, MAX_REGISTERS - 2, 5),
            VerdictCode.MODBUS_REGISTER_OOB,
        ),
        (
            "fc06_register_oob",
            struct.pack("!HHHBBHH", 1, 0, 6, 1, 0x06, MAX_REGISTERS, 10),
            VerdictCode.MODBUS_REGISTER_OOB,
        ),
        (
            "fc05_invalid_coil_mask",
            struct.pack("!HHHBBHH", 1, 0, 6, 1, 0x05, 2, 0x1234),
            VerdictCode.MODBUS_INVALID_COIL_VALUE,
        ),
        (
            "fc10_byte_count_mismatch",
            struct.pack("!HHHBBHHBHHH", 1, 0, 12, 1, 0x10, 10, 2, 5, 1, 2, 3)[:18],
            VerdictCode.MODBUS_BYTE_COUNT_MISMATCH,
        ),
        (
            "fc08_unauthorized_diagnostics",
            struct.pack("!HHHBBHH", 1, 0, 6, 1, 0x08, 0, 0),
            VerdictCode.MODBUS_UNAUTHORIZED_FC,
        ),
    ],
)
def test_f2_eca_modbus_individual_rejection_codes_and_cve_2026_54410(
    case_name: str,
    raw_frame: bytes,
    expected_code: VerdictCode,
) -> None:
    """Verify exact priority order for all 8 Modbus rejection codes and CVE-2026-54410."""
    assert len(case_name) > 0
    err, op = decode_modbus_tcp(raw_frame)
    assert err == expected_code
    assert op is None


@pytest.mark.parametrize("qos", [0, 1, 2])
def test_f3_mqtt_valid_ascii_and_binary_commands_across_qos(qos: int) -> None:
    """Decode MQTT PUBLISH ASCII SET and binary 6-byte writes across QoS 0, 1, and 2."""
    ascii_frame = _build_mqtt_publish(b"plant/valve", b"SET 12 -450", qos=qos, packet_id=7)
    err, op = decode_mqtt_publish(ascii_frame)
    assert err is None and op is not None
    assert op.is_write and op.topic == "plant/valve" and op.writes == ((12, -450),)

    bin_payload = struct.pack("!Hi", 15, -32_768)
    bin_frame = _build_mqtt_publish(b"plant/temp", bin_payload, qos=qos, packet_id=99)
    err, op = decode_wire_packet(ProtocolType.MQTT, bin_frame.hex())
    assert err is None and op is not None
    assert op.writes == ((15, -32_768),)


@pytest.mark.parametrize(
    ("case_name", "raw_frame", "expected_code"),
    [
        ("frame_1b", b"\x30", VerdictCode.MQTT_FRAME_TOO_SHORT),
        ("truncated_varint", b"\x30\x80", VerdictCode.MQTT_FRAME_TOO_SHORT),
        (
            "unsupported_connect_type",
            b"\x10\x02\x00\x00",
            VerdictCode.MQTT_UNSUPPORTED_PACKET_TYPE,
        ),
        ("invalid_qos3_flag", b"\x36\x02\x00\x00", VerdictCode.MQTT_INVALID_FLAGS),
        (
            "cve_2026_21888_5byte_varint",
            bytes([0x30, 0x80, 0x80, 0x80, 0x80, 0x01]),
            VerdictCode.MQTT_VARINT_OVERFLOW,
        ),
        (
            "overlong_varint_non_minimal",
            bytes([0x30, 0x80, 0x00, 0x00]),
            VerdictCode.MQTT_OVERLONG_VARINT,
        ),
        (
            "cve_2026_25627_packet_len_mismatch",
            bytes([0x30, 0x10, 0x00, 0x01, ord("a")]),
            VerdictCode.MQTT_PACKET_LEN_MISMATCH,
        ),
        (
            "topic_length_exceeds_remaining",
            bytes([0x30, 0x03, 0x00, 0x05, ord("a")]),
            VerdictCode.MQTT_TOPIC_OOB,
        ),
        (
            "invalid_utf8_topic",
            _build_mqtt_publish(b"\xff\xfe", b"SET 0 1"),
            VerdictCode.MQTT_INVALID_TOPIC,
        ),
        (
            "wildcard_hash_in_topic",
            _build_mqtt_publish(b"plant/#", b"SET 0 1"),
            VerdictCode.MQTT_INVALID_TOPIC,
        ),
        (
            "wildcard_plus_in_topic",
            _build_mqtt_publish(b"plant/+/cmd", b"SET 0 1"),
            VerdictCode.MQTT_INVALID_TOPIC,
        ),
        (
            "invalid_payload_crlf",
            _build_mqtt_publish(b"plant/cmd", b"SET 0 1\r\n"),
            VerdictCode.MQTT_INVALID_PAYLOAD,
        ),
        (
            "register_addr_oob",
            _build_mqtt_publish(b"plant/cmd", b"SET 256 10"),
            VerdictCode.MQTT_REGISTER_OOB,
        ),
        (
            "register_val_below_min",
            _build_mqtt_publish(b"plant/cmd", b"SET 1 -40000"),
            VerdictCode.MQTT_REGISTER_OOB,
        ),
    ],
)
def test_f3_ecb_mqtt_individual_rejection_codes_and_cves(
    case_name: str,
    raw_frame: bytes,
    expected_code: VerdictCode,
) -> None:
    """Verify all 10 MQTT rejection codes including CVE-2026-21888 and CVE-2026-25627."""
    assert len(case_name) > 0
    err, op = decode_mqtt_publish(raw_frame)
    assert err == expected_code
    assert op is None

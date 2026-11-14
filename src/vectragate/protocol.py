"""Layer 1 binary wire protocol decoders for Modbus TCP and MQTT v3.1.1."""

from __future__ import annotations

from vectragate.models import (
    MAX_REG_VAL,
    MAX_REGISTERS,
    MIN_REG_VAL,
    DecodedOperation,
    ProtocolType,
    VerdictCode,
)


def _decode_modbus_fc03_05_06(
    raw: bytes,
    func_code: int,
    mbap_len: int,
) -> tuple[VerdictCode | None, DecodedOperation | None]:
    """Decode Modbus FC 0x03 read and FC 0x05/0x06 single-write PDUs."""
    assert isinstance(raw, (bytes, bytearray))
    assert func_code in (0x03, 0x05, 0x06)
    if mbap_len != 6:
        return VerdictCode.MODBUS_MBAP_LEN_MISMATCH, None
    reg_addr = (raw[8] << 8) | raw[9]
    val_u16 = (raw[10] << 8) | raw[11]
    if func_code == 0x03:
        if val_u16 < 1 or val_u16 > 125 or reg_addr + val_u16 > MAX_REGISTERS:
            return VerdictCode.MODBUS_REGISTER_OOB, None
        return None, DecodedOperation(
            ProtocolType.MODBUS_TCP, False, (), reg_addr, val_u16, ""
        )
    if reg_addr >= MAX_REGISTERS:
        return VerdictCode.MODBUS_REGISTER_OOB, None
    if func_code == 0x05:
        if val_u16 not in (0x0000, 0xFF00):
            return VerdictCode.MODBUS_INVALID_COIL_VALUE, None
        coil_bit = (val_u16 >> 8) & 1
        return None, DecodedOperation(
            ProtocolType.MODBUS_TCP, True, ((reg_addr, coil_bit),)
        )
    return None, DecodedOperation(ProtocolType.MODBUS_TCP, True, ((reg_addr, val_u16),))


def _decode_modbus_fc16(
    raw: bytes,
    mbap_len: int,
) -> tuple[VerdictCode | None, DecodedOperation | None]:
    """Decode Modbus FC 0x10 Write Multiple Registers PDU."""
    assert isinstance(raw, (bytes, bytearray))
    assert mbap_len >= 2
    if mbap_len < 9:
        return VerdictCode.MODBUS_MBAP_LEN_MISMATCH, None
    reg_addr = (raw[8] << 8) | raw[9]
    reg_count = (raw[10] << 8) | raw[11]
    byte_count = raw[12]
    if reg_count < 1 or reg_count > 123 or reg_addr + reg_count > MAX_REGISTERS:
        return VerdictCode.MODBUS_REGISTER_OOB, None
    if byte_count != 2 * reg_count or mbap_len != 7 + byte_count:
        return VerdictCode.MODBUS_BYTE_COUNT_MISMATCH, None
    writes = tuple(
        (reg_addr + idx, (raw[13 + 2 * idx] << 8) | raw[14 + 2 * idx])
        for idx in range(reg_count)
    )
    return None, DecodedOperation(ProtocolType.MODBUS_TCP, True, writes)


def decode_modbus_tcp(
    raw: bytes,
) -> tuple[VerdictCode | None, DecodedOperation | None]:
    """Validate and decode a Modbus TCP ADU following strict rejection priority."""
    assert isinstance(raw, (bytes, bytearray))
    assert len(raw) <= 65_535
    if len(raw) < 8:
        return VerdictCode.MODBUS_FRAME_TOO_SHORT, None
    proto_id = (raw[2] << 8) | raw[3]
    if proto_id != 0:
        return VerdictCode.MODBUS_INVALID_PROTOCOL, None
    mbap_len = (raw[4] << 8) | raw[5]
    if mbap_len < 2 or mbap_len > 254:
        return VerdictCode.MODBUS_LENGTH_OUT_OF_BOUNDS, None
    if len(raw) != 6 + mbap_len:
        return VerdictCode.MODBUS_MBAP_LEN_MISMATCH, None
    func_code = raw[7]
    if func_code in (0x03, 0x05, 0x06):
        return _decode_modbus_fc03_05_06(raw, func_code, mbap_len)
    if func_code == 0x10:
        return _decode_modbus_fc16(raw, mbap_len)
    return VerdictCode.MODBUS_UNAUTHORIZED_FC, None


def _decode_mqtt_varint(raw: bytes) -> tuple[VerdictCode | None, int, int]:
    """Decode MQTT variable-byte Remaining Length with overlong/overflow guards."""
    n = len(raw)
    assert isinstance(raw, (bytes, bytearray))
    assert n >= 2
    rem_len = 0
    for idx in range(1, 5):
        digit = raw[idx]
        rem_len |= (digit & 0x7F) << (7 * (idx - 1))
        if (digit & 0x80) != 0:
            if idx == 4:
                return VerdictCode.MQTT_VARINT_OVERFLOW, 0, 0
            if idx == n - 1:
                return VerdictCode.MQTT_FRAME_TOO_SHORT, 0, 0
        else:
            if idx > 1 and digit == 0x00:
                return VerdictCode.MQTT_OVERLONG_VARINT, 0, 0
            return None, rem_len, 1 + idx
    return VerdictCode.MQTT_VARINT_OVERFLOW, 0, 0


def _parse_ascii_i64(token: str) -> tuple[bool, int]:
    """Parse strict ASCII base-10 integer without underscores or whitespace."""
    assert isinstance(token, str)
    assert len(token) < 4096
    if not token:
        return False, 0
    neg = token[0] == "-"
    digits = token[1:] if neg else token
    if not digits or len(digits) > 10:
        return False, 0
    for ch in digits:
        if ch < "0" or ch > "9":
            return False, 0
    val = int(digits)
    return True, (-val if neg else val)


def _decode_mqtt_payload(
    payload: bytes,
    topic: str,
) -> tuple[VerdictCode | None, DecodedOperation | None]:
    """Decode MQTT PUBLISH command payload (ASCII SET or binary 6-byte)."""
    assert isinstance(payload, (bytes, bytearray))
    assert isinstance(topic, str)
    if payload.startswith(b"SET "):
        if not all(32 <= b < 128 for b in payload):
            return VerdictCode.MQTT_INVALID_PAYLOAD, None
        parts = payload.decode("ascii").split(" ")
        if len(parts) != 3 or parts[0] != "SET":
            return VerdictCode.MQTT_INVALID_PAYLOAD, None
        ok_a, reg_addr = _parse_ascii_i64(parts[1])
        ok_v, reg_val = _parse_ascii_i64(parts[2])
        if not ok_a or not ok_v:
            return VerdictCode.MQTT_INVALID_PAYLOAD, None
    elif len(payload) == 6:
        reg_addr = (payload[0] << 8) | payload[1]
        raw_u32 = (
            (payload[2] << 24)
            | (payload[3] << 16)
            | (payload[4] << 8)
            | payload[5]
        )
        reg_val = raw_u32 - 0x1_0000_0000 if (raw_u32 & 0x8000_0000) else raw_u32
    else:
        return VerdictCode.MQTT_INVALID_PAYLOAD, None
    if not (0 <= reg_addr < MAX_REGISTERS and MIN_REG_VAL <= reg_val <= MAX_REG_VAL):
        return VerdictCode.MQTT_REGISTER_OOB, None
    return None, DecodedOperation(
        ProtocolType.MQTT, True, ((reg_addr, reg_val),), 0, 0, topic
    )


def decode_mqtt_publish(
    raw: bytes,
) -> tuple[VerdictCode | None, DecodedOperation | None]:
    """Validate and decode an MQTT v3.1.1 PUBLISH packet with CVE defenses."""
    assert isinstance(raw, (bytes, bytearray))
    assert len(raw) <= 65_535
    n = len(raw)
    if n < 2:
        return VerdictCode.MQTT_FRAME_TOO_SHORT, None
    packet_type = (raw[0] >> 4) & 0x0F
    qos = ((raw[0] & 0x0F) >> 1) & 0x03
    if packet_type != 3:
        return VerdictCode.MQTT_UNSUPPORTED_PACKET_TYPE, None
    if qos == 3:
        return VerdictCode.MQTT_INVALID_FLAGS, None
    err, rem_len, hdr_len = _decode_mqtt_varint(raw)
    if err is not None:
        return err, None
    if hdr_len + rem_len != n:
        return VerdictCode.MQTT_PACKET_LEN_MISMATCH, None
    if rem_len < 2:
        return VerdictCode.MQTT_TOPIC_OOB, None
    topic_len = (raw[hdr_len] << 8) | raw[hdr_len + 1]
    var_hdr_len = 2 + topic_len + (2 if qos > 0 else 0)
    if topic_len == 0 or var_hdr_len > rem_len:
        return VerdictCode.MQTT_TOPIC_OOB, None
    try:
        topic = raw[hdr_len + 2 : hdr_len + 2 + topic_len].decode("utf-8")
    except UnicodeDecodeError:
        return VerdictCode.MQTT_INVALID_TOPIC, None
    if "\x00" in topic or "+" in topic or "#" in topic:
        return VerdictCode.MQTT_INVALID_TOPIC, None
    return _decode_mqtt_payload(raw[hdr_len + var_hdr_len : n], topic)


def decode_wire_packet(
    protocol: ProtocolType,
    payload_hex: str,
) -> tuple[VerdictCode | None, DecodedOperation | None]:
    """Decode hex-encoded wire bytes according to protocol framing contract."""
    assert isinstance(protocol, ProtocolType)
    assert isinstance(payload_hex, str)
    raw = bytes.fromhex(payload_hex)
    if protocol == ProtocolType.MODBUS_TCP:
        return decode_modbus_tcp(raw)
    return decode_mqtt_publish(raw)

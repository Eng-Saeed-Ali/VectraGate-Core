#ifndef VECTRAGATE_CORE_HPP
#define VECTRAGATE_CORE_HPP

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace vectragate {

static constexpr size_t MAX_REGISTERS = 256U;
static constexpr size_t MAX_DAG_NODES = 128U;
static constexpr size_t MAX_DAG_INPUTS = 8U;
static constexpr size_t MAX_SOURCES = 64U;
static constexpr size_t MAX_WINDOW_TIMESTAMPS = 64U;
static constexpr size_t SPSC_RING_SLOTS = 256U;
static constexpr size_t MAX_RAW_PACKET_BYTES = 512U;
static constexpr size_t MAX_ID_BUF = 40U;
static constexpr int64_t MIN_REG_VAL = -32768LL;
static constexpr int64_t MAX_REG_VAL = 65535LL;
static constexpr uint64_t GENESIS_HASH_U64 = 0x5645435452413236ULL;

enum class ProtocolType : uint8_t {
    MODBUS_TCP = 0,
    MQTT = 1
};

enum class NodeOp : uint8_t {
    CMP_GT = 0,
    CMP_GE = 1,
    CMP_LT = 2,
    CMP_LE = 3,
    CMP_EQ = 4,
    CMP_NE = 5,
    AND = 6,
    OR = 7,
    XOR = 8,
    NOT = 9,
    NAND = 10,
    NOR = 11
};

enum class BreakerState : uint8_t {
    CLOSED = 0,
    OPEN = 1,
    HALF_OPEN = 2
};

enum class VerdictCode : uint8_t {
    ALLOW_READ = 0,
    ALLOW_WRITE = 1,
    CIRCUIT_BREAKER_OPEN = 2,
    REPLAY_ATTACK_BLOCKED = 3,
    RATE_LIMIT_EXCEEDED = 4,
    INTERLOCK_TRIPPED = 5,
    MODBUS_FRAME_TOO_SHORT = 6,
    MODBUS_INVALID_PROTOCOL = 7,
    MODBUS_LENGTH_OUT_OF_BOUNDS = 8,
    MODBUS_MBAP_LEN_MISMATCH = 9,
    MODBUS_REGISTER_OOB = 10,
    MODBUS_INVALID_COIL_VALUE = 11,
    MODBUS_BYTE_COUNT_MISMATCH = 12,
    MODBUS_UNAUTHORIZED_FC = 13,
    MQTT_FRAME_TOO_SHORT = 14,
    MQTT_UNSUPPORTED_PACKET_TYPE = 15,
    MQTT_INVALID_FLAGS = 16,
    MQTT_VARINT_OVERFLOW = 17,
    MQTT_OVERLONG_VARINT = 18,
    MQTT_PACKET_LEN_MISMATCH = 19,
    MQTT_TOPIC_OOB = 20,
    MQTT_INVALID_TOPIC = 21,
    MQTT_INVALID_PAYLOAD = 22,
    MQTT_REGISTER_OOB = 23
};

inline const char* protocol_to_cstr(ProtocolType p) noexcept {
    return (p == ProtocolType::MODBUS_TCP) ? "MODBUS_TCP" : "MQTT";
}

inline const char* breaker_to_cstr(BreakerState s) noexcept {
    switch (s) {
        case BreakerState::CLOSED:
            return "CLOSED";
        case BreakerState::OPEN:
            return "OPEN";
        case BreakerState::HALF_OPEN:
            return "HALF_OPEN";
    }
    return "CLOSED";
}

inline const char* verdict_to_cstr(VerdictCode c) noexcept {
    static constexpr const char* kNames[24] = {
        "ALLOW_READ",
        "ALLOW_WRITE",
        "CIRCUIT_BREAKER_OPEN",
        "REPLAY_ATTACK_BLOCKED",
        "RATE_LIMIT_EXCEEDED",
        "INTERLOCK_TRIPPED",
        "MODBUS_FRAME_TOO_SHORT",
        "MODBUS_INVALID_PROTOCOL",
        "MODBUS_LENGTH_OUT_OF_BOUNDS",
        "MODBUS_MBAP_LEN_MISMATCH",
        "MODBUS_REGISTER_OOB",
        "MODBUS_INVALID_COIL_VALUE",
        "MODBUS_BYTE_COUNT_MISMATCH",
        "MODBUS_UNAUTHORIZED_FC",
        "MQTT_FRAME_TOO_SHORT",
        "MQTT_UNSUPPORTED_PACKET_TYPE",
        "MQTT_INVALID_FLAGS",
        "MQTT_VARINT_OVERFLOW",
        "MQTT_OVERLONG_VARINT",
        "MQTT_PACKET_LEN_MISMATCH",
        "MQTT_TOPIC_OOB",
        "MQTT_INVALID_TOPIC",
        "MQTT_INVALID_PAYLOAD",
        "MQTT_REGISTER_OOB"
    };
    const size_t idx = static_cast<size_t>(c);
    return (idx < 24U) ? kNames[idx] : "MODBUS_UNAUTHORIZED_FC";
}

struct FirewallPolicyPod {
    int64_t window_ms{10000LL};
    int64_t max_requests_per_window{10LL};
    int64_t trip_threshold{3LL};
    int64_t cooldown_ms{30000LL};
};

struct alignas(64) DagNodePod {
    int32_t node_id{0};
    int32_t target_reg{0};
    int64_t threshold{0};
    NodeOp op{NodeOp::CMP_GT};
    uint8_t is_hazard_output{0};
    uint8_t input_count{0};
    std::array<int32_t, MAX_DAG_INPUTS> inputs{};
    char tag[MAX_ID_BUF]{};
};

struct alignas(64) SourceSecurityPod {
    char source_id[MAX_ID_BUF]{};
    int64_t last_seq_no{0};
    BreakerState breaker_state{BreakerState::CLOSED};
    int64_t consecutive_failures{0};
    int64_t total_violations{0};
    int64_t opened_at_ms{-1};
    size_t window_count{0};
    std::array<int64_t, MAX_WINDOW_TIMESTAMPS> window_timestamps{};
};

struct WritePairPod {
    int32_t reg_addr{0};
    int64_t reg_val{0};
};

struct DecodedOpPod {
    bool is_write{false};
    size_t write_count{0};
    std::array<WritePairPod, 128U> writes{};
};

struct alignas(64) PacketEventPod {
    char packet_id[MAX_ID_BUF]{};
    char source_id[MAX_ID_BUF]{};
    int64_t seq_no{0};
    int64_t timestamp_ms{0};
    ProtocolType protocol{ProtocolType::MODBUS_TCP};
    uint16_t raw_len{0};
    std::array<uint8_t, MAX_RAW_PACKET_BYTES> raw_bytes{};
};

struct PacketVerdictPod {
    int64_t seq_index{0};
    char packet_id[MAX_ID_BUF]{};
    char source_id[MAX_ID_BUF]{};
    int64_t seq_no{0};
    int64_t timestamp_ms{0};
    ProtocolType protocol{ProtocolType::MODBUS_TCP};
    VerdictCode verdict_code{VerdictCode::ALLOW_READ};
    bool is_allowed{false};
    int32_t tripped_node_id{-1};
    BreakerState breaker_state_after{BreakerState::CLOSED};
    uint64_t prev_hash_u64{0};
    uint64_t chain_hash_u64{0};
};

struct alignas(64) SpscRingBuffer {
    alignas(64) std::atomic<uint64_t> write_idx{0};
    alignas(64) std::atomic<uint64_t> read_idx{0};
    alignas(64) std::array<PacketEventPod, SPSC_RING_SLOTS> slots{};

    void reset() noexcept {
        write_idx.store(0ULL, std::memory_order_relaxed);
        read_idx.store(0ULL, std::memory_order_relaxed);
    }

    bool try_push(const PacketEventPod& item) noexcept {
        const uint64_t w = write_idx.load(std::memory_order_relaxed);
        const uint64_t r = read_idx.load(std::memory_order_acquire);
        if ((w - r) >= static_cast<uint64_t>(SPSC_RING_SLOTS)) {
            return false;
        }
        slots[static_cast<size_t>(w & (SPSC_RING_SLOTS - 1U))] = item;
        write_idx.store(w + 1ULL, std::memory_order_release);
        return true;
    }

    bool try_pop(PacketEventPod& out) noexcept {
        const uint64_t r = read_idx.load(std::memory_order_relaxed);
        const uint64_t w = write_idx.load(std::memory_order_acquire);
        if (r == w) {
            return false;
        }
        out = slots[static_cast<size_t>(r & (SPSC_RING_SLOTS - 1U))];
        read_idx.store(r + 1ULL, std::memory_order_release);
        return true;
    }

    bool is_full() const noexcept {
        const uint64_t w = write_idx.load(std::memory_order_relaxed);
        const uint64_t r = read_idx.load(std::memory_order_acquire);
        return (w - r) >= static_cast<uint64_t>(SPSC_RING_SLOTS);
    }
};

namespace detail {

inline uint64_t rotr64(uint64_t x, uint32_t n) noexcept {
    return (x >> n) | (x << (64U - n));
}

inline uint64_t load_le64(const uint8_t* p) noexcept {
    return static_cast<uint64_t>(p[0]) |
           (static_cast<uint64_t>(p[1]) << 8U) |
           (static_cast<uint64_t>(p[2]) << 16U) |
           (static_cast<uint64_t>(p[3]) << 24U) |
           (static_cast<uint64_t>(p[4]) << 32U) |
           (static_cast<uint64_t>(p[5]) << 40U) |
           (static_cast<uint64_t>(p[6]) << 48U) |
           (static_cast<uint64_t>(p[7]) << 56U);
}

inline void blake2b_g(
    std::array<uint64_t, 16>& v,
    size_t a,
    size_t b,
    size_t c,
    size_t d,
    uint64_t x,
    uint64_t y
) noexcept {
    v[a] = v[a] + v[b] + x;
    v[d] = rotr64(v[d] ^ v[a], 32U);
    v[c] = v[c] + v[d];
    v[b] = rotr64(v[b] ^ v[c], 24U);
    v[a] = v[a] + v[b] + y;
    v[d] = rotr64(v[d] ^ v[a], 16U);
    v[c] = v[c] + v[d];
    v[b] = rotr64(v[b] ^ v[c], 63U);
}

inline void blake2b_compress(
    std::array<uint64_t, 8>& h,
    const uint8_t block[128],
    uint64_t t0,
    uint64_t t1,
    bool last_block
) noexcept {
    static constexpr std::array<uint64_t, 8> kIv = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };
    static constexpr uint8_t kSigma[12][16] = {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
        {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
        {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
        {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
        {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
        {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
        {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
        {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
        {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}
    };
    std::array<uint64_t, 16> m{};
    for (size_t i = 0U; i < 16U; ++i) {
        m[i] = load_le64(block + (i * 8U));
    }
    std::array<uint64_t, 16> v{};
    for (size_t i = 0U; i < 8U; ++i) {
        v[i] = h[i];
        v[i + 8U] = kIv[i];
    }
    v[12] ^= t0;
    v[13] ^= t1;
    if (last_block) {
        v[14] = ~v[14];
    }
    for (size_t r = 0U; r < 12U; ++r) {
        const uint8_t* s = kSigma[r];
        blake2b_g(v, 0U, 4U, 8U, 12U, m[s[0]], m[s[1]]);
        blake2b_g(v, 1U, 5U, 9U, 13U, m[s[2]], m[s[3]]);
        blake2b_g(v, 2U, 6U, 10U, 14U, m[s[4]], m[s[5]]);
        blake2b_g(v, 3U, 7U, 11U, 15U, m[s[6]], m[s[7]]);
        blake2b_g(v, 0U, 5U, 10U, 15U, m[s[8]], m[s[9]]);
        blake2b_g(v, 1U, 6U, 11U, 12U, m[s[10]], m[s[11]]);
        blake2b_g(v, 2U, 7U, 8U, 13U, m[s[12]], m[s[13]]);
        blake2b_g(v, 3U, 4U, 9U, 14U, m[s[14]], m[s[15]]);
    }
    for (size_t i = 0U; i < 8U; ++i) {
        h[i] ^= v[i] ^ v[i + 8U];
    }
}

struct AsciiCursor {
    std::array<uint8_t, 512U> buf{};
    size_t len{0};

    void push_char(char ch) noexcept {
        if (len < buf.size()) {
            buf[len++] = static_cast<uint8_t>(ch);
        }
    }

    void push_cstr(const char* s) noexcept {
        for (size_t i = 0U; s[i] != '\0'; ++i) {
            push_char(s[i]);
        }
    }

    void push_hex64(uint64_t val) noexcept {
        static constexpr char kHex[] = "0123456789abcdef";
        for (int shift = 60; shift >= 0; shift -= 4) {
            push_char(kHex[(val >> static_cast<uint32_t>(shift)) & 0xFU]);
        }
    }

    void push_i64(int64_t val) noexcept {
        char tmp[32]{};
        size_t pos = 0U;
        uint64_t u = 0ULL;
        if (val < 0LL) {
            push_char('-');
            u = static_cast<uint64_t>(-(val + 1LL)) + 1ULL;
        } else {
            u = static_cast<uint64_t>(val);
        }
        if (u == 0ULL) {
            push_char('0');
            return;
        }
        while (u > 0ULL && pos < sizeof(tmp)) {
            tmp[pos++] = static_cast<char>('0' + (u % 10ULL));
            u /= 10ULL;
        }
        while (pos > 0U) {
            push_char(tmp[--pos]);
        }
    }
};

inline bool is_valid_utf8_no_wildcards(const uint8_t* data, size_t len) noexcept {
    size_t i = 0U;
    while (i < len) {
        const uint8_t b0 = data[i];
        if (b0 == 0x00U || b0 == static_cast<uint8_t>('+') ||
            b0 == static_cast<uint8_t>('#')) {
            return false;
        }
        if (b0 <= 0x7FU) {
            i += 1U;
        } else if (b0 >= 0xC2U && b0 <= 0xDFU) {
            if (i + 1U >= len) {
                return false;
            }
            const uint8_t b1 = data[i + 1U];
            if (b1 < 0x80U || b1 > 0xBFU) {
                return false;
            }
            i += 2U;
        } else if (b0 >= 0xE0U && b0 <= 0xEFU) {
            if (i + 2U >= len) {
                return false;
            }
            const uint8_t b1 = data[i + 1U];
            const uint8_t b2 = data[i + 2U];
            if (b2 < 0x80U || b2 > 0xBFU) {
                return false;
            }
            if (b0 == 0xE0U && (b1 < 0xA0U || b1 > 0xBFU)) {
                return false;
            }
            if (b0 == 0xEDU && (b1 < 0x80U || b1 > 0x9FU)) {
                return false;
            }
            if (b0 != 0xE0U && b0 != 0xEDU && (b1 < 0x80U || b1 > 0xBFU)) {
                return false;
            }
            i += 3U;
        } else if (b0 >= 0xF0U && b0 <= 0xF4U) {
            if (i + 3U >= len) {
                return false;
            }
            const uint8_t b1 = data[i + 1U];
            const uint8_t b2 = data[i + 2U];
            const uint8_t b3 = data[i + 3U];
            if (b2 < 0x80U || b2 > 0xBFU || b3 < 0x80U || b3 > 0xBFU) {
                return false;
            }
            if (b0 == 0xF0U && (b1 < 0x90U || b1 > 0xBFU)) {
                return false;
            }
            if (b0 == 0xF4U && (b1 < 0x80U || b1 > 0x8FU)) {
                return false;
            }
            if (b0 != 0xF0U && b0 != 0xF4U && (b1 < 0x80U || b1 > 0xBFU)) {
                return false;
            }
            i += 4U;
        } else {
            return false;
        }
    }
    return true;
}

inline bool parse_ascii_i64_span(const uint8_t* ptr, size_t len, int64_t& out) noexcept {
    if (len == 0U) {
        return false;
    }
    bool neg = false;
    size_t idx = 0U;
    if (ptr[0] == static_cast<uint8_t>('-')) {
        neg = true;
        idx = 1U;
    }
    const size_t digit_count = len - idx;
    if (digit_count == 0U || digit_count > 10U) {
        return false;
    }
    int64_t acc = 0;
    for (; idx < len; ++idx) {
        const uint8_t ch = ptr[idx];
        if (ch < static_cast<uint8_t>('0') || ch > static_cast<uint8_t>('9')) {
            return false;
        }
        acc = (acc * 10LL) + static_cast<int64_t>(ch - static_cast<uint8_t>('0'));
    }
    out = neg ? -acc : acc;
    return true;
}

}  // namespace detail

inline uint64_t blake2b_64(const uint8_t* msg, size_t len) noexcept {
    std::array<uint64_t, 8> h = {
        0x6a09e667f3bcc908ULL ^ 0x01010008ULL,
        0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL,
        0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL,
        0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL,
        0x5be0cd19137e2179ULL
    };
    uint64_t t0 = 0ULL;
    uint64_t t1 = 0ULL;
    while (len > 128U) {
        t0 += 128ULL;
        if (t0 < 128ULL) {
            ++t1;
        }
        detail::blake2b_compress(h, msg, t0, t1, false);
        msg += 128U;
        len -= 128U;
    }
    std::array<uint8_t, 128U> final_block{};
    if (len > 0U) {
        std::memcpy(final_block.data(), msg, len);
    }
    t0 += static_cast<uint64_t>(len);
    if (t0 < static_cast<uint64_t>(len)) {
        ++t1;
    }
    detail::blake2b_compress(h, final_block.data(), t0, t1, true);
    return h[0];
}

inline uint64_t compute_verdict_hash_u64(
    uint64_t prev_hash_u64,
    const char* packet_id,
    int64_t seq_no,
    int64_t timestamp_ms,
    const char* source_id,
    ProtocolType protocol,
    VerdictCode verdict_code,
    int32_t tripped_node_id,
    BreakerState breaker_state
) noexcept {
    detail::AsciiCursor cur;
    cur.push_hex64(prev_hash_u64);
    cur.push_char('|');
    cur.push_cstr(packet_id);
    cur.push_char('|');
    cur.push_i64(seq_no);
    cur.push_char('|');
    cur.push_i64(timestamp_ms);
    cur.push_char('|');
    cur.push_cstr(source_id);
    cur.push_char('|');
    cur.push_cstr(protocol_to_cstr(protocol));
    cur.push_char('|');
    cur.push_cstr(verdict_to_cstr(verdict_code));
    cur.push_char('|');
    cur.push_i64(static_cast<int64_t>(tripped_node_id));
    cur.push_char('|');
    cur.push_cstr(breaker_to_cstr(breaker_state));
    return blake2b_64(cur.buf.data(), cur.len);
}

inline VerdictCode decode_modbus_tcp(
    const uint8_t* raw,
    size_t len,
    DecodedOpPod& op,
    bool& ok
) noexcept {
    ok = false;
    op.is_write = false;
    op.write_count = 0U;
    if (len < 8U) {
        return VerdictCode::MODBUS_FRAME_TOO_SHORT;
    }
    const uint32_t proto_id =
        (static_cast<uint32_t>(raw[2]) << 8U) | static_cast<uint32_t>(raw[3]);
    if (proto_id != 0U) {
        return VerdictCode::MODBUS_INVALID_PROTOCOL;
    }
    const uint32_t mbap_len =
        (static_cast<uint32_t>(raw[4]) << 8U) | static_cast<uint32_t>(raw[5]);
    if (mbap_len < 2U || mbap_len > 254U) {
        return VerdictCode::MODBUS_LENGTH_OUT_OF_BOUNDS;
    }
    if (len != static_cast<size_t>(6U + mbap_len)) {
        return VerdictCode::MODBUS_MBAP_LEN_MISMATCH;
    }
    const uint8_t fc = raw[7];
    if (fc == 0x03U || fc == 0x05U || fc == 0x06U) {
        if (mbap_len != 6U) {
            return VerdictCode::MODBUS_MBAP_LEN_MISMATCH;
        }
        const uint32_t reg_addr =
            (static_cast<uint32_t>(raw[8]) << 8U) | static_cast<uint32_t>(raw[9]);
        const uint32_t val_u16 =
            (static_cast<uint32_t>(raw[10]) << 8U) | static_cast<uint32_t>(raw[11]);
        if (fc == 0x03U) {
            if (val_u16 < 1U || val_u16 > 125U ||
                (reg_addr + val_u16) > static_cast<uint32_t>(MAX_REGISTERS)) {
                return VerdictCode::MODBUS_REGISTER_OOB;
            }
            op.is_write = false;
            ok = true;
            return VerdictCode::ALLOW_READ;
        }
        if (reg_addr >= static_cast<uint32_t>(MAX_REGISTERS)) {
            return VerdictCode::MODBUS_REGISTER_OOB;
        }
        if (fc == 0x05U) {
            if (val_u16 != 0x0000U && val_u16 != 0xFF00U) {
                return VerdictCode::MODBUS_INVALID_COIL_VALUE;
            }
            op.is_write = true;
            op.write_count = 1U;
            op.writes[0] = {static_cast<int32_t>(reg_addr),
                            static_cast<int64_t>((val_u16 >> 8U) & 1U)};
            ok = true;
            return VerdictCode::ALLOW_WRITE;
        }
        op.is_write = true;
        op.write_count = 1U;
        op.writes[0] = {static_cast<int32_t>(reg_addr), static_cast<int64_t>(val_u16)};
        ok = true;
        return VerdictCode::ALLOW_WRITE;
    }
    if (fc == 0x10U) {
        if (mbap_len < 9U) {
            return VerdictCode::MODBUS_MBAP_LEN_MISMATCH;
        }
        const uint32_t reg_addr =
            (static_cast<uint32_t>(raw[8]) << 8U) | static_cast<uint32_t>(raw[9]);
        const uint32_t reg_count =
            (static_cast<uint32_t>(raw[10]) << 8U) | static_cast<uint32_t>(raw[11]);
        const uint32_t byte_count = static_cast<uint32_t>(raw[12]);
        if (reg_count < 1U || reg_count > 123U ||
            (reg_addr + reg_count) > static_cast<uint32_t>(MAX_REGISTERS)) {
            return VerdictCode::MODBUS_REGISTER_OOB;
        }
        if (byte_count != 2U * reg_count || mbap_len != 7U + byte_count) {
            return VerdictCode::MODBUS_BYTE_COUNT_MISMATCH;
        }
        op.is_write = true;
        op.write_count = static_cast<size_t>(reg_count);
        for (size_t k = 0U; k < op.write_count; ++k) {
            const uint32_t wval =
                (static_cast<uint32_t>(raw[13U + 2U * k]) << 8U) |
                static_cast<uint32_t>(raw[14U + 2U * k]);
            op.writes[k] = {static_cast<int32_t>(reg_addr + k), static_cast<int64_t>(wval)};
        }
        ok = true;
        return VerdictCode::ALLOW_WRITE;
    }
    return VerdictCode::MODBUS_UNAUTHORIZED_FC;
}

inline VerdictCode decode_mqtt_publish(
    const uint8_t* raw,
    size_t len,
    DecodedOpPod& op,
    bool& ok
) noexcept {
    ok = false;
    op.is_write = false;
    op.write_count = 0U;
    if (len < 2U) {
        return VerdictCode::MQTT_FRAME_TOO_SHORT;
    }
    const uint8_t ptype = (raw[0] >> 4U) & 0x0FU;
    const uint8_t qos = ((raw[0] & 0x0FU) >> 1U) & 0x03U;
    if (ptype != 3U) {
        return VerdictCode::MQTT_UNSUPPORTED_PACKET_TYPE;
    }
    if (qos == 3U) {
        return VerdictCode::MQTT_INVALID_FLAGS;
    }
    size_t rem_len = 0U;
    size_t hdr_len = 0U;
    for (size_t idx = 1U; idx <= 4U; ++idx) {
        const uint8_t digit = raw[idx];
        rem_len |= static_cast<size_t>(digit & 0x7FU) << (7U * (idx - 1U));
        if ((digit & 0x80U) != 0U) {
            if (idx == 4U) {
                return VerdictCode::MQTT_VARINT_OVERFLOW;
            }
            if (idx == (len - 1U)) {
                return VerdictCode::MQTT_FRAME_TOO_SHORT;
            }
        } else {
            if (idx > 1U && digit == 0x00U) {
                return VerdictCode::MQTT_OVERLONG_VARINT;
            }
            hdr_len = 1U + idx;
            break;
        }
    }
    if ((hdr_len + rem_len) != len) {
        return VerdictCode::MQTT_PACKET_LEN_MISMATCH;
    }
    if (rem_len < 2U) {
        return VerdictCode::MQTT_TOPIC_OOB;
    }
    const size_t topic_len =
        (static_cast<size_t>(raw[hdr_len]) << 8U) | static_cast<size_t>(raw[hdr_len + 1U]);
    const size_t var_hdr_len = 2U + topic_len + ((qos > 0U) ? 2U : 0U);
    if (topic_len == 0U || var_hdr_len > rem_len) {
        return VerdictCode::MQTT_TOPIC_OOB;
    }
    if (!detail::is_valid_utf8_no_wildcards(raw + hdr_len + 2U, topic_len)) {
        return VerdictCode::MQTT_INVALID_TOPIC;
    }
    const size_t pay_off = hdr_len + var_hdr_len;
    const size_t pay_len = len - pay_off;
    const uint8_t* pay = raw + pay_off;
    int64_t reg_addr = -1;
    int64_t reg_val = 0;
    if (pay_len >= 4U && pay[0] == 'S' && pay[1] == 'E' && pay[2] == 'T' && pay[3] == ' ') {
        for (size_t i = 0U; i < pay_len; ++i) {
            if (pay[i] < 32U || pay[i] >= 128U) {
                return VerdictCode::MQTT_INVALID_PAYLOAD;
            }
        }
        size_t sp1 = 3U;
        size_t sp2 = pay_len;
        size_t space_cnt = 0U;
        for (size_t i = 3U; i < pay_len; ++i) {
            if (pay[i] == static_cast<uint8_t>(' ')) {
                ++space_cnt;
                if (space_cnt == 2U) {
                    sp2 = i;
                }
            }
        }
        if (space_cnt != 2U) {
            return VerdictCode::MQTT_INVALID_PAYLOAD;
        }
        if (!detail::parse_ascii_i64_span(pay + sp1 + 1U, sp2 - sp1 - 1U, reg_addr) ||
            !detail::parse_ascii_i64_span(pay + sp2 + 1U, pay_len - sp2 - 1U, reg_val)) {
            return VerdictCode::MQTT_INVALID_PAYLOAD;
        }
    } else if (pay_len == 6U) {
        reg_addr = static_cast<int64_t>(
            (static_cast<uint32_t>(pay[0]) << 8U) | static_cast<uint32_t>(pay[1])
        );
        const uint64_t raw_u32 =
            (static_cast<uint64_t>(pay[2]) << 24U) |
            (static_cast<uint64_t>(pay[3]) << 16U) |
            (static_cast<uint64_t>(pay[4]) << 8U) |
            static_cast<uint64_t>(pay[5]);
        reg_val = ((raw_u32 & 0x80000000ULL) != 0ULL)
                      ? (static_cast<int64_t>(raw_u32) - 4294967296LL)
                      : static_cast<int64_t>(raw_u32);
    } else {
        return VerdictCode::MQTT_INVALID_PAYLOAD;
    }
    if (reg_addr < 0LL || reg_addr >= static_cast<int64_t>(MAX_REGISTERS) ||
        reg_val < MIN_REG_VAL || reg_val > MAX_REG_VAL) {
        return VerdictCode::MQTT_REGISTER_OOB;
    }
    op.is_write = true;
    op.write_count = 1U;
    op.writes[0] = {static_cast<int32_t>(reg_addr), reg_val};
    ok = true;
    return VerdictCode::ALLOW_WRITE;
}

struct alignas(64) EngineArena {
    alignas(64) std::array<int64_t, MAX_REGISTERS> regs{};
    alignas(64) std::array<int64_t, MAX_REGISTERS> scratch_regs{};
    alignas(64) std::array<DagNodePod, MAX_DAG_NODES> dag_nodes{};
    alignas(64) std::array<int32_t, MAX_DAG_NODES> node_slot_by_id{};
    alignas(64) std::array<int32_t, MAX_DAG_NODES> topo_order{};
    alignas(64) std::array<uint8_t, MAX_DAG_NODES> node_bits{};
    alignas(64) std::array<SourceSecurityPod, MAX_SOURCES> sources{};
    alignas(64) SpscRingBuffer ring{};

    FirewallPolicyPod policy{};
    size_t dag_node_count{0U};
    size_t source_count{0U};
    int64_t packet_seq_index{0LL};
    int64_t allowed_count{0LL};
    int64_t blocked_count{0LL};
    uint64_t chain_hash_u64{GENESIS_HASH_U64};

    void reset() noexcept {
        regs.fill(0LL);
        scratch_regs.fill(0LL);
        node_slot_by_id.fill(-1);
        topo_order.fill(0);
        node_bits.fill(0U);
        for (size_t i = 0U; i < MAX_DAG_NODES; ++i) {
            dag_nodes[i] = DagNodePod{};
        }
        for (size_t i = 0U; i < MAX_SOURCES; ++i) {
            sources[i] = SourceSecurityPod{};
        }
        ring.reset();
        policy = FirewallPolicyPod{};
        dag_node_count = 0U;
        source_count = 0U;
        packet_seq_index = 0LL;
        allowed_count = 0LL;
        blocked_count = 0LL;
        chain_hash_u64 = GENESIS_HASH_U64;
    }

    bool add_dag_node(const DagNodePod& node) noexcept {
        if (dag_node_count >= MAX_DAG_NODES || node.node_id < 0 ||
            static_cast<size_t>(node.node_id) >= MAX_DAG_NODES) {
            return false;
        }
        if (node.target_reg < 0 ||
            static_cast<size_t>(node.target_reg) >= MAX_REGISTERS ||
            node.threshold < MIN_REG_VAL || node.threshold > MAX_REG_VAL) {
            return false;
        }
        const uint8_t op_u8 = static_cast<uint8_t>(node.op);
        if (op_u8 <= static_cast<uint8_t>(NodeOp::CMP_NE)) {
            if (node.input_count != 0U) {
                return false;
            }
        } else if (node.op == NodeOp::NOT) {
            if (node.input_count != 1U) {
                return false;
            }
        } else if (op_u8 <= static_cast<uint8_t>(NodeOp::NOR)) {
            if (node.input_count < 1U ||
                static_cast<size_t>(node.input_count) > MAX_DAG_INPUTS) {
                return false;
            }
        } else {
            return false;
        }
        for (size_t k = 0U; k < static_cast<size_t>(node.input_count); ++k) {
            const int32_t inp_id = node.inputs[k];
            if (inp_id < 0 || static_cast<size_t>(inp_id) >= MAX_DAG_NODES ||
                inp_id == node.node_id) {
                return false;
            }
        }
        if (node_slot_by_id[static_cast<size_t>(node.node_id)] != -1) {
            return false;
        }
        node_slot_by_id[static_cast<size_t>(node.node_id)] =
            static_cast<int32_t>(dag_node_count);
        dag_nodes[dag_node_count++] = node;
        return true;
    }

    bool validate_and_sort_dag() noexcept {
        std::array<int32_t, MAX_DAG_NODES> in_deg{};
        std::array<int32_t, MAX_DAG_NODES> ready{};
        size_t ready_cnt = 0U;
        for (size_t slot = 0U; slot < dag_node_count; ++slot) {
            const DagNodePod& n = dag_nodes[slot];
            for (size_t k = 0U; k < static_cast<size_t>(n.input_count); ++k) {
                const int32_t inp_id = n.inputs[k];
                if (inp_id < 0 || static_cast<size_t>(inp_id) >= MAX_DAG_NODES ||
                    node_slot_by_id[static_cast<size_t>(inp_id)] == -1 ||
                    inp_id == n.node_id) {
                    return false;
                }
            }
            in_deg[slot] = static_cast<int32_t>(n.input_count);
            if (in_deg[slot] == 0) {
                ready[ready_cnt++] = n.node_id;
            }
        }
        auto sort_ready = [&]() noexcept {
            for (size_t i = 1U; i < ready_cnt; ++i) {
                const int32_t key = ready[i];
                size_t j = i;
                while (j > 0U && ready[j - 1U] > key) {
                    ready[j] = ready[j - 1U];
                    --j;
                }
                ready[j] = key;
            }
        };
        sort_ready();
        size_t topo_cnt = 0U;
        while (ready_cnt > 0U) {
            const int32_t curr_id = ready[0];
            for (size_t i = 1U; i < ready_cnt; ++i) {
                ready[i - 1U] = ready[i];
            }
            --ready_cnt;
            topo_order[topo_cnt++] = curr_id;
            for (size_t slot = 0U; slot < dag_node_count; ++slot) {
                const DagNodePod& child = dag_nodes[slot];
                for (size_t k = 0U; k < static_cast<size_t>(child.input_count); ++k) {
                    if (child.inputs[k] == curr_id) {
                        --in_deg[slot];
                        if (in_deg[slot] == 0) {
                            ready[ready_cnt++] = child.node_id;
                        }
                    }
                }
            }
            sort_ready();
        }
        return topo_cnt == dag_node_count;
    }

    bool evaluate_scratch_dag(int32_t& tripped_node_id) noexcept {
        tripped_node_id = -1;
        for (size_t idx = 0U; idx < dag_node_count; ++idx) {
            const int32_t nid = topo_order[idx];
            const size_t slot = static_cast<size_t>(node_slot_by_id[static_cast<size_t>(nid)]);
            const DagNodePod& node = dag_nodes[slot];
            uint8_t bit = 0U;
            const size_t safe_reg =
                (node.target_reg >= 0 &&
                 static_cast<size_t>(node.target_reg) < MAX_REGISTERS)
                    ? static_cast<size_t>(node.target_reg)
                    : 0U;
            switch (node.op) {
                case NodeOp::CMP_GT:
                    bit = (scratch_regs[safe_reg] > node.threshold) ? 1U : 0U;
                    break;
                case NodeOp::CMP_GE:
                    bit = (scratch_regs[safe_reg] >= node.threshold) ? 1U : 0U;
                    break;
                case NodeOp::CMP_LT:
                    bit = (scratch_regs[safe_reg] < node.threshold) ? 1U : 0U;
                    break;
                case NodeOp::CMP_LE:
                    bit = (scratch_regs[safe_reg] <= node.threshold) ? 1U : 0U;
                    break;
                case NodeOp::CMP_EQ:
                    bit = (scratch_regs[safe_reg] == node.threshold) ? 1U : 0U;
                    break;
                case NodeOp::CMP_NE:
                    bit = (scratch_regs[safe_reg] != node.threshold) ? 1U : 0U;
                    break;
                case NodeOp::NOT:
                    bit = static_cast<uint8_t>(
                        (node_bits[static_cast<size_t>(node.inputs[0])] ^ 1U) & 1U
                    );
                    break;
                case NodeOp::AND:
                case NodeOp::NAND: {
                    uint8_t acc = 1U;
                    for (size_t k = 0U; k < static_cast<size_t>(node.input_count); ++k) {
                        acc &= static_cast<uint8_t>(
                            node_bits[static_cast<size_t>(node.inputs[k])] & 1U
                        );
                    }
                    bit = (node.op == NodeOp::NAND) ? static_cast<uint8_t>((acc ^ 1U) & 1U) : acc;
                    break;
                }
                case NodeOp::OR:
                case NodeOp::NOR: {
                    uint8_t acc = 0U;
                    for (size_t k = 0U; k < static_cast<size_t>(node.input_count); ++k) {
                        acc |= static_cast<uint8_t>(
                            node_bits[static_cast<size_t>(node.inputs[k])] & 1U
                        );
                    }
                    bit = (node.op == NodeOp::NOR) ? static_cast<uint8_t>((acc ^ 1U) & 1U) : acc;
                    break;
                }
                case NodeOp::XOR: {
                    uint8_t acc = 0U;
                    for (size_t k = 0U; k < static_cast<size_t>(node.input_count); ++k) {
                        acc ^= static_cast<uint8_t>(
                            node_bits[static_cast<size_t>(node.inputs[k])] & 1U
                        );
                    }
                    bit = acc;
                    break;
                }
            }
            node_bits[static_cast<size_t>(nid)] = bit;
            if (node.is_hazard_output != 0U && bit == 1U) {
                if (tripped_node_id == -1 || nid < tripped_node_id) {
                    tripped_node_id = nid;
                }
            }
        }
        return tripped_node_id != -1;
    }

    SourceSecurityPod* find_or_create_source(const char* source_id) noexcept {
        for (size_t i = 0U; i < source_count; ++i) {
            if (std::strcmp(sources[i].source_id, source_id) == 0) {
                return &sources[i];
            }
        }
        if (source_count >= MAX_SOURCES) {
            return nullptr;
        }
        SourceSecurityPod& s = sources[source_count++];
        s = SourceSecurityPod{};
        const size_t slen = std::strlen(source_id);
        const size_t copy_len = (slen < (MAX_ID_BUF - 1U)) ? slen : (MAX_ID_BUF - 1U);
        if (copy_len > 0U) {
            std::memcpy(s.source_id, source_id, copy_len);
        }
        s.source_id[copy_len] = '\0';
        return &s;
    }

    bool evaluate_event(const PacketEventPod& ev, PacketVerdictPod& out) noexcept {
        SourceSecurityPod* src = find_or_create_source(ev.source_id);
        if (src == nullptr) {
            return false;
        }
        VerdictCode verdict_code = VerdictCode::ALLOW_READ;
        int32_t tripped_id = -1;
        bool allowed = false;
        if (src->breaker_state == BreakerState::OPEN &&
            (ev.timestamp_ms - src->opened_at_ms) < policy.cooldown_ms) {
            verdict_code = VerdictCode::CIRCUIT_BREAKER_OPEN;
        } else {
            if (src->breaker_state == BreakerState::OPEN) {
                src->breaker_state = BreakerState::HALF_OPEN;
            }
            if (ev.seq_no <= src->last_seq_no) {
                verdict_code = VerdictCode::REPLAY_ATTACK_BLOCKED;
            } else {
                src->last_seq_no = ev.seq_no;
                const int64_t cutoff = ev.timestamp_ms - policy.window_ms;
                size_t kept = 0U;
                for (size_t i = 0U; i < src->window_count; ++i) {
                    if (src->window_timestamps[i] >= cutoff) {
                        src->window_timestamps[kept++] = src->window_timestamps[i];
                    }
                }
                src->window_count = kept;
                if (static_cast<int64_t>(src->window_count) >= policy.max_requests_per_window) {
                    verdict_code = VerdictCode::RATE_LIMIT_EXCEEDED;
                } else {
                    src->window_timestamps[src->window_count++] = ev.timestamp_ms;
                    DecodedOpPod op{};
                    bool dec_ok = false;
                    verdict_code =
                        (ev.protocol == ProtocolType::MODBUS_TCP)
                            ? decode_modbus_tcp(ev.raw_bytes.data(), ev.raw_len, op, dec_ok)
                            : decode_mqtt_publish(ev.raw_bytes.data(), ev.raw_len, op, dec_ok);
                    if (dec_ok) {
                        if (op.is_write) {
                            scratch_regs = regs;
                            for (size_t w = 0U; w < op.write_count; ++w) {
                                scratch_regs[static_cast<size_t>(op.writes[w].reg_addr)] =
                                    op.writes[w].reg_val;
                            }
                            if (evaluate_scratch_dag(tripped_id)) {
                                verdict_code = VerdictCode::INTERLOCK_TRIPPED;
                            } else {
                                regs = scratch_regs;
                                verdict_code = VerdictCode::ALLOW_WRITE;
                            }
                        } else {
                            verdict_code = VerdictCode::ALLOW_READ;
                        }
                    }
                }
            }
            allowed = (verdict_code == VerdictCode::ALLOW_READ ||
                       verdict_code == VerdictCode::ALLOW_WRITE);
            if (allowed) {
                src->consecutive_failures = 0LL;
                if (src->breaker_state == BreakerState::HALF_OPEN) {
                    src->breaker_state = BreakerState::CLOSED;
                }
            } else {
                src->consecutive_failures += 1LL;
                src->total_violations += 1LL;
                if (src->breaker_state == BreakerState::HALF_OPEN ||
                    src->consecutive_failures >= policy.trip_threshold) {
                    src->breaker_state = BreakerState::OPEN;
                    src->opened_at_ms = ev.timestamp_ms;
                }
            }
        }
        const uint64_t prev_h = chain_hash_u64;
        const uint64_t next_h = compute_verdict_hash_u64(
            prev_h,
            ev.packet_id,
            ev.seq_no,
            ev.timestamp_ms,
            ev.source_id,
            ev.protocol,
            verdict_code,
            tripped_id,
            src->breaker_state
        );
        chain_hash_u64 = next_h;
        out.seq_index = packet_seq_index++;
        std::memcpy(out.packet_id, ev.packet_id, MAX_ID_BUF);
        std::memcpy(out.source_id, ev.source_id, MAX_ID_BUF);
        out.seq_no = ev.seq_no;
        out.timestamp_ms = ev.timestamp_ms;
        out.protocol = ev.protocol;
        out.verdict_code = verdict_code;
        out.is_allowed = allowed;
        out.tripped_node_id = tripped_id;
        out.breaker_state_after = src->breaker_state;
        out.prev_hash_u64 = prev_h;
        out.chain_hash_u64 = next_h;
        if (allowed) {
            allowed_count += 1LL;
        } else {
            blocked_count += 1LL;
        }
        return true;
    }

    bool process_packet(const PacketEventPod& ev, PacketVerdictPod& out) noexcept {
        return evaluate_event(ev, out);
    }
};

static_assert(alignof(SpscRingBuffer) == 64U, "SpscRingBuffer must be 64-byte aligned");
static_assert(alignof(EngineArena) == 64U, "EngineArena must be 64-byte aligned");

}  // namespace vectragate

#endif

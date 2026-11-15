#include "vectragate_core.hpp"

#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

namespace { // VectraGate-Core C++17/20 native CLI

vectragate::EngineArena g_arena;

bool parse_node_op(const std::string& s, vectragate::NodeOp& out) noexcept {
    using vectragate::NodeOp;
    if (s == "CMP_GT") { out = NodeOp::CMP_GT; return true; }
    if (s == "CMP_GE") { out = NodeOp::CMP_GE; return true; }
    if (s == "CMP_LT") { out = NodeOp::CMP_LT; return true; }
    if (s == "CMP_LE") { out = NodeOp::CMP_LE; return true; }
    if (s == "CMP_EQ") { out = NodeOp::CMP_EQ; return true; }
    if (s == "CMP_NE") { out = NodeOp::CMP_NE; return true; }
    if (s == "AND") { out = NodeOp::AND; return true; }
    if (s == "OR") { out = NodeOp::OR; return true; }
    if (s == "XOR") { out = NodeOp::XOR; return true; }
    if (s == "NOT") { out = NodeOp::NOT; return true; }
    if (s == "NAND") { out = NodeOp::NAND; return true; }
    if (s == "NOR") { out = NodeOp::NOR; return true; }
    return false;
}

bool decode_hex_bytes(
    const std::string& hex,
    std::array<uint8_t, vectragate::MAX_RAW_PACKET_BYTES>& out,
    uint16_t& out_len
) noexcept {
    if ((hex.size() % 2U) != 0U || (hex.size() / 2U) > out.size()) {
        return false;
    }
    auto nibble = [](char ch, uint8_t& v) noexcept -> bool {
        if (ch >= '0' && ch <= '9') { v = static_cast<uint8_t>(ch - '0'); return true; }
        if (ch >= 'a' && ch <= 'f') { v = static_cast<uint8_t>(10 + (ch - 'a')); return true; }
        if (ch >= 'A' && ch <= 'F') { v = static_cast<uint8_t>(10 + (ch - 'A')); return true; }
        return false;
    };
    const size_t nbytes = hex.size() / 2U;
    for (size_t i = 0U; i < nbytes; ++i) {
        uint8_t hi = 0U;
        uint8_t lo = 0U;
        if (!nibble(hex[2U * i], hi) || !nibble(hex[2U * i + 1U], lo)) {
            return false;
        }
        out[i] = static_cast<uint8_t>((hi << 4U) | lo);
    }
    out_len = static_cast<uint16_t>(nbytes);
    return true;
}

void print_topo() {
    std::cout << "TOPO";
    for (size_t i = 0U; i < g_arena.dag_node_count; ++i) {
        std::cout << ' ' << g_arena.topo_order[i];
    }
    std::cout << '\n';
}

void print_verdict(const vectragate::PacketVerdictPod& v) {
    std::cout << "VERDICT " << v.seq_index << ' ' << v.packet_id << ' '
              << v.source_id << ' ' << v.seq_no << ' ' << v.timestamp_ms << ' '
              << vectragate::protocol_to_cstr(v.protocol) << ' '
              << vectragate::verdict_to_cstr(v.verdict_code) << ' '
              << (v.is_allowed ? 1 : 0) << ' ' << v.tripped_node_id << ' '
              << vectragate::breaker_to_cstr(v.breaker_state_after) << ' '
              << std::hex << std::nouppercase << std::setw(16) << std::setfill('0')
              << v.prev_hash_u64 << ' ' << std::setw(16) << std::setfill('0')
              << v.chain_hash_u64 << std::dec << '\n';
}

bool drain_ring() {
    vectragate::PacketEventPod popped{};
    while (g_arena.ring.try_pop(popped)) {
        vectragate::PacketVerdictPod verdict{};
        if (!g_arena.process_packet(popped, verdict)) {
            std::cerr << "Source capacity exceeded\n";
            return false;
        }
        print_verdict(verdict);
    }
    return true;
}

bool run_selftest_spsc() noexcept {
    g_arena.ring.reset();
    for (int64_t s = 1LL; s <= 256LL; ++s) {
        vectragate::PacketEventPod ev{};
        ev.seq_no = s;
        if (!g_arena.ring.try_push(ev)) {
            return false;
        }
    }
    vectragate::PacketEventPod extra{};
    extra.seq_no = 999LL;
    if (!g_arena.ring.is_full() || g_arena.ring.try_push(extra)) {
        return false;
    }
    for (int64_t s = 1LL; s <= 128LL; ++s) {
        vectragate::PacketEventPod out{};
        if (!g_arena.ring.try_pop(out) || out.seq_no != s) {
            return false;
        }
    }
    for (int64_t s = 257LL; s <= 384LL; ++s) {
        vectragate::PacketEventPod ev{};
        ev.seq_no = s;
        if (!g_arena.ring.try_push(ev)) {
            return false;
        }
    }
    if (!g_arena.ring.is_full() || g_arena.ring.try_push(extra)) {
        return false;
    }
    for (int64_t s = 129LL; s <= 384LL; ++s) {
        vectragate::PacketEventPod out{};
        if (!g_arena.ring.try_pop(out) || out.seq_no != s) {
            return false;
        }
    }
    vectragate::PacketEventPod empty_out{};
    return !g_arena.ring.try_pop(empty_out);
}

void print_sources_regs_summary() {
    std::array<size_t, vectragate::MAX_SOURCES> order{};
    for (size_t i = 0U; i < g_arena.source_count; ++i) {
        order[i] = i;
    }
    for (size_t i = 1U; i < g_arena.source_count; ++i) {
        const size_t key = order[i];
        size_t j = i;
        while (j > 0U &&
               std::strcmp(g_arena.sources[order[j - 1U]].source_id,
                           g_arena.sources[key].source_id) > 0) {
            order[j] = order[j - 1U];
            --j;
        }
        order[j] = key;
    }
    for (size_t k = 0U; k < g_arena.source_count; ++k) {
        const vectragate::SourceSecurityPod& s = g_arena.sources[order[k]];
        std::cout << "SOURCE " << s.source_id << ' ' << s.last_seq_no << ' '
                  << vectragate::breaker_to_cstr(s.breaker_state) << ' '
                  << s.consecutive_failures << ' ' << s.total_violations << ' '
                  << s.opened_at_ms << ' ' << s.window_count;
        for (size_t t = 0U; t < s.window_count; ++t) {
            std::cout << ' ' << s.window_timestamps[t];
        }
        std::cout << '\n';
    }
    std::cout << "REGS";
    for (size_t i = 0U; i < vectragate::MAX_REGISTERS; ++i) {
        std::cout << ' ' << g_arena.regs[i];
    }
    std::cout << '\n';
    std::cout << "SUMMARY " << g_arena.allowed_count << ' ' << g_arena.blocked_count
              << ' ' << std::hex << std::nouppercase << std::setw(16)
              << std::setfill('0') << g_arena.chain_hash_u64 << std::dec << '\n';
}

}  // namespace

int main(int argc, char* argv[]) {
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);
    g_arena.reset();
    if (argc >= 2 && std::strcmp(argv[1], "--selftest-spsc") == 0) {
        if (!run_selftest_spsc()) {
            std::cerr << "SPSC_SELFTEST_FAILED\n";
            return 1;
        }
        std::cout << "SPSC_SELFTEST_OK\n";
        return 0;
    }
    bool dag_compiled = false;
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) {
            continue;
        }
        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;
        if (cmd == "POLICY") {
            if (!(iss >> g_arena.policy.window_ms >>
                  g_arena.policy.max_requests_per_window >>
                  g_arena.policy.trip_threshold >> g_arena.policy.cooldown_ms) ||
                g_arena.policy.window_ms < 1LL ||
                g_arena.policy.window_ms > 86400000LL ||
                g_arena.policy.max_requests_per_window < 1LL ||
                g_arena.policy.max_requests_per_window >
                    static_cast<int64_t>(vectragate::MAX_WINDOW_TIMESTAMPS) ||
                g_arena.policy.trip_threshold < 1LL ||
                g_arena.policy.trip_threshold > 1000LL ||
                g_arena.policy.cooldown_ms < 1LL ||
                g_arena.policy.cooldown_ms > 86400000LL) {
                std::cerr << "Invalid POLICY directive\n";
                return 1;
            }
        } else if (cmd == "REG") {
            size_t addr = 0U;
            int64_t val = 0LL;
            if (!(iss >> addr >> val) || addr >= vectragate::MAX_REGISTERS ||
                val < vectragate::MIN_REG_VAL || val > vectragate::MAX_REG_VAL) {
                std::cerr << "Invalid REG directive\n";
                return 1;
            }
            g_arena.regs[addr] = val;
        } else if (cmd == "NODE") {
            vectragate::DagNodePod node{};
            std::string tag;
            std::string op_str;
            int is_haz = 0;
            size_t in_cnt = 0U;
            if (!(iss >> node.node_id >> tag >> op_str >> node.target_reg >>
                  node.threshold >> is_haz >> in_cnt) ||
                tag.empty() || tag.size() >= vectragate::MAX_ID_BUF ||
                !parse_node_op(op_str, node.op) ||
                in_cnt > vectragate::MAX_DAG_INPUTS) {
                std::cerr << "Invalid NODE directive\n";
                return 1;
            }
            std::memcpy(node.tag, tag.data(), tag.size());
            node.tag[tag.size()] = '\0';
            node.is_hazard_output = (is_haz != 0) ? 1U : 0U;
            node.input_count = static_cast<uint8_t>(in_cnt);
            for (size_t i = 0U; i < in_cnt; ++i) {
                if (!(iss >> node.inputs[i])) {
                    std::cerr << "Invalid NODE input\n";
                    return 1;
                }
            }
            if (!g_arena.add_dag_node(node)) {
                std::cerr << "Failed to add DAG node\n";
                return 1;
            }
        } else if (cmd == "PKT") {
            if (!dag_compiled) {
                if (!g_arena.validate_and_sort_dag()) {
                    std::cerr << "Cyclic or invalid DAG\n";
                    return 1;
                }
                dag_compiled = true;
                print_topo();
            }
            std::string pid;
            std::string sid;
            std::string proto_str;
            std::string hex;
            vectragate::PacketEventPod ev{};
            if (!(iss >> pid >> sid >> ev.seq_no >> ev.timestamp_ms >>
                  proto_str >> hex) ||
                pid.empty() || pid.size() >= vectragate::MAX_ID_BUF ||
                sid.empty() || sid.size() >= vectragate::MAX_ID_BUF ||
                ev.seq_no < 1LL || ev.timestamp_ms < 0LL ||
                (proto_str != "MODBUS_TCP" && proto_str != "MQTT") ||
                !decode_hex_bytes(hex, ev.raw_bytes, ev.raw_len)) {
                std::cerr << "Invalid PKT line\n";
                return 1;
            }
            std::memcpy(ev.packet_id, pid.data(), pid.size());
            ev.packet_id[pid.size()] = '\0';
            std::memcpy(ev.source_id, sid.data(), sid.size());
            ev.source_id[sid.size()] = '\0';
            ev.protocol = (proto_str == "MODBUS_TCP")
                              ? vectragate::ProtocolType::MODBUS_TCP
                              : vectragate::ProtocolType::MQTT;
            if (!g_arena.ring.try_push(ev)) {
                if (!drain_ring() || !g_arena.ring.try_push(ev)) {
                    std::cerr << "SPSC ring buffer overflow\n";
                    return 1;
                }
            }
            if (g_arena.ring.is_full() && !drain_ring()) {
                return 1;
            }
        } else if (cmd == "END") {
            if (!dag_compiled) {
                if (!g_arena.validate_and_sort_dag()) {
                    std::cerr << "Cyclic or invalid DAG\n";
                    return 1;
                }
                dag_compiled = true;
                print_topo();
            }
            if (!drain_ring()) {
                return 1;
            }
            print_sources_regs_summary();
            return 0;
        } else {
            std::cerr << "Unknown command\n";
            return 1;
        }
    }
    return 0;
}

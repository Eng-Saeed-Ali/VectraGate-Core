# BLUEPRINT.md — Mathematical, Silicon & Protocol Blueprint for `VectraGate-Core (بَرْزَخ)`

- **System Identity:** `VectraGate-Core (بَرْزَخ)` — Deterministic OT/ICS Protocol Firewall, Combinational Logic-Gate Interlock Engine & Cryptographic SIEM Audit Plane
- **Architecture Tier:** Phase 0-B Gate 6 Verified Blueprint (`vectragate.bundle/v1`)
- **Engineering Canon Anchors:** Codex #01 (TigerStyle Bounded Control & Assertions), Codex #02 (NASA JPL Power of 10 Rules 1–10), Codex #03 (Ulrich Drepper `alignas(64)` Cache-Line Physics), Codex #04 (ISO C++20 Core Guidelines), Codex #12 (Ousterhout Deep Modules), Codex #13 (Nygard 3-State Circuit Breaker), Codex #14 (Kleppmann Monotonic Fencing Tokens), Codex #16 (CS:APP Two's-Complement, Big-Endian Bitwise & Underflow Defense), Codex #17 (Ford Automated Fitness Functions), Codex #18 (Dr. Fedor Pikus Siemens EDA Branchless Bitwise DAG & Wait-Free SPSC Ring Buffers).

---

## § 0. Global Numeric, Bitwise, Memory & Determinism Contract (`R0.1` – `R0.5`)

### `R0.1` — Zero-Float, Zero-Division & Fixed-Width Integer Law
1. **Dimensional Vocabulary & Fixed-Width Domains:**
   - **Register/Sensor Values (`{reg_val}`):** Exact 64-bit signed integers (`int64_t` in C++, `int` in Python) bounded to `-32_768 ≤ reg_val ≤ 65_535`, unifying signed 16-bit industrial telemetry (`-32_768..32_767`) and unsigned 16-bit holding registers/coils (`0..65_535`).
   - **Monotonic Fencing Sequence Numbers (`{seq}`):** `seq_no: int ≥ 1` (`int64_t`).
   - **Event Timestamps (`{ms}`):** `timestamp_ms: int ≥ 0` (`int64_t`).
   - **Time Windows & Cooldowns (`{ms}`):** `window_ms: int ≥ 1`, `cooldown_ms: int ≥ 1` (`int64_t`).
   - **Indices, Counts & Wire Lengths (`{idx}`, `{cnt}`, `{bytes}`):** `0 ≤ reg_addr < 256`, `1 ≤ trip_threshold ≤ 1_000`, `1 ≤ max_requests_per_window ≤ 64`.
2. **Total Float & True-Division Ban:**
   - Zero `float`, `double`, `long double`, `Decimal`, `Fraction`, or true-division `/` operators anywhere in `src/` or `tests/`.
   - All integer scaling uses bitwise shifts (`<<`, `>>`), masks (`&`, `|`, `^`), floor division `a // b`, or exact positive ceiling division `ceil_div(n, d) = (n + d - 1) // d` for `n ≥ 0, d > 0`.
3. **Zero-LaTeX-Dollar Documentation Law (`FF-8`):**
   - No raw dollar character may appear in any `.md` document (`BLUEPRINT.md`, `SPEC.md`, `ADR.md`, `HANDOFF.md`, `README.md`). All mathematical specifications use pure Unicode symbols (`≠`, `→`, `∑`, `∏`, `⌈`, `⌉`, `⌊`, `⌋`, `≤`, `≥`, `∧`, `∨`, `⊕`, `∈`).

### `R0.2` — Static Cache-Aligned Arena & Zero Post-Init Heap Law in C++ (`NASA Rule 3` & `Codex #03/#18`)
1. **Fixed-Capacity Silicon Arena (`EngineArena`):**
   - The native C++17/20 engine (`src/cpp/vectragate_core.hpp`) stores all mutable state inside `alignas(64) struct EngineArena` with compile-time constants:
     - `MAX_REGISTERS = 256` (`alignas(64) std::array<int64_t, 256> regs`)
     - `MAX_DAG_NODES = 128` (`alignas(64) std::array<DagNodePod, 128> dag_nodes`)
     - `MAX_SOURCES = 64` (`alignas(64) std::array<SourceSecurityPod, 64> sources`)
     - `MAX_WINDOW_TIMESTAMPS = 64` (per-source fixed circular timestamp ring inside `SourceSecurityPod`)
     - `SPSC_RING_SLOTS = 256` (`alignas(64)` Wait-Free Single-Producer Single-Consumer ring buffer of `PacketEventPod`, power-of-two mask `idx & 0xFF`, with producer `write_idx` and consumer `read_idx` isolated on separate 64-byte cache lines to prevent `MESI RFO` false sharing).
2. **Zero Post-Init Heap Allocation & Pedantic Compilation:**
   - Dynamic memory primitives (`new`, `delete`, `malloc`, `calloc`, `realloc`, `free`, `aligned_alloc`) are forbidden in the C++ evaluation core.
   - Must compile cleanly with zero warnings under `g++ -std=c++17 -O3 -Wall -Wextra -Wpedantic -Werror` (`C++17/20` compatible) on Windows MinGW (`g++.exe`).

### `R0.3` — Acyclic Combinational Logic-Gate DAG (`NASA Rule 1` & `Codex #18`)
- Physical safety interlocks are modeled as a Directed Acyclic Graph (`DAG`) validated at initialization via **Kahn's Iterative Topological Sort** (`0` recursion, bounded loop `≤ MAX_DAG_NODES`).
- Evaluated in a single linear pass over `topological_order` using branchless integer/bitwise operations (`& 1`, `|`, `^`, `^ 1`) with zero virtual dispatch.

### `R0.4` — Multi-Block Bit-for-Bit C++ == Python RFC 7693 `BLAKE2b-64` Audit Chain
- Every `PacketVerdict` is cryptographically chained into an unsigned 64-bit `BLAKE2b` digest (`digest_size = 8`, anchored at `GENESIS_HASH_U64 = 0x5645435452413236`, ASCII `"VECTRA26"`).
- Both the standalone C++17/20 multi-block RFC 7693 `blake2b_64(const uint8_t* msg, size_t len)` compressor (`while (len > 128) { t0 += 128; compress(h, block, t0, false); msg += 128; len -= 128; }` followed by final block `t0 += len; compress(h, final_block, t0, true)`) and Python `int.from_bytes(hashlib.blake2b(msg, digest_size=8).digest(), "little")` produce the exact same 64-bit integer `chain_hash_u64` for any byte length.

### `R0.5` — Cross-Language & Cross-Platform Total Determinism
- `100%` bit-for-bit parity between the C++17/20 native binary (`vectragate_cli.exe`), the Python functional core, and the independent test oracle (`tests/_oracle.py`) across `1,050` seeded differential instances (`50` fast + `1,000` deep).

---

## § 1. Protocol Framing, Logic-Gate DAG & SIEM Firewall Rules (`F1` – `F8` & `EC-A` – `EC-E`)

### `F1` — Boundary Hygiene in `__post_init__`
- **Strict Integer Type Gate:** Every integer field checks `type(v) is int` (rejecting `bool`, `float`, `str` before any numeric comparison).
- **Identifier Regex & NUL Defense:** `source_id`, `packet_id`, and `tag` must match `^[A-Z0-9_-]{1,32}\Z`; reject `\x00` and control chars (`ord(c) < 32`).
- **Hex Wire Payload Hygiene:** `payload_hex` must be a non-empty even-length ASCII hexadecimal string (`len(payload_hex) ≤ 1024`, i.e., `≤ 512` raw bytes).

### `F2` + `EC-A` — Modbus TCP Binary Wire Decoder & `CVE-2026-54410` / Underflow Defense
Given raw byte array `b` of length `N = len(b)`:
1. **7-Byte Big-Endian MBAP Header + 1-Byte Function Code (`b[0..7]`):**
   - `tx_id = (b[0] << 8) | b[1]`, `proto_id = (b[2] << 8) | b[3]`, `mbap_len = (b[4] << 8) | b[5]`, `unit_id = b[6]`, `func_code = b[7]`.
2. **Strict Priority Rejection Order:**
   - **Priority 1:** `N < 8` → `VerdictCode.MODBUS_FRAME_TOO_SHORT`
   - **Priority 2:** `proto_id ≠ 0` → `VerdictCode.MODBUS_INVALID_PROTOCOL`
   - **Priority 3 (`EC-A` Underflow & `CVE-2026-54410` ADU Overflow Defense):** `mbap_len < 2 or mbap_len > 254` → `VerdictCode.MODBUS_LENGTH_OUT_OF_BOUNDS` (guarantees `pdu_len = mbap_len - 2 ≥ 0` cannot underflow unsigned arithmetic and total ADU `6 + mbap_len ≤ 260`).
   - **Priority 4:** `N ≠ 6 + mbap_len` → `VerdictCode.MODBUS_MBAP_LEN_MISMATCH`
   - **Priority 5 (Function Code Dispatch & Register Bounds `MAX_REGISTERS = 256`):**
     - **`FC 0x03` (Read Holding Registers):** Requires `mbap_len == 6` (else `MODBUS_MBAP_LEN_MISMATCH`). Decodes `reg_addr = (b[8] << 8) | b[9]`, `reg_count = (b[10] << 8) | b[11]`. If `reg_count < 1 or reg_count > 125 or reg_addr + reg_count > 256` → `VerdictCode.MODBUS_REGISTER_OOB`.
     - **`FC 0x05` (Write Single Coil):** Requires `mbap_len == 6` (else `MODBUS_MBAP_LEN_MISMATCH`). Decodes `reg_addr = (b[8] << 8) | b[9]`, `val_u16 = (b[10] << 8) | b[11]`. If `reg_addr ≥ 256` → `VerdictCode.MODBUS_REGISTER_OOB`. If `val_u16 ∉ {0x0000, 0xFF00}` → `VerdictCode.MODBUS_INVALID_COIL_VALUE`. Normalizes coil value to `reg_val = (val_u16 >> 8) & 1` (`0` or `1`).
     - **`FC 0x06` (Write Single Register):** Requires `mbap_len == 6` (else `MODBUS_MBAP_LEN_MISMATCH`). Decodes `reg_addr = (b[8] << 8) | b[9]`, `val_u16 = (b[10] << 8) | b[11]`. If `reg_addr ≥ 256` → `VerdictCode.MODBUS_REGISTER_OOB`. Writes `reg_val = val_u16`.
     - **`FC 0x10` (Write Multiple Registers):** Requires `mbap_len ≥ 9` (else `MODBUS_MBAP_LEN_MISMATCH`). Decodes `reg_addr = (b[8] << 8) | b[9]`, `reg_count = (b[10] << 8) | b[11]`, `byte_count = b[12]`. If `reg_count < 1 or reg_count > 123 or reg_addr + reg_count > 256` → `VerdictCode.MODBUS_REGISTER_OOB`. If `byte_count ≠ 2 * reg_count or mbap_len ≠ 7 + byte_count` → `VerdictCode.MODBUS_BYTE_COUNT_MISMATCH`. Decodes `k ∈ [0, reg_count - 1]` writes `(reg_addr + k, (b[13 + 2*k] << 8) | b[14 + 2*k])`.
     - **Any other `func_code` (e.g., `FC 0x08` Diagnostics):** → `VerdictCode.MODBUS_UNAUTHORIZED_FC`.

### `F3` + `EC-B` — MQTT v3.1.1 Binary Wire Decoder & `CVE-2026-21888` / `CVE-2026-25627` Defense
Given raw byte array `b` of length `N = len(b)`:
1. **Fixed Header & Variable-Byte `Remaining Length` Priority Order:**
   - **Priority 1:** `N < 2` → `VerdictCode.MQTT_FRAME_TOO_SHORT`
   - **Priority 2:** `packet_type = (b[0] >> 4) & 0x0F`, `flags = b[0] & 0x0F`, `qos = (flags >> 1) & 0x03`. If `packet_type ≠ 3` (`PUBLISH`) → `VerdictCode.MQTT_UNSUPPORTED_PACKET_TYPE`.
   - **Priority 3:** If `qos == 3` (`0b11` reserved flag) → `VerdictCode.MQTT_INVALID_FLAGS`.
   - **Priority 4 (`EC-B` Varint Decoder at `b[1..4]`):**
     - Loop `varint_bytes` from `1` to `4`: read `digit = b[varint_bytes]`, accumulate `rem_len |= (digit & 0x7F) << (7 * (varint_bytes - 1))`.
     - If `(digit & 0x80) ≠ 0`: if `varint_bytes == 4` → `VerdictCode.MQTT_VARINT_OVERFLOW` (`CVE-2026-21888` 5-byte varint defense); if `varint_bytes == N - 1` → `VerdictCode.MQTT_FRAME_TOO_SHORT`.
     - If `(digit & 0x80) == 0`: if `varint_bytes > 1 and digit == 0x00` → `VerdictCode.MQTT_OVERLONG_VARINT` (rejects non-minimal encodings like `0x80 0x00`); break loop.
   - **Priority 5 (`CVE-2026-25627` Frame Length Exactness):** Let `hdr_len = 1 + varint_bytes`. If `hdr_len + rem_len ≠ N` → `VerdictCode.MQTT_PACKET_LEN_MISMATCH`.
2. **Topic & Command Payload Decoding:**
   - **Priority 6:** If `rem_len < 2` → `VerdictCode.MQTT_TOPIC_OOB`. Decode `topic_len = (b[hdr_len] << 8) | b[hdr_len + 1]`. Let `var_hdr_len = 2 + topic_len + (2 if qos > 0 else 0)`. If `topic_len == 0 or var_hdr_len > rem_len` → `VerdictCode.MQTT_TOPIC_OOB`.
   - **Priority 7:** Validate `topic_bytes = b[hdr_len + 2 : hdr_len + 2 + topic_len]` as strict UTF-8 containing zero `\x00`, `+`, or `#` characters; else → `VerdictCode.MQTT_INVALID_TOPIC`.
   - **Priority 8 (Command Payload `p = b[hdr_len + var_hdr_len : N]`):**
     - **Format A (ASCII Command):** Starts with `b"SET "` — parse exact ASCII `SET <reg_addr> <reg_val>` (two base-10 integer tokens).
     - **Format B (Binary 6-Byte Command):** `len(p) == 6` — `reg_addr = (p[0] << 8) | p[1]`; `raw_u32 = (p[2] << 24) | (p[3] << 16) | (p[4] << 8) | p[5]`; signed `reg_val = raw_u32 - 0x1_0000_0000 if (raw_u32 & 0x8000_0000) else raw_u32`.
     - If neither format matches → `VerdictCode.MQTT_INVALID_PAYLOAD`. If `reg_addr < 0 or reg_addr ≥ 256 or reg_val < -32_768 or reg_val > 65_535` → `VerdictCode.MQTT_REGISTER_OOB`.

### `F4` + `EC-C` — Siemens EDA Combinational Logic-Gate DAG Interlock Engine
1. **Node Operations (`NodeOp`):**
   - **Comparators (`0..5`):** `CMP_GT`, `CMP_GE`, `CMP_LT`, `CMP_LE`, `CMP_EQ`, `CMP_NE` compare `scratch_regs[target_reg]` against `threshold: int` → `1` or `0`.
   - **Logic Gates (`6..11`, Branchless Bitwise Evaluation):** Given upstream bit outputs `v_0, ..., v_{k-1} ∈ {0, 1}`:
     - `AND`: `1` if all `v_i == 1` else `0`; `OR`: `1` if any `v_i == 1` else `0`; `XOR`: `(∑ v_i) & 1`; `NOT`: `(v_0 ^ 1) & 1`; `NAND`: `(AND ^ 1) & 1`; `NOR`: `(OR ^ 1) & 1`.
2. **Kahn's Iterative Topological Validation (`EC-C`):**
   - Compute `in_degree[u]` for `u ∈ [0, M - 1]`. Push all `u` with `in_degree[u] == 0` into fixed queue `q` (in ascending `node_id` order). Pop `u`, append to `topological_order`, and decrement `in_degree[v]` for each child `v`, enqueuing `v` when `in_degree[v] == 0`.
   - If `len(topological_order) ≠ M`, raise `ValueError("Cyclic DAG detected")` (`0` recursion).
3. **Trial Write & Atomic Rollback Guarantee:**
   - Copy `live_regs` to `scratch_regs`, apply candidate packet mutations to `scratch_regs`, and evaluate all DAG nodes in `topological_order`.
   - If any node with `is_hazard_output == True` outputs `1`, reject with **`VerdictCode.INTERLOCK_TRIPPED`** (`tripped_node_id` = lowest hazard `node_id` with output `1`) and leave `live_regs` **100% unmodified**.

### `F5` + `EC-D` — Fencing Tokens, Sliding-Window Rate Limiter & Nygard 3-State Circuit Breaker
For each incoming `RawPacket(packet_id, source_id, seq_no, timestamp_ms, protocol, payload_hex)`:
1. **Step 1 — Nygard Circuit Breaker Check (`CLOSED = 0`, `OPEN = 1`, `HALF_OPEN = 2`):**
   - If `state == OPEN`:
     - If `timestamp_ms - opened_at_ms < cooldown_ms`: return **`VerdictCode.CIRCUIT_BREAKER_OPEN`** immediately (`< 1 µs` fail-fast; `last_seq_no`, rate window, and `consecutive_failures` remain unchanged).
     - Else (`timestamp_ms - opened_at_ms ≥ cooldown_ms`): transition `state = HALF_OPEN` and proceed to Step 2 with this single probe packet.
2. **Step 2 — Kleppmann Monotonic Fencing Token (`EC-D` Anti-Replay):**
   - If `seq_no ≤ last_seq_no`: reject with **`VerdictCode.REPLAY_ATTACK_BLOCKED`** and jump to Step 6.
   - Else: set `last_seq_no = seq_no`.
3. **Step 3 — Sliding-Window Rate Limiter:**
   - Evict all timestamps `t` from `window_timestamps` where `t < timestamp_ms - window_ms`.
   - If `len(window_timestamps) ≥ max_requests_per_window`: reject with **`VerdictCode.RATE_LIMIT_EXCEEDED`** and jump to Step 6.
   - Else: append `timestamp_ms` to `window_timestamps`.
4. **Step 4 — Wire Protocol Decode (`F2` / `F3`):**
   - Decode `payload_hex`. On any `MODBUS_*` or `MQTT_*` failure, jump to Step 6 with that `VerdictCode`.
5. **Step 5 — Combinational DAG Interlock (`F4`):**
   - For write packets (`FC 0x05`, `FC 0x06`, `FC 0x10`, `MQTT PUBLISH`), run Trial Write Evaluation. If tripped, jump to Step 6 with **`VerdictCode.INTERLOCK_TRIPPED`**.
   - Otherwise commit `scratch_regs → live_regs` and emit **`VerdictCode.ALLOW_WRITE`** (or **`VerdictCode.ALLOW_READ`** for `FC 0x03`).
6. **Step 6 — Violation Accounting & State Transitions:**
   - **If Rejected in Steps 2–5:** increment `consecutive_failures += 1` and `total_violations += 1`. If `state == HALF_OPEN` or `consecutive_failures ≥ trip_threshold`, set `state = OPEN` and `opened_at_ms = timestamp_ms`.
   - **If Allowed (`ALLOW_READ` / `ALLOW_WRITE`):** set `consecutive_failures = 0`; if `state == HALF_OPEN`, set `state = CLOSED`.

### `F6` — Multi-Block RFC 7693 `BLAKE2b-64` Cryptographic Audit Chain
- **Complete Canonical ASCII Pre-Image:**
  `f"{prev_hash_u64:016x}|{packet_id}|{seq_no}|{timestamp_ms}|{source_id}|{protocol.value}|{verdict_code.value}|{tripped_node_id}|{breaker_state.value}"`
  (where `tripped_node_id = -1` when no interlock tripped, and `prev_hash_u64` starts at `GENESIS_HASH_U64 = 0x5645435452413236`).
- **Digest Calculation:** Multi-block RFC 7693 `BLAKE2b` with `outlen = 8` (`h[0] = 0x6a09e667f3bcc908 ^ 0x01010008 = 0x6a09e667f2bd0900`). Resulting 64-bit unsigned integer `chain_hash_u64` becomes `prev_hash_u64` for the next verdict.

### `F7` — `vectragate.bundle/v1` 4-Stage JSON Boundary Gate
1. **Stage 1 (Byte & UTF-8 Ceiling):** Enforce `len(raw_bytes) ≤ 4_194_304` (`4 MiB`), strict UTF-8 decode, and zero `\x00` bytes.
2. **Stage 2 (Iterative Depth Scanner):** Single-pass non-recursive bracket/brace scanner respecting JSON string escapes; reject if nesting depth `> 8`.
3. **Stage 3 (Zero-Float JSON Parse & Schema Gate):** Parse via `json.loads` with `parse_float` and `parse_constant` raising `IntakeError("FLOAT_FORBIDDEN")`; validate `schema_version == "vectragate.bundle/v1"`.
4. **Stage 4 (Per-Packet Quarantine):** Validate each item in `packets`; malformed items are isolated as `PacketRejection(packet_index, packet_id, code, detail)` without aborting valid packets.

### `F8` + `EC-E` — OWASP 2026 `CWE-1236` Neutralized `.xlsx` Exporter, `DuckDB 2.0` SIEM Views & Atomic Persistence
1. **Full OWASP 2026 `CWE-1236` Formula Neutralization (`EC-E`):** `neutralize_formula_cell(val: str) -> str` checks BOTH raw `val` and `unicodedata.normalize("NFKC", val).lstrip()` against all 9 dangerous triggers `("=", "+", "-", "@", "|", "%", "\t", "\r", "\n")` (defeating fullwidth `＝` `U+FF1D` and leading whitespace bypasses), prepending `"'"` and setting `cell.data_type = "s"` on all text cells (replacing `""` with `"—"`).
2. **Big-4 Executive `.xlsx` Workbook & Atomic `.tmp_` Persistence:** 4 sheets (`PacketVerdicts`, `RegisterSnapshot`, `SourceSecurityState`, `SIEMSummary`) styled with dark navy `#0F172A` headers, emerald `#D1FAE5` total rows with live `=SUM(...)` formulas, `#,##0` integer formatting, and persisted via `.tmp_<name>.<pid>` + `os.open`/`os.fsync`/`os.close` + `os.replace` (`0` `open()` calls in `src/vectragate/`).
3. **`DuckDB 2.0` SIEM Analytics (`duckdb`):** Populates tables `packet_verdicts`, `register_snapshot`, `source_security_state` and SQL views `v_siem_threat_summary` and `v_interlock_trips`.

---

## § 2. Module Topology & Dependency DAG (`src/cpp/`, `src/vectragate/`, `tests/`)

```text
C:\projects\VectraGate_Core\
├── BLUEPRINT.md / SPEC.md / ADR.md / HANDOFF.md / README.md / pyproject.toml
├── src/
│   ├── cpp/
│   │   ├── vectragate_core.hpp       # Header-only C++17/20 EngineArena, Modbus/MQTT, Kahn DAG, Nygard, BLAKE2b-64, SPSC
│   │   └── vectragate_cli.cpp        # Deterministic CLI runner compiling to vectragate_cli.exe
│   └── vectragate/
│       ├── __init__.py               # Public package exports
│       ├── models.py                 # Layer 0: Enums, 8 frozen dataclasses, F1 __post_init__ hygiene, BLAKE2b-64 helper
│       ├── protocol.py               # Layer 1: F2 Modbus TCP & F3 MQTT v3.1.1 binary wire decoders (depends: models)
│       ├── dag_engine.py             # Layer 1: F4 Kahn topological sort & branchless DAG evaluator (depends: models)
│       ├── firewall.py               # Layer 2: F5 Nygard breaker, Fencing tokens, Rate limiter, F6 chain (depends: models, protocol, dag_engine)
│       ├── intake_gate.py            # Layer 3: F7 4-stage JSON boundary gate (depends: models, dag_engine)
│       ├── cpp_bridge.py             # Layer 3: Subprocess bridge & parity verifier for vectragate_cli.exe (depends: models, firewall)
│       ├── exporters.py              # Layer 3: F8 CWE-1236 .xlsx exporter & DuckDB 2.0 SIEM views (depends: models, firewall)
│       └── cli_visualizer.py         # Layer 4: Rich ASCII/Unicode SIEM dashboard & CLI entrypoint (depends: Layers 0–3)
└── tests/
    ├── _oracle.py                    # Independent reference oracle (0 imports from src.vectragate)
    ├── test_architecture_fitness.py  # Automated Fitness Functions FF-1 through FF-9 & 1,050-seed parity
    ├── test_protocol_decoders.py     # F2 Modbus & F3 MQTT wire boundary & CVE defense tests
    ├── test_dag_and_firewall.py      # F4 DAG interlock, F5 breaker/fencing/rate-limit, F6 BLAKE2b chain tests
    ├── test_intake_and_exporters.py  # F7 4-stage intake, F8 CWE-1236 .xlsx & DuckDB 2.0 view tests
    └── test_property_hypothesis.py   # Seeded property-based wire, Kahn DAG, CWE-1236 & BLAKE2b fuzzing
```

---

## § 3. Automated Architectural Fitness Functions (`FF-1` – `FF-9`)

| ID | Fitness Function | Mechanical Verification Rule |
| :--- | :--- | :--- |
| **`FF-1`** | **Acyclic Layered Import DAG** | AST scan of `src/vectragate/*.py` proving strict upward dependency layering (`models ← {protocol, dag_engine} ← firewall ← {intake_gate, cpp_bridge, exporters} ← cli_visualizer`) with `0` cycles and strict per-module allowed-imports sets. |
| **`FF-2`** | **Zero-Float & Zero-Division Gate** | AST scan across `src/vectragate/` and `tests/` banning `float` literals, `float()`, `Decimal`, `ast.Div` (`/`), and floating-point imports (`R0.1`). |
| **`FF-3`** | **Bounded Functions, Assertions & Zero-Recursion** | AST scan enforcing `≤ 60` LOC per function (`NASA Rule 4`), `≥ 2` `assert` statements per function (`NASA Rule 5`), `0` direct/indirect recursion (`NASA Rule 1`), and `0` `open`/`eval`/`exec`/`pickle` in `src/vectragate/`. |
| **`FF-4`** | **Immutable Value Objects Gate** | AST + runtime check that all `8` domain dataclasses in `models.py` declare `@dataclass(slots=True, frozen=True)`. |
| **`FF-5`** | **Oracle Independence Gate** | AST scan proving `tests/_oracle.py` has `0` imports from `src/` or `vectragate`. |
| **`FF-6`** | **`CWE-1236` & Live Excel Formula Gate** | Verifies NFKC + whitespace + 9-trigger payloads (`=CMD\|...`, `＝SUM(1)`, ` +1+1`, `\|calc`, `%0A`) are prefixed with `'` (`data_type == "s"`) while all 4 sheets preserve live `=SUM(...)` formulas (`0` `None` cells) and `.tmp_` atomic persistence. |
| **`FF-7`** | **C++17/20 Arena & Zero-Heap Source Gate** | Scans `src/cpp/vectragate_core.hpp` for `alignas(64)`, `static_assert`, SPSC ring buffer, multi-block `blake2b_64`, and `0` dynamic allocation calls (`new`, `delete`, `malloc`, `free`, `calloc`, `realloc`). |
| **`FF-8`** | **Zero-Dollar Docs, SVG Geometry & LOC Gate** | Verifies `0` raw dollar chars across all `.md` files, XML well-formedness & `≤ 46` chars per panel line + `0` unused `<marker>` defs on all SVGs in `assets/`, and exact LOC parity in `README.md`. |
| **`FF-9`** | **C++17/20 Native Compilation & `1,050`-Seed Parity** | Compiles `src/cpp/vectragate_cli.cpp` with `g++ -std=c++17 -O3 -Wall -Wextra -Wpedantic -Werror` (`C++17/20` compatible) and verifies `100%` bit-for-bit parity across `50` fast + `1,000` deep seeds (`1,050` total instances) for `C++ Binary == Python Core == Independent _oracle.py` (`R0.4`, `R0.5`). |

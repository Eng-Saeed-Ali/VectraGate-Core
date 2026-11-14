# SPEC.md — Normative Module, Interface & Silicon Contract for `VectraGate-Core (بَرْزَخ)`

- **Schema & Contract Version:** `vectragate.bundle/v1` (`1.0.0`)
- **Global Coding Constraints (`FF-1` – `FF-9`):**
  1. Every function in `src/vectragate/` MUST be `≤ 60` lines (`NASA Rule 4`) and contain `≥ 2` side-effect-free `assert` statements (`NASA Rule 5` / `TigerStyle`).
  2. Zero `float`, `double`, `Decimal`, or `/` true-division operators anywhere in `src/` or `tests/` (`R0.1`, `FF-2`).
  3. Zero direct or indirect recursion (`NASA Rule 1`) and zero `open()`, `eval()`, `exec()`, or `pickle` calls in `src/vectragate/` (`FF-3`).
  4. Zero raw dollar characters in any `.md` document (`FF-8`).

---

## § 1. Layer 0: `src/vectragate/models.py`

### 1.1 Allowed Imports
- Strictly `{"__future__", "dataclasses", "enum", "hashlib", "re"}`.

### 1.2 Global Constants
- `MAX_REGISTERS: int = 256`
- `MAX_DAG_NODES: int = 128`
- `MAX_SOURCES: int = 64`
- `MAX_WINDOW_TIMESTAMPS: int = 64`
- `SPSC_RING_SLOTS: int = 256`
- `MIN_REG_VAL: int = -32_768`
- `MAX_REG_VAL: int = 65_535`
- `GENESIS_HASH_U64: int = 0x5645435452413236` (ASCII `"VECTRA26"`)
- `MAX_PAYLOAD_BYTES: int = 4_194_304` (`4 MiB`)
- `MAX_JSON_DEPTH: int = 8`
- `MAX_PACKETS: int = 10_000`
- `ID_PATTERN: re.Pattern[str] = re.compile(r"^[A-Z0-9_-]{1,32}\Z")`
- `HEX_PATTERN: re.Pattern[str] = re.compile(r"^[0-9a-fA-F]{2,1024}\Z")`

### 1.3 Enumerations (`enum.StrEnum`)
1. **`ProtocolType(StrEnum)`:**
   - `MODBUS_TCP = "MODBUS_TCP"`
   - `MQTT = "MQTT"`
2. **`NodeOp(StrEnum)` (`12` operations):**
   - Comparators (`6`): `CMP_GT = "CMP_GT"`, `CMP_GE = "CMP_GE"`, `CMP_LT = "CMP_LT"`, `CMP_LE = "CMP_LE"`, `CMP_EQ = "CMP_EQ"`, `CMP_NE = "CMP_NE"`
   - Logic Gates (`6`): `AND = "AND"`, `OR = "OR"`, `XOR = "XOR"`, `NOT = "NOT"`, `NAND = "NAND"`, `NOR = "NOR"`
3. **`BreakerState(StrEnum)` (`3` states):**
   - `CLOSED = "CLOSED"`, `OPEN = "OPEN"`, `HALF_OPEN = "HALF_OPEN"`
4. **`VerdictCode(StrEnum)` (`24` exact codes):**
   - Allow (`2`): `ALLOW_READ = "ALLOW_READ"`, `ALLOW_WRITE = "ALLOW_WRITE"`
   - Security & Interlock (`4`): `CIRCUIT_BREAKER_OPEN = "CIRCUIT_BREAKER_OPEN"`, `REPLAY_ATTACK_BLOCKED = "REPLAY_ATTACK_BLOCKED"`, `RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"`, `INTERLOCK_TRIPPED = "INTERLOCK_TRIPPED"`
   - Modbus TCP (`8`): `MODBUS_FRAME_TOO_SHORT = "MODBUS_FRAME_TOO_SHORT"`, `MODBUS_INVALID_PROTOCOL = "MODBUS_INVALID_PROTOCOL"`, `MODBUS_LENGTH_OUT_OF_BOUNDS = "MODBUS_LENGTH_OUT_OF_BOUNDS"`, `MODBUS_MBAP_LEN_MISMATCH = "MODBUS_MBAP_LEN_MISMATCH"`, `MODBUS_REGISTER_OOB = "MODBUS_REGISTER_OOB"`, `MODBUS_INVALID_COIL_VALUE = "MODBUS_INVALID_COIL_VALUE"`, `MODBUS_BYTE_COUNT_MISMATCH = "MODBUS_BYTE_COUNT_MISMATCH"`, `MODBUS_UNAUTHORIZED_FC = "MODBUS_UNAUTHORIZED_FC"`
   - MQTT v3.1.1 (`10`): `MQTT_FRAME_TOO_SHORT = "MQTT_FRAME_TOO_SHORT"`, `MQTT_UNSUPPORTED_PACKET_TYPE = "MQTT_UNSUPPORTED_PACKET_TYPE"`, `MQTT_INVALID_FLAGS = "MQTT_INVALID_FLAGS"`, `MQTT_VARINT_OVERFLOW = "MQTT_VARINT_OVERFLOW"`, `MQTT_OVERLONG_VARINT = "MQTT_OVERLONG_VARINT"`, `MQTT_PACKET_LEN_MISMATCH = "MQTT_PACKET_LEN_MISMATCH"`, `MQTT_TOPIC_OOB = "MQTT_TOPIC_OOB"`, `MQTT_INVALID_TOPIC = "MQTT_INVALID_TOPIC"`, `MQTT_INVALID_PAYLOAD = "MQTT_INVALID_PAYLOAD"`, `MQTT_REGISTER_OOB = "MQTT_REGISTER_OOB"`

### 1.4 Pure Mathematical & Cryptographic Helpers
- `ceil_div(n: int, d: int) -> int`:
  - Requires `type(n) is int and type(d) is int`, `n ≥ 0`, `d > 0`; returns `(n + d - 1) // d`.
- `blake2b_u64(data: bytes) -> int`:
  - Computes `int.from_bytes(hashlib.blake2b(data, digest_size=8).digest(), "little")`, returning an unsigned 64-bit integer `0 ≤ h < 2**64`.
- `compute_verdict_hash(prev_hash_u64: int, packet_id: str, seq_no: int, timestamp_ms: int, source_id: str, protocol: ProtocolType, verdict_code: VerdictCode, tripped_node_id: int, breaker_state: BreakerState) -> int`:
  - Encodes canonical ASCII pre-image:
    `f"{prev_hash_u64:016x}|{packet_id}|{seq_no}|{timestamp_ms}|{source_id}|{protocol.value}|{verdict_code.value}|{tripped_node_id}|{breaker_state.value}".encode("ascii")`
  - Returns `blake2b_u64(canonical_bytes)`.

### 1.5 Immutable Value Objects (`@dataclass(slots=True, frozen=True)` — `8` Classes)
Every class validates all fields in `__post_init__`, rejecting `bool` for `int` (`type(x) is int`), NUL bytes, and out-of-range values with `ValueError` or `TypeError`:
1. **`FirewallPolicy`:**
   - `window_ms: int = 10_000` (`1 ≤ window_ms ≤ 86_400_000`)
   - `max_requests_per_window: int = 10` (`1 ≤ max_requests_per_window ≤ MAX_WINDOW_TIMESTAMPS`)
   - `trip_threshold: int = 3` (`1 ≤ trip_threshold ≤ 1_000`)
   - `cooldown_ms: int = 30_000` (`1 ≤ cooldown_ms ≤ 86_400_000`)
2. **`DagNode`:**
   - `node_id: int` (`0 ≤ node_id < MAX_DAG_NODES`)
   - `tag: str` (matches `ID_PATTERN`)
   - `op: NodeOp`
   - `target_reg: int = 0` (`0 ≤ target_reg < MAX_REGISTERS`)
   - `threshold: int = 0` (`MIN_REG_VAL ≤ threshold ≤ MAX_REG_VAL`)
   - `inputs: tuple[int, ...] = ()` (for comparators: must be `()`; for `NOT`: `len(inputs) == 1`; for `AND`/`OR`/`XOR`/`NAND`/`NOR`: `1 ≤ len(inputs) ≤ 8`; all input IDs `0 ≤ i < MAX_DAG_NODES` and `i ≠ node_id`)
   - `is_hazard_output: bool = False` (`type(is_hazard_output) is bool`)
3. **`RawPacket`:**
   - `packet_id: str` (matches `ID_PATTERN`)
   - `source_id: str` (matches `ID_PATTERN`)
   - `seq_no: int` (`seq_no ≥ 1`)
   - `timestamp_ms: int` (`timestamp_ms ≥ 0`)
   - `protocol: ProtocolType`
   - `payload_hex: str` (even length, matches `HEX_PATTERN`)
4. **`DecodedOperation`:**
   - `protocol: ProtocolType`
   - `is_write: bool`
   - `writes: tuple[tuple[int, int], ...]` (each `(reg_addr, reg_val)` satisfies `0 ≤ reg_addr < MAX_REGISTERS` and `MIN_REG_VAL ≤ reg_val ≤ MAX_REG_VAL`)
   - `read_start: int = 0` (`0 ≤ read_start < MAX_REGISTERS`)
   - `read_count: int = 0` (`0 ≤ read_count ≤ MAX_REGISTERS`)
   - `topic: str = ""` (no `\x00`)
5. **`SourceSecurityState`:**
   - `source_id: str` (matches `ID_PATTERN`)
   - `last_seq_no: int` (`last_seq_no ≥ 0`)
   - `breaker_state: BreakerState`
   - `consecutive_failures: int` (`consecutive_failures ≥ 0`)
   - `total_violations: int` (`total_violations ≥ 0`)
   - `opened_at_ms: int` (`opened_at_ms ≥ -1`)
   - `window_timestamps: tuple[int, ...]` (`len ≤ MAX_WINDOW_TIMESTAMPS`)
6. **`PacketVerdict`:**
   - `seq_index: int` (`seq_index ≥ 0`)
   - `packet_id: str`
   - `source_id: str`
   - `seq_no: int` (`seq_no ≥ 1`)
   - `timestamp_ms: int` (`timestamp_ms ≥ 0`)
   - `protocol: ProtocolType`
   - `verdict_code: VerdictCode`
   - `is_allowed: bool` (`is_allowed == (verdict_code in (VerdictCode.ALLOW_READ, VerdictCode.ALLOW_WRITE))`)
   - `tripped_node_id: int` (`-1 ≤ tripped_node_id < MAX_DAG_NODES`)
   - `breaker_state_after: BreakerState`
   - `prev_hash_u64: int` (`0 ≤ prev_hash_u64 < 2**64`)
   - `chain_hash_u64: int` (`0 ≤ chain_hash_u64 < 2**64`)
7. **`PacketRejection`:**
   - `packet_index: int` (`packet_index ≥ 0`)
   - `packet_id: str | None`
   - `code: str` (non-empty ASCII error code)
   - `detail: str` (non-empty diagnostic description)
8. **`FirewallRunResult`:**
   - `verdicts: tuple[PacketVerdict, ...]`
   - `final_registers: tuple[int, ...]` (`len(final_registers) == MAX_REGISTERS`)
   - `source_states: tuple[SourceSecurityState, ...]`
   - `topological_order: tuple[int, ...]`
   - `final_chain_hash_u64: int` (`0 ≤ final_chain_hash_u64 < 2**64`)
   - `allowed_count: int` (`allowed_count ≥ 0`)
   - `blocked_count: int` (`blocked_count ≥ 0`, `allowed_count + blocked_count == len(verdicts)`)

---

## § 2. Layer 1: `src/vectragate/protocol.py` & `src/vectragate/dag_engine.py`

### 2.1 `src/vectragate/protocol.py`
- **Allowed Imports:** `{"__future__", "vectragate.models"}`.
- **Public Signatures:**
  - `decode_modbus_tcp(raw: bytes) -> tuple[VerdictCode | None, DecodedOperation | None]`
    - Implements `F2 + EC-A` priority checks (`MODBUS_FRAME_TOO_SHORT`, `MODBUS_INVALID_PROTOCOL`, `MODBUS_LENGTH_OUT_OF_BOUNDS`, `MODBUS_MBAP_LEN_MISMATCH`, `FC 0x03/0x05/0x06/0x10` register bounds & byte counts, `MODBUS_UNAUTHORIZED_FC`). Returns `(None, DecodedOperation(...))` on valid frame, or `(VerdictCode.MODBUS_*, None)` on rejection.
  - `decode_mqtt_publish(raw: bytes) -> tuple[VerdictCode | None, DecodedOperation | None]`
    - Implements `F3 + EC-B` priority checks (`MQTT_FRAME_TOO_SHORT`, `MQTT_UNSUPPORTED_PACKET_TYPE`, `MQTT_INVALID_FLAGS`, `MQTT_VARINT_OVERFLOW`, `MQTT_OVERLONG_VARINT`, `MQTT_PACKET_LEN_MISMATCH`, `MQTT_TOPIC_OOB`, `MQTT_INVALID_TOPIC`, `MQTT_INVALID_PAYLOAD`, `MQTT_REGISTER_OOB`). Returns `(None, DecodedOperation(...))` on valid frame, or `(VerdictCode.MQTT_*, None)` on rejection.
  - `decode_wire_packet(protocol: ProtocolType, payload_hex: str) -> tuple[VerdictCode | None, DecodedOperation | None]`
    - Converts `bytes.fromhex(payload_hex)` and dispatches to `decode_modbus_tcp` or `decode_mqtt_publish`.

### 2.2 `src/vectragate/dag_engine.py`
- **Allowed Imports:** `{"__future__", "collections.abc", "vectragate.models"}`.
- **Public Signatures:**
  - `validate_and_sort_dag(nodes: Sequence[DagNode]) -> tuple[int, ...]`
    - Validates unique `node_id`s (`≤ MAX_DAG_NODES`), confirms all `inputs` reference existing `node_id`s in `nodes`, and executes **Kahn's Iterative Topological Sort** (`0` recursion, deterministic tie-breaking by ascending `node_id`). Raises `ValueError("Cyclic DAG detected")` if `len(topo_order) ≠ len(nodes)`.
  - `evaluate_dag(nodes_by_id: dict[int, DagNode], topo_order: Sequence[int], registers: Sequence[int]) -> tuple[bool, int, tuple[int, ...]]`
    - Evaluates each `DagNode` in `topo_order` using branchless integer/bitwise operations (`& 1`, `|`, `^`, `^ 1`) against `registers`.
    - Returns `(is_tripped, tripped_node_id, node_outputs_tuple)` where `tripped_node_id` is the lowest `node_id` among nodes with `is_hazard_output == True` that evaluated to `1` (or `-1` if `is_tripped is False`).

---

## § 3. Layer 2: `src/vectragate/firewall.py`

### 3.1 Allowed Imports
- Strictly `{"__future__", "collections.abc", "dataclasses", "vectragate.models", "vectragate.protocol", "vectragate.dag_engine"}`.

### 3.2 Public Signatures
- `evaluate_packet_stream(packets: Sequence[RawPacket], dag_nodes: Sequence[DagNode], initial_registers: Sequence[int] | None = None, policy: FirewallPolicy = FirewallPolicy()) -> FirewallRunResult`
  - Validates `len(packets) ≤ MAX_PACKETS`, initializes `live_regs` of length `MAX_REGISTERS` (from `initial_registers` or all zeros), computes `topo_order = validate_and_sort_dag(dag_nodes)`, and evaluates packets sequentially using the exact 6-step pipeline (`F5 + EC-D`):
    1. Nygard Circuit Breaker check (`OPEN` fail-fast vs `cooldown_ms → HALF_OPEN`).
    2. Kleppmann Fencing Token anti-replay (`seq_no ≤ last_seq_no → REPLAY_ATTACK_BLOCKED`).
    3. Sliding-window rate limiter (`evict t < timestamp_ms - window_ms`; `len ≥ max_requests_per_window → RATE_LIMIT_EXCEEDED`).
    4. Wire protocol decode (`decode_wire_packet`).
    5. Combinational DAG trial-write interlock (`evaluate_dag` on `scratch_regs`; if tripped → `INTERLOCK_TRIPPED` with `live_regs` untouched; else commit `scratch_regs` and emit `ALLOW_WRITE` / `ALLOW_READ`).
    6. Violation accounting, breaker state transitions, and multi-block `BLAKE2b-64` chain sealing (`compute_verdict_hash`).
  - Source states in `FirewallRunResult.source_states` are returned sorted by `source_id` ascending.
- `verify_verdict_chain(verdicts: Sequence[PacketVerdict]) -> bool`
  - Recomputes `compute_verdict_hash` from `GENESIS_HASH_U64` across every `PacketVerdict` in `verdicts` and returns `True` iff all `prev_hash_u64` and `chain_hash_u64` links match.

---

## § 4. Layer 3: `intake_gate.py`, `cpp_bridge.py` (+ C++17/20 Core), and `exporters.py`

### 4.1 `src/vectragate/intake_gate.py`
- **Allowed Imports:** `{"__future__", "collections.abc", "json", "re", "vectragate.models", "vectragate.dag_engine"}`.
- **Exception Class:** `class IntakeError(ValueError): pass`
- **Public Signatures:**
  - `ingest_json_bundle_report(raw: str | bytes) -> tuple[tuple[RawPacket, ...], tuple[DagNode, ...], tuple[int, ...], FirewallPolicy, tuple[PacketRejection, ...]]`
    - Executes the 4-stage boundary gate (`F7`): Stage 1 (`≤ 4 MiB`, UTF-8, no `\x00`), Stage 2 (iterative bracket depth scanner `≤ 8`), Stage 3 (`json.loads` with `parse_float`/`parse_constant` raising `IntakeError("FLOAT_FORBIDDEN")`, schema `"vectragate.bundle/v1"`, valid `policy`, `initial_registers`, `dag_nodes`), Stage 4 (per-packet validation isolating invalid packet entries into `PacketRejection` objects).
  - `ingest_json_bundle(raw: str | bytes) -> tuple[tuple[RawPacket, ...], tuple[DagNode, ...], tuple[int, ...], FirewallPolicy]`
    - Calls `ingest_json_bundle_report(raw)`; if `rejections` is non-empty, raises `IntakeError` detailing the first rejection; otherwise returns the 4-tuple.

### 4.2 `src/cpp/vectragate_core.hpp`, `src/cpp/vectragate_cli.cpp` & `src/vectragate/cpp_bridge.py`
- **C++17/20 Header-Only Core (`src/cpp/vectragate_core.hpp`):**
  - Defines `alignas(64) struct EngineArena` with `static_assert(alignof(EngineArena) == 64)` and `alignas(64) struct SpscRingBuffer` (`256` slots, separate cache-aligned `write_idx` and `read_idx` atomics).
  - Implements multi-block RFC 7693 `blake2b_64(const uint8_t* msg, size_t len)` (`while (len > 128) ...`), Kahn's iterative topological sort, branchless bitwise DAG evaluation, Modbus TCP & MQTT v3.1.1 binary decoders, and Nygard/Kleppmann firewall state machine with zero post-init heap allocation (`FF-7`).
- **Deterministic Line-Oriented Text Wire Protocol (`vectragate_cli.exe` stdin → stdout):**
  - **Input (stdin):**
    - `POLICY <window_ms> <max_requests_per_window> <trip_threshold> <cooldown_ms>`
    - `REG <reg_addr> <reg_val>` (for non-zero initial registers)
    - `NODE <node_id> <tag> <op_str> <target_reg> <threshold> <is_hazard:0|1> <in_cnt> [in_0 ...]`
    - `PKT <packet_id> <source_id> <seq_no> <timestamp_ms> <protocol_str> <payload_hex>`
    - `END`
  - **Output (stdout):**
    - `TOPO <n_0> <n_1> ...`
    - `VERDICT <seq_index> <packet_id> <source_id> <seq_no> <timestamp_ms> <protocol> <verdict_code> <is_allowed:0|1> <tripped_node_id> <breaker_state_after> <prev_hash_hex16> <chain_hash_hex16>`
    - `SOURCE <source_id> <last_seq_no> <breaker_state> <consecutive_failures> <total_violations> <opened_at_ms> <win_cnt> [ts_0 ...]`
    - `REGS <r_0> <r_1> ... <r_255>`
    - `SUMMARY <allowed_count> <blocked_count> <final_chain_hash_hex16>`
- **`src/vectragate/cpp_bridge.py`:**
  - **Allowed Imports:** `{"__future__", "collections.abc", "pathlib", "subprocess", "vectragate.models", "vectragate.firewall"}`.
  - **Public Signatures:**
    - `compile_cpp_engine(binary_path: str | pathlib.Path | None = None) -> pathlib.Path`
    - `run_cpp_engine(packets: Sequence[RawPacket], dag_nodes: Sequence[DagNode], initial_registers: Sequence[int] | None = None, policy: FirewallPolicy = FirewallPolicy(), binary_path: pathlib.Path | None = None) -> FirewallRunResult`

### 4.3 `src/vectragate/exporters.py`
- **Allowed Imports:** `{"__future__", "collections.abc", "os", "pathlib", "unicodedata", "duckdb", "openpyxl", "openpyxl.styles", "openpyxl.utils", "openpyxl.worksheet.worksheet", "vectragate.models", "vectragate.firewall"}`.
- **Public Signatures:**
  - `neutralize_formula_cell(val: str) -> str`:
    - Replaces `""` with `"—"`. Checks both raw `val` and `unicodedata.normalize("NFKC", val).lstrip()` against `("=", "+", "-", "@", "|", "%", "\t", "\r", "\n")`; if matched, prepends `"'"`.
  - `export_xlsx_atomic(result: FirewallRunResult, target_path: str | os.PathLike[str]) -> None`:
    - Builds 4 sheets (`PacketVerdicts`, `RegisterSnapshot`, `SourceSecurityState`, `SIEMSummary`) with Big-4 `openpyxl.styles` (`#0F172A` navy header fill, `#D1FAE5` emerald summary row with live `=SUM(...)` formulas, `#,##0` integer formatting, `cell.data_type = "s"` on neutralized text cells) and writes atomically via `.tmp_<name>.<pid>` + `os.open`/`os.fsync`/`os.close` + `os.replace`.
  - `query_duckdb_siem_summary(result: FirewallRunResult) -> dict[str, int]`:
    - Loads `result` into an in-memory `DuckDB 2.0` connection, creates SQL views `v_siem_threat_summary` and `v_interlock_trips`, and returns deterministic integer telemetry (`total_packets`, `allowed_packets`, `blocked_packets`, `interlock_trips`, `replay_blocks`, `rate_limit_blocks`, `breaker_blocks`, `protocol_errors`, `open_breakers`).

---

## § 5. Layer 4: `src/vectragate/cli_visualizer.py` & `src/vectragate/__init__.py`

### 5.1 `src/vectragate/cli_visualizer.py`
- **Allowed Imports:** `{"__future__", "argparse", "collections.abc", "pathlib", "vectragate.models", "vectragate.firewall", "vectragate.intake_gate", "vectragate.cpp_bridge", "vectragate.exporters"}`.
- **Public Signatures:**
  - `build_demo_scenario() -> tuple[tuple[RawPacket, ...], tuple[DagNode, ...], tuple[int, ...], FirewallPolicy]`
  - `render_firewall_report(result: FirewallRunResult) -> str`
  - `main(argv: Sequence[str] | None = None) -> int`

### 5.2 `src/vectragate/__init__.py`
- Re-exports all public models, enums, constants, protocol decoders, DAG functions, firewall functions, intake gate functions, C++ bridge functions, and exporter functions via explicit `__all__`.

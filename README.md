<p align="center">
  <img src="assets/vectragate_hero_banner.png" width="100%" alt="VectraGate-Core Hero Banner"/>
</p>

# VectraGate-Core (بَرْزَخ)

![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-2563eb.svg)
![C++17/20 Native Core](https://img.shields.io/badge/C%2B%2B-17%2F20%20Native%20Core-059669.svg)
![Zero Float](https://img.shields.io/badge/arithmetic-64--bit%20zero--float-d97706.svg)
![Oracle Parity](https://img.shields.io/badge/oracle%20parity-1%2C050%20%2F%201%2C050%20seeds-10b981.svg)
![License MIT](https://img.shields.io/badge/license-MIT-64748b.svg)

**Deterministic C++17/20 & Python OT/ICS Protocol Firewall, Logic-Gate DAG Interlock Engine & Cryptographic Audit Ledger**

`VectraGate-Core (بَرْزَخ)` is an industrial operational-technology (OT) and industrial control system (ICS) protocol firewall that inspects **Modbus TCP** and **MQTT v3.1.1** command frames before they reach physical Programmable Logic Controllers (PLCs). Every write command is evaluated on a scratchpad register copy through a topologically sorted **Logic-Gate DAG Interlock Engine**, guarded by **Kleppmann monotonic fencing tokens**, a **sliding-window integer rate limiter**, and a **Nygard 3-state circuit breaker**, and sealed into a tamper-evident **RFC 7693 `BLAKE2b-64` hash chain**.

---

## 1. Architecture & Silicon Layout

![VectraGate-Core 4-Layer Architecture & 64-Byte Cache-Aligned Pipeline](assets/architecture_pipeline.svg)

- **Layer 1 (`src/vectragate/models.py`):** Immutable domain contracts (`@dataclass(slots=True, frozen=True)` across `8` dataclasses), 64-bit integer register ranges bounded to **`[-32_768, 65_535]` (`MIN_REG_VAL .. MAX_REG_VAL`)**, and **`24` deterministic `VerdictCode` values**.
- **Layer 2A (`src/cpp/vectragate_core.hpp`, `src/cpp/vectragate_cli.cpp`):** Header-only C++17/20 engine featuring `alignas(64)` cache-line structures (`EngineArena`, `DagNodePod`, `SourceSecurityPod`, `PacketEventPod`, `SpscRingBuffer`), a wait-free 256-slot `SpscRingBuffer` exercised in 256-packet batches (with `--selftest-spsc` verification), and branchless bitwise DAG evaluation (`-(int64_t)(cond)`).
- **Layer 2B (`protocol.py`, `dag_engine.py`, `firewall.py`):** Pure-integer Python reference core with bit-for-bit parity against the native C++17/20 binary and independent oracle (`tests/_oracle.py`).
- **Layer 3 (`intake_gate.py`, `cpp_bridge.py`):** 4-stage `vectragate.bundle/v1` JSON boundary validation gate (`<= 4 MiB`, iterative nesting depth `<= 8`, zero-float enforcement, and per-packet `PacketRejection` quarantine) and subprocess C++17/20 parity bridge.
- **Layer 4 (`exporters.py`, `cli_visualizer.py`):** In-memory **DuckDB 2.0** `BIGINT` SIEM SQL views (`v_siem_threat_summary`, `v_interlock_trips`), Big-4 styled **Excel (`.xlsx`)** workbooks with live `=SUM(...)` formulas across all 4 sheets (`0` `None` cells, OWASP 2026 `CWE-1236` shield, atomic `.tmp_` + `os.fsync` + `os.replace`), and a 100% pure Python stdlib Unicode/ASCII CLI visualizer.

---

## 2. Protocol Inspection, DAG Interlock & Nygard Circuit Breaker

![Protocol Inspection, Kahn DAG Interlock & Nygard 3-State Circuit Breaker](assets/protocol_dag_interlock.svg)

### 2.1 Security & CVE Defense Matrix

| Threat / Vulnerability Class | Attack Vector & Wire Anomaly | Deterministic Defense & `VerdictCode` |
| :--- | :--- | :--- |
| **`CVE-2026-54410` (Modbus ADU Overflow & Underflow)** | Crafted MBAP length `mbap_len < 2` (unsigned underflow of `mbap_len - 2`) or `mbap_len > 254` (ADU buffer overflow `> 260` bytes) | Rejects with `MODBUS_LENGTH_OUT_OF_BOUNDS` before PDU allocation; enforces exact `len(raw) == 6 + mbap_len` (`MODBUS_MBAP_LEN_MISMATCH`) |
| **Modbus Coil & Byte-Count Desynchronization** | Non-canonical `FC 0x05` coil payload (`∉ {0x0000, 0xFF00}`) or `FC 0x10` `byte_count ≠ 2 * reg_count` | Rejects with `MODBUS_INVALID_COIL_VALUE` or `MODBUS_BYTE_COUNT_MISMATCH`; bounds all register spans to `[0, 255]` (`MODBUS_REGISTER_OOB`) |
| **`CVE-2026-21888` (MQTT 5-Byte Varint Overflow)** | Malformed 5th continuation byte (`digit & 0x80 != 0` at byte 4) or non-minimal overlong varint (`0x80 0x00`) | Rejects with `MQTT_VARINT_OVERFLOW` or `MQTT_OVERLONG_VARINT` inside a bounded 4-iteration loop (`0` recursion) |
| **`CVE-2026-25627` (MQTT Length Mismatch & Topic Injection)** | `hdr_len + rem_len != len(raw)`, `QoS == 3`, or wildcard/NUL injection (`+`, `#`, `\x00`) in PUBLISH topic | Rejects with `MQTT_PACKET_LEN_MISMATCH`, `MQTT_INVALID_FLAGS`, `MQTT_TOPIC_OOB`, or `MQTT_INVALID_TOPIC` |
| **Stale Replay, Flood & Fault Cascades** | Out-of-order `seq_no <= last_seq_no`, packet burst `>= max_requests_per_window`, or repeated protocol/interlock violations | Enforces Kleppmann monotonic fencing (`REPLAY_ATTACK_BLOCKED`), sliding-window rate limiting (`RATE_LIMIT_EXCEEDED`), and Nygard 3-state circuit breaker (`CIRCUIT_BREAKER_OPEN`) |
| **OWASP 2026 `CWE-1236` Spreadsheet Formula Injection** | Malicious string prefixes (`=`, `+`, `-`, `@`, `BIT_OR`, `%`, `\t`, `\r`, `\n`) or Unicode NFKC fullwidth `＝` (`U+FF1D`) bypasses | `neutralize_formula_cell()` checks raw and `NFKC`-normalized `.lstrip()` strings, prepends `'`, and locks `cell.data_type = "s"` |

---

## 3. Quick Start & Deterministic Demo

```bash
# 1. Compile the native C++17/20 engine (zero warnings under -Werror) and run SPSC self-test
g++ -std=c++17 -O3 -Wall -Wextra -Wpedantic -Werror src/cpp/vectragate_cli.cpp -o vectragate_cli.exe
./vectragate_cli.exe --selftest-spsc

# 2. Run the 14-packet deterministic OT/ICS demo with native C++ parity check & Excel export
python -m vectragate.cli_visualizer --demo --verify-cpp --export-xlsx vectragate_demo_report.xlsx

# 3. Run the 104-test verification suite (including 1,050-seed C++/Python/Oracle parity & FF-1..FF-9)
pytest -v
```

### Sample Output (`python -m vectragate.cli_visualizer --demo --verify-cpp`)

```text
╔════════════════════════════════════════════════════════════════════════════╗
║               VectraGate-Core (بَرْزَخ) OT/ICS Firewall Report              ║
╚════════════════════════════════════════════════════════════════════════════╝
  Topological Order : 0 -> 1 -> 2 -> 3 -> 4
  BLAKE2b-64 Chain  : VALID | Final = 0x8ebb59e8dce5ccc2
  SIEM DuckDB 2.0   : total=14 allow=8 block=6 interlock=1 replay=1 rate=1 breaker=1 proto=2 open=0

── Packet Verdicts ───────────────────────────────────────────────────────────
  Seq PacketID   SourceID   SeqNo   TimeMs Protocol    Status   Trip Breaker    VerdictCode
  --- ---------- ---------- ----- -------- ----------- -------- ---- ---------- --------------------------
    0 PKT_01     PLC_MAIN       1      100 MODBUS_TCP  ALLOW      -1 CLOSED     ALLOW_WRITE
    1 PKT_02     PLC_MAIN       2      200 MODBUS_TCP  ALLOW      -1 CLOSED     ALLOW_READ
    2 PKT_03     PLC_MAIN       3      300 MQTT        ALLOW      -1 CLOSED     ALLOW_WRITE
    3 PKT_04     PLC_MAIN       4      400 MODBUS_TCP  BLOCK       4 CLOSED     INTERLOCK_TRIPPED
    4 PKT_05     PLC_MAIN       4      450 MODBUS_TCP  BLOCK      -1 CLOSED     REPLAY_ATTACK_BLOCKED
    5 PKT_06     PLC_MAIN       5     1500 MODBUS_TCP  BLOCK      -1 OPEN       MODBUS_BYTE_COUNT_MISMATCH
    6 PKT_07     PLC_MAIN       6     2000 MODBUS_TCP  BLOCK      -1 OPEN       CIRCUIT_BREAKER_OPEN
    7 PKT_08     PLC_MAIN       6     7000 MQTT        ALLOW      -1 CLOSED     ALLOW_WRITE
    8 PKT_09     PLC_MAIN       7     7100 MODBUS_TCP  ALLOW      -1 CLOSED     ALLOW_WRITE
    9 PKT_10     EDGE_GW        1     7200 MQTT        ALLOW      -1 CLOSED     ALLOW_WRITE
   10 PKT_11     EDGE_GW        2     7300 MQTT        BLOCK      -1 CLOSED     MQTT_VARINT_OVERFLOW
   11 PKT_12     EDGE_GW        3     7400 MODBUS_TCP  ALLOW      -1 CLOSED     ALLOW_READ
   12 PKT_13     EDGE_GW        4     7500 MODBUS_TCP  ALLOW      -1 CLOSED     ALLOW_READ
   13 PKT_14     EDGE_GW        5     7600 MODBUS_TCP  BLOCK      -1 CLOSED     RATE_LIMIT_EXCEEDED

── Source Security States ────────────────────────────────────────────────────
  SourceID   LastSeq Breaker    Fail Viol OpenedMs WinLen
  ---------- ------- ---------- ---- ---- -------- ------
  EDGE_GW          5 CLOSED        1    2       -1      4
  PLC_MAIN         7 CLOSED        0    3     1500      2

[C++ NATIVE PARITY VERIFIED: vectragate_cli.exe == Python Core | Final Chain 0x8ebb59e8dce5ccc2]
```

---

## 4. Automated Architecture Fitness Functions (`FF-1`–`FF-9`)

| Gate ID | Fitness Function | Mechanical Verification Rule (`tests/test_architecture_fitness.py`) |
| :--- | :--- | :--- |
| **`FF-1`** | **Acyclic Layered Import DAG** | AST scan of `src/vectragate/*.py` proving strict upward dependency layering (`models <- {protocol, dag_engine} <- firewall <- {intake_gate, cpp_bridge, exporters} <- cli_visualizer`) with `0` cycles and strict per-module allowed-imports sets. |
| **`FF-2`** | **Zero-Float & Zero-Division Gate** | AST scan across `src/vectragate/` and `tests/` banning `float` literals, `float()`, `Decimal`, `ast.Div` (`/`), and floating-point imports (`R0.1`). |
| **`FF-3`** | **Bounded Functions, Assertions & Zero-Recursion** | AST scan enforcing `<= 60` LOC per function (`NASA Rule 4`), `>= 2` `assert` statements per function (`NASA Rule 5`), `0` direct/indirect recursion (`NASA Rule 1`), and `0` `open`/`eval`/`exec`/`pickle` in `src/vectragate/`. |
| **`FF-4`** | **Immutable Value Objects Gate** | AST + runtime check that all `8` domain dataclasses in `models.py` declare `@dataclass(slots=True, frozen=True)`. |
| **`FF-5`** | **Oracle Independence Gate** | AST scan proving `tests/_oracle.py` has `0` imports from `src/` or `vectragate`. |
| **`FF-6`** | **`CWE-1236` & Live Excel Formula Gate** | Verifies NFKC + whitespace + 9-trigger payloads (`=CMD...`, `＝SUM(1)`, ` +1+1`, `BIT_OR calc`, `%0A`) are prefixed with `'` (`data_type == "s"`) while all 4 sheets preserve live `=SUM(...)` formulas (`0` `None` cells) and `.tmp_` atomic persistence. |
| **`FF-7`** | **C++17/20 Arena & Zero-Heap Source Gate** | Scans `src/cpp/vectragate_core.hpp` for `alignas(64)`, `static_assert`, `SpscRingBuffer`, multi-block `blake2b_64`, and `0` dynamic allocation calls (`new`, `delete`, `malloc`, `free`, `calloc`, `realloc`). |
| **`FF-8`** | **Zero-Dollar Docs, SVG Geometry & LOC Gate** | Verifies `0` raw dollar chars across all `.md`/`.svg` files, XML well-formedness & disjoint SVG box geometry in `assets/`, and `100%` exact file LOC parity in `README.md`. |
| **`FF-9`** | **C++17/20 Native Compilation & `1,050`-Seed Parity** | Compiles `src/cpp/vectragate_cli.cpp` with `g++ -std=c++17 -O3 -Wall -Wextra -Wpedantic -Werror`, runs `ruff check` & `ty check`, and verifies `100%` bit-for-bit parity across `50` fast + `1,000` deep seeds (`1,050` total instances) for `C++ Binary == Python Core == Independent _oracle.py`. |

---

## 5. Repository File & Line-Count Inventory (`FF-8` Synced)

| File Path | Lines (`LOC`) | Architectural Role |
| :--- | ---: | :--- |
| `BLUEPRINT.md` | 186 | Mathematical, Silicon & Protocol Blueprint |
| `SPEC.md` | 222 | Normative System & Protocol Specification |
| `ADR.md` | 87 | Architecture Decision Records (`ADR-001`–`ADR-005`) |
| `HANDOFF.md` | 58 | Multi-Agent Execution & Gate 6 Tracker |
| `README.md` | 145 | Project Documentation & Architecture Guide |
| `pyproject.toml` | 35 | Hatchling Build, Pytest, Ruff & Ty Configuration |
| `src/cpp/vectragate_core.hpp` | 1083 | Header-Only C++17/20 `alignas(64)` Engine & BLAKE2b-64 |
| `src/cpp/vectragate_cli.cpp` | 303 | Native C++17/20 CLI Executable Entrypoint |
| `src/vectragate/__init__.py` | 108 | Public Package Facade |
| `src/vectragate/models.py` | 443 | Layer 1 Immutable Domain Dataclasses & Enums |
| `src/vectragate/protocol.py` | 210 | Layer 2B Modbus TCP & MQTT v3.1.1 Wire Decoders |
| `src/vectragate/dag_engine.py` | 135 | Layer 2B Kahn Topological Sort & Bitwise DAG Engine |
| `src/vectragate/firewall.py` | 277 | Layer 2B Stateful Firewall, Breaker & BLAKE2b-64 Chain |
| `src/vectragate/intake_gate.py` | 404 | Layer 3 4-Stage JSON Boundary Gate & Quarantine |
| `src/vectragate/cpp_bridge.py` | 225 | Layer 3 Native C++17/20 Subprocess Bridge |
| `src/vectragate/exporters.py` | 386 | Layer 4 DuckDB 2.0 SIEM & CWE-1236 Excel `.xlsx` Exporter |
| `src/vectragate/cli_visualizer.py` | 224 | Layer 4 Pure-Stdlib Unicode/ASCII SIEM CLI Runner |
| `tests/_oracle.py` | 625 | Zero-Dependency Independent Verification Oracle |
| `tests/test_protocol_decoders.py` | 282 | Protocol Wire Decoder Unit Tests |
| `tests/test_dag_and_firewall.py` | 389 | DAG Engine, Breaker, Rate-Limiter & Hash-Chain Tests |
| `tests/test_intake_and_exporters.py` | 325 | Intake Gate, Exporters, DuckDB & C++ Parity Tests |
| `tests/test_property_hypothesis.py` | 152 | Hypothesis Property-Based & 1,000-Mutation Tamper Suite |
| `tests/test_architecture_fitness.py` | 471 | `FF-1`–`FF-9` Fitness Suite & 1,050-Seed Oracle Parity |
| `assets/architecture_pipeline.svg` | 111 | 4-Layer Architecture & 64-Byte Cache-Line Diagram |
| `assets/protocol_dag_interlock.svg` | 132 | Protocol Frame, DAG Interlock & Circuit Breaker Diagram |

# ADR.md — Architecture Decision Records for `VectraGate-Core (بَرْزَخ)`

All architectural decisions follow the formal trade-off methodology of **Codex #12 (Ousterhout — *Design It Twice*)** and **Codex #17 (Ford, Richards, Sadalage & Dehghani — *Software Architecture: The Hard Parts*)**.

---

## ADR-001: Fixed-Width 64-Bit Integer Algebra & Total Ban on IEEE 754 Floating-Point (`R0.1`)

- **Status:** Accepted
- **Context:** Industrial OT/ICS safety interlocks and SIEM audit logs evaluated across heterogeneous CPU/compiler stacks (`g++ -O3` x86-64 C++17/20 vs. CPython 3.12+) suffer non-deterministic rounding drift, `NaN`/`Infinity` poisoning, and associativity violations under IEEE 754 floating-point arithmetic (`(3.14 + 1e20) - 1e20 ≠ 3.14 + (1e20 - 1e20)` per `Codex #16 Sec. 2.4.5`).
- **Alternatives Considered:**
  - *Option A:* IEEE 754 `double` / Python `float` with epsilon tolerance (`abs(a - b) < 1e-9`).
  - *Option B:* Exact 64-bit signed/unsigned integers (`int64_t` / `uint64_t` in C++, `int` in Python) with floor division `//`, `ceil_div(n, d) = (n + d - 1) // d`, and bitwise shifts/masks, enforced mechanically by AST Fitness Function `FF-2`.
- **Decision:** Adopt **Option B**. All register values (`-32_768 ≤ reg_val ≤ 65_535`), sequence numbers (`seq_no ≥ 1`), and millisecond timestamps (`timestamp_ms ≥ 0`) are exact integers.
- **Consequences:**
  - **Pros:** `100%` bit-for-bit reproducibility between C++17/20 and Python; immune to `NaN` injection at the JSON boundary (`parse_float` raises `IntakeError`); single-cycle integer ALU execution.
  - **Cons:** Physical sensor quantities must be scaled to integer engineering units (e.g., tenths of a degree Celsius or millibars) prior to ingestion.

---

## ADR-002: Cache-Aligned Static `EngineArena` (`alignas(64)`) & Wait-Free SPSC Ring Buffer (`R0.2`)

- **Status:** Accepted
- **Context:** Dynamic heap allocation (`new`/`malloc`) in packet-processing hot paths introduces non-deterministic allocator lock contention, `16-byte` metadata cache pollution (`50%` L1d waste per `Codex #03 Law 4.2`), fragmentation, and Out-of-Memory (`OOM`) hazards prohibited by `NASA JPL Rule 3`.
- **Alternatives Considered:**
  - *Option A:* Node-based heap containers (`std::vector`, `std::unordered_map`, `std::shared_ptr`).
  - *Option B:* Pre-allocated fixed-capacity `alignas(64) struct EngineArena` (`MAX_REGISTERS = 256`, `MAX_DAG_NODES = 128`, `MAX_SOURCES = 64`) paired with an `alignas(64)` 256-slot Wait-Free Single-Producer Single-Consumer (`SPSC`) ring buffer with producer/consumer indices isolated on separate 64-byte cache lines (`Codex #03 Law 5.1` & `Codex #18 Ch. 7`).
- **Decision:** Adopt **Option B**.
- **Consequences:**
  - **Pros:** Zero post-init heap allocations (`FF-7`); zero `MESI RFO` false-sharing invalidation storms; deterministic L1/L2 cache residency.
  - **Cons:** Fixed upper bounds (`256` registers, `128` DAG nodes, `64` sources) must be sized at compile time.

---

## ADR-003: Kahn's Iterative Topological Sort & Branchless Trial-Write DAG Interlock (`R0.3`, `F4`)

- **Status:** Accepted
- **Context:** OT safety interlocks combine threshold comparators and combinational logic gates (`AND`, `OR`, `XOR`, `NOT`, `NAND`, `NOR`). Recursive DFS traversal violates `NASA Rule 1` (unbounded stack depth on malformed graphs), and mutating live registers before checking safety interlocks risks transient physical actuation hazards.
- **Alternatives Considered:**
  - *Option A:* Recursive depth-first evaluation with post-hoc register rollback on interlock failure.
  - *Option B:* **Kahn's Iterative In-Degree Topological Sort** at initialization (`0` recursion) + **Trial Write Evaluation** on a scratch register array (`scratch_regs[0..255]`) using branchless bitwise gate evaluation (`& 1`, `|`, `^`, `^ 1` per `Codex #18 Ch. 3`).
- **Decision:** Adopt **Option B**.
- **Consequences:**
  - **Pros:** Statically bounded stack and loop iterations; cyclic graphs are rejected deterministically (`EC-C`); live registers remain `100%` untouched when `VerdictCode.INTERLOCK_TRIPPED` fires.
  - **Cons:** Requires copying `256 × 8 = 2,048 bytes` (`32` cache lines) to `scratch_regs` on candidate write packets (~`15 ns` sequential L1d copy).

---

## ADR-004: Per-Source Kleppmann Fencing Tokens, Sliding-Window Rate Limiter & Nygard Circuit Breaker (`F5`)

- **Status:** Accepted
- **Context:** Compromised or malfunctioning PLCs can launch packet replay attacks, high-rate command floods, or repeated malformed frames (`CVE-2026-54410`, `CVE-2026-21888`, `CVE-2026-25627`).
- **Alternatives Considered:**
  - *Option A:* Stateless per-packet signature/protocol checking only.
  - *Option B:* Ordered 6-step per-source defense: (1) **Nygard 3-State Circuit Breaker** (`CLOSED → OPEN → HALF_OPEN`, `< 1 µs` fail-fast while `OPEN`), (2) **Kleppmann Monotonic Fencing Token** (`seq_no ≤ last_seq_no → REPLAY_ATTACK_BLOCKED`), (3) **Sliding-Window Rate Limiter**, (4) **Wire Decoder**, (5) **DAG Interlock**, and (6) **Violation Accounting**.
- **Decision:** Adopt **Option B**.
- **Consequences:**
  - **Pros:** Immediate `< 1 µs` perimeter shedding during active attacks; single-probe `HALF_OPEN` recovery after `cooldown_ms`; total immunity to replay reordering.
  - **Cons:** Requires maintaining bounded per-source state (`SourceSecurityState`) across packets.

---

## ADR-005: Multi-Block RFC 7693 `BLAKE2b-64` Audit Chain & `1,050`-Seed Differential Verification (`R0.4`, `R0.5`, `F6`)

- **Status:** Accepted
- **Context:** SIEM audit logs require tamper-evident cryptographic chaining across all verdicts, verified identically by both the C++17/20 native engine and Python core regardless of canonical pre-image length.
- **Alternatives Considered:**
  - *Option A:* Non-cryptographic `CRC32` / `FNV-1a` or single-block-only (`≤ 128B`) hashing.
  - *Option B:* Full multi-block **RFC 7693 `BLAKE2b-64`** (`digest_size = 8`, anchored at `GENESIS_HASH_U64 = 0x5645435452413236`) over the complete 9-field canonical pre-image, verified across `1,050` seeded instances (`50` fast + `1,000` deep) against both `vectragate_cli.exe` and `tests/_oracle.py` (`FF-9`).
- **Decision:** Adopt **Option B**.
- **Consequences:**
  - **Pros:** Cryptographic tamper resistance; zero truncation or length limit on canonical pre-images; `100%` cross-language bit-for-bit proof.
  - **Cons:** Requires implementing the full 12-round RFC 7693 compression loop in `src/cpp/vectragate_core.hpp`.

---

## ADR-006: OWASP 2026 `CWE-1236` NFKC Neutralization, Atomic `.tmp_` Persistence & `DuckDB 2.0` (`F8`)

- **Status:** Accepted
- **Context:** Exporting untrusted network identifiers or diagnostics to `.xlsx` spreadsheets exposes analysts to `CWE-1236` CSV/Excel Formula Injection (including Unicode compatibility fullwidth `＝` `U+FF1D` and leading-whitespace bypasses), while in-place file writes risk torn workbooks on crash (`Codex #11 OSTEP Crash Consistency`).
- **Alternatives Considered:**
  - *Option A:* Naive ASCII prefix check (`val.startswith(("=", "+", "-", "@"))`) and direct `wb.save(target_path)`.
  - *Option B:* Dual raw + `unicodedata.normalize("NFKC", val).lstrip()` check against all 9 triggers `("=", "+", "-", "@", "|", "%", "\t", "\r", "\n")`, explicit `cell.data_type = "s"`, atomic `.tmp_<name>.<pid>` + `os.fsync` + `os.replace` persistence, and in-memory `DuckDB 2.0` SQL analytical views.
- **Decision:** Adopt **Option B**.
- **Consequences:**
  - **Pros:** Defeats Unicode homoglyph and whitespace `CWE-1236` bypasses (`FF-6`); crash-atomic `.xlsx` output; sub-millisecond OLAP SQL telemetry via `DuckDB 2.0`.
  - **Cons:** Slight `fsync` I/O overhead during `.xlsx` export (confined strictly to Layer 3 control plane).

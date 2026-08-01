# Phase 0.5: Stall-Measurement Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A headless, CI-able harness that measures how long a desktop session actually stalls under memory pressure — so every later phase is judged on numbers instead of intuition.

**Architecture:** A small `rlm-probe` binary runs a fixed-interval sleep loop and records, per iteration, the drift between intended and actual wake time plus two decomposition signals (runqueue wait from `/proc/self/schedstat`, major faults from `/proc/self/stat`). Three probe instances run concurrently under different placements and modes; a runner script places them via `systemd-run --user`, drives a synthetic memory hog, samples PSI throughout, and emits one JSON report. A compare tool diffs two reports.

**Tech Stack:** Rust (new `harness/` crate producing `rlm-probe` and `rlm-harness` binaries), serde_json, systemd-run for cgroup placement, bash for the reproducer.

**Spec:** `docs/superpowers/specs/2026-07-31-roadmap.md` — Phase 0.5 section, plus the Phase 1 tradeoff it must measure.

## Global Constraints

- `cargo fmt && cargo clippy --workspace --all-targets -- -D warnings` clean before every commit; conventional commits.
- **NEVER add `Co-Authored-By` or any trailer to commit messages.**
- **Commit as soon as your gates are green.** Do not hold work uncommitted while waiting on any review — uncommitted work is this project's known loss vector.
- The probe must not allocate in its measurement loop (allocation under memory pressure is the thing being measured, not a thing the measurer may do).
- No dependency on rlm-core or the guard — the harness must be able to measure a machine with rlm not installed at all (that is the control arm).
- Every parser is a pure function with unit tests; anything needing systemd/cgroups is `#[ignore]`d with a reason.
- Probes and hogs must clean up after themselves even on failure — never leave a memory hog running.

---

### Task 1: `rlm-probe` core loop and pure parsers

**Files:**
- Create: `harness/Cargo.toml`, `harness/src/bin/rlm-probe.rs`, `harness/src/lib.rs`, `harness/src/proc_parse.rs`
- Modify: root `Cargo.toml` (add `harness` to `[workspace] members`)

**Interfaces:**
- Produces (later tasks depend on these):

```rust
// harness/src/proc_parse.rs — all pure, all unit-tested
/// Field 8 (0-indexed 7) of /proc/self/schedstat is time spent waiting on a
/// runqueue, in nanoseconds. Format: "<run_ns> <wait_ns> <timeslices>".
pub fn parse_schedstat_wait_ns(s: &str) -> Option<u64>;
/// Field 12 (1-indexed) of /proc/self/stat is majflt. The comm field may
/// contain spaces and parentheses — split after the LAST ')'.
pub fn parse_majflt(stat: &str) -> Option<u64>;

// harness/src/lib.rs
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Tick {
    pub t_ms: u64,          // ms since probe start
    pub drift_us: i64,      // actual_elapsed - intended_interval, microseconds
    pub wait_ns: u64,       // cumulative runqueue wait at this tick
    pub majflt: u64,        // cumulative major faults at this tick
}
```

- [ ] **Step 1: Write failing tests** in `proc_parse.rs`:

```rust
#[test]
fn schedstat_takes_second_field() {
    assert_eq!(parse_schedstat_wait_ns("12345 67890 42\n"), Some(67890));
    assert_eq!(parse_schedstat_wait_ns("1 2 3"), Some(2));
    assert_eq!(parse_schedstat_wait_ns("only_one_field"), None);
    assert_eq!(parse_schedstat_wait_ns(""), None);
}

#[test]
fn majflt_survives_parens_in_comm() {
    // comm can contain spaces AND parens: "(my (weird) proc)"
    let stat = "42 (my (weird) proc) S 1 42 42 0 -1 4194304 100 0 7 0 5 6 0 0 20 0 1 0 900";
    // After the last ')': fields are state(3) ppid(4) pgrp(5) session(6) tty(7)
    // tpgid(8) flags(9) minflt(10) cminflt(11) majflt(12) -> 7
    assert_eq!(parse_majflt(stat), Some(7));
}

#[test]
fn majflt_simple_comm() {
    let stat = "1 (systemd) S 0 1 1 0 -1 4194560 2000 100 3 0 10 20 0 0 20 0 1 0 5";
    assert_eq!(parse_majflt(stat), Some(3));
}

#[test]
fn majflt_malformed_is_none() {
    assert_eq!(parse_majflt("no parens here"), None);
    assert_eq!(parse_majflt("1 (x) S 1"), None); // too few fields
}
```

- [ ] **Step 2: Run `cargo test -p harness` — expect failure (crate/module missing).**
- [ ] **Step 3: Implement the parsers:**

```rust
pub fn parse_schedstat_wait_ns(s: &str) -> Option<u64> {
    s.split_whitespace().nth(1)?.parse().ok()
}

pub fn parse_majflt(stat: &str) -> Option<u64> {
    let after = &stat[stat.rfind(')')? + 1..];
    // After ')': state, ppid, pgrp, session, tty, tpgid, flags, minflt,
    // cminflt, majflt -> index 9 of this remainder.
    after.split_whitespace().nth(9)?.parse().ok()
}
```

- [ ] **Step 4: Implement the probe loop** in `rlm-probe.rs`. Requirements:
  - Args: `--interval-ms <u64>` (default 50), `--duration-s <u64>` (default 60), `--out <path>` (JSON-lines of `Tick`), `--label <string>`.
  - Pre-allocate the `Vec<Tick>` to `duration_s * 1000 / interval_ms + 16` **before** the loop; the loop must not allocate or format.
  - Use `std::time::Instant`; compute drift as `actual.as_micros() - intended.as_micros()` (i64, may be negative).
  - Read `/proc/self/schedstat` and `/proc/self/stat` each iteration into **reused** `String` buffers (`String::clear()` + `File::read_to_string`), so no allocation per tick.
  - Write all ticks to `--out` **after** the loop ends, one JSON object per line.
- [ ] **Step 5: Verify no per-tick allocation** — run `cargo build -p harness --release`, then run the probe for 5s and confirm from `/proc/<pid>/status` that `VmRSS` is stable across the run (record before/after in the commit message).
- [ ] **Step 6: fmt+clippy, commit** `feat(harness): rlm-probe sleep-loop with drift, runqueue-wait and majflt decomposition`

---

### Task 2: Probe modes — locked control and unlocked treatment

**Files:**
- Modify: `harness/src/bin/rlm-probe.rs`, `harness/src/lib.rs`

**Interfaces:**
- Consumes: Task 1's `Tick` and loop.
- Produces: `--mode locked|touch` CLI flag; `ProbeMode` in lib.rs.

Rationale (from the spec — state it in the module doc): an mlocked probe can never major-fault, so it cannot measure residency; an unlocked probe's drift conflates scheduling with faulting. One process cannot measure both, so the harness runs a **pair** and takes the difference.

- [ ] **Step 1: Implement `--mode locked`:**
  - Allocate a small working set (`--working-set-mb`, default 2), write one byte per 4096-byte page to pre-fault it.
  - `mlockall(MCL_CURRENT | MCL_FUTURE)` via `libc`; on `EPERM`/`ENOMEM` (RLIMIT_MEMLOCK too low), print a clear diagnostic naming `ulimit -l` and **exit non-zero** — a silently-unlocked "locked" probe would corrupt the whole comparison.
  - Record `mode: "locked"` and `mlock_ok: true` in the output header line.
- [ ] **Step 2: Implement `--mode touch`:**
  - Same working set, **not** locked. Each iteration, touch one byte per page across the whole working set, plus read a fixed 1 MB file-backed mapping (`--file <path>`, default: the probe binary itself via `/proc/self/exe`) to keep file pages in play.
  - No mlock.
- [ ] **Step 3: Write the header line** as the first line of `--out`: `{"label":..,"mode":..,"interval_ms":..,"working_set_mb":..,"mlock_ok":..,"slice":<from --slice-label>}`.
- [ ] **Step 4: Test** — run both modes for 5s each with no pressure; assert (manually, recorded in the report) that locked-mode `majflt` stays 0 and touch-mode drift is comparable when the machine is idle.
- [ ] **Step 5: fmt+clippy, commit** `feat(harness): locked-control and touch-treatment probe modes`

---

### Task 3: PSI sampler and integral

**Files:**
- Create: `harness/src/psi.rs`
- Modify: `harness/src/lib.rs`

**Interfaces:**

```rust
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PsiSample { pub t_ms: u64, pub some_avg10: f64, pub full_avg10: f64, pub some_total_us: u64, pub full_total_us: u64 }

/// Pure. Parses one /proc/pressure/<res> body.
pub fn parse_psi(body: &str) -> Option<(f64, f64, u64, u64)>; // some_avg10, full_avg10, some_total, full_total

/// Pure. PSI "integral" over a run = the delta of the kernel's own `total`
/// counters (microseconds of stall), which is exact — NOT a trapezoid of avg10
/// samples, which double-counts because avg10 is itself a decaying average.
pub fn stall_us(first: &PsiSample, last: &PsiSample) -> (u64, u64);
```

- [ ] **Step 1: Write failing tests:**

```rust
#[test]
fn psi_parses_some_and_full_with_totals() {
    let b = "some avg10=12.34 avg60=5.00 avg300=1.00 total=999999\n\
             full avg10=3.21 avg60=2.00 avg300=0.50 total=42424\n";
    assert_eq!(parse_psi(b), Some((12.34, 3.21, 999999, 42424)));
}

#[test]
fn psi_missing_full_defaults_zero() {
    let b = "some avg10=1.00 avg60=0.00 avg300=0.00 total=10\n";
    assert_eq!(parse_psi(b), Some((1.0, 0.0, 10, 0)));
}

#[test]
fn stall_us_is_counter_delta_not_average_integral() {
    let a = PsiSample { t_ms: 0, some_avg10: 0.0, full_avg10: 0.0, some_total_us: 1000, full_total_us: 100 };
    let b = PsiSample { t_ms: 60_000, some_avg10: 50.0, full_avg10: 10.0, some_total_us: 31_000, full_total_us: 5_100 };
    assert_eq!(stall_us(&a, &b), (30_000, 5_000));
}

#[test]
fn stall_us_tolerates_counter_reset() {
    // If the second sample is lower (shouldn't happen, but don't underflow).
    let a = PsiSample { t_ms: 0, some_avg10: 0.0, full_avg10: 0.0, some_total_us: 500, full_total_us: 50 };
    let b = PsiSample { t_ms: 1000, some_avg10: 0.0, full_avg10: 0.0, some_total_us: 10, full_total_us: 5 };
    assert_eq!(stall_us(&a, &b), (0, 0));
}
```

- [ ] **Step 2: Run — fail. Implement (`saturating_sub` for the deltas) — pass.**
- [ ] **Step 3: Add `--psi` mode to `rlm-probe`** that samples `/proc/pressure/memory` (and `/proc/pressure/io` when `--psi-io` is given) at `--interval-ms` and writes `PsiSample` JSON lines. Same no-allocation-in-loop discipline.
- [ ] **Step 4: fmt+clippy, commit** `feat(harness): PSI sampler with exact counter-delta stall integral`

---

### Task 4: Reproducer and runner

**Files:**
- Create: `harness/scripts/hog.sh`, `harness/src/bin/rlm-harness.rs`
- Create: `harness/README.md`

**Interfaces:** `rlm-harness --out-dir <dir> --duration-s <n> --hog-fraction <f>` produces `<dir>/report.json`.

The runner orchestrates one measurement run:

1. Preflight: refuse to run unless `/proc/pressure/memory` exists; **warn loudly and require `--i-know` if `MemTotal` > 12 GiB and `--hog-fraction` would exceed it** (protects the operator's own desktop).
2. Place three probes with `systemd-run --user`:
   - `session-locked` → `--slice=session.slice --mode locked`
   - `session-touch` → `--slice=session.slice --mode touch`
   - `app-touch` → default slice (app.slice) `--mode touch` — the only probe under Phase 1's dynamic cap, and therefore the only source of the foreground-throttling number.
   - Plus one `--psi` sampler (no slice preference).
3. Sleep `--baseline-s` (default 10) to collect a quiet baseline.
4. Run `hog.sh` — allocates `--hog-fraction` of `MemAvailable` in a `systemd-run --user --scope` unit, touching every page, then holds.
5. On completion **or any failure or signal**: kill the hog scope, stop all probe units, collect their JSON, write `report.json`.
6. `trap`/`Drop`-based cleanup is mandatory: a panicking runner must not leave a 6 GB hog resident.

`report.json` shape:

```json
{"schema":1,"host":{"mem_total_kb":0,"kernel":"","rlm_installed":false,"guard_enabled":false},
 "run":{"duration_s":0,"baseline_s":0,"hog_fraction":0.0},
 "probes":[{"label":"session-locked","mode":"locked","ticks":[]}],
 "psi":{"samples":[],"stall_some_us":0,"stall_full_us":0}}
```

- [ ] **Step 1: Write `hog.sh`** — `stress-ng` if present, else a pure-bash/`dd`-to-tmpfs fallback so the harness has no hard external dependency. Must respond to SIGTERM by freeing immediately.
- [ ] **Step 2: Implement the runner** with cleanup-on-drop and the preflight guard.
- [ ] **Step 3: `#[ignore]`d integration test** `harness_run_produces_report` that runs a 20s, tiny-fraction (0.05) run and asserts `report.json` parses, has 3 probes with non-empty ticks, and `stall_some_us > 0`.
- [ ] **Step 4: `harness/README.md`** — how to run, what each probe measures, the observer-effect note (probes draw from the same `memory.min` budget they measure), and an explicit warning that this induces real memory pressure and should not be run on a machine doing work that matters.
- [ ] **Step 5: fmt+clippy, commit** `feat(harness): three-probe runner, hog reproducer, JSON report`

---

### Task 5: Summary and comparison tool

**Files:**
- Create: `harness/src/report.rs`
- Modify: `harness/src/bin/rlm-harness.rs` (add `summarize` and `compare` subcommands)

**Interfaces:**

```rust
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ProbeSummary {
    pub label: String,
    pub p50_drift_us: i64, pub p95_drift_us: i64, pub p99_drift_us: i64, pub max_drift_us: i64,
    pub stalls_over_200ms: usize,   // the roadmap's "perceptible stall" count
    pub total_wait_ms: u64,         // schedstat delta over the run
    pub total_majflt: u64,          // majflt delta over the run
}
/// Pure. Percentiles by nearest-rank on a sorted copy; empty input -> all zeros.
pub fn summarize(label: &str, ticks: &[Tick]) -> ProbeSummary;
/// Pure. The decomposition the spec asks for: (unlocked - locked) drift isolates
/// the memory-induced component; schedstat isolates scheduling.
pub fn decompose(locked: &ProbeSummary, touch: &ProbeSummary) -> Decomposition;
```

- [ ] **Step 1: Write failing tests** for `summarize` (known tick vector → known p50/p95/max, correct `stalls_over_200ms` boundary at exactly 200_000 µs — assert the boundary is exclusive, i.e. exactly 200ms does NOT count) and for `decompose` (locked p95 subtracted from touch p95; negative results clamp to 0 with a `suspect: true` flag, since a locked probe stalling more than an unlocked one means the run is invalid).
- [ ] **Step 2: Run — fail. Implement — pass.**
- [ ] **Step 3: `summarize` subcommand** prints a table for one report; `compare A B` prints per-probe deltas and a verdict line (`stall_some_us` delta, p95 drift delta, `stalls_over_200ms` delta).
- [ ] **Step 4: fmt+clippy, commit** `feat(harness): percentile summary, locked/touch decomposition, run comparison`

---

## Self-Review

- **Spec coverage:** probe pair with locked control + unlocked treatment (T1/T2); third `app.slice` probe for the foreground-throttling number (T4); drift + schedstat + majflt decomposition (T1/T5); PSI integral as exact counter delta (T3); synthetic hog reproducer (T4); observer-effect documented (T4 README); comparison across arms for Phase 6 growth (T5). Deferred by spec: input-to-photon latency (Phase 6), the full three-arm matrix (Phase 6).
- **Type consistency:** `Tick` defined in T1 is consumed unchanged by T5's `summarize`; `PsiSample` from T3 is embedded in T4's report; `ProbeSummary` from T5 is the only summary type.
- **Placeholder scan:** none — every step has code or an exact command.

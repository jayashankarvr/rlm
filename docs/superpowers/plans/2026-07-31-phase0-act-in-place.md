# Phase 0: Act-in-Place Freeze Guard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The guard freezes/caps the cgroup a process already lives in (scope or rlm rule group) instead of migrating single PIDs into `guard-<pid>` cgroups — with a pure `resolve_target`, a write-ahead restore journal, and a D-Bus effector.

**Architecture:** New pure modules (`resolve`, `journal` guards, cgroupfs parsers) feed a reworked `Action`/`PolicyEngine` that keys interventions by resolved cgroup. The `Effector` journals before mutating, acts via systemd D-Bus (`FreezeUnit`/`ThawUnit`/`SetUnitProperties`) with raw-write fallback, and restores mechanism-independently. `guard-<pid>` migration, guard `unlimit` usage, and `rules.rs` `guard_held` plumbing are deleted.

**Tech Stack:** Rust workspace (crates: `common`, `rlm-core`, `guard`, `cli`, `gtk-gui`), zbus (blocking, no tokio), serde/serde_json, cgroups v2, systemd user manager D-Bus API.

**Spec:** `docs/superpowers/specs/2026-07-31-roadmap.md` (Phase 0 section — frozen).

## Global Constraints

- `cargo fmt && cargo clippy` clean before every commit; conventional commits (`feat:`, `fix:`, `refactor:`, `test:`).
- **NEVER add `Co-Authored-By` or any trailer to commit messages.**
- No tokio; zbus must run blocking (`zbus = { version = "5", default-features = false, features = ["blocking-api"] }` — if the feature name differs on the current zbus 5.x, use whatever feature enables `zbus::blocking`; verify with `cargo build`).
- Time is injected (`now_ms`); pure modules make **no** syscalls and read **no** clock.
- Never kill: no kill action exists anywhere.
- D-Bus calls in the storm path use a short timeout (2s) and fall back to raw cgroupfs writes.
- Journal is write-ahead: append + fsync **before** the mutation it records.
- Restore (thaw) is mechanism-independent: `ThawUnit` best-effort, then raw `cgroup.freeze=0` unconditionally.
- All tests that need root/delegation are `#[ignore]`d with a reason string.

---

### Task 1: Pure target resolution (`resolve.rs`)

**Files:**
- Create: `rlm-core/src/guard/resolve.rs`
- Modify: `rlm-core/src/guard/mod.rs` (add `pub mod resolve;`)

**Interfaces:**
- Consumes: nothing (pure, leaf module).
- Produces (later tasks depend on these exact shapes):

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict { Freeze, CapOnly }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage { Full, Partial }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism { Unit, Raw }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// cgroupfs path relative to /sys/fs/cgroup, e.g.
    /// "/user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox-12.scope"
    pub cgroup: String,
    /// systemd unit name (the final path component) when mechanism == Unit.
    pub unit: Option<String>,
    pub mechanism: Mechanism,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    pub cgroup: String,
    pub unit: Option<String>,
    pub verdict: Verdict,
    pub coverage: Coverage,
    pub mechanism: Mechanism,
}

/// Pure. `victim_cgroup` is the "0::" path from /proc/<pid>/cgroup.
/// `rlm_base` is CgroupManager::base_path() minus the "/sys/fs/cgroup" prefix.
pub fn candidate_target(victim_cgroup: &str, uid: u32, rlm_base: &str) -> Option<Candidate>;

/// Pure. `member_exes` = exe basenames of every process in the candidate cgroup.
pub fn finalize(
    c: Candidate,
    member_exes: &[String],
    protect: &std::collections::HashSet<String>,
) -> Resolution;
```

Semantics (from the spec, verbatim):
- Permitted roots: strictly below `/user.slice/user-{uid}.slice/user@{uid}.service/app.slice/` (Unit mechanism) OR strictly below `rlm_base/` (Raw mechanism). Anything else → `None`.
- Under app.slice: the target is the path up to and including the **deepest** component ending in `.scope` or `.service`; `unit` = that component. No such component → `None`.
- Under rlm_base: the target is `rlm_base/<first child component>`; `unit = None`, `Mechanism::Raw`.
- `finalize`: any member exe in `protect` → `Verdict::CapOnly` + `Coverage::Partial` (safety over coverage; never freeze a protected process's cgroup). Otherwise `Freeze` + `Full`.

- [x] **Step 1: Write failing tests** in `resolve.rs` `#[cfg(test)]`:

```rust
const RLM: &str = "/user.slice/user-1000.slice/user@1000.service/rlm";

#[test]
fn scope_under_app_slice_resolves_to_unit() {
    let c = candidate_target(
        "/user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox-12.scope",
        1000, RLM,
    ).unwrap();
    assert_eq!(c.cgroup, "/user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox-12.scope");
    assert_eq!(c.unit.as_deref(), Some("app-firefox-12.scope"));
    assert_eq!(c.mechanism, Mechanism::Unit);
}

#[test]
fn process_deep_inside_scope_resolves_to_scope_boundary() {
    // Firefox content process nested below the scope.
    let c = candidate_target(
        "/user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox-12.scope/child",
        1000, RLM,
    ).unwrap();
    assert_eq!(c.unit.as_deref(), Some("app-firefox-12.scope"));
}

#[test]
fn deepest_unit_wins_for_nested_service_paths() {
    // app.slice/app-x.slice/foo.service style nesting: pick foo.service, not a slice.
    let c = candidate_target(
        "/user.slice/user-1000.slice/user@1000.service/app.slice/app-x.slice/foo.service/leaf",
        1000, RLM,
    ).unwrap();
    assert_eq!(c.unit.as_deref(), Some("foo.service"));
    assert!(c.cgroup.ends_with("app.slice/app-x.slice/foo.service"));
}

#[test]
fn rlm_rule_cgroup_resolves_raw() {
    let c = candidate_target(&format!("{RLM}/app-firefox"), 1000, RLM).unwrap();
    assert_eq!(c.cgroup, format!("{RLM}/app-firefox"));
    assert_eq!(c.unit, None);
    assert_eq!(c.mechanism, Mechanism::Raw);
}

#[test]
fn session_slice_is_outside_permitted_roots() {
    assert_eq!(candidate_target(
        "/user.slice/user-1000.slice/user@1000.service/session.slice/org.gnome.Shell@ubuntu.service",
        1000, RLM,
    ), None);
}

#[test]
fn rlm_base_itself_is_not_a_target() {
    // "strictly below": the base dir itself must not resolve.
    assert_eq!(candidate_target(RLM, 1000, RLM), None);
}

#[test]
fn app_slice_without_unit_component_is_none() {
    assert_eq!(candidate_target(
        "/user.slice/user-1000.slice/user@1000.service/app.slice", 1000, RLM,
    ), None);
}

#[test]
fn other_uid_path_is_none() {
    assert_eq!(candidate_target(
        "/user.slice/user-1001.slice/user@1001.service/app.slice/app-x-1.scope", 1000, RLM,
    ), None);
}

#[test]
fn finalize_unprotected_is_freeze_full() {
    let c = candidate_target(
        "/user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox-12.scope",
        1000, RLM,
    ).unwrap();
    let protect: HashSet<String> = ["bash".to_string()].into();
    let r = finalize(c, &["firefox".into(), "Isolated Web Co".into()], &protect);
    assert_eq!(r.verdict, Verdict::Freeze);
    assert_eq!(r.coverage, Coverage::Full);
}

#[test]
fn finalize_protected_member_degrades_to_caponly_partial() {
    // alacritty case: shell shares the leaf with the runaway script.
    let c = candidate_target(
        "/user.slice/user-1000.slice/user@1000.service/app.slice/app-alacritty-9.scope",
        1000, RLM,
    ).unwrap();
    let protect: HashSet<String> = ["zsh".to_string()].into();
    let r = finalize(c, &["zsh".into(), "python3".into()], &protect);
    assert_eq!(r.verdict, Verdict::CapOnly);
    assert_eq!(r.coverage, Coverage::Partial);
}
```

- [x] **Step 2: Run `cargo test -p rlm-core resolve` — expect compile failure (module missing).**
- [x] **Step 3: Implement:**

```rust
pub fn candidate_target(victim_cgroup: &str, uid: u32, rlm_base: &str) -> Option<Candidate> {
    let app_root = format!("/user.slice/user-{uid}.slice/user@{uid}.service/app.slice/");
    if let Some(rest) = victim_cgroup.strip_prefix(&app_root) {
        // Deepest component ending in .scope/.service wins.
        let comps: Vec<&str> = rest.split('/').filter(|c| !c.is_empty()).collect();
        let unit_idx = comps.iter().rposition(|c| c.ends_with(".scope") || c.ends_with(".service"))?;
        let unit = comps[unit_idx].to_string();
        let cgroup = format!("{app_root}{}", comps[..=unit_idx].join("/"));
        return Some(Candidate { cgroup, unit: Some(unit), mechanism: Mechanism::Unit });
    }
    let rlm_root = format!("{}/", rlm_base.trim_end_matches('/'));
    if let Some(rest) = victim_cgroup.strip_prefix(&rlm_root) {
        let first = rest.split('/').find(|c| !c.is_empty())?;
        return Some(Candidate {
            cgroup: format!("{rlm_root}{first}"),
            unit: None,
            mechanism: Mechanism::Raw,
        });
    }
    None
}

pub fn finalize(c: Candidate, member_exes: &[String], protect: &HashSet<String>) -> Resolution {
    let protected = member_exes.iter().any(|e| protect.contains(e));
    let (verdict, coverage) = if protected {
        (Verdict::CapOnly, Coverage::Partial)
    } else {
        (Verdict::Freeze, Coverage::Full)
    };
    Resolution { cgroup: c.cgroup, unit: c.unit, verdict, coverage, mechanism: c.mechanism }
}
```

- [x] **Step 4: `cargo test -p rlm-core resolve` — all pass. `cargo fmt && cargo clippy`.**
- [x] **Step 5: Commit** `feat(guard): pure resolve_target — permitted roots, verdict, coverage, mechanism`

---

### Task 2: cgroupfs read/write helpers (`cgfs.rs`)

**Files:**
- Create: `rlm-core/src/guard/cgfs.rs`
- Modify: `rlm-core/src/guard/mod.rs` (add `pub mod cgfs;`)

**Interfaces:**
- Produces:

```rust
/// All paths are relative to /sys/fs/cgroup (same convention as Resolution.cgroup).
pub fn abs(cg: &str) -> PathBuf;                      // "/sys/fs/cgroup" + cg
pub fn read_frozen(cg: &str) -> Option<bool>;         // cgroup.events "frozen 1"
pub fn write_freeze(cg: &str, on: bool) -> common::Result<()>;
pub fn read_high(cg: &str) -> Option<String>;         // memory.high verbatim, trimmed ("max" or bytes)
pub fn write_high(cg: &str, val: &str) -> common::Result<()>;
pub fn anon_swap_bytes(cg: &str) -> Option<u64>;      // memory.stat anon + memory.swap.current
pub fn dir_inode(cg: &str) -> Option<u64>;            // st_ino of the cgroup dir
pub fn pids_in(cg: &str) -> Vec<u32>;                 // cgroup.procs
pub fn exe_basename(pid: u32) -> Option<String>;      // file_name of readlink /proc/<pid>/exe
pub fn boot_id() -> String;                           // /proc/sys/kernel/random/boot_id, trimmed; "" on failure
// Pure, tested parsers:
pub fn parse_frozen(events: &str) -> Option<bool>;
pub fn parse_anon(stat: &str) -> Option<u64>;
```

- [x] **Step 1: Write failing tests for the pure parsers:**

```rust
#[test]
fn parse_frozen_reads_events() {
    assert_eq!(parse_frozen("populated 1\nfrozen 0\n"), Some(false));
    assert_eq!(parse_frozen("populated 1\nfrozen 1\n"), Some(true));
    assert_eq!(parse_frozen("populated 1\n"), None);
}

#[test]
fn parse_anon_reads_memory_stat() {
    let stat = "anon 1073741824\nfile 536870912\nkernel 1000\n";
    assert_eq!(parse_anon(stat), Some(1_073_741_824));
    assert_eq!(parse_anon("file 5\n"), None);
}
```

- [x] **Step 2: Run — compile failure.**
- [x] **Step 3: Implement.** IO functions are thin wrappers (`fs::read_to_string(abs(cg).join("cgroup.events"))` etc.); `anon_swap_bytes` = `parse_anon(memory.stat)? + memory.swap.current.trim().parse().unwrap_or(0)`; `write_*` map io errors through the crate's existing error type (see `cgroup.rs` for the pattern — `RlmError::CgroupWrite` or nearest equivalent); `dir_inode` uses `fs::metadata(abs(cg)).ok()?.ino()` (`use std::os::unix::fs::MetadataExt`).

```rust
pub fn parse_frozen(events: &str) -> Option<bool> {
    events.lines().find_map(|l| {
        let rest = l.strip_prefix("frozen ")?;
        Some(rest.trim() == "1")
    })
}

pub fn parse_anon(stat: &str) -> Option<u64> {
    stat.lines().find_map(|l| l.strip_prefix("anon ")?.trim().parse().ok())
}
```

- [x] **Step 4: `cargo test -p rlm-core cgfs` — pass. fmt+clippy.**
- [x] **Step 5: Commit** `feat(guard): cgroupfs helpers — frozen state, memory.high, anon+swap, inode, boot id`

---

### Task 3: Write-ahead restore journal (`journal.rs`)

**Files:**
- Create: `rlm-core/src/guard/journal.rs`
- Modify: `rlm-core/src/guard/mod.rs`, `rlm-core/Cargo.toml` (add `serde.workspace = true`, `serde_json = "1"`; dev-dep `tempfile = "3"`)

**Interfaces:**
- Consumes: `cgfs::boot_id()` (passed in by caller, not called inside — keeps the module testable).
- Produces:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JournalAction { Freeze, Cap }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    pub cgroup: String,           // relative cgroupfs path (Resolution.cgroup)
    pub inode: u64,               // dir inode at act time
    pub unit: Option<String>,
    pub action: JournalAction,
    pub prev_high: Option<String>, // Cap only: memory.high before we touched it
    pub our_high: Option<String>,  // Cap only: the value we wrote
}

pub struct Journal { path: PathBuf, boot_id: String }

impl Journal {
    /// Opens (creating parent dirs). If the file's header boot_id differs from
    /// `boot_id`, the file is truncated (no cgroup state survives reboot).
    pub fn open(path: PathBuf, boot_id: String) -> common::Result<Self>;
    /// Write-ahead: appends one JSON line and fsyncs BEFORE returning.
    pub fn append(&self, e: &JournalEntry) -> common::Result<()>;
    /// All live entries (current boot).
    pub fn entries(&self) -> Vec<JournalEntry>;
    /// Remove all entries for `cgroup` (atomic rewrite: temp file + rename + fsync).
    pub fn remove(&self, cgroup: &str) -> common::Result<()>;
    /// Truncate to header only (clean shutdown compaction).
    pub fn clear(&self) -> common::Result<()>;
}

/// Pure restore guard: should this entry's memory.high be restored?
/// true iff inode matches AND (for Cap) current memory.high == our_high.
pub fn should_restore(e: &JournalEntry, current_inode: Option<u64>, current_high: Option<&str>) -> bool;
```

File format: line 1 `{"boot_id":"<id>"}`, then one `JournalEntry` JSON per line.

- [ ] **Step 1: Write failing tests** (use `tempfile::tempdir()`):

```rust
fn entry(cg: &str) -> JournalEntry {
    JournalEntry { cgroup: cg.into(), inode: 42, unit: None,
        action: JournalAction::Cap,
        prev_high: Some("max".into()), our_high: Some("1000000".into()) }
}

#[test]
fn append_then_entries_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let j = Journal::open(dir.path().join("j.jsonl"), "boot-a".into()).unwrap();
    j.append(&entry("/x/a")).unwrap();
    j.append(&entry("/x/b")).unwrap();
    assert_eq!(j.entries().len(), 2);
    assert_eq!(j.entries()[0].cgroup, "/x/a");
}

#[test]
fn stale_boot_id_truncates() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("j.jsonl");
    let j = Journal::open(p.clone(), "boot-a".into()).unwrap();
    j.append(&entry("/x/a")).unwrap();
    drop(j);
    let j2 = Journal::open(p, "boot-b".into()).unwrap();
    assert!(j2.entries().is_empty(), "prior-boot entries must be discarded");
}

#[test]
fn remove_deletes_only_matching_cgroup() {
    let dir = tempfile::tempdir().unwrap();
    let j = Journal::open(dir.path().join("j.jsonl"), "b".into()).unwrap();
    j.append(&entry("/x/a")).unwrap();
    j.append(&entry("/x/b")).unwrap();
    j.remove("/x/a").unwrap();
    let e = j.entries();
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].cgroup, "/x/b");
}

#[test]
fn clear_leaves_header_only() {
    let dir = tempfile::tempdir().unwrap();
    let j = Journal::open(dir.path().join("j.jsonl"), "b".into()).unwrap();
    j.append(&entry("/x/a")).unwrap();
    j.clear().unwrap();
    assert!(j.entries().is_empty());
}

#[test]
fn corrupt_lines_are_skipped_not_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("j.jsonl");
    let j = Journal::open(p.clone(), "b".into()).unwrap();
    j.append(&entry("/x/a")).unwrap();
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
    writeln!(f, "{{garbage").unwrap();
    assert_eq!(j.entries().len(), 1);
}

#[test]
fn should_restore_guards() {
    let e = entry("/x/a"); // inode 42, our_high "1000000"
    assert!(should_restore(&e, Some(42), Some("1000000")));
    assert!(!should_restore(&e, Some(43), Some("1000000")), "inode mismatch → skip");
    assert!(!should_restore(&e, None, Some("1000000")), "cgroup gone → skip");
    assert!(!should_restore(&e, Some(42), Some("999")), "someone changed high → skip");
    let f = JournalEntry { action: JournalAction::Freeze, prev_high: None, our_high: None, ..e };
    assert!(should_restore(&f, Some(42), None), "freeze entries only need inode");
}
```

- [ ] **Step 2: Run — compile failure.**
- [ ] **Step 3: Implement.** `append`: `OpenOptions::new().append(true)`, `serde_json::to_string`, `writeln!`, then `f.sync_data()?` before `Ok(())`. `open`: read first line, compare boot_id, on mismatch/absence write fresh header + `sync_data`. `remove`/`clear`: write temp file in same dir, `sync_data`, `fs::rename`, fsync parent dir best-effort. `should_restore`:

```rust
pub fn should_restore(e: &JournalEntry, current_inode: Option<u64>, current_high: Option<&str>) -> bool {
    if current_inode != Some(e.inode) { return false; }
    match e.action {
        JournalAction::Freeze => true,
        JournalAction::Cap => e.our_high.as_deref() == current_high,
    }
}
```

- [ ] **Step 4: `cargo test -p rlm-core journal` — pass. fmt+clippy.**
- [ ] **Step 5: Commit** `feat(guard): write-ahead restore journal with boot-id, inode, and value guards`

---

### Task 4: systemd D-Bus client (`systemd.rs`)

**Files:**
- Create: `rlm-core/src/guard/systemd.rs`
- Modify: `rlm-core/src/guard/mod.rs`, `rlm-core/Cargo.toml` (add zbus per Global Constraints)

**Interfaces:**
- Produces:

```rust
pub struct SystemdUser { conn: zbus::blocking::Connection }

impl SystemdUser {
    /// Connect to the session bus at daemon startup. None if unavailable
    /// (headless, no bus) — callers then use Raw everywhere.
    pub fn connect() -> Option<Self>;
    /// FreezeUnit(name). Err on failure OR timeout — caller falls back to raw.
    pub fn freeze_unit(&self, unit: &str, timeout: Duration) -> common::Result<()>;
    pub fn thaw_unit(&self, unit: &str, timeout: Duration) -> common::Result<()>;
    /// SetUnitProperties(name, runtime=true, [("MemoryHigh", u64)]).
    /// `bytes = u64::MAX` means "max" (systemd's infinity convention).
    pub fn set_memory_high(&self, unit: &str, bytes: u64, timeout: Duration) -> common::Result<()>;
}
```

Implementation notes for the engineer:
- Destination `org.freedesktop.systemd1`, path `/org/freedesktop/systemd1`, interface `org.freedesktop.systemd1.Manager`.
- zbus's blocking call has its own default method timeout (25s) — too long for the storm path. Enforce ours by running the call on a spawned thread and waiting on an `mpsc::Receiver` with `recv_timeout(timeout)`. On timeout return `Err` immediately (the thread finishes in the background and is detached — bounded leak, acceptable and documented in a comment).
- The connection is created once in `connect()` (pre-storm) and reused. `Connection::session()` blocking variant.
- `set_memory_high` body: `conn.call_method(Some("org.freedesktop.systemd1"), "/org/freedesktop/systemd1", Some("org.freedesktop.systemd1.Manager"), "SetUnitProperties", &(unit, true, vec![("MemoryHigh", zbus::zvariant::Value::from(bytes))]))` — exact zvariant signature is `(sba(sv))`; the implementer should confirm against zbus docs/compile errors.

- [ ] **Step 1: Write the one pure test** (timeout wrapper) plus an `#[ignore]` live test:

```rust
#[test]
#[ignore = "requires a session bus and a running user unit; run manually"]
fn freeze_thaw_transient_unit_roundtrip() {
    // systemd-run --user --unit=rlm-dbus-test sleep 30 must be running.
    let s = SystemdUser::connect().expect("session bus");
    s.freeze_unit("rlm-dbus-test.service", Duration::from_secs(2)).expect("freeze");
    s.thaw_unit("rlm-dbus-test.service", Duration::from_secs(2)).expect("thaw");
}
```

- [ ] **Step 2: Implement `SystemdUser` as specified. `cargo build -p rlm-core` clean.**
- [ ] **Step 3: Manual verification (once, by the reviewer):** `systemd-run --user --unit=rlm-dbus-test sleep 30`, then `cargo test -p rlm-core --ignored freeze_thaw_transient_unit_roundtrip`. Confirm via `systemctl --user status rlm-dbus-test` that the unit froze/thawed.
- [ ] **Step 4: fmt+clippy. Commit** `feat(guard): blocking systemd user-bus client with hard call timeouts`

---

### Task 5: Types + policy engine rework (act on resolutions)

**Files:**
- Modify: `rlm-core/src/guard/types.rs`, `rlm-core/src/guard/policy.rs`

**Interfaces:**
- Consumes: `resolve::{Resolution, Verdict, Coverage}` (Task 1).
- Produces (Effector and daemon depend on these):

```rust
// types.rs
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,
    pub rss_kb: u64,
    /// Where and how the guard may act for this process. None = not actionable
    /// (outside permitted roots) — the engine must skip it.
    pub resolution: Option<Resolution>,
}

pub enum Action {
    Notify  { message: String },
    Freeze  { res: Resolution, name: String },
    Thaw    { res: Resolution },
    Cap     { res: Resolution, name: String },
    LiftCap { res: Resolution },
}
// Intervention unchanged in shape, but the engine keys state by cgroup path.
```

Engine changes (policy.rs):
- `interventions: HashMap<String, (Intervention, Resolution)>` keyed by `Resolution.cgroup`; `last_freeze_ms: HashMap<String, u64>` likewise.
- `interventions()` returns `Vec<(String, Intervention)>` sorted by cgroup path. **Callers change:** `guard status` in the CLI (Task 8).
- Victim selection: same highest-`rss_kb` filter, plus `p.resolution.is_some()`, plus resolved cgroup not already under intervention/thawed-this-tick. Dead-cgroup pruning: an intervention whose cgroup no longer appears among `procs` resolutions IS still pruned via LiftCap (the effector's LiftCap tolerates a missing cgroup).
- `Verdict::CapOnly` → emit `Cap`, never `Freeze`, regardless of cooldown state.
- **Partial-coverage gate shortening (spec):** add field `last_action_partial: bool`. The escalation gate uses `gate_ms = if self.last_action_partial { 0 } else { freeze_hold_ms }` — after acting with `Coverage::Partial`, the gate is open again on the next tick.

- [ ] **Step 1: Update existing policy tests to build `ProcInfo` with resolutions** (test helper below) and add the two new behaviors:

```rust
fn res(cg: &str) -> Resolution {
    Resolution { cgroup: cg.into(), unit: Some(format!("{}.scope", cg.rsplit('/').next().unwrap())),
        verdict: Verdict::Freeze, coverage: Coverage::Full, mechanism: Mechanism::Unit }
}
fn proc_at(pid: u32, name: &str, rss_mb: u64, cg: &str) -> ProcInfo {
    ProcInfo { pid, name: name.into(), rss_kb: rss_mb * 1024, resolution: Some(res(cg)) }
}

#[test]
fn caponly_verdict_never_freezes() {
    let mut e = PolicyEngine::new(cfg());
    let mut p = proc_at(2, "script", 4000, "/app.slice/app-alacritty-9.scope");
    let r = p.resolution.as_mut().unwrap();
    r.verdict = Verdict::CapOnly;
    r.coverage = Coverage::Partial;
    let a = e.tick(0, high(), &[p]);
    assert!(freeze_targets(&a).is_empty(), "CapOnly must not freeze: {a:?}");
    assert!(has_cap_target(&a, "/app.slice/app-alacritty-9.scope"));
}

#[test]
fn partial_coverage_shortens_escalation_gate() {
    let mut e = PolicyEngine::new(cfg());
    let mut p1 = proc_at(1, "script", 4000, "/app.slice/a.scope");
    { let r = p1.resolution.as_mut().unwrap(); r.verdict = Verdict::CapOnly; r.coverage = Coverage::Partial; }
    let p2 = proc_at(2, "hog", 3000, "/app.slice/b.scope");
    // Partial action at t=0...
    let a0 = e.tick(0, high(), &[p1.clone(), p2.clone()]);
    assert!(has_cap_target(&a0, "/app.slice/a.scope"));
    // ...gate must already be open on the very next tick (1s later, < freeze_hold).
    let a1 = e.tick(1_000, high(), &[p1, p2]);
    assert!(has_freeze_target(&a1, "/app.slice/b.scope"),
        "gate should be open after Partial: {a1:?}");
}

#[test]
fn unresolvable_process_is_never_selected() {
    let mut e = PolicyEngine::new(cfg());
    let p = ProcInfo { pid: 1, name: "stray".into(), rss_kb: 4_000_000, resolution: None };
    assert!(e.tick(0, high(), &[p]).is_empty());
}

#[test]
fn two_pids_same_scope_yield_one_intervention() {
    let mut e = PolicyEngine::new(cfg());
    let procs = vec![
        proc_at(10, "firefox", 4000, "/app.slice/app-firefox-1.scope"),
        proc_at(11, "Isolated Web Co", 3000, "/app.slice/app-firefox-1.scope"),
    ];
    let a = e.tick(0, high(), &procs);
    assert_eq!(freeze_targets(&a).len(), 1, "one freeze for the shared scope: {a:?}");
}
```

(Helpers `freeze_targets`/`has_cap_target`/`has_freeze_target` mirror the old pid-based ones but match on `res.cgroup`.)

- [ ] **Step 2: Run — compile failures across policy tests. Mechanically migrate every existing test** (each `proc(pid, name, rss)` becomes `proc_at(pid, name, rss, "/app.slice/app-<name>-<pid>.scope")` so distinct pids keep distinct targets and every existing behavioral assertion — hysteresis, cooldown-cap, calm-hold lift, gate, dead-prune, notify — is preserved against cgroup-keyed state).
- [ ] **Step 3: Implement the engine changes. All policy tests pass.**
- [ ] **Step 4: fmt+clippy. Commit** `feat(guard): policy engine acts on resolved cgroups — CapOnly verdicts, Partial gate shortening`

---

### Task 6: Effector rework — act in place, journal, D-Bus with fallback

**Files:**
- Modify: `rlm-core/src/guard/effector.rs`, `rlm-core/src/guard/mod.rs`

**Interfaces:**
- Consumes: Tasks 1–5 (`Resolution`, `cgfs`, `Journal`, `should_restore`, `SystemdUser`, new `Action`).
- Produces:

```rust
pub struct Effector<'a> {
    manager: &'a CgroupManager,       // kept only for legacy sweep
    journal: &'a Journal,
    systemd: Option<&'a SystemdUser>,
}
impl<'a> Effector<'a> {
    pub fn new(manager: &'a CgroupManager, journal: &'a Journal, systemd: Option<&'a SystemdUser>) -> Self;
    pub fn apply(&self, action: &Action) -> common::Result<()>;
    /// Startup: legacy guard-<pid> sweep (one release, upgrade path), then journal replay.
    pub fn sweep_leftovers(&self) -> common::Result<()>;
    /// Shutdown: undo every live journal entry, then clear the journal.
    pub fn undo_all(&self) -> common::Result<()>;
}
```

Behavior (each point is spec, verbatim):
- `Freeze`: `journal.append(Freeze entry with dir_inode)` + fsync **before** acting; then `FreezeUnit(unit, 2s)` if `mechanism==Unit && systemd.is_some()`, on Err/timeout fall back to `cgfs::write_freeze(cg, true)`. Raw mechanism goes straight to the raw write.
- `Thaw` (mechanism-independent): `ThawUnit` best-effort (if unit+bus), then `cgfs::write_freeze(cg, false)` **unconditionally**; then `journal.remove(cg)`.
- `Cap`: `prev_high = cgfs::read_high(cg)`; `our_high = max(anon_swap_bytes(cg) * 9 / 10, MIN_CAP_BYTES)` (fallback `MIN_CAP_BYTES` if unreadable) as a decimal string; journal-append (Cap, prev+our) **before** writing; write via `set_memory_high` (unit) with raw `write_high` fallback; Raw mechanism raw-writes.
- `LiftCap`: restore `prev_high` **only if** `should_restore(entry, cgfs::dir_inode(cg), cgfs::read_high(cg).as_deref())`; restore raw-writes `prev_high` (and additionally `set_memory_high(unit, u64::MAX)` best-effort when the entry has a unit, so systemd's runtime property doesn't linger); then `journal.remove(cg)`. Missing cgroup → just `journal.remove` (dead-cgroup prune path).
- `sweep_leftovers`: `manager.sweep_guard_leftovers()` first (legacy, logged, non-fatal), then for each `journal.entries()`: thaw mechanism-independently; for Cap entries restore per `should_restore`; log skips; finally `journal.clear()`.
- `undo_all`: identical replay over live entries (without the legacy sweep), then `clear`.
- `Notify`: unchanged (`notify-send`, best-effort — replacement is Phase 4).

- [ ] **Step 1: Extract the journal-replay decision into a pure function and test it:**

```rust
/// Pure: what to do for one journal entry at restore time.
#[derive(Debug, PartialEq, Eq)]
pub enum RestoreStep { ThawOnly, ThawAndRestoreHigh { to: String }, SkipRemove }
pub fn restore_step(e: &JournalEntry, inode: Option<u64>, high: Option<&str>) -> RestoreStep;

#[test]
fn restore_step_matrix() {
    let cap = entry_cap("/x", 42, "max", "1000");         // helpers as in Task 3 tests
    assert_eq!(restore_step(&cap, Some(42), Some("1000")),
        RestoreStep::ThawAndRestoreHigh { to: "max".into() });
    assert_eq!(restore_step(&cap, Some(43), Some("1000")), RestoreStep::SkipRemove);
    assert_eq!(restore_step(&cap, Some(42), Some("777")), RestoreStep::SkipRemove);
    let frz = entry_freeze("/x", 42);
    assert_eq!(restore_step(&frz, Some(42), None), RestoreStep::ThawOnly);
    assert_eq!(restore_step(&frz, None, None), RestoreStep::SkipRemove);
}
```

- [ ] **Step 2: Run — fail. Implement `restore_step` (delegating to `should_restore`) — pass.**
- [ ] **Step 3: Rewrite `apply`/`sweep_leftovers`/`undo_all` per the behavior list.** Keep `cap_target_bytes`-style pure sizing helper but source it from `anon_swap_bytes`:

```rust
pub fn cap_from_anon(anon_swap: Option<u64>) -> u64 {
    anon_swap.map(|b| (b / 10 * 9).max(MIN_CAP_BYTES)).unwrap_or(MIN_CAP_BYTES)
}
#[test]
fn cap_from_anon_sizes_and_floors() {
    assert_eq!(cap_from_anon(Some(1_000_000_000)), 900_000_000);
    assert_eq!(cap_from_anon(Some(1_000_000)), MIN_CAP_BYTES);
    assert_eq!(cap_from_anon(None), MIN_CAP_BYTES);
}
```

  Delete `cap_target_bytes_from_status` and its tests (RSS-of-one-process is the wrong denominator now — spec). Replace the old `#[ignore]` integration test with an act-in-place one: `systemd-run --user --scope --unit=rlm-e2e-<rand> sleep 30`, resolve its cgroup, `apply(Freeze)`, assert `cgfs::read_frozen == Some(true)` and the journal has one entry, `apply(Thaw)`, assert thawed + journal empty.
- [ ] **Step 4: `cargo test -p rlm-core` — all pass. fmt+clippy.**
- [ ] **Step 5: Commit** `feat(guard): act-in-place effector — write-ahead journal, D-Bus freeze with raw fallback, mechanism-independent restore`

---

### Task 7: Sampler — resolution assembly + protect matching by exe

**Files:**
- Modify: `rlm-core/src/guard/sampler.rs`

**Interfaces:**
- Consumes: `resolve::{candidate_target, finalize}`, `cgfs::{pids_in, exe_basename}`, `CgroupManager::base_path()`.
- Produces: `Sampler::new(cfg, self_pid, uid, rlm_base: String)` (**signature change** — daemon passes `manager.base_path()` stripped of `/sys/fs/cgroup`); `eligible()` now fills `ProcInfo.resolution`.

Changes:
1. **Protect matching (spec):** a process is protected if `exe_basename(pid)` (realpath, full name, no 15-char truncation) OR its comm is in the protect set. Fixes the user-extension silent failure; comm kept as fallback for exe-unreadable processes.
2. **Resolution assembly** per eligible process: read `/proc/<pid>/cgroup` (format `0::<path>`), `candidate_target(path, uid, rlm_base)`; if `Some`, gather `member_exes` = `pids_in(candidate.cgroup)` mapped through `exe_basename` (fallback comm from `/proc/<pid>/status` `Name:`), then `finalize`. Cache per-candidate-cgroup within one `eligible()` call (`HashMap<String, Resolution>`) so N Firefox processes cost one member scan.
3. New pure parser + tests:

```rust
/// Parse the v2 line of /proc/<pid>/cgroup ("0::/path").
pub fn parse_cgroup_path(content: &str) -> Option<String>;

#[test]
fn cgroup_path_parses_v2_line() {
    assert_eq!(parse_cgroup_path("0::/user.slice/x.scope\n"), Some("/user.slice/x.scope".into()));
    // Hybrid line noise is skipped; only the "0::" entry counts.
    assert_eq!(parse_cgroup_path("1:name=systemd:/foo\n0::/bar\n"), Some("/bar".into()));
    assert_eq!(parse_cgroup_path(""), None);
}
```

- [ ] **Step 1: Write `parse_cgroup_path` tests — fail — implement — pass.**
- [ ] **Step 2: Implement protect-by-exe + resolution assembly.** Update `Sampler::new` callers (`guard/src/main.rs`, `cli` guard test path if it constructs one — grep `Sampler::new`).
- [ ] **Step 3: `cargo test --workspace` — pass. fmt+clippy.**
- [ ] **Step 4: Commit** `feat(guard): sampler resolves targets and matches protect-list on exe basename`

---

### Task 8: Delete old machinery; rules skip frozen; CLI status from journal

**Files:**
- Modify: `rlm-core/src/cgroup.rs`, `rlm-core/src/rules.rs`, `cli/src/main.rs`, `guard/src/main.rs`

Changes:
1. **cgroup.rs:** delete `freeze_pid`, `thaw_pid`, `soft_cap_pid`, `lift_cap_pid`, `cleanup_guard`, `list_guard_pids` (inline whatever `sweep_guard_leftovers` needs — the legacy sweep STAYS for one release, with a comment saying when it can go). Delete the guard-path uses of the `unlimit` migration; the manual `rlm unlimit` command path is untouched.
2. **rules.rs:** remove the `guard_held` parameter from `plan` and `list_guard_pids` from `reconcile` (the guard no longer migrates, so there is nothing to fight over — spec). Delete `plan_skips_guard_held_pids` test. Add frozen-skip in `reconcile`: before applying actions for a rule, `if cgfs::read_frozen(&format!("{}/{}", rlm_rel_base, rule.cgroup)) == Some(true) { continue; }` — reading the **kernel's** view via cgroup.events (the freeze may not be ours). New test for the pure part is not possible (IO) — cover with a comment and keep reconcile best-effort.
3. **cli/src/main.rs `guard status`:** replace `guard-*` cgroup enumeration with journal reading: open `Journal` at the shared path (see Task 9 for the path constant), list entries as active interventions (`<cgroup> [frozen|capped our_high=..]`). PSI display unchanged.
4. **guard/src/main.rs:** construct `Journal` + `SystemdUser::connect()` + new `Effector::new(&manager, &journal, systemd.as_ref())`, new `Sampler::new(cfg, pid, uid, rlm_rel_base)`.

Journal path (shared constant, put it in `rlm-core/src/guard/mod.rs`):

```rust
/// Journal lives in XDG state: ~/.local/state/rlm/guard-journal.jsonl
pub fn journal_path() -> std::path::PathBuf {
    dirs::state_dir().unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join("rlm").join("guard-journal.jsonl")
}
```

- [ ] **Step 1: Make the deletions and let the compiler drive the migration; update `rules.rs` tests (drop `guard_held` args).**
- [ ] **Step 2: `cargo test --workspace` — pass; `cargo build --release` — clean. fmt+clippy.**
- [ ] **Step 3: Commit** `refactor(guard)!: delete guard-<pid> migration machinery; rules read kernel frozen state; status reads journal`

---

### Task 9: Gate verification (live) + docs

**Files:**
- Modify: `docs/superpowers/specs/2026-05-30-freeze-guard-design.md` (§6 note pointing at roadmap), `README.md` (guard section: act-in-place, journal path), `dist/rlm-guard.service` unchanged this phase (placement move is Phase 1).

**The Phase 0 gate (from the spec, run manually, record output in the PR/commit message):**

- [ ] **Step 1:** Build + install: `cargo build --release && ./install.sh` (or the repo's documented install path), `systemctl --user restart rlm-guard`.
- [ ] **Step 2:** Launch a memory hog in its own scope: `systemd-run --user --scope --unit=rlm-gate-hog python3 -c 'a=bytearray(6_000_000_000); import time; time.sleep(120)'` (size below RAM but enough to push PSI with a parallel `stress-ng --vm 2 --vm-bytes 75%` if needed).
- [ ] **Step 3:** Observe via `journalctl --user -u rlm-guard -f`: freeze targets the **scope**, not a `guard-<pid>`. `systemd-cgls --user-unit app.slice` confirms the hog never left `rlm-gate-hog.scope`.
- [ ] **Step 4:** After thaw: `cat .../rlm-gate-hog.scope/memory.high` == original value (`max` unless capped and lifted). Journal file empty of live entries.
- [ ] **Step 5:** Repeat, and mid-freeze `kill -9 $(pgrep rlm-guard)`; restart the daemon; confirm the sweep thaws the scope and restores `memory.high`. **This is the gate criterion — paste the journalctl excerpt into the commit message.**
- [ ] **Step 6:** Docs edits; `cargo fmt && cargo clippy && cargo test --workspace` final. Commit `docs(guard): act-in-place notes; Phase 0 gate transcript`

---

## Self-Review (done at write time)

- **Spec coverage:** resolve_target contract incl. containment-predicate roots + deepest-unit rule (T1); cap sizing anon+swap (T6, `cap_from_anon`); D-Bus pre-open/timeout/fallback (T4/T6); thaw mechanism-independence (T6); journal boot-id/inode/value guards + write-ahead fsync + compaction (T3/T6); Partial gate shortening + CapOnly (T5); one-intervention-per-scope (T5 test); protect-by-exe fix (T7); guard_held deletion + frozen-skip via cgroup.events (T8); legacy sweep retained one release (T6/T8); gate incl. kill-9 replay (T9). Deferred by spec: notification replacement (Phase 4), daemon Slice= move (Phase 1), probes (Phase 0.5).
- **Type consistency:** `Resolution{cgroup: String, unit: Option<String>, verdict, coverage, mechanism}` used identically in T1/T5/T6/T7; `Journal::{open,append,entries,remove,clear}` + `should_restore` signatures match between T3 and T6; `Sampler::new` 4-arg form updated at both call sites (T7/T8).
- **Placeholder scan:** none — every step has code or an exact command; the two spots delegating detail to the implementer (zbus feature name, zvariant signature) explicitly say how to verify (compile).

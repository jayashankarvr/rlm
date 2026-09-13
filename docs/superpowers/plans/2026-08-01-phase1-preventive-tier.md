# Phase 1: Preventive Tier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop a large fraction of freezes before the daemon ever wakes, using static configuration rather than running privileged code — and make the guard's own D-Bus path survive the storm it exists to handle.

**Architecture:** Two shipping units. The **core package** gains only what is safe and user-scoped: `memory.min` protection drop-ins for the session chain, a dynamic `app.slice` cap maintained by the daemon, and the daemon's own slice move. A **separate `rlm-preset` package** carries everything system-wide and opinionated — sysctl values, zram, MGLRU — so a distro can adopt one without the other, which is what makes the core package's MIR tractable.

**Tech Stack:** systemd unit drop-ins, `sysctl.d`, `zram-generator`, cgroups v2 `memory.min`/`memory.high`, Rust (daemon-side dynamic cap + `rlm doctor` checks).

**Spec:** `docs/superpowers/specs/2026-07-31-roadmap.md` — Phase 1 section, plus the Phase 0 interlock note and the Named Limitations section.

## Global Constraints

- `cargo fmt && cargo clippy --workspace --all-targets -- -D warnings` clean before every commit; conventional commits.
- **NEVER add `Co-Authored-By` or any trailer to commit messages.**
- **Commit as soon as your gates are green.** Do not hold work uncommitted waiting on a review you dispatched — an independent gate runs at the controller level afterward.
- **The core package must not change system-wide behavior.** Anything touching `/etc/sysctl.d`, zram, or MGLRU belongs to `rlm-preset`, never to `rlm`.
- **Nothing in this phase runs privileged code at runtime.** Drop-ins and sysctl files are installed once, by the package manager. The only running component is the existing per-user daemon.
- Every value written into a unit file must be derivable from a measurement or a documented rationale — no round numbers chosen because they look tidy.
- Verified facts from the Phase 0 investigation (do not re-derive, do not contradict): on Ubuntu 26.04 GNOME, `dbus.service` runs in `session.slice`; `systemd --user` runs in `user@.service/init.scope`, i.e. **outside** `session.slice`; `rlm-guard.service` currently defaults to `Slice=app.slice` with `Delegate=no`.

---

### Task 1: `memory.min` chain with the ancestor-sum invariant

**Files:**
- Create: `dist/dropins/session.slice.d/10-rlm-memory-min.conf`, `dist/dropins/user@.service.d/10-rlm-memory-min.conf`, `dist/dropins/user-.slice.d/10-rlm-memory-min.conf`, `dist/dropins/init.scope.d/10-rlm-memory-min.conf`
- Create: `rlm-core/src/protect.rs` (the sum invariant, pure)
- Modify: `install.sh` (or the packaging path) to place user-level drop-ins

**Interfaces:**

```rust
/// One node in the protection chain: its own floor and the children it must cover.
#[derive(Debug, Clone, PartialEq)]
pub struct ProtectNode { pub path: String, pub floor_bytes: u64, pub children: Vec<String> }

/// Pure. Returns the nodes that violate `ancestor >= sum(protected children)`,
/// each with the shortfall in bytes. Empty vec == chain is sound.
pub fn check_chain(nodes: &[ProtectNode]) -> Vec<ChainViolation>;

#[derive(Debug, Clone, PartialEq)]
pub struct ChainViolation { pub path: String, pub declared: u64, pub required: u64 }
```

**Why the invariant, stated in the module doc:** `memory.min` is distributed proportionally among children on overcommit, so the effective floor at any node is bounded by its share of the parent. Copying one measured number up the chain silently dilutes every leaf, and the failure presents as "`memory.min` doesn't do much" rather than as a misconfiguration. Each ancestor must therefore declare **at least the sum** of its protected children — which implies, and is strictly stronger than, monotone non-decreasing toward the root.

- [ ] **Step 1: Write failing tests** in `protect.rs`:

```rust
fn node(path: &str, floor_mb: u64, children: &[&str]) -> ProtectNode {
    ProtectNode { path: path.into(), floor_bytes: floor_mb * 1024 * 1024,
                  children: children.iter().map(|s| s.to_string()).collect() }
}

#[test]
fn sound_chain_has_no_violations() {
    // user@.service (1400) >= session.slice (1200) + init.scope (200)
    let nodes = vec![
        node("/user.slice/user-1000.slice/user@1000.service", 1400,
             &["/user.slice/user-1000.slice/user@1000.service/session.slice",
               "/user.slice/user-1000.slice/user@1000.service/init.scope"]),
        node("/user.slice/user-1000.slice/user@1000.service/session.slice", 1200, &[]),
        node("/user.slice/user-1000.slice/user@1000.service/init.scope", 200, &[]),
    ];
    assert!(check_chain(&nodes).is_empty());
}

#[test]
fn monotone_but_undersummed_chain_is_a_violation() {
    // THE case monotonicity misses: 1200 >= 1200 and 1200 >= 200 at every EDGE,
    // but the parent must carry 1400.
    let nodes = vec![
        node("/u/user@.service", 1200, &["/u/user@.service/session.slice", "/u/user@.service/init.scope"]),
        node("/u/user@.service/session.slice", 1200, &[]),
        node("/u/user@.service/init.scope", 200, &[]),
    ];
    let v = check_chain(&nodes);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].path, "/u/user@.service");
    assert_eq!(v[0].declared, 1200 * 1024 * 1024);
    assert_eq!(v[0].required, 1400 * 1024 * 1024);
}

#[test]
fn missing_child_node_is_not_silently_zero() {
    // A declared child with no corresponding node is a broken chain description,
    // not a zero-floor child — it must be reported, never treated as 0.
    let nodes = vec![node("/u/parent", 500, &["/u/parent/ghost"])];
    let v = check_chain(&nodes);
    assert_eq!(v.len(), 1, "unknown child must surface: {v:?}");
}

#[test]
fn leaf_with_no_children_never_violates() {
    assert!(check_chain(&[node("/u/leaf", 0, &[])]).is_empty());
}
```

- [ ] **Step 2: Run `cargo test -p rlm-core protect` — expect failure.**
- [ ] **Step 3: Implement `check_chain`.** Sum each node's declared children by lookup; an unresolvable child is itself a violation (report `required: u64::MAX` or a dedicated variant — pick one and test it). Do not silently treat a missing child as zero.
- [ ] **Step 4: Write the four drop-in files** with `MemoryMin=` values left as install-time placeholders **and a comment naming the measurement that must set them** — do not ship invented numbers. The installer or `rlm doctor --calibrate` (Task 4) fills them.
- [ ] **Step 5: `cargo test -p rlm-core protect` green; fmt+clippy. Commit** `feat(protect): memory.min chain with ancestor-sum invariant`

---

### Task 2: Daemon slice move + dynamic `app.slice` cap

**Files:**
- Modify: `dist/rlm-guard.service`
- Create: `rlm-core/src/guard/appcap.rs`
- Modify: `guard/src/main.rs`

**Interfaces:**

```rust
/// Pure. Dynamic cap for app.slice = MemTotal - reserve, floored so a
/// pathological reserve can never cap app.slice into immediate reclaim.
pub fn app_slice_high(mem_total_bytes: u64, reserve_bytes: u64, min_app_bytes: u64) -> u64;
```

Two changes, and they interact — read both before starting:

1. **`Slice=session.slice` on `rlm-guard.service`.** Verified: the unit currently lands in `app.slice`, so Phase 1's own cap would throttle the daemon enforcing it, and its existing `MemoryMin=48M` is inert there because `app.slice` carries no protection chain. Include the upstream justification as a comment in the unit file (see the roadmap's daemon-placement bullet) — a third-party daemon in `session.slice` will be questioned at MIR and the answer should already be written down.
2. **Dynamic `memory.high` on `app.slice`**, maintained by the daemon: recompute on a slow cadence (not every tick — this is not storm-path work) and write via the same D-Bus path Phase 0 established, with the raw-write fallback.

- [ ] **Step 1: Tests for `app_slice_high`:**

```rust
#[test]
fn cap_is_total_minus_reserve() {
    assert_eq!(app_slice_high(16 * GIB, 2 * GIB, GIB), 14 * GIB);
}
#[test]
fn reserve_larger_than_total_clamps_to_floor() {
    // Must never return 0 or underflow — that would cap app.slice into instant reclaim.
    assert_eq!(app_slice_high(4 * GIB, 8 * GIB, GIB), GIB);
}
#[test]
fn cap_never_below_min_app_bytes() {
    assert_eq!(app_slice_high(4 * GIB, 3 * GIB + 512 * MIB, GIB), GIB);
}
```

- [ ] **Step 2: Run — fail — implement with `saturating_sub().max(min_app_bytes)` — pass.**
- [ ] **Step 3: Unit-file change** + a comment recording the verified placement facts.
- [ ] **Step 4: Wire the periodic recompute** into the daemon loop, gated behind a config flag (default off until the harness has measured the foreground-throttling cost — see Task 5's gate).
- [ ] **Step 5: fmt+clippy. Commit** `feat(guard): move daemon to session.slice; dynamic app.slice cap`

---

### Task 3: `rlm-preset` — the separable system-wide package

**Files:**
- Create: `preset/README.md`, `preset/sysctl.d/60-rlm.conf`, `preset/zram-generator.conf`, `preset/systemd/rlm-mglru.service`
- Create: `preset/install.sh`, `preset/uninstall.sh`

Everything here is system-wide and opinionated, which is exactly why it ships separately: a distro can seed the core package without adopting these, and the core package's MIR does not have to defend them.

- [ ] **Step 1: `sysctl.d/60-rlm.conf`** — `vm.watermark_scale_factor` and `vm.min_free_kbytes`, each with a comment stating what it does, the default it overrides, and the failure it addresses. Include the uninstall path (removing the file restores defaults on reboot).
- [ ] **Step 2: zram config** via `zram-generator`, ranked above the sysctl values on expected effect: on a swapless machine only file pages are reclaimable, so anon growth goes straight to OOM with no thrash window; compressed swap gives reclaim somewhere to put anon pages at RAM speed. Document that Fedora enables this by default and Ubuntu does not.
- [ ] **Step 3: MGLRU `min_ttl_ms` oneshot unit**, `ConditionPathExists=/sys/kernel/mm/lru_gen/`, default 1000, configurable. Must be a no-op (not a failure) on kernels without MGLRU.
- [ ] **Step 4: `preset/README.md`** — state plainly that this package changes system-wide memory behavior, list every value and its rationale, and give the exact uninstall steps.
- [ ] **Step 5: Commit** `feat(preset): separable system-wide memory preset package`

---

### Task 4: `rlm doctor` verifies the whole tier

**Files:**
- Modify: `cli/src/main.rs` (doctor command), `rlm-core/src/protect.rs`

`doctor` becomes the single place a user finds out whether the preventive tier is actually in effect — because every part of it is silent when missing.

- [ ] **Step 1:** Report, for each Phase 1 knob: present/absent, the effective value, and where it came from (`core`, `preset`, or unset).
- [ ] **Step 2:** Run `check_chain` against the live cgroup tree and report any ancestor-sum violation with the shortfall — this is the check that catches the silent-dilution failure.
- [ ] **Step 3:** Flag any configured `memory.min` that substantially exceeds its measurement, per the roadmap's sizing discipline (a generous floor is what turns the compositor-leak limitation from bounded into severe).
- [ ] **Step 4:** Report the daemon's actual slice, so a regression back to `app.slice` is visible.
- [ ] **Step 5:** Tests for the pure reporting logic; fmt+clippy. **Commit** `feat(doctor): verify preventive-tier knobs and the protection chain`

---

### Task 5: Measure it — the gate for this phase

**Files:** none (a harness run), then `docs/superpowers/specs/2026-07-31-roadmap.md` if the numbers contradict the plan.

Phase 0.5's harness exists precisely so this phase is judged rather than assumed.

- [ ] **Step 1:** Run the harness on three arms: stock, stock + `rlm-preset`, full rlm. Record probe drift percentiles, the locked/touch decomposition, and the PSI stall integral for each.
- [ ] **Step 2:** Report the **foreground-throttling cost** from the `app.slice` probe — this is the number the dynamic cap's tradeoff was deferred on, and the flag from Task 2 Step 4 stays off until it is known.
- [ ] **Step 3:** Compare against the harness's measured noise floor (~±40µs at defaults). **Any claimed improvement below the floor is not a result** — report it as inconclusive rather than as a win.
- [ ] **Step 4:** If the numbers contradict any Phase 1 assumption, amend the roadmap rather than the numbers. Record what was measured, on what hardware, with what kernel.
- [ ] **Step 5: Commit** `docs: Phase 1 measurement results`

---

## Self-Review

- **Spec coverage:** `memory.min` chain incl. `init.scope` (T1, from the Phase 0 interlock discovery); ancestor-sum invariant with the monotone-but-undersummed case tested explicitly (T1); daemon slice move with upstream justification (T2); dynamic `app.slice` cap with underflow floor (T2); preset package separable for MIR (T3) carrying sysctl + zram + MGLRU; doctor verification incl. chain check and oversized-floor flag (T4); measurement gate against the real noise floor (T5). Deferred by spec: `memory.low` on the focused app (needs focus tracking), the swap.max reconsideration (needs the Phase 0 live gate first).
- **Type consistency:** `ProtectNode`/`ChainViolation` defined in T1 are consumed unchanged by T4's doctor check; `app_slice_high` from T2 is the only cap computation.
- **Placeholder scan:** the drop-in `MemoryMin=` values are *deliberately* placeholders — Task 1 Step 4 requires a comment naming the measurement that sets them, and Task 4 provides the calibration. Shipping invented numbers is the failure mode being avoided.

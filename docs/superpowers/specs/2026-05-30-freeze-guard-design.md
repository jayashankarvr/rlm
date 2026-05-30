# Design: System-wide Freeze Guard (`rlm-guard`)

**Date:** 2026-05-30
**Status:** Approved (brainstorming) — ready for implementation
**Component:** new `rlm-guard` daemon + `rlm-core` guard engine

## 1. Goal

rlm's tagline is "proactively prevent system freezes," but today the tool is
entirely manual. The freeze guard delivers the actual promise: a per-user
background daemon that watches memory pressure and **automatically pauses or
throttles the user's biggest memory hog before the system locks up** — and
heals itself once pressure clears. It never kills processes.

## 2. Decisions (locked during brainstorming)

| Decision | Choice |
|----------|--------|
| Scope / privilege | **Per-user daemon** — runs as the user via existing cgroup delegation, no root. Acts only on the user's own processes. |
| Action policy | **Recovery-only, never kill.** Escalation: notify → freeze → soft-cap (`memory.high`). rlm never issues a kill signal. |
| Victim selection | **Highest `RSS+swap`** among eligible processes, with a protect-list. |
| Recovery model | **Self-healing circuit breaker.** Freeze is a short (~5s) auto-thawed pause; if pressure persists, soft-cap; everything auto-lifts once memory is calm. Hysteresis + cooldowns prevent flapping. |
| Trigger signal | **PSI** (`/proc/pressure/memory`) primary, `MemAvailable` floor as backstop. |
| Architecture | **Pure engine in `rlm-core` + thin `rlm-guard` binary** (Approach A). Notifications best-effort via `notify-send`. |

## 3. Architecture

Three isolated units; the engine is pure and syscall-free.

```
 /proc/pressure/memory ─┐
 /proc/<pid>/* (RSS,uid)─┤
                        ▼
   ┌─────────────┐   Sample    ┌──────────────┐  Action[]  ┌───────────┐
   │  Sampler    │────────────▶│ PolicyEngine │───────────▶│ Effector  │
   │ (rlm-core)  │  + ProcList │ (pure FSM,   │            │ (CgroupMgr│
   │  reads /proc│             │  rlm-core)   │            │  reuse)   │
   └─────────────┘             └──────────────┘            └───────────┘
                                     ▲ holds state               │
                            (interventions, cooldowns)           ▼
                                                   cgroup.freeze / memory.high
```

- **Sampler** (`rlm-core::guard::sampler`): pure reads. Parses PSI `some`/`full
  avg10` + `MemAvailable`; enumerates the user's eligible processes with
  `RSS+swap`. No decisions.
- **PolicyEngine** (`rlm-core::guard::policy`): pure state machine. Input =
  `(now_ms, Sample, &[ProcInfo])`; output = `Vec<Action>`. Owns hysteresis,
  cooldowns, escalation, recovery. **No syscalls → fully unit-testable without
  root.** Time is injected (`now_ms`) for determinism.
- **Effector** (`rlm-core::guard::effector`): executes `Action`s by reusing
  `CgroupManager` (freeze / soft-cap / thaw / lift / cleanup / startup-sweep).
- **`rlm-guard` binary** (new `guard/` crate): thin loop wiring the three;
  runs as a systemd **user** service. `rlm guard {status,enable,disable,test}`
  are CLI wrappers; `status` is stateless (inspects PSI + `guard-*` cgroups).

## 4. Contract (shared types)

Defined in `rlm-core/src/guard/types.rs` (the interface parallel work codes against):

```rust
/// One memory-pressure sample.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sample {
    pub some_avg10: f64,        // PSI "some" avg10, percent (0..=100)
    pub full_avg10: f64,        // PSI "full" avg10, percent
    pub mem_available_mb: u64,  // MemAvailable, MB
}

/// Derived pressure level (hysteresis handled inside the engine).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level { Calm, Warn, High, Critical }

/// One candidate process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,
    pub rss_kb: u64,            // RSS + swap, KB
}

/// What the engine asks the effector to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Notify  { message: String },
    Freeze  { pid: u32, name: String },
    Thaw    { pid: u32 },
    Cap     { pid: u32, name: String },   // soft cap via memory.high
    LiftCap { pid: u32 },
}
```

`GuardConfig` lives in `common::config` (serde, YAML, baked-in defaults), read by
the engine and effector.

### Engine API

```rust
impl PolicyEngine {
    pub fn new(cfg: GuardConfig) -> Self;
    /// Advance the FSM. `now_ms` is a monotonic timestamp (ms). Pure given inputs+state.
    pub fn tick(&mut self, now_ms: u64, sample: Sample, procs: &[ProcInfo]) -> Vec<Action>;
    /// Active interventions (for `guard status` / shutdown undo).
    pub fn interventions(&self) -> Vec<(u32, Intervention)>;
}
```

## 5. Policy engine behavior

**Pressure levels** (rise/fall hysteresis):

| Level | Rises at (defaults) | Falls back below |
|-------|---------------------|------------------|
| Calm | — | — |
| Warn | `some.avg10 ≥ 10` | 5 |
| High | `some.avg10 ≥ 30` or `full.avg10 ≥ 3` | 15 |
| Critical | `full.avg10 ≥ 10` or `avail < floor_mb` | 5 |

**Per-tick logic:**
1. **Recover first.** Frozen target held ≥ `freeze_hold_secs` (5) → `Thaw`.
   Capped target while Calm sustained ≥ `calm_hold_secs` (30) → `LiftCap` (+ effector tears down `guard-<pid>`).
2. **Escalate.** If level ≥ High → victim = highest `rss_kb` among eligible
   (not protected, `rss_kb ≥ min_rss`, not currently frozen). If victim was frozen
   within `freeze_cooldown_secs` (60) → `Cap` it instead of re-freezing. Else → `Freeze`.
3. **Warn.** Rate-limited `Notify`.
4. Global min-interval gates new interventions (act on one hog, then re-measure).

Net flow on a spike: **notify → freeze 5s → auto-thaw → still high? soft-cap →
calm 30s → lift.** No kill action is ever emitted.

## 6. Effector mechanics

- **Freeze:** create `<base>/guard-<pid>`, write PID to its `cgroup.procs`, write
  `1` to `guard-<pid>/cgroup.freeze`. (Freezer is unconditional in cgroup v2.)
- **Thaw:** write `0` to `cgroup.freeze`; process stays in `guard-<pid>`.
- **Cap:** set `memory.high` on `guard-<pid>` to ~90% of the process's current
  `RSS` (forces reclaim/throttle, never an OOM-kill).
- **LiftCap / recovery:** `memory.high=max`; once Calm sustained, move the process
  to the controller-free `unlimit` cgroup and `rmdir guard-<pid>`.
- **`CgroupManager` additions:** `freeze_pid`, `thaw_pid`, `soft_cap_pid`,
  `lift_cap_pid`, `cleanup_guard`, `list_guard_pids`, `sweep_guard_leftovers`.

**Eligibility** (Sampler filters, engine enforces):
- Only the user's own processes (`/proc/<pid>` owner uid == our uid).
- Protect-list (baked-in defaults + user additions): `gnome-shell`, `kwin_wayland`,
  `sway`, `Xwayland`, `Xorg`, `plasmashell`, the user's shells, `sshd`,
  `systemd`, `dbus-daemon`, `pipewire`, `rlm-guard` itself, PID 1.
- `rss_kb ≥ min_rss_mb` (default 200 MB).

## 7. Config

`guard:` section in `~/.config/rlm/config.yaml`; all fields default so zero-config works:

```yaml
guard:
  enabled: true
  trigger:   { psi_some_warn: 10, psi_some_high: 30, psi_full_critical: 10, mem_available_floor_mb: 400 }
  timing:    { freeze_hold_secs: 5, calm_hold_secs: 30, freeze_cooldown_secs: 60, sample_interval_ms: 1000 }
  selection: { min_rss_mb: 200, protect: [] }      # user names ADD to built-in protect-list
  notify: true
```

## 8. Daemon lifecycle & CLI

- **Loop:** read config → open PSI (poll trigger + periodic sample at
  `sample_interval_ms`) → `tick` → apply actions → repeat.
- **CLI:** `rlm guard status` (PSI level + live interventions, statelessly from
  PSI + `guard-*` cgroups), `enable`/`disable` (wrap `systemctl --user … rlm-guard`),
  `test` (dry-run: print actions without executing).
- **Notifications:** best-effort `notify-send` if present; failures ignored.
- **systemd unit** (`dist/rlm-guard.service`, user service): `Restart=on-failure`.

## 9. Safety

- **Graceful shutdown (SIGTERM):** thaw all, lift all caps, tear down `guard-*`.
  Never leave a process frozen.
- **Startup recovery sweep:** scan for leftover `guard-*` cgroups (prior crash),
  thaw + clean before starting. Even a SIGKILL self-heals on restart.
- **Residual risk (documented):** SIGKILL while a process is frozen leaves it
  paused until restart (which sweeps). Bounded by 5s freezes + `Restart=on-failure`.
- **Loop robustness:** every effector action is best-effort + logged; a failure
  never crashes the loop. Guard excludes its own PID so it can never target itself.

## 10. Testing

- **PolicyEngine (bulk):** pure unit tests — synthetic `(now_ms, Sample, ProcList)`
  sequences asserting emitted `Action`s: escalation ladder, hysteresis (no flap
  across rise/fall), freeze→cap cooldown, self-healing recovery, never-pick-protected,
  min-RSS gate. No root needed.
- **Sampler:** table-driven parsing of PSI + `/proc/<pid>` fixtures.
- **Effector:** one optional integration test under delegation — freeze a throwaway
  `sleep`, assert paused via `cgroup.freeze`/proc state, then thaw.

## 11. Out of scope (future)

- System-wide root mode (Phase 2; same engine, wider scope).
- GUI surfacing of guard status / interactive notification actions.
- Kill-as-last-resort policy (deliberately excluded by the "never kill" decision).

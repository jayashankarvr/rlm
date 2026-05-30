# Design: Process Grouping & Persistent Application Rules

**Date:** 2026-05-31
**Status:** Approved (brainstorming) — implementing
**Components:** `common::config`, new `rlm-core::rules`, `rlm-guard`, `cli`, `gtk-gui`

## 1. Goal

Two related capabilities sharing one data model:

1. **Process grouping (UX):** present instances of the same executable as an
   expandable group; limit the *whole group* (one shared cgroup) or expand and
   limit individual PIDs. Largely surfaces logic that already exists
   (`group_by_executable`, `--application`, `apply_limit_to_multiple`).
2. **Persistent application rules (new):** an application limit can be saved as a
   standing rule. `rlm-guard` enforces saved rules continuously — applying them
   to running instances on startup and absorbing newly-launched matching
   instances into the app's shared cgroup.

**Per-process (`pid-*`) limits are never persisted** — PIDs do not survive a
reboot. Only application rules (matched by executable) persist.

## 2. Decisions (locked during brainstorming)

| Decision | Choice |
|----------|--------|
| Persist semantics | Standing policy: re-apply to running **and** future instances. |
| Enforcer | Extend `rlm-guard` (no new daemon/autostart). |
| Limit semantics | **Shared pool** — all instances share one `app-<exe>` cgroup. |
| Rule creation/match | Save from a limit action; explicit `rules:` config section keyed by exe; match by exe basename. |
| Stored limits | **Inline snapshot** (not a live reference to a profile). |
| Group UX | Grouped expandable rows: "Limit group" on header + per-PID when expanded. |
| Rule lifecycle | Rule persists until explicit removal; cgroup auto-created on demand / torn down when empty; `unlimit` keeps the rule unless `--forget`. |

## 3. Architecture

```
                 ┌──────────────────────────────┐
   config.yaml   │ rules:                        │  (new persistent section)
   ◄────────────►│   firefox: {match_exe, limit} │
                 └─────────────┬────────────────┘
                               │ read
   CLI  ─ limit --application --save ─┐        ┌── rlm-guard (already autostarts)
   GUI  ─ "Limit group" + save ───────┼──────► │  each tick: RulesEnforcer.reconcile()
                               write   │        │  + existing freeze PolicyEngine
                                       ▼        │
                             CgroupManager ◄────┘
                          app-<exe> shared cgroup (on demand; removed when empty)
```

New unit `rlm-core::rules`. The daemon gains a `RulesEnforcer` run in the same
tick loop as the freeze engine. No new binary, no new autostart.

## 4. Data model (`common::config`)

```rust
pub struct Config {
    pub profiles: HashMap<String, Profile>,
    pub guard: GuardConfig,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub rules: HashMap<String, AppRule>,   // key = rule name (defaults to exe basename)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppRule {
    pub match_exe: Vec<String>,            // exe basenames
    #[serde(skip_serializing_if = "Option::is_none")] pub memory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub cpu: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub io_read: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub io_write: Option<String>,
}
impl AppRule { pub fn to_limit(&self) -> Result<Limit>; }   // mirrors Profile::to_limit
```

Config helpers: `add_rule(name, AppRule)`, `remove_rule(name) -> bool`, plus the
existing atomic `save()`. `rules:` is omitted from serialized output when empty.

`rules` are separate from `profiles`: profiles are reusable templates; rules are
active policies. A `--save` that references a profile stores the **resolved
inline limits**, so later profile edits don't silently change an active rule.

```yaml
rules:
  firefox:
    match_exe: [firefox]
    memory: "4G"
    cpu: "75%"
```

## 5. Enforcement (`rlm-core::rules`)

```rust
pub struct CompiledRule { pub name: String, pub match_exe: Vec<String>, pub limit: Limit }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleAction {
    EnsureCgroup { rule: String },
    AddPid { rule: String, pid: u32 },
    TeardownEmpty { rule: String },
}

pub struct RulesEnforcer { rules: Vec<CompiledRule> }
impl RulesEnforcer {
    pub fn new(cfg: &Config) -> Result<Self>;          // compile + parse limits
    pub fn reconcile(&self, mgr: &CgroupManager) -> Vec<RuleAction>;  // idempotent
}
```

**Per reconcile, for each rule** (cgroup name = `app-<exe>` via existing scheme):
1. Find matching live PIDs (`find_all_by_executable` over `match_exe`).
2. If matches exist: ensure `app-<exe>` exists with the rule's limits set
   (create + `set_limits`, idempotent); add any matching PID not already in it.
3. If no matches: tear down `app-<exe>` if present; **keep the rule**.

Properties:
- **Idempotent & cheap** — steady state does almost nothing; reuses the daemon's
  existing per-tick `/proc` scan (no extra polling).
- **Startup = first reconcile** — no special boot path.
- **Best-effort & isolated** — a failure on one rule logs and never aborts other
  rules or the freeze loop (mirrors the Effector discipline).
- **No fight with the freeze guard** — a PID already in an `app-<exe>` rule
  cgroup counts as already-managed, so the freeze engine won't re-cage it.
- **Cadence** — every tick (~1s); new instances are absorbed within ~1s.

Tick loop:
```
sample → freeze PolicyEngine.tick → apply freeze actions
       → RulesEnforcer.reconcile  → apply rule actions
```

## 6. CLI surface

- `rlm limit --application <exe> --memory … [--cpu …] [--io-read …] [--io-write …] --save`
  applies the shared limit now **and** writes/updates the `rules:` entry (keyed
  by `<exe>`, `match_exe: [<exe>]`).
- `rlm rule list` — table of saved rules.
- `rlm rule remove <name>` — delete a rule (does not touch a live cgroup).
- `rlm unlimit --application <exe>` — drop the live cgroup; **keep** the rule
  unless `--forget` is passed (which also removes the rule).

## 7. GUI surface (`gtk-gui` Limit page)

- Replace the flat multi-select list with an `adw::ExpanderRow` per executable:
  title `"<exe> (<n> instances, <agg mem>)"`, a "Limit group" affordance on the
  header (limits the whole group → shared `app-<exe>` cgroup), and child rows per
  PID each with an individual "Limit" affordance.
- In the apply flow for a group, a "Save as persistent rule" switch writes the
  rule via the same config path as the CLI `--save`.
- Individual-PID limiting keeps current (non-persistent) behavior.

## 8. Error handling

- `AppRule::to_limit` validation errors surface at save time (CLI/GUI), not in
  the daemon. The daemon skips a rule whose limit fails to parse and logs once.
- Reconcile actions are best-effort; per-rule/per-PID failures are logged at
  `warn` and never propagate to crash the loop.
- Saving a rule uses the existing atomic config write (`save()`).

## 9. Testing

- **`AppRule::to_limit`** — parse/validation, mirrors Profile tests.
- **Config** — `rules` round-trips; empty `rules` is omitted on serialize;
  add/remove helpers.
- **RulesEnforcer** — pure decision tests with an injected process list:
  matching by exe basename, "ensure then add new PID", "teardown when no
  matches", idempotency (no duplicate AddPid when PID already present). Process
  enumeration is injected so these need no root.
- **Effector/integration** — one ignored test (under delegation): a rule absorbs
  a freshly-spawned matching process into `app-<exe>`.

## 10. Out of scope

- System-wide (root) rules.
- Glob/regex exe matching (basename equality only for now).
- Rules that live-track a profile (we snapshot inline).
- GUI management page for rules (create via save; remove via CLI for now).

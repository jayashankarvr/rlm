//! Persistent application rules: keep matching processes in a shared per-app
//! cgroup with the rule's limits, continuously reconciled by `rlm-guard`.
//!
//! The decision logic ([`plan`]) is pure and takes an injected snapshot of the
//! currently-running processes plus the set of PIDs already placed, so it is
//! unit-testable without root. [`RulesEnforcer::reconcile`] wires that decision
//! to real `/proc` enumeration and a [`CgroupManager`].

use crate::process::{self, ProcessInfo};
use crate::CgroupManager;
use common::{AppRule, Config, Limit};

/// A rule with its limits parsed once up front.
pub struct CompiledRule {
    pub name: String,
    pub match_exe: Vec<String>,
    pub limit: Limit,
    /// Shared cgroup name for this rule (`app-<name>`).
    pub cgroup: String,
}

/// One reconcile decision for a single rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleAction {
    /// Ensure the shared cgroup exists with the rule's limits set.
    EnsureCgroup { rule: String },
    /// Add a matching process to the rule's shared cgroup.
    AddPid { rule: String, pid: u32 },
    /// No matching processes remain — tear down the (now empty) cgroup.
    TeardownEmpty { rule: String },
}

/// Sanitize a rule name into the `app-<name>` cgroup form, matching the CLI's
/// existing scheme (`app-{name with '/' and ' ' replaced by '_'}`).
pub fn cgroup_name_for(rule_name: &str) -> String {
    format!("app-{}", rule_name.replace(['/', ' '], "_"))
}

impl CompiledRule {
    fn compile(name: &str, rule: &AppRule) -> Option<Self> {
        match rule.to_limit() {
            Ok(limit) => Some(CompiledRule {
                name: name.to_string(),
                match_exe: rule.match_exe.clone(),
                limit,
                cgroup: cgroup_name_for(name),
            }),
            Err(e) => {
                tracing::warn!(rule = name, error = %e, "skipping rule with invalid limits");
                None
            }
        }
    }

    fn matches(&self, proc: &ProcessInfo) -> bool {
        self.match_exe.iter().any(|want| {
            proc.name == *want
                || proc
                    .executable
                    .as_ref()
                    .and_then(|exe| exe.file_name())
                    .and_then(|n| n.to_str())
                    .map(|n| n == want)
                    .unwrap_or(false)
        })
    }
}

/// Pure planner: decide the actions for one rule given the current process
/// snapshot, the PIDs already in this rule's cgroup, the PIDs the freeze guard
/// is currently holding (frozen/capped in a `guard-*` cgroup), and whether this
/// rule's cgroup currently has any process in it.
///
/// - matches present (excluding guard-held), some not placed -> EnsureCgroup + AddPid(each new)
/// - matches present, all already placed                     -> EnsureCgroup only (idempotent)
/// - no placeable matches, cgroup occupied                   -> nothing (don't evict)
/// - no placeable matches, cgroup empty-but-present          -> TeardownEmpty
/// - no placeable matches, no cgroup                         -> nothing
///
/// `guard_held` PIDs are skipped entirely: re-adding a soft-capped/frozen
/// process would migrate it out of its `guard-<pid>` cgroup and discard the
/// guard's intervention. The freeze guard wins while pressure is high; the rule
/// re-absorbs the process on a later tick once the guard releases it.
pub fn plan(
    rule: &CompiledRule,
    procs: &[ProcessInfo],
    already_placed: &[u32],
    guard_held: &[u32],
    cgroup_exists: bool,
) -> Vec<RuleAction> {
    let matches: Vec<&ProcessInfo> = procs
        .iter()
        .filter(|p| rule.matches(p) && !guard_held.contains(&p.pid))
        .collect();

    if matches.is_empty() {
        // Only tear down a cgroup that exists AND is empty. A populated
        // `app-<exe>` (e.g. created by a manual one-off `--application` limit
        // that shares the name) must never be evicted from under its owner.
        return if cgroup_exists && already_placed.is_empty() {
            vec![RuleAction::TeardownEmpty {
                rule: rule.name.clone(),
            }]
        } else {
            Vec::new()
        };
    }

    let mut actions = vec![RuleAction::EnsureCgroup {
        rule: rule.name.clone(),
    }];
    for p in matches {
        if !already_placed.contains(&p.pid) {
            actions.push(RuleAction::AddPid {
                rule: rule.name.clone(),
                pid: p.pid,
            });
        }
    }
    actions
}

/// Enforces persistent application rules against real cgroups.
pub struct RulesEnforcer {
    rules: Vec<CompiledRule>,
}

impl RulesEnforcer {
    /// Compile the rules from config. Rules with unparseable limits are skipped
    /// (logged once) rather than failing the whole enforcer.
    pub fn new(cfg: &Config) -> Self {
        let rules = cfg
            .rules
            .iter()
            .filter_map(|(name, rule)| CompiledRule::compile(name, rule))
            .collect();
        Self { rules }
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Reconcile every rule once. Best-effort: a failure on one rule or PID is
    /// logged and never aborts the others. Returns the actions that were applied
    /// (useful for logging/tests).
    pub fn reconcile(&self, mgr: &CgroupManager) -> Vec<RuleAction> {
        // One /proc scan shared across all rules.
        let procs = match process::list_all() {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "rules: failed to list processes; skipping tick");
                return Vec::new();
            }
        };

        // PIDs the freeze guard currently holds (frozen/capped). Re-adding one
        // to a rule cgroup would migrate it out of guard-<pid> and discard the
        // guard's intervention, so the planner skips these.
        let guard_held = mgr.list_guard_pids();

        let mut applied = Vec::new();
        for rule in &self.rules {
            // Which matching PIDs are already in this rule's cgroup?
            let placed = mgr.pids_in_cgroup(&rule.cgroup);
            let exists = !placed.is_empty() || mgr.cgroup_exists(&rule.cgroup);

            for action in plan(rule, &procs, &placed, &guard_held, exists) {
                if let Err(e) = self.apply(mgr, rule, &action) {
                    tracing::warn!(?action, error = %e, "rules: action failed");
                } else {
                    applied.push(action);
                }
            }
        }
        applied
    }

    fn apply(
        &self,
        mgr: &CgroupManager,
        rule: &CompiledRule,
        action: &RuleAction,
    ) -> common::Result<()> {
        match action {
            RuleAction::EnsureCgroup { .. } => {
                // prepare_cgroup creates the cgroup (idempotent) and (re)sets limits.
                mgr.prepare_cgroup(&rule.cgroup, &rule.limit)?;
                Ok(())
            }
            RuleAction::AddPid { pid, .. } => {
                let path = mgr.base_path().join(&rule.cgroup);
                mgr.add_to_cgroup(&path, *pid)
            }
            RuleAction::TeardownEmpty { .. } => mgr.cleanup_cgroup(&rule.cgroup),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn rule(name: &str, exes: &[&str]) -> CompiledRule {
        CompiledRule {
            name: name.to_string(),
            match_exe: exes.iter().map(|s| s.to_string()).collect(),
            limit: Limit::default(),
            cgroup: cgroup_name_for(name),
        }
    }

    fn proc(pid: u32, name: &str, exe: Option<&str>) -> ProcessInfo {
        ProcessInfo {
            pid,
            name: name.to_string(),
            ppid: None,
            session: None,
            executable: exe.map(PathBuf::from),
        }
    }

    #[test]
    fn cgroup_name_matches_cli_scheme() {
        assert_eq!(cgroup_name_for("firefox"), "app-firefox");
        assert_eq!(cgroup_name_for("my app/x"), "app-my_app_x");
    }

    #[test]
    fn matches_by_comm_or_exe_basename() {
        let r = rule("firefox", &["firefox"]);
        assert!(r.matches(&proc(1, "firefox", None)));
        assert!(r.matches(&proc(2, "Web Content", Some("/usr/lib/firefox/firefox"))));
        assert!(!r.matches(&proc(3, "code", Some("/usr/bin/code"))));
    }

    #[test]
    fn plan_ensures_and_adds_unplaced_matches() {
        let r = rule("firefox", &["firefox"]);
        let procs = vec![proc(10, "firefox", None), proc(11, "firefox", None)];
        let actions = plan(&r, &procs, &[], &[], false);
        assert_eq!(
            actions[0],
            RuleAction::EnsureCgroup {
                rule: "firefox".into()
            }
        );
        assert!(actions.contains(&RuleAction::AddPid {
            rule: "firefox".into(),
            pid: 10
        }));
        assert!(actions.contains(&RuleAction::AddPid {
            rule: "firefox".into(),
            pid: 11
        }));
    }

    #[test]
    fn plan_is_idempotent_when_all_placed() {
        let r = rule("firefox", &["firefox"]);
        let procs = vec![proc(10, "firefox", None)];
        let actions = plan(&r, &procs, &[10], &[], true);
        // Ensure only; no AddPid for the already-placed pid.
        assert_eq!(
            actions,
            vec![RuleAction::EnsureCgroup {
                rule: "firefox".into()
            }]
        );
    }

    #[test]
    fn plan_adds_only_new_pid() {
        let r = rule("firefox", &["firefox"]);
        let procs = vec![proc(10, "firefox", None), proc(12, "firefox", None)];
        let actions = plan(&r, &procs, &[10], &[], true);
        assert_eq!(
            actions,
            vec![
                RuleAction::EnsureCgroup {
                    rule: "firefox".into()
                },
                RuleAction::AddPid {
                    rule: "firefox".into(),
                    pid: 12
                },
            ]
        );
    }

    #[test]
    fn plan_teardown_only_when_empty_and_present() {
        let r = rule("firefox", &["firefox"]);
        // Present + empty (no placed pids) + no matches -> teardown.
        let actions = plan(&r, &[proc(1, "code", None)], &[], &[], true);
        assert_eq!(
            actions,
            vec![RuleAction::TeardownEmpty {
                rule: "firefox".into()
            }]
        );
    }

    #[test]
    fn plan_does_not_evict_occupied_cgroup_with_no_matches() {
        // No rule-matching process, but the cgroup still holds something (e.g. a
        // manual one-off `--application firefox` sharing the name). Must NOT tear
        // it down out from under its owner.
        let r = rule("firefox", &["firefox"]);
        let actions = plan(&r, &[proc(1, "code", None)], &[999], &[], true);
        assert!(
            actions.is_empty(),
            "must not evict an occupied cgroup: {actions:?}"
        );
    }

    #[test]
    fn plan_skips_guard_held_pids() {
        // A matching process the freeze guard is currently holding must not be
        // re-added (that would migrate it out of guard-<pid> and discard the cap).
        let r = rule("firefox", &["firefox"]);
        let procs = vec![proc(10, "firefox", None), proc(11, "firefox", None)];
        let actions = plan(&r, &procs, &[], &[10], false);
        assert!(
            !actions.contains(&RuleAction::AddPid {
                rule: "firefox".into(),
                pid: 10
            }),
            "guard-held pid 10 must be skipped: {actions:?}"
        );
        assert!(actions.contains(&RuleAction::AddPid {
            rule: "firefox".into(),
            pid: 11
        }));
    }

    #[test]
    fn plan_noop_when_no_matches_and_no_cgroup() {
        let r = rule("firefox", &["firefox"]);
        let actions = plan(&r, &[proc(1, "code", None)], &[], &[], false);
        assert!(actions.is_empty());
    }
}

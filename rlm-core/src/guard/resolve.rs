//! Pure target resolution — determines whether a victim cgroup should be frozen,
//! capped, or protected based on its path and membership.
//!
//! No syscalls, no clock reads, no filesystem access. Pure logic over paths and process names.

use std::collections::HashSet;

/// Verdict: freeze or cap-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Freeze,
    CapOnly,
}

/// Coverage: full freezing or partial (due to protected processes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    Full,
    Partial,
}

/// Resolution mechanism: systemd unit or raw cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    Unit,
    Raw,
}

/// Candidate target for resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// cgroupfs path relative to /sys/fs/cgroup, e.g.
    /// "/user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox-12.scope"
    pub cgroup: String,
    /// systemd unit name (the final path component) when mechanism == Unit.
    pub unit: Option<String>,
    pub mechanism: Mechanism,
}

/// Final resolution with verdict and coverage.
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
pub fn candidate_target(victim_cgroup: &str, uid: u32, rlm_base: &str) -> Option<Candidate> {
    let app_root = format!("/user.slice/user-{uid}.slice/user@{uid}.service/app.slice/");
    if let Some(rest) = victim_cgroup.strip_prefix(&app_root) {
        // Deepest component ending in .scope/.service wins.
        let comps: Vec<&str> = rest.split('/').filter(|c| !c.is_empty()).collect();
        let unit_idx = comps
            .iter()
            .rposition(|c| c.ends_with(".scope") || c.ends_with(".service"))?;
        let unit = comps[unit_idx].to_string();
        let cgroup = format!("{app_root}{}", comps[..=unit_idx].join("/"));
        return Some(Candidate {
            cgroup,
            unit: Some(unit),
            mechanism: Mechanism::Unit,
        });
    }
    let rlm_root = format!("{}/", rlm_base.trim_end_matches('/'));
    if let Some(rest) = victim_cgroup.strip_prefix(&rlm_root) {
        let first = rest.split('/').find(|c| !c.is_empty())?;
        // The shared "unlimit" leaf is where every `rlm unlimit`/teardown
        // dumps released processes (and where `sweep_guard_leftovers` dumps
        // legacy `guard-<pid>` victims on upgrade) — it's a grab-bag of
        // processes the user explicitly released from rlm's control, not a
        // valid freeze/cap target. `status.rs` already excludes it by the
        // same name; mirror that here (D3 fix).
        if first == crate::cgroup::UNLIMIT_CGROUP_NAME {
            return None;
        }
        return Some(Candidate {
            cgroup: format!("{rlm_root}{first}"),
            unit: None,
            mechanism: Mechanism::Raw,
        });
    }
    None
}

/// Pure. `member_exes` = exe basenames of every process in the candidate cgroup.
pub fn finalize(c: Candidate, member_exes: &[String], protect: &HashSet<String>) -> Resolution {
    let protected = member_exes.iter().any(|e| protect.contains(e));
    let (verdict, coverage) = if protected {
        (Verdict::CapOnly, Coverage::Partial)
    } else {
        (Verdict::Freeze, Coverage::Full)
    };
    Resolution {
        cgroup: c.cgroup,
        unit: c.unit,
        verdict,
        coverage,
        mechanism: c.mechanism,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RLM: &str = "/user.slice/user-1000.slice/user@1000.service/rlm";

    #[test]
    fn scope_under_app_slice_resolves_to_unit() {
        let c = candidate_target(
            "/user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox-12.scope",
            1000,
            RLM,
        )
        .unwrap();
        assert_eq!(
            c.cgroup,
            "/user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox-12.scope"
        );
        assert_eq!(c.unit.as_deref(), Some("app-firefox-12.scope"));
        assert_eq!(c.mechanism, Mechanism::Unit);
    }

    #[test]
    fn process_deep_inside_scope_resolves_to_scope_boundary() {
        // Firefox content process nested below the scope.
        let c = candidate_target(
            "/user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox-12.scope/child",
            1000,
            RLM,
        )
        .unwrap();
        assert_eq!(c.unit.as_deref(), Some("app-firefox-12.scope"));
    }

    #[test]
    fn deepest_unit_wins_for_nested_service_paths() {
        // app.slice/app-x.slice/foo.service style nesting: pick foo.service, not a slice.
        let c = candidate_target(
            "/user.slice/user-1000.slice/user@1000.service/app.slice/app-x.slice/foo.service/leaf",
            1000,
            RLM,
        )
        .unwrap();
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

    /// D3 fix: the shared `unlimit` leaf holds processes the user explicitly
    /// released from rlm's control (and, on upgrade, legacy `guard-<pid>`
    /// victims swept there at startup) — it must never resolve as a
    /// freeze/cap target, mirroring `status.rs`'s exclusion of the same
    /// cgroup.
    #[test]
    fn unlimit_bucket_is_not_a_target() {
        assert_eq!(
            candidate_target(
                &format!("{RLM}/{}", crate::cgroup::UNLIMIT_CGROUP_NAME),
                1000,
                RLM,
            ),
            None
        );
        // Nor is a process nested somewhere below it.
        assert_eq!(
            candidate_target(
                &format!("{RLM}/{}/child", crate::cgroup::UNLIMIT_CGROUP_NAME),
                1000,
                RLM,
            ),
            None
        );
    }

    #[test]
    fn session_slice_is_outside_permitted_roots() {
        assert_eq!(
            candidate_target(
                "/user.slice/user-1000.slice/user@1000.service/session.slice/org.gnome.Shell@ubuntu.service",
                1000,
                RLM,
            ),
            None
        );
    }

    #[test]
    fn rlm_base_itself_is_not_a_target() {
        // "strictly below": the base dir itself must not resolve.
        assert_eq!(candidate_target(RLM, 1000, RLM), None);
    }

    #[test]
    fn app_slice_without_unit_component_is_none() {
        assert_eq!(
            candidate_target(
                "/user.slice/user-1000.slice/user@1000.service/app.slice",
                1000,
                RLM,
            ),
            None
        );
    }

    #[test]
    fn other_uid_path_is_none() {
        assert_eq!(
            candidate_target(
                "/user.slice/user-1001.slice/user@1001.service/app.slice/app-x-1.scope",
                1000,
                RLM,
            ),
            None
        );
    }

    #[test]
    fn finalize_unprotected_is_freeze_full() {
        let c = candidate_target(
            "/user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox-12.scope",
            1000,
            RLM,
        )
        .unwrap();
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
            1000,
            RLM,
        )
        .unwrap();
        let protect: HashSet<String> = ["zsh".to_string()].into();
        let r = finalize(c, &["zsh".into(), "python3".into()], &protect);
        assert_eq!(r.verdict, Verdict::CapOnly);
        assert_eq!(r.coverage, Coverage::Partial);
    }
}

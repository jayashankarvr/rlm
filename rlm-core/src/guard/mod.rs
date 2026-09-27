//! Freeze-guard engine: watch memory pressure and proactively freeze/soft-cap
//! the non-protected app driving the pressure before the system locks up, healing
//! itself once pressure clears. Pure engine + sampler live here; the daemon loop
//! lives in the `rlm-guard` binary.

use std::path::PathBuf;

pub mod cgfs;
pub mod effector;
pub mod history;
pub mod journal;
pub mod lock;
pub mod policy;
pub mod report;
pub mod resolve;
pub mod sampler;
pub mod service;
pub mod systemd;
pub mod types;

pub use effector::Effector;
pub use journal::Journal;
pub use policy::PolicyEngine;
pub use sampler::Sampler;
pub use systemd::SystemdUser;
pub use types::{Action, Intervention, Level, ProcInfo, PsiSource, Sample, Target};

/// Default path for the guard's write-ahead restore journal.
///
/// Prefers `$XDG_STATE_HOME` (`~/.local/state` by default), matching the
/// XDG-first convention `common::Config` already uses for `config_dir()`.
/// Falls back to `/tmp/rlm` on the rare system where no state dir can be
/// resolved (e.g. `$HOME` unset); the journal is still boot_id-guarded, so a
/// non-persistent fallback location only costs us WAL recovery across a
/// reboot in that degraded case, not correctness.
pub fn journal_path() -> PathBuf {
    dirs::state_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("rlm")
        .join("guard-journal.jsonl")
}

/// Path of the lock file that keeps a second `rlm-guard` from running.
///
/// It sits next to the journal the lock protects, in the per-user state dir.
/// When no state dir can be resolved it falls back to `$XDG_RUNTIME_DIR`,
/// which is per-user and mode 0700. It never falls back to a shared,
/// world-writable dir such as `/tmp`, where another user could create and
/// hold the lock file to keep the guard from starting. `None` means neither
/// dir is known; the caller then runs without the lock.
pub fn lock_path() -> Option<PathBuf> {
    lock_path_from(dirs::state_dir(), dirs::runtime_dir())
}

fn lock_path_from(state: Option<PathBuf>, runtime: Option<PathBuf>) -> Option<PathBuf> {
    state
        .map(|d| d.join("rlm").join("rlm-guard.lock"))
        .or_else(|| runtime.map(|d| d.join("rlm-guard.lock")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_prefers_the_state_dir() {
        assert_eq!(
            lock_path_from(Some("/s".into()), Some("/r".into())),
            Some(PathBuf::from("/s/rlm/rlm-guard.lock"))
        );
    }

    #[test]
    fn lock_falls_back_to_the_runtime_dir_not_tmp() {
        assert_eq!(
            lock_path_from(None, Some("/run/user/1000".into())),
            Some(PathBuf::from("/run/user/1000/rlm-guard.lock"))
        );
        assert_eq!(lock_path_from(None, None), None);
    }
}

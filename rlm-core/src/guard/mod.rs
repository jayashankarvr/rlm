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

/// Path of a guard state file named `name`, in a per-user dir.
///
/// Prefers `$XDG_STATE_HOME/rlm` (`~/.local/state/rlm` by default), matching
/// the XDG-first convention `common::Config` uses for `config_dir()`. When no
/// state dir can be resolved (e.g. `$HOME` unset) it falls back to
/// `$XDG_RUNTIME_DIR/rlm`; that dir is per-user and mode 0700, and the
/// journal is boot_id-guarded, so losing it at reboot costs nothing. It never
/// falls back to a shared, world-writable dir such as `/tmp`, where another
/// user could pre-create or read the files. `None` means neither dir is known.
pub fn guard_file(name: &str) -> Option<PathBuf> {
    guard_file_from(dirs::state_dir(), dirs::runtime_dir(), name)
}

fn guard_file_from(
    state: Option<PathBuf>,
    runtime: Option<PathBuf>,
    name: &str,
) -> Option<PathBuf> {
    state.or(runtime).map(|d| d.join("rlm").join(name))
}

/// Path of the guard's write-ahead restore journal, or `None` when no
/// per-user dir is known (see [`guard_file`]). Without it the guard must not
/// freeze or cap, since it could not guarantee a restore.
pub fn try_journal_path() -> Option<PathBuf> {
    guard_file("guard-journal.jsonl")
}

/// [`try_journal_path`] for read-only callers such as `rlm guard status`.
/// Returns an empty path when no per-user dir is known; reading it finds
/// nothing, which is the right answer since no guard can have written it.
pub fn journal_path() -> PathBuf {
    try_journal_path().unwrap_or_default()
}

/// Path of the lock file that keeps a second `rlm-guard` from running. It
/// sits next to the journal it protects. `None` means no per-user dir is
/// known (see [`guard_file`]); the caller then runs without the lock.
pub fn lock_path() -> Option<PathBuf> {
    guard_file("rlm-guard.lock")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_files_prefer_the_state_dir() {
        assert_eq!(
            guard_file_from(Some("/s".into()), Some("/r".into()), "rlm-guard.lock"),
            Some(PathBuf::from("/s/rlm/rlm-guard.lock"))
        );
    }

    #[test]
    fn guard_files_fall_back_to_the_runtime_dir_not_tmp() {
        assert_eq!(
            guard_file_from(None, Some("/run/user/1000".into()), "guard-journal.jsonl"),
            Some(PathBuf::from("/run/user/1000/rlm/guard-journal.jsonl"))
        );
        assert_eq!(guard_file_from(None, None, "guard-journal.jsonl"), None);
    }

    #[test]
    fn journal_reader_path_is_empty_without_a_dir() {
        // An empty path reads as missing; it is never under /tmp.
        let p = try_journal_path().unwrap_or_default();
        assert!(!p.starts_with("/tmp"), "{p:?}");
        assert!(Journal::read_entries(&PathBuf::new(), "boot").is_empty());
    }
}

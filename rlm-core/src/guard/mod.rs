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
pub mod notify;
pub mod policy;
pub mod report;
pub mod resolve;
pub mod sampler;
pub mod service;
pub mod systemd;
pub mod types;

pub use effector::{Applied, Effector};
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
/// `$XDG_RUNTIME_DIR/rlm`, but only when that dir is owned by us and not group
/// or world writable (see [`private_runtime_dir`]). The journal is
/// boot_id-guarded, so losing it at reboot costs nothing. It never falls back
/// to a shared, world-writable dir such as `/tmp`, where another user could
/// pre-create or read the files. `None` means neither dir is usable.
pub fn guard_file(name: &str) -> Option<PathBuf> {
    let state = dirs::state_dir();
    let runtime = if state.is_none() {
        private_runtime_dir()
    } else {
        None
    };
    guard_file_from(state, runtime, name)
}

/// `$XDG_RUNTIME_DIR`, or `None` when it is unset or not private to us: not
/// owned by our uid, or group or world writable. A rejected dir is logged once.
fn private_runtime_dir() -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    static WARNED: std::sync::Once = std::sync::Once::new();
    let dir = dirs::runtime_dir()?;
    let uid = crate::process::current_uid();
    match std::fs::metadata(&dir) {
        Ok(m) if runtime_dir_is_private(m.uid(), m.mode(), uid) => Some(dir),
        Ok(m) => {
            WARNED.call_once(|| {
                tracing::warn!(
                    "ignoring XDG_RUNTIME_DIR {}: owner uid {} mode {:o}, expected owner {} \
                     and not group or world writable",
                    dir.display(),
                    m.uid(),
                    m.mode() & 0o7777,
                    uid
                )
            });
            None
        }
        Err(e) => {
            WARNED.call_once(|| tracing::warn!("ignoring XDG_RUNTIME_DIR {}: {e}", dir.display()));
            None
        }
    }
}

/// Whether a runtime dir with this owner and mode is safe for guard files.
fn runtime_dir_is_private(owner: u32, mode: u32, uid: u32) -> bool {
    owner == uid && mode & 0o022 == 0
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
    fn runtime_dir_is_used_only_when_private_to_us() {
        assert!(runtime_dir_is_private(1000, 0o40700, 1000));
        assert!(runtime_dir_is_private(1000, 0o40750, 1000));
        // Owned by someone else.
        assert!(!runtime_dir_is_private(0, 0o40700, 1000));
        // Group or world writable.
        assert!(!runtime_dir_is_private(1000, 0o40770, 1000));
        assert!(!runtime_dir_is_private(1000, 0o40702, 1000));
        assert!(!runtime_dir_is_private(1000, 0o41777, 1000));
    }

    #[test]
    fn journal_reader_path_is_empty_without_a_dir() {
        // An empty path reads as missing; it is never under /tmp.
        let p = try_journal_path().unwrap_or_default();
        assert!(!p.starts_with("/tmp"), "{p:?}");
        assert!(Journal::read_entries(&PathBuf::new(), "boot").is_empty());
    }
}

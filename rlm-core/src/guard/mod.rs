//! Freeze-guard engine: watch memory pressure and proactively freeze/soft-cap
//! the user's biggest non-protected process before the system locks up, healing
//! itself once pressure clears. Pure engine + sampler live here; the daemon loop
//! lives in the `rlm-guard` binary.

use std::path::PathBuf;

pub mod cgfs;
pub mod effector;
pub mod journal;
pub mod policy;
pub mod resolve;
pub mod sampler;
pub mod systemd;
pub mod types;

pub use effector::Effector;
pub use journal::Journal;
pub use policy::PolicyEngine;
pub use sampler::Sampler;
pub use systemd::SystemdUser;
pub use types::{Action, Intervention, Level, ProcInfo, Sample};

/// Default path for the guard's write-ahead restore journal.
///
/// Prefers `$XDG_STATE_HOME` (`~/.local/state` by default), matching the
/// XDG-first convention `common::Config` already uses for `config_dir()`.
/// Falls back to `/tmp/rlm` on the rare system where no state dir can be
/// resolved (e.g. `$HOME` unset) — the journal is still boot_id-guarded, so a
/// non-persistent fallback location only costs us WAL recovery across a
/// reboot in that degraded case, not correctness.
pub fn journal_path() -> PathBuf {
    dirs::state_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("rlm")
        .join("guard-journal.jsonl")
}

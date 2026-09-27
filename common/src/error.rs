use std::path::PathBuf;

/// Instructions to enable cgroup delegation for the calling user, shared by
/// every error and hint that needs to explain the fix.
pub const DELEGATION_HINT: &str = "enable cgroup delegation (then log out and back in):\n  sudo mkdir -p /etc/systemd/system/user@.service.d\n  printf '[Service]\\nDelegate=cpu memory io\\n' | sudo tee /etc/systemd/system/user@.service.d/rlm-delegate.conf\n  sudo systemctl daemon-reload";

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("process with pid {0} not found (process may have exited)")]
    ProcessNotFound(u32),

    #[error("no process found matching '{0}'\n  hint: check the name with: pgrep -a {0}")]
    ProcessNameNotFound(String),

    #[error("cgroup operation failed: {0}")]
    Cgroup(String),

    #[error("invalid memory value: {0}\n  hint: use format like '512M', '2G', or '1024' (bytes)")]
    InvalidMemory(String),

    #[error("invalid cpu value: {0}\n  hint: use percentage like '50%' or '150%' (for 1.5 cores)")]
    InvalidCpu(String),

    #[error("invalid arguments: {0}")]
    InvalidArgs(String),

    #[error("permission denied: {path}\n  hint: {hint}", hint = DELEGATION_HINT)]
    PermissionDenied { path: PathBuf },

    #[error("cgroups v2 not available at {0}\n  hint: ensure your kernel supports cgroups v2 (Linux 4.5+) and it's mounted")]
    CgroupsV2NotAvailable(PathBuf),

    #[error("config error: {0}")]
    Config(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

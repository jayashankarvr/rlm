use common::{CpuLimit, Error, IoLimit, Limit, MemoryLimit, Result};
use std::fs;
use std::path::{Path, PathBuf};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Sanitize cgroup name to prevent path traversal attacks.
/// Only allows alphanumeric characters, dashes, and underscores.
fn sanitize_cgroup_name(name: &str) -> Result<&str> {
    // Reject empty names
    if name.is_empty() {
        return Err(Error::InvalidArgs("cgroup name cannot be empty".into()));
    }

    // Reject path traversal attempts
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(Error::InvalidArgs(
            "cgroup name contains invalid characters".into(),
        ));
    }

    // Validate characters: alphanumeric, dash, underscore only
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Error::InvalidArgs(
            "cgroup name must contain only alphanumeric characters, dashes, or underscores".into(),
        ));
    }

    Ok(name)
}

pub struct CgroupManager {
    base_path: PathBuf,
}

impl CgroupManager {
    pub fn new() -> Result<Self> {
        // Verify cgroups v2 is available
        let controllers_path = PathBuf::from(CGROUP_ROOT).join("cgroup.controllers");
        if !controllers_path.exists() {
            return Err(Error::CgroupsV2NotAvailable(PathBuf::from(CGROUP_ROOT)));
        }

        // Try to find a suitable cgroup path with delegated controllers
        let base_path = Self::find_delegated_cgroup()?;

        Ok(Self { base_path })
    }

    /// Find a cgroup path where we have write access and controllers are delegated
    fn find_delegated_cgroup() -> Result<PathBuf> {
        // First, try user's systemd scope (for non-root with systemd)
        if let Ok(uid) = std::env::var("UID").or_else(|_| {
            // Fallback: read from /proc/self/status
            fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|s| {
                    s.lines()
                        .find(|l| l.starts_with("Uid:"))
                        .and_then(|l| l.split_whitespace().nth(1))
                        .map(String::from)
                })
                .ok_or(std::env::VarError::NotPresent)
        }) {
            let user_slice = PathBuf::from(CGROUP_ROOT).join(format!(
                "user.slice/user-{uid}.slice/user@{uid}.service/rlm"
            ));

            if let Some(parent) = user_slice.parent() {
                if parent.exists() {
                    return Ok(user_slice);
                }
            }
        }

        // Fallback: try directly under cgroup root (requires root or delegation)
        let root_path = PathBuf::from(CGROUP_ROOT).join("rlm");
        Ok(root_path)
    }

    /// Get the base path (for testing/status)
    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    /// Create a cgroup for a process and set limits BEFORE adding the process
    /// Returns the cgroup path for later cleanup
    pub fn prepare_cgroup(&self, name: &str, limit: &Limit) -> Result<PathBuf> {
        // Sanitize name to prevent path traversal
        let safe_name = sanitize_cgroup_name(name)?;
        let cgroup_path = self.base_path.join(safe_name);
        self.create_cgroup(&cgroup_path)?;
        self.set_limits(&cgroup_path, limit)?;
        Ok(cgroup_path)
    }

    /// Set limits on an existing cgroup
    fn set_limits(&self, cgroup_path: &Path, limit: &Limit) -> Result<()> {
        if let Some(mem) = &limit.memory {
            self.set_memory_limit(cgroup_path, *mem)?;
        }

        if let Some(cpu) = &limit.cpu {
            self.set_cpu_limit(cgroup_path, *cpu)?;
        }

        if let Some(io) = &limit.io {
            if !io.is_empty() {
                self.set_io_limit(cgroup_path, *io)?;
            }
        }

        Ok(())
    }

    /// Add a process to an existing cgroup
    pub fn add_to_cgroup(&self, cgroup_path: &Path, pid: u32) -> Result<()> {
        self.add_process(cgroup_path, pid)?;
        tracing::info!(pid, ?cgroup_path, "added process to cgroup");
        Ok(())
    }

    /// Find if a PID is already in an rlm-managed cgroup
    pub fn find_cgroup_for_pid(&self, pid: u32) -> Option<String> {
        let entries = fs::read_dir(&self.base_path).ok()?;

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let procs_file = path.join("cgroup.procs");
            if let Ok(content) = fs::read_to_string(&procs_file) {
                for line in content.lines() {
                    if line.trim().parse::<u32>().ok() == Some(pid) {
                        return path.file_name()?.to_str().map(String::from);
                    }
                }
            }
        }
        None
    }

    /// Apply resource limits to a process (creates cgroup and adds process)
    pub fn apply_limit(&self, pid: u32, limit: &Limit) -> Result<()> {
        // Check if process is already managed
        if let Some(existing_cgroup) = self.find_cgroup_for_pid(pid) {
            // If it's in a pid-{pid} cgroup, update the limits
            if existing_cgroup == format!("pid-{pid}") {
                let cgroup_path = self.base_path.join(&existing_cgroup);
                self.set_limits(&cgroup_path, limit)?;
                tracing::info!(pid, "updated existing limits");
                return Ok(());
            }
            // Process is in a different cgroup (run-* or gtk-*)
            return Err(Error::InvalidArgs(format!(
                "process {} is already managed in cgroup '{}'",
                pid, existing_cgroup
            )));
        }

        let cgroup_path = self.prepare_cgroup(&format!("pid-{pid}"), limit)?;

        // Try to add process - if it fails because process doesn't exist,
        // clean up the cgroup and return appropriate error
        if let Err(e) = self.add_process(&cgroup_path, pid) {
            // Clean up the cgroup we just created
            let _ = self.cleanup_cgroup(&format!("pid-{pid}"));
            // Check if process exists to give better error message
            if !PathBuf::from(format!("/proc/{pid}")).exists() {
                return Err(Error::ProcessNotFound(pid));
            }
            return Err(e);
        }

        tracing::info!(pid, ?cgroup_path, "applied limits");
        Ok(())
    }

    /// Remove limits from a process
    pub fn remove_limit(&self, pid: u32) -> Result<()> {
        self.cleanup_cgroup(&format!("pid-{pid}"))
    }

    /// Clean up a cgroup by name (moves processes out and deletes cgroup)
    pub fn cleanup_cgroup(&self, name: &str) -> Result<()> {
        // Sanitize name to prevent path traversal
        let safe_name = sanitize_cgroup_name(name)?;
        let cgroup_path = self.base_path.join(safe_name);

        if !cgroup_path.exists() {
            return Ok(());
        }

        // Try to move processes out
        if let Ok(content) = fs::read_to_string(cgroup_path.join("cgroup.procs")) {
            let pids: Vec<u32> = content
                .lines()
                .filter_map(|l| l.trim().parse().ok())
                .collect();

            if !pids.is_empty() {
                // Create/use an "unlimit" leaf cgroup (no controllers = no limits)
                let unlimit_path = self.base_path.join("unlimit");
                let _ = fs::create_dir(&unlimit_path);
                let unlimit_procs = unlimit_path.join("cgroup.procs");

                for pid in pids {
                    if fs::write(&unlimit_procs, pid.to_string()).is_ok() {
                        tracing::debug!(pid, "moved process to unlimit cgroup");
                    } else {
                        // Fallback - reset limits in place
                        tracing::debug!(pid, "couldn't move process, resetting limits");
                        let _ = fs::write(cgroup_path.join("memory.max"), "max");
                        let _ = fs::write(cgroup_path.join("cpu.max"), "max");
                        let _ = fs::write(cgroup_path.join("io.max"), "");
                    }
                }
            }
        }

        // Try to remove the cgroup
        for _ in 0..3 {
            match fs::remove_dir(&cgroup_path) {
                Ok(()) => {
                    tracing::info!(?cgroup_path, "removed cgroup");
                    return Ok(());
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }

        Ok(())
    }

    fn create_cgroup(&self, path: &Path) -> Result<()> {
        // Ensure base path exists (create_dir_all is idempotent, avoids TOCTOU)
        if let Err(e) = fs::create_dir_all(&self.base_path) {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                return Err(Error::PermissionDenied {
                    path: self.base_path.clone(),
                });
            } else if e.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(e.into());
            }
        }

        // Enable controllers in base cgroup for child cgroups
        self.enable_controllers(&self.base_path)?;

        // Create cgroup directory (handle AlreadyExists to avoid TOCTOU)
        match fs::create_dir(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                Err(Error::PermissionDenied {
                    path: path.to_path_buf(),
                })
            }
            Err(e) => Err(e.into()),
        }
    }

    fn enable_controllers(&self, path: &Path) -> Result<()> {
        let subtree_control = path.join("cgroup.subtree_control");

        // Read available controllers first
        let controllers_file = path.join("cgroup.controllers");
        let available = fs::read_to_string(&controllers_file).unwrap_or_default();

        // Only enable controllers that are available
        let mut to_enable = Vec::new();
        for controller in ["memory", "cpu", "io"] {
            if available.contains(controller) {
                to_enable.push(format!("+{controller}"));
            }
        }

        if to_enable.is_empty() {
            return Err(Error::Cgroup(
                "no controllers available - run as root or configure cgroup delegation".into(),
            ));
        }

        fs::write(&subtree_control, to_enable.join(" ")).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                Error::Cgroup(
                    "cannot enable cgroup controllers - run as root or configure systemd cgroup delegation".into()
                )
            } else {
                Error::Cgroup(format!("failed to enable controllers: {e}"))
            }
        })?;

        Ok(())
    }

    fn set_memory_limit(&self, cgroup_path: &Path, limit: MemoryLimit) -> Result<()> {
        let memory_max = cgroup_path.join("memory.max");
        fs::write(&memory_max, limit.bytes().to_string())
            .map_err(|e| Error::Cgroup(format!("failed to set memory.max: {e}")))?;
        Ok(())
    }

    fn set_cpu_limit(&self, cgroup_path: &Path, limit: CpuLimit) -> Result<()> {
        // cpu.max format: "$QUOTA $PERIOD" (in microseconds)
        // e.g., "50000 100000" = 50% of one CPU
        // For multi-core: 200% = 200000 quota with 100000 period
        let period: u64 = 100_000; // 100ms
        let quota = u64::from(limit.percent())
            .checked_mul(period)
            .map(|v| v / 100)
            .ok_or_else(|| Error::InvalidCpu("CPU percentage too large".into()))?;

        let cpu_max = cgroup_path.join("cpu.max");
        fs::write(&cpu_max, format!("{quota} {period}"))
            .map_err(|e| Error::Cgroup(format!("failed to set cpu.max: {e}")))?;
        Ok(())
    }

    fn add_process(&self, cgroup_path: &Path, pid: u32) -> Result<()> {
        let procs = cgroup_path.join("cgroup.procs");
        fs::write(&procs, pid.to_string())
            .map_err(|e| Error::Cgroup(format!("failed to add process {pid}: {e}")))?;
        Ok(())
    }

    fn set_io_limit(&self, cgroup_path: &Path, limit: IoLimit) -> Result<()> {
        let io_max = cgroup_path.join("io.max");

        let devices = Self::get_real_block_devices()?;
        if devices.is_empty() {
            tracing::debug!("no block devices found for I/O limiting");
            return Ok(());
        }

        let mut content = String::new();
        for (major, minor) in devices {
            let mut line = format!("{major}:{minor}");
            if let Some(rbps) = limit.read_bps {
                line.push_str(&format!(" rbps={rbps}"));
            }
            if let Some(wbps) = limit.write_bps {
                line.push_str(&format!(" wbps={wbps}"));
            }
            content.push_str(&line);
            content.push('\n');
        }

        fs::write(&io_max, content)
            .map_err(|e| Error::Cgroup(format!("failed to set io.max: {e}")))?;
        Ok(())
    }

    /// Get real block devices (exclude loop, ram, etc.)
    fn get_real_block_devices() -> Result<Vec<(u32, u32)>> {
        let mut devices = Vec::new();

        let sys_block = Path::new("/sys/block");
        if !sys_block.exists() {
            return Ok(devices);
        }

        for entry in fs::read_dir(sys_block)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Skip virtual devices
            if name_str.starts_with("loop")
                || name_str.starts_with("ram")
                || name_str.starts_with("dm-")
                || name_str.starts_with("nbd")
                || name_str.starts_with("zram")
            {
                continue;
            }

            let dev_file = entry.path().join("dev");
            if let Ok(content) = fs::read_to_string(&dev_file) {
                if let Some((major, minor)) = content.trim().split_once(':') {
                    if let (Ok(major), Ok(minor)) = (major.parse(), minor.parse()) {
                        devices.push((major, minor));
                    }
                }
            }
        }

        Ok(devices)
    }
}

use common::{CpuLimit, Error, IoLimit, Limit, MemoryLimit, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Name of the shared, controller-free leaf cgroup that every `cleanup_cgroup`
/// (i.e. every `rlm unlimit`, `remove_limit`/`remove_application_limit`, and
/// `RuleAction::TeardownEmpty`) moves released processes into so the cgroup
/// being torn down can be emptied and removed. It is a grab-bag of unrelated
/// processes the user has explicitly released from rlm's control, so nothing
/// in rlm may treat it as an actionable target (see `status.rs` and
/// `guard/resolve.rs`).
pub const UNLIMIT_CGROUP_NAME: &str = "unlimit";

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

/// Refuse to limit init (PID 1). Constraining PID 1 (systemd/init) can wedge or
/// freeze the entire system — the opposite of what this tool is for.
fn reject_critical_pid(pid: u32) -> Result<()> {
    if pid <= 1 {
        return Err(Error::InvalidArgs(format!(
            "refusing to limit PID {pid} (init/system critical)"
        )));
    }
    Ok(())
}

/// Result of [`CgroupManager::prepare_cgroup`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    /// Absolute path of the cgroup directory.
    pub path: PathBuf,
    /// Whether this call created the directory (false when it already existed).
    pub created: bool,
    /// Non-fatal problems, such as I/O limits the kernel refused.
    pub warnings: Vec<String>,
}

/// One `io.max` line per device, e.g. `8:0 rbps=5242880 wbps=1048576`.
/// The kernel parses one device per write, so each line is written on its own.
pub fn io_max_lines(devices: &[(u32, u32)], limit: IoLimit) -> Vec<String> {
    devices
        .iter()
        .map(|(major, minor)| {
            let mut line = format!("{major}:{minor}");
            if let Some(rbps) = limit.read_bps {
                line.push_str(&format!(" rbps={rbps}"));
            }
            if let Some(wbps) = limit.write_bps {
                line.push_str(&format!(" wbps={wbps}"));
            }
            line
        })
        .collect()
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

        Ok(Self {
            base_path: Self::default_base_path(),
        })
    }

    /// A manager rooted at `base_path`, with no checks. For tests and
    /// diagnostics.
    pub fn at(base_path: PathBuf) -> Self {
        Self { base_path }
    }

    /// rlm's base cgroup: `user@UID.service/rlm` when the user's systemd
    /// service cgroup exists, else `/sys/fs/cgroup/rlm`.
    pub fn default_base_path() -> PathBuf {
        // Determine our real UID from the kernel via /proc/self/status — NOT from
        // the `$UID` environment variable, which is caller-controllable and must
        // not be allowed to steer which cgroup path we operate on. Parsing as u32
        // also guarantees the value can't inject path components.
        let uid = fs::read_to_string("/proc/self/status").ok().and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|u| u.parse::<u32>().ok())
        });

        // Try the user's systemd scope (for non-root with cgroup delegation).
        if let Some(uid) = uid {
            let user_slice = PathBuf::from(CGROUP_ROOT).join(format!(
                "user.slice/user-{uid}.slice/user@{uid}.service/rlm"
            ));

            if let Some(parent) = user_slice.parent() {
                if parent.exists() {
                    return user_slice;
                }
            }
        }

        // Fallback: try directly under cgroup root (requires root or delegation)
        PathBuf::from(CGROUP_ROOT).join("rlm")
    }

    /// Get the base path (for testing/status)
    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    /// Create a cgroup for a process and set limits BEFORE adding the process.
    /// If a memory or CPU limit cannot be set, a cgroup this call created is
    /// removed again; one that already existed is left alone, so a failed
    /// limit write never empties a cgroup that holds processes.
    pub fn prepare_cgroup(&self, name: &str, limit: &Limit) -> Result<Prepared> {
        // Sanitize name to prevent path traversal
        let safe_name = sanitize_cgroup_name(name)?;
        let path = self.base_path.join(safe_name);
        let created = self.create_cgroup(&path)?;
        match self.set_limits(&path, limit) {
            Ok(warnings) => Ok(Prepared {
                path,
                created,
                warnings,
            }),
            Err(e) => {
                if created {
                    let _ = self.cleanup_cgroup(safe_name);
                }
                Err(e)
            }
        }
    }

    /// Set limits on an existing cgroup. Memory and CPU failures are errors;
    /// I/O problems come back as warnings.
    fn set_limits(&self, cgroup_path: &Path, limit: &Limit) -> Result<Vec<String>> {
        if let Some(mem) = &limit.memory {
            self.set_memory_limit(cgroup_path, *mem)?;
        }

        if let Some(cpu) = &limit.cpu {
            self.set_cpu_limit(cgroup_path, *cpu)?;
        }

        let mut warnings = Vec::new();
        if let Some(io) = &limit.io {
            if !io.is_empty() {
                warnings = self.set_io_limit(cgroup_path, *io);
            }
        }

        Ok(warnings)
    }

    /// Build a [`Command`] that places the spawned child into `cgroup_path`
    /// *before* it execs the target program, so resource limits apply from the
    /// process's very first instruction.
    ///
    /// Without this, a process that allocates aggressively at startup could blow
    /// past the limit during the window between spawn and being added to the
    /// cgroup — exactly the freeze scenario this tool exists to prevent.
    ///
    /// Writing "0" to `cgroup.procs` from the post-fork, pre-exec child moves it
    /// into the cgroup. The file is opened in the parent so the closure performs
    /// only an async-signal-safe `write` to an already-open fd (no allocation, no
    /// locks). Placement is best-effort: on failure the process still launches,
    /// so callers should still call [`add_to_cgroup`](Self::add_to_cgroup) after
    /// spawn as a fallback. Add command arguments to the returned `Command`.
    pub fn placement_command(&self, cgroup_path: &Path, program: &str) -> Command {
        use std::os::unix::process::CommandExt;

        let mut cmd = Command::new(program);
        if let Ok(file) = fs::OpenOptions::new()
            .write(true)
            .open(cgroup_path.join("cgroup.procs"))
        {
            // SAFETY: the closure only writes a fixed byte slice to an already-open
            // file descriptor — an async-signal-safe operation that allocates
            // nothing and takes no locks. Errors are ignored (best-effort).
            unsafe {
                cmd.pre_exec(move || {
                    use std::io::Write;
                    let _ = (&file).write_all(b"0");
                    Ok(())
                });
            }
        }
        cmd
    }

    /// Add a process to an existing cgroup
    pub fn add_to_cgroup(&self, cgroup_path: &Path, pid: u32) -> Result<()> {
        self.add_process(cgroup_path, pid)?;
        tracing::info!(pid, ?cgroup_path, "added process to cgroup");
        Ok(())
    }

    /// Find if a PID is already in an rlm-managed cgroup. The `unlimit`
    /// bucket is not a managed cgroup, so released processes can be limited
    /// again.
    pub fn find_cgroup_for_pid(&self, pid: u32) -> Option<String> {
        let entries = fs::read_dir(&self.base_path).ok()?;

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() || entry.file_name() == UNLIMIT_CGROUP_NAME {
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

    /// Apply resource limits to a process (creates cgroup and adds process).
    /// Returns non-fatal warnings.
    pub fn apply_limit(&self, pid: u32, limit: &Limit) -> Result<Vec<String>> {
        reject_critical_pid(pid)?;

        // Check if process is already managed
        if let Some(existing_cgroup) = self.find_cgroup_for_pid(pid) {
            // If it's in a pid-{pid} cgroup, update the limits
            if existing_cgroup == format!("pid-{pid}") {
                let cgroup_path = self.base_path.join(&existing_cgroup);
                let warnings = self.set_limits(&cgroup_path, limit)?;
                tracing::info!(pid, "updated existing limits");
                return Ok(warnings);
            }
            // Process is in a different cgroup (run-* or gtk-*)
            return Err(Error::InvalidArgs(format!(
                "process {pid} is already limited in cgroup '{existing_cgroup}'; run rlm unlimit --pid {pid} first"
            )));
        }

        let Prepared {
            path: cgroup_path,
            warnings,
            ..
        } = self.prepare_cgroup(&format!("pid-{pid}"), limit)?;

        // Try to add process - if it fails because process doesn't exist,
        // clean up the cgroup and return appropriate error
        if let Err(e) = self.add_process(&cgroup_path, pid) {
            // Remove the cgroup again; it holds nothing we put there.
            let _ = self.remove_if_empty(&format!("pid-{pid}"));
            // Check if process exists to give better error message
            if !PathBuf::from(format!("/proc/{pid}")).exists() {
                return Err(Error::ProcessNotFound(pid));
            }
            return Err(e);
        }

        tracing::info!(pid, ?cgroup_path, "applied limits");
        Ok(warnings)
    }

    /// Apply resource limits to multiple processes (all share the same limit pool)
    /// All processes are added to a single cgroup, so they share the resource limits.
    /// For example, if you limit 10 processes to 4GB memory, they share 4GB total, not 4GB each.
    /// Returns non-fatal warnings, including PIDs that could not be added.
    pub fn apply_limit_to_multiple(
        &self,
        pids: &[u32],
        limit: &Limit,
        cgroup_name: &str,
    ) -> Result<Vec<String>> {
        if pids.is_empty() {
            return Err(Error::InvalidArgs("no processes specified".into()));
        }

        for pid in pids {
            reject_critical_pid(*pid)?;
        }

        // Sanitize cgroup name
        let safe_name = sanitize_cgroup_name(cgroup_name)?;

        // Check if any process is already managed
        for pid in pids {
            if let Some(existing_cgroup) = self.find_cgroup_for_pid(*pid) {
                // Allow if it's already in the same cgroup we're creating
                if existing_cgroup != safe_name {
                    return Err(Error::InvalidArgs(format!(
                        "process {pid} is already limited in cgroup '{existing_cgroup}'; run rlm unlimit --cgroup {existing_cgroup} first"
                    )));
                }
            }
        }

        // Create cgroup and set limits
        let Prepared {
            path: cgroup_path,
            created,
            mut warnings,
        } = self.prepare_cgroup(safe_name, limit)?;

        // Add all processes to the cgroup
        let mut failed_pids = Vec::new();
        for pid in pids {
            if let Err(e) = self.add_process(&cgroup_path, *pid) {
                tracing::warn!(pid, error = %e, "failed to add process to cgroup");
                failed_pids.push(*pid);
            } else {
                tracing::info!(pid, ?cgroup_path, "added process to shared cgroup");
            }
        }

        // If all processes failed, remove a cgroup this call created.
        if failed_pids.len() == pids.len() {
            if created {
                let _ = self.cleanup_cgroup(safe_name);
            }
            return Err(Error::InvalidArgs(
                "failed to add any processes to cgroup".into(),
            ));
        }

        // If some failed, report it but continue
        if !failed_pids.is_empty() {
            warnings.push(format!(
                "could not add {} of {} processes: {:?}",
                failed_pids.len(),
                pids.len(),
                failed_pids
            ));
        }

        Ok(warnings)
    }

    /// Remove limits from a process
    pub fn remove_limit(&self, pid: u32) -> Result<()> {
        self.cleanup_cgroup(&format!("pid-{pid}"))
    }

    /// Remove limits from an application cgroup (removes all processes in the cgroup)
    pub fn remove_application_limit(&self, cgroup_name: &str) -> Result<()> {
        self.cleanup_cgroup(cgroup_name)
    }

    /// Clean up a cgroup by name (moves processes out and deletes cgroup)
    pub fn cleanup_cgroup(&self, name: &str) -> Result<()> {
        // Sanitize name to prevent path traversal
        let safe_name = sanitize_cgroup_name(name)?;
        let cgroup_path = self.base_path.join(safe_name);

        if !cgroup_path.exists() {
            return Ok(());
        }

        // Move any processes out to the controller-free "unlimit" cgroup so this
        // cgroup becomes empty and can be removed.
        if let Ok(content) = fs::read_to_string(cgroup_path.join("cgroup.procs")) {
            let pids: Vec<u32> = content
                .lines()
                .filter_map(|l| l.trim().parse().ok())
                .collect();

            if !pids.is_empty() {
                // Create/use an "unlimit" leaf cgroup (no controllers = no limits)
                let unlimit_path = self.base_path.join(UNLIMIT_CGROUP_NAME);
                let _ = fs::create_dir(&unlimit_path);
                let unlimit_procs = unlimit_path.join("cgroup.procs");

                for pid in pids {
                    if fs::write(&unlimit_procs, pid.to_string()).is_ok() {
                        tracing::debug!(pid, "moved process to unlimit cgroup");
                    }
                }
            }
        }

        // Try to remove the (now hopefully empty) cgroup.
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

        // Removal failed. If processes are still inside (couldn't be moved out),
        // reset the limits in place so the caller's "remove limits" intent is
        // still satisfied — report success but warn that the cgroup lingers.
        let still_has_procs = fs::read_to_string(cgroup_path.join("cgroup.procs"))
            .map(|c| c.lines().any(|l| !l.trim().is_empty()))
            .unwrap_or(false);

        if still_has_procs {
            // Defensive: if this is a frozen guard cgroup we couldn't empty, at
            // least unfreeze it so its tasks are never stuck paused.
            let _ = fs::write(cgroup_path.join("cgroup.freeze"), "0");
            let _ = fs::write(cgroup_path.join("memory.high"), "max");
            let _ = fs::write(cgroup_path.join("memory.max"), "max");
            let _ = fs::write(cgroup_path.join("memory.swap.max"), "max");
            let _ = fs::write(cgroup_path.join("cpu.max"), "max");
            let _ = fs::write(cgroup_path.join("io.max"), "");
            tracing::warn!(
                ?cgroup_path,
                "could not remove cgroup (still has live processes); limits reset in place"
            );
            return Ok(());
        }

        // Empty but still not removable — a genuine failure the caller should see.
        Err(Error::Cgroup(format!(
            "failed to remove cgroup '{safe_name}'"
        )))
    }

    /// Whether the named child cgroup (or a descendant) holds a process, from
    /// its `cgroup.events`. `None` if unreadable.
    pub fn is_populated(&self, name: &str) -> Option<bool> {
        let content = fs::read_to_string(self.base_path.join(name).join("cgroup.events")).ok()?;
        crate::guard::cgfs::parse_populated(&content)
    }

    /// The `oom_kill` count from the named cgroup's `memory.events`.
    pub fn oom_kills(&self, name: &str) -> Option<u64> {
        let content = fs::read_to_string(self.base_path.join(name).join("memory.events")).ok()?;
        crate::guard::cgfs::parse_events_field(&content, "oom_kill")
    }

    /// The named cgroup's `memory.max` in bytes; `None` for `max` or unreadable.
    pub fn memory_max(&self, name: &str) -> Option<u64> {
        let content = fs::read_to_string(self.base_path.join(name).join("memory.max")).ok()?;
        content.trim().parse().ok()
    }

    /// Remove the named cgroup only if it holds no process. `Ok(false)` when
    /// it is populated; a cgroup that is already gone counts as removed.
    /// Never moves processes.
    pub fn remove_if_empty(&self, name: &str) -> Result<bool> {
        let safe_name = sanitize_cgroup_name(name)?;
        if self.is_populated(safe_name) == Some(true) {
            return Ok(false);
        }
        let path = self.base_path.join(safe_name);
        let mut last_err = None;
        for _ in 0..3 {
            match fs::remove_dir(&path) {
                Ok(()) => {
                    tracing::info!(?path, "removed empty cgroup");
                    return Ok(true);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
                Err(e) => {
                    last_err = Some(e);
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        }
        Err(Error::Cgroup(format!(
            "failed to remove cgroup '{safe_name}': {}",
            last_err.map(|e| e.to_string()).unwrap_or_default()
        )))
    }

    /// Whether a child cgroup with this name currently exists.
    pub fn cgroup_exists(&self, name: &str) -> bool {
        self.base_path.join(name).is_dir()
    }

    /// PIDs currently in the named child cgroup (empty if it doesn't exist).
    pub fn pids_in_cgroup(&self, name: &str) -> Vec<u32> {
        let procs = self.base_path.join(name).join("cgroup.procs");
        match fs::read_to_string(procs) {
            Ok(content) => content
                .lines()
                .filter_map(|l| l.trim().parse::<u32>().ok())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Startup recovery: thaw and clean up every leftover `guard-<pid>`
    /// cgroup so no process is left frozen after a prior crash.
    ///
    /// Legacy: pre-act-in-place `rlm-guard` builds moved a target process into
    /// its own `guard-<pid>` cgroup to freeze/cap it; the guard now acts in
    /// place on the process's existing cgroup (journal-backed, see
    /// `guard/effector.rs`) and never creates `guard-<pid>` cgroups itself.
    /// This sweep only exists to clean up leftovers from an upgrade across
    /// that change and can be removed after one release.
    pub fn sweep_guard_leftovers(&self) -> Result<()> {
        let Ok(entries) = fs::read_dir(&self.base_path) else {
            return Ok(());
        };
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if !name.starts_with("guard-") {
                continue;
            }
            // Always thaw first: a frozen task can't be migrated out, and we
            // must never leave a process stuck frozen even if the teardown
            // below fails.
            let _ = fs::write(entry.path().join("cgroup.freeze"), "0");
            let _ = self.cleanup_cgroup(&name);
        }
        Ok(())
    }

    /// Create the cgroup directory. `Ok(true)` only when this call created it.
    fn create_cgroup(&self, path: &Path) -> Result<bool> {
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
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
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
        let bytes = limit.bytes();

        // memory.high (~90%): soft limit that triggers reclaim/throttling before
        // the hard cap, giving the process a chance to free memory gracefully
        // instead of being killed outright. Best-effort.
        let high = bytes / 100 * 90;
        if high > 0 {
            let _ = fs::write(cgroup_path.join("memory.high"), high.to_string());
        }

        // memory.max: hard cap. Process is OOM-killed if it exceeds this.
        let memory_max = cgroup_path.join("memory.max");
        fs::write(&memory_max, bytes.to_string())
            .map_err(|e| Error::Cgroup(format!("failed to set memory.max: {e}")))?;

        // memory.swap.max=0: prevent the limited process from spilling to swap, so
        // memory.max is a true RAM ceiling rather than an invitation to thrash.
        // Best-effort: absent on kernels without swap accounting.
        let _ = fs::write(cgroup_path.join("memory.swap.max"), "0");

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

    /// Write `io.max` one device per write (the kernel rejects a multi-line
    /// write with EINVAL). Never fails: problems come back as warnings, since
    /// memory and CPU limits still apply without I/O throttling.
    fn set_io_limit(&self, cgroup_path: &Path, limit: IoLimit) -> Vec<String> {
        let devices = match Self::get_real_block_devices() {
            Ok(d) => d,
            Err(e) => {
                return vec![format!(
                    "I/O limits were not applied (could not list block devices: {e}); memory and CPU limits still apply"
                )]
            }
        };
        if devices.is_empty() {
            return vec![
                "I/O limits were not applied (no eligible block devices found); memory and CPU limits still apply"
                    .to_string(),
            ];
        }

        let io_max = cgroup_path.join("io.max");
        let mut warnings = Vec::new();
        let mut first_err = None;
        let mut applied = 0;
        for line in io_max_lines(&devices, limit) {
            match fs::write(&io_max, &line) {
                Ok(()) => applied += 1,
                Err(e) => {
                    let dev = line.split_whitespace().next().unwrap_or_default();
                    warnings.push(format!("I/O limit not applied to device {dev}: {e}"));
                    first_err.get_or_insert(e);
                }
            }
        }
        if applied == 0 {
            if let Some(e) = first_err {
                warnings = vec![format!(
                    "I/O limits were not applied to any device ({e}); memory and CPU limits still apply"
                )];
            }
        }
        for w in &warnings {
            tracing::warn!("{w}");
        }
        warnings
    }

    /// Get block devices eligible for I/O throttling.
    ///
    /// Note: device-mapper (`dm-*`) devices are intentionally included — on the
    /// very common LVM and LUKS-encrypted-root setups, filesystem I/O is issued
    /// to a dm device, so excluding them would silently disable I/O limiting.
    /// Only purely virtual/pseudo devices are skipped.
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

            // Skip virtual/pseudo devices that never carry real filesystem I/O.
            if name_str.starts_with("loop")
                || name_str.starts_with("ram")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_init_and_kernel_pids() {
        assert!(reject_critical_pid(0).is_err()); // kernel/swapper
        assert!(reject_critical_pid(1).is_err()); // init/systemd
    }

    #[test]
    fn allows_normal_pids() {
        assert!(reject_critical_pid(2).is_ok());
        assert!(reject_critical_pid(1234).is_ok());
    }

    #[test]
    fn sanitize_rejects_traversal_and_separators() {
        assert!(sanitize_cgroup_name("../etc").is_err());
        assert!(sanitize_cgroup_name("a/b").is_err());
        assert!(sanitize_cgroup_name("a\\b").is_err());
        assert!(sanitize_cgroup_name("").is_err());
        assert!(sanitize_cgroup_name("bad name").is_err()); // space
    }

    #[test]
    fn sanitize_accepts_valid_names() {
        assert_eq!(sanitize_cgroup_name("pid-1234").unwrap(), "pid-1234");
        assert_eq!(sanitize_cgroup_name("app_firefox").unwrap(), "app_firefox");
        assert_eq!(sanitize_cgroup_name("run-42-99").unwrap(), "run-42-99");
    }

    #[test]
    fn io_max_is_one_line_per_device_without_newlines() {
        let l = io_max_lines(
            &[(8, 0), (259, 0)],
            IoLimit {
                read_bps: Some(5_242_880),
                write_bps: Some(1_048_576),
            },
        );
        assert_eq!(
            l,
            vec![
                "8:0 rbps=5242880 wbps=1048576".to_string(),
                "259:0 rbps=5242880 wbps=1048576".to_string()
            ]
        );
    }

    #[test]
    fn released_processes_can_be_limited_again() {
        let dir = tempfile::tempdir().unwrap();
        for (name, procs) in [("unlimit", "4242\n"), ("pid-7", "7\n")] {
            std::fs::create_dir(dir.path().join(name)).unwrap();
            std::fs::write(dir.path().join(name).join("cgroup.procs"), procs).unwrap();
        }
        let m = CgroupManager::at(dir.path().to_path_buf());
        assert_eq!(
            m.find_cgroup_for_pid(4242),
            None,
            "the unlimit bucket is not a managed cgroup"
        );
        assert_eq!(m.find_cgroup_for_pid(7).as_deref(), Some("pid-7"));
    }

    #[test]
    fn populated_cgroup_is_not_removed() {
        let dir = tempfile::tempdir().unwrap();
        let cg = dir.path().join("run-1-2");
        std::fs::create_dir(&cg).unwrap();
        std::fs::write(cg.join("cgroup.events"), "populated 1\nfrozen 0\n").unwrap();
        let m = CgroupManager::at(dir.path().to_path_buf());
        assert_eq!(m.is_populated("run-1-2"), Some(true));
        assert!(!m.remove_if_empty("run-1-2").unwrap());
        assert!(cg.exists());
    }

    #[test]
    fn oom_kills_and_memory_max_are_read() {
        let dir = tempfile::tempdir().unwrap();
        let cg = dir.path().join("run-1-2");
        std::fs::create_dir(&cg).unwrap();
        std::fs::write(
            cg.join("memory.events"),
            "low 0\nhigh 3\nmax 10\noom 1\noom_kill 2\n",
        )
        .unwrap();
        std::fs::write(cg.join("memory.max"), "157286400\n").unwrap();
        let m = CgroupManager::at(dir.path().to_path_buf());
        assert_eq!(m.oom_kills("run-1-2"), Some(2));
        assert_eq!(m.memory_max("run-1-2"), Some(157_286_400));
    }
}

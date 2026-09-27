use common::{Error, Result};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Basic process info
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    /// comm, from /proc/<pid>/status `Name:` (kernel-truncated to 15 chars).
    pub name: String,
    pub ppid: Option<u32>,
    pub session: Option<u32>,
    pub executable: Option<PathBuf>,
    /// Real uid, from /proc/<pid>/status `Uid:`.
    pub uid: u32,
    /// VmRSS + VmSwap, in KB.
    pub rss_kb: u64,
    /// The v2 ("0::") cgroup path from /proc/<pid>/cgroup, if readable.
    pub cgroup: Option<String>,
}

impl ProcessInfo {
    /// Basename of `executable`, if set and valid UTF-8, without the
    /// ` (deleted)` suffix the kernel adds after the binary was replaced
    /// (e.g. by a package upgrade).
    pub fn exe_name(&self) -> Option<&str> {
        let name = self.executable.as_deref()?.file_name()?.to_str()?;
        Some(name.strip_suffix(" (deleted)").unwrap_or(name))
    }

    /// The executable's basename when readable (not truncated by the
    /// kernel); falls back to `name` (comm) otherwise.
    pub fn display_name(&self) -> &str {
        self.exe_name().unwrap_or(&self.name)
    }
}

/// The fields of /proc/<pid>/status this crate cares about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusFields {
    pub uid: u32,
    pub name: String,
    pub rss_kb: u64,
}

/// Parse `/proc/<pid>/status`.
///
/// - `Uid:` line is `Uid:\t<real>\t<effective>\t<saved>\t<fs>`; we take the
///   first (real) field.
/// - `Name:` is the comm, truncated to 15 chars by the kernel; that is fine:
///   it matches the protect-list which also compares against comm.
/// - `VmSwap:` may be absent (e.g. kernel thread / no swap) and then counts as 0.
///
/// Returns `None` only if the required `Uid:` or `Name:` lines are missing.
pub fn parse_status(status: &str) -> Option<StatusFields> {
    let mut uid = None;
    let mut name = None;
    let mut vm_rss = 0u64;
    let mut vm_swap = 0u64;

    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Name:") {
            name = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("Uid:") {
            // First whitespace-separated field is the real uid.
            uid = rest.split_whitespace().next().and_then(|v| v.parse().ok());
        } else if let Some(rest) = line.strip_prefix("VmRSS:") {
            vm_rss = first_kb(rest).unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("VmSwap:") {
            vm_swap = first_kb(rest).unwrap_or(0);
        }
    }

    Some(StatusFields {
        uid: uid?,
        name: name?,
        rss_kb: vm_rss.saturating_add(vm_swap),
    })
}

/// Parse the leading integer of a `"   1234 kB"` style value as a kB count.
fn first_kb(rest: &str) -> Option<u64> {
    rest.split_whitespace().next()?.parse().ok()
}

/// Parse the v2 line of /proc/<pid>/cgroup ("0::<path>"). Hybrid-mode lines
/// for other controllers are noise and skipped.
pub fn parse_cgroup_v2(content: &str) -> Option<String> {
    content
        .lines()
        .find_map(|l| l.strip_prefix("0::").map(|p| p.to_string()))
}

/// The calling process's real uid.
pub fn current_uid() -> u32 {
    // SAFETY: getuid() is always safe; it only reads our real UID.
    unsafe { libc::getuid() }
}

/// Extended process info with grouping information
pub struct ProcessGroup {
    pub name: String,
    pub executable: Option<PathBuf>,
    pub processes: Vec<ProcessInfo>,
}

/// Read process stat file to get PPID and session
fn read_process_stat(proc_path: &Path) -> Option<(u32, u32)> {
    // Format: pid comm state ppid pgrp session ...
    // Fields: 0   1    2     3    4    5
    if let Ok(content) = fs::read_to_string(proc_path.join("stat")) {
        let parts: Vec<&str> = content.split_whitespace().collect();
        if parts.len() >= 6 {
            if let (Ok(ppid), Ok(session)) = (parts[3].parse(), parts[5].parse()) {
                return Some((ppid, session));
            }
        }
    }
    None
}

/// Get executable path for a process
fn get_executable(proc_path: &Path) -> Option<PathBuf> {
    fs::read_link(proc_path.join("exe")).ok()
}

/// Read the full `ProcessInfo` snapshot for one pid. `status` is required
/// (its `Uid:`/`Name:` fields anchor the snapshot); `stat`, `exe`, and
/// `cgroup` are each best-effort and simply left at their default/`None` if
/// unreadable (e.g. the process exited mid-read, or `exe` requires
/// permissions we don't have). Returns `None` only if `status` can't be read
/// or parsed.
pub fn read_process(pid: u32) -> Option<ProcessInfo> {
    let proc_path = Path::new("/proc").join(pid.to_string());

    let status = fs::read_to_string(proc_path.join("status")).ok()?;
    let fields = parse_status(&status)?;

    let (ppid, session) = read_process_stat(&proc_path).unwrap_or((0, 0));
    let executable = get_executable(&proc_path);
    let cgroup = fs::read_to_string(proc_path.join("cgroup"))
        .ok()
        .and_then(|c| parse_cgroup_v2(&c));

    Some(ProcessInfo {
        pid,
        name: fields.name,
        ppid: if ppid > 0 { Some(ppid) } else { None },
        session: if session > 0 { Some(session) } else { None },
        executable,
        uid: fields.uid,
        rss_kb: fields.rss_kb,
        cgroup,
    })
}

/// List all running processes with extended information
pub fn list_all() -> Result<Vec<ProcessInfo>> {
    let mut processes = Vec::new();

    for entry in fs::read_dir("/proc")?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };

        if let Some(p) = read_process(pid) {
            processes.push(p);
        }
    }

    processes.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(processes)
}

/// List processes owned by `uid`. A cheap `stat()` pre-filter (comparing the
/// `/proc/<pid>` directory's owning uid) skips reading any file belonging to
/// another user's process before `read_process` opens `status`/`stat`/`exe`.
pub fn list_for_uid(uid: u32) -> Result<Vec<ProcessInfo>> {
    use std::os::unix::fs::MetadataExt;
    let mut out = Vec::new();
    for entry in fs::read_dir("/proc")?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        // Cheap pre-filter: one stat() before reading any file of another user's process.
        if entry.metadata().ok().map(|m| m.uid()) != Some(uid) {
            continue;
        }
        if let Some(p) = read_process(pid) {
            if p.uid == uid {
                out.push(p);
            }
        }
    }
    Ok(out)
}

/// Find all PIDs matching a process name
pub fn find_by_name(name: &str) -> Result<Vec<u32>> {
    let mut pids = Vec::new();

    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let path = entry.path();

        // Only look at numeric directories (PIDs)
        let Some(pid_str) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };

        if matches_name(&path, name) {
            pids.push(pid);
        }
    }

    if pids.is_empty() {
        return Err(Error::ProcessNameNotFound(name.to_string()));
    }

    Ok(pids)
}

fn matches_name(proc_path: &Path, name: &str) -> bool {
    // Try /proc/PID/comm first (max 15 chars, may be truncated)
    if let Ok(comm) = fs::read_to_string(proc_path.join("comm")) {
        let comm = comm.trim();
        if comm == name {
            return true;
        }
        // comm is 15 chars (possibly truncated) and name is longer - verify via exe
        if comm.len() == 15 && name.len() > 15 && name.starts_with(comm) {
            if let Ok(exe) = fs::read_link(proc_path.join("exe")) {
                if let Some(exe_name) = exe.file_name().and_then(|n| n.to_str()) {
                    return exe_name == name;
                }
            }
        }
    }

    // Try /proc/PID/exe symlink (full path)
    if let Ok(exe) = fs::read_link(proc_path.join("exe")) {
        if let Some(exe_name) = exe.file_name().and_then(|n| n.to_str()) {
            if exe_name == name {
                return true;
            }
        }
    }

    false
}

/// Result of [`find_by_name_for_uid`]: matches owned by the requested uid,
/// plus a count of matches owned by other users (so the caller can tell "no
/// such process" apart from "that process belongs to someone else").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameMatches {
    pub pids: Vec<u32>,
    pub other_users: usize,
}

/// Find all PIDs matching `name`, split by ownership. Only errors
/// (`ProcessNameNotFound`) when there are no matches at all, own-uid or
/// otherwise.
pub fn find_by_name_for_uid(name: &str, uid: u32) -> Result<NameMatches> {
    use std::os::unix::fs::MetadataExt;

    let mut pids = Vec::new();
    let mut other_users = 0usize;

    for entry in fs::read_dir("/proc")?.flatten() {
        let path = entry.path();

        let Some(pid) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };

        if !matches_name(&path, name) {
            continue;
        }

        let Ok(owner_uid) = entry.metadata().map(|m| m.uid()) else {
            continue;
        };

        if owner_uid == uid {
            pids.push(pid);
        } else {
            other_users += 1;
        }
    }

    if pids.is_empty() && other_users == 0 {
        return Err(Error::ProcessNameNotFound(name.to_string()));
    }

    Ok(NameMatches { pids, other_users })
}

/// Group processes by executable basename (same application). Apps with a
/// single process get a group of their own.
pub fn group_by_executable(processes: &[ProcessInfo]) -> Vec<ProcessGroup> {
    let mut groups: HashMap<String, Vec<ProcessInfo>> = HashMap::new();

    for proc in processes {
        let key = proc
            .executable
            .as_ref()
            .and_then(|exe| exe.file_name())
            .and_then(|n| n.to_str())
            .map(String::from)
            .unwrap_or_else(|| proc.name.clone());

        groups.entry(key).or_default().push(proc.clone());
    }

    let mut groups: Vec<ProcessGroup> = groups
        .into_iter()
        .map(|(name, procs)| {
            let executable = procs.first().and_then(|p| p.executable.clone());
            ProcessGroup {
                name,
                executable,
                processes: procs,
            }
        })
        .collect();
    groups.sort_by(|a, b| {
        b.processes
            .len()
            .cmp(&a.processes.len())
            .then_with(|| a.name.cmp(&b.name))
    });
    groups
}

/// Group processes by session ID (same process group)
pub fn group_by_session(processes: &[ProcessInfo]) -> Vec<ProcessGroup> {
    let mut groups: HashMap<u32, Vec<ProcessInfo>> = HashMap::new();

    for proc in processes {
        if let Some(session) = proc.session {
            groups.entry(session).or_default().push(proc.clone());
        }
    }

    groups
        .into_iter()
        .map(|(session_id, procs)| {
            let name = procs
                .first()
                .map(|p| format!("{} (session {})", p.name, session_id))
                .unwrap_or_else(|| format!("Session {}", session_id));
            let executable = procs.first().and_then(|p| p.executable.clone());
            ProcessGroup {
                name,
                executable,
                processes: procs,
            }
        })
        .filter(|group| group.processes.len() > 1)
        .collect()
}

/// Find all processes that share the same parent process tree
/// Returns processes that are descendants of the given PID
pub fn find_process_tree(root_pid: u32) -> Result<Vec<u32>> {
    let all_processes = list_all()?;
    let mut result = vec![root_pid];
    let mut to_check = vec![root_pid];
    let mut checked = std::collections::HashSet::new();
    checked.insert(root_pid);

    while let Some(pid) = to_check.pop() {
        // Find all processes with this PID as parent
        for proc in &all_processes {
            if let Some(ppid) = proc.ppid {
                if ppid == pid && !checked.contains(&proc.pid) {
                    result.push(proc.pid);
                    to_check.push(proc.pid);
                    checked.insert(proc.pid);
                }
            }
        }
    }

    Ok(result)
}

/// Find all processes matching an executable name (all instances)
pub fn find_all_by_executable(executable_name: &str) -> Result<Vec<ProcessInfo>> {
    let all = list_all()?;
    let mut matches = Vec::new();

    for proc in all {
        let matches_name = proc.name == executable_name
            || proc
                .executable
                .as_ref()
                .and_then(|exe| exe.file_name())
                .and_then(|n| n.to_str())
                .map(|n| n == executable_name)
                .unwrap_or(false);

        if matches_name {
            matches.push(proc);
        }
    }

    if matches.is_empty() {
        return Err(Error::ProcessNameNotFound(executable_name.to_string()));
    }

    Ok(matches)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_status_reads_uid_name_and_rss_plus_swap() {
        let s = "Name:\tIsolated Web Co\nUid:\t1000\t1000\t1000\t1000\nVmRSS:\t  500000 kB\nVmSwap:\t   2000 kB\n";
        assert_eq!(
            parse_status(s),
            Some(StatusFields {
                uid: 1000,
                name: "Isolated Web Co".into(),
                rss_kb: 502_000
            })
        );
    }

    #[test]
    fn parse_status_requires_uid_and_name() {
        assert_eq!(parse_status("VmRSS:\t1 kB\n"), None);
        assert_eq!(parse_status("Name:\tx\n"), None);
    }

    #[test]
    fn parse_cgroup_v2_skips_hybrid_lines() {
        assert_eq!(
            parse_cgroup_v2("1:name=systemd:/foo\n0::/bar\n"),
            Some("/bar".into())
        );
        assert_eq!(parse_cgroup_v2(""), None);
    }

    #[test]
    fn list_for_uid_contains_self_and_only_that_uid() {
        let uid = current_uid();
        let procs = list_for_uid(uid).unwrap();
        let me = procs
            .iter()
            .find(|p| p.pid == std::process::id())
            .expect("own process listed");
        assert!(me.cgroup.is_some(), "cgroup path read");
        assert!(me.rss_kb > 0, "rss read");
        assert!(procs.iter().all(|p| p.uid == uid));
    }

    #[test]
    fn display_name_prefers_exe_basename() {
        let p = ProcessInfo {
            name: "Isolated Web Co".into(),
            executable: Some(PathBuf::from("/usr/lib/firefox/firefox")),
            ..Default::default()
        };
        assert_eq!(p.display_name(), "firefox");
        let q = ProcessInfo {
            name: "kworker".into(),
            ..Default::default()
        };
        assert_eq!(q.display_name(), "kworker");
    }

    #[test]
    fn exe_name_ignores_deleted_suffix() {
        let p = ProcessInfo {
            executable: Some(PathBuf::from("/opt/google/chrome/chrome (deleted)")),
            ..Default::default()
        };
        assert_eq!(p.exe_name(), Some("chrome"));
    }

    #[test]
    fn groups_are_ordered_by_size_then_name() {
        let p = |pid: u32, exe: &str| ProcessInfo {
            pid,
            name: exe.into(),
            executable: Some(format!("/bin/{exe}").into()),
            ..Default::default()
        };
        let procs = vec![
            p(1, "b"),
            p(2, "b"),
            p(3, "a"),
            p(4, "a"),
            p(5, "c"),
            p(6, "c"),
            p(7, "c"),
            p(8, "d"),
        ];
        let names: Vec<String> = group_by_executable(&procs)
            .into_iter()
            .map(|g| g.name)
            .collect();
        // Single-process apps are listed too.
        assert_eq!(names, vec!["c", "a", "b", "d"]);
    }
}

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use common::Result;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Convert a cgroup path (relative to /sys/fs/cgroup) to an absolute path.
/// All paths passed to this module are relative to /sys/fs/cgroup (same convention as Resolution.cgroup).
/// Handles both absolute-style paths (starting with '/') and relative paths.
pub fn abs(cg: &str) -> PathBuf {
    let clean = cg.strip_prefix('/').unwrap_or(cg);
    PathBuf::from(CGROUP_ROOT).join(clean)
}

/// Read the frozen state from cgroup.events.
/// Returns Some(true) if frozen, Some(false) if not, None if not readable.
pub fn read_frozen(cg: &str) -> Option<bool> {
    let content = fs::read_to_string(abs(cg).join("cgroup.events")).ok()?;
    parse_frozen(&content)
}

/// Freeze or unfreeze a cgroup (write to cgroup.freeze).
pub fn write_freeze(cg: &str, on: bool) -> Result<()> {
    let value = if on { "1" } else { "0" };
    fs::write(abs(cg).join("cgroup.freeze"), value)
        .map_err(|e| common::Error::Cgroup(format!("failed to write cgroup.freeze: {e}")))?;
    Ok(())
}

/// Read memory.high value (verbatim, trimmed: either "max" or bytes).
pub fn read_high(cg: &str) -> Option<String> {
    fs::read_to_string(abs(cg).join("memory.high"))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Write memory.high value.
pub fn write_high(cg: &str, val: &str) -> Result<()> {
    fs::write(abs(cg).join("memory.high"), val)
        .map_err(|e| common::Error::Cgroup(format!("failed to write memory.high: {e}")))?;
    Ok(())
}

/// Get total anonymous + swap memory (anon from memory.stat + memory.swap.current).
pub fn anon_swap_bytes(cg: &str) -> Option<u64> {
    let stat = fs::read_to_string(abs(cg).join("memory.stat")).ok()?;
    let anon = parse_anon(&stat)?;
    let swap = fs::read_to_string(abs(cg).join("memory.swap.current"))
        .ok()?
        .trim()
        .parse::<u64>()
        .unwrap_or(0);
    Some(anon + swap)
}

/// Get the inode number of the cgroup directory.
pub fn dir_inode(cg: &str) -> Option<u64> {
    let metadata = fs::metadata(abs(cg)).ok()?;
    Some(metadata.ino())
}

/// Get all PIDs currently in the cgroup (reads cgroup.procs).
pub fn pids_in(cg: &str) -> Vec<u32> {
    match fs::read_to_string(abs(cg).join("cgroup.procs")) {
        Ok(content) => content
            .lines()
            .filter_map(|line| line.trim().parse::<u32>().ok())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Get all PIDs in the cgroup AND every descendant cgroup (recursive
/// `cgroup.procs` scan). `cgroup.freeze` and systemd's `FreezeUnit`/unit-stop
/// both propagate to the whole subtree, so a protect-check that only sees
/// the candidate directory's own `cgroup.procs` (via [`pids_in`]) would miss
/// a protected process one level down (a shell in a terminal scope's child
/// cgroup, a nested `systemd-run`, an app-created sub-cgroup) and wrongly
/// clear it to freeze. Unlike `pids_in`, this is the membership view that
/// must back any freeze/protect decision. `pids_in` is left unchanged —
/// other callers (e.g. inode/liveness checks) rely on its exact-directory
/// semantics.
pub fn pids_under(cg: &str) -> Vec<u32> {
    let mut out = Vec::new();
    collect_pids_recursive(&abs(cg), &mut out);
    out
}

/// Recursive helper for [`pids_under`]. Reads `cgroup.procs` in `dir`, then
/// descends into every subdirectory. Unreadable directories/files are
/// skipped, not fatal (a cgroup can vanish mid-walk). Does not follow
/// symlinks — `DirEntry::file_type` reports the on-disk type without
/// dereferencing, and only entries reporting as directories are recursed
/// into.
fn collect_pids_recursive(dir: &Path, out: &mut Vec<u32>) {
    if let Ok(content) = fs::read_to_string(dir.join("cgroup.procs")) {
        out.extend(
            content
                .lines()
                .filter_map(|line| line.trim().parse::<u32>().ok()),
        );
    }

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        if entry.file_type().is_ok_and(|ft| ft.is_dir()) {
            collect_pids_recursive(&entry.path(), out);
        }
    }
}

/// Get the executable basename for a process (from /proc/<pid>/exe).
pub fn exe_basename(pid: u32) -> Option<String> {
    let path = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    path.file_name()?.to_str().map(|s| s.to_string())
}

/// Get the boot_id from /proc/sys/kernel/random/boot_id, trimmed.
/// Returns empty string on failure.
pub fn boot_id() -> String {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Pure parser: extract frozen state from cgroup.events text.
/// Looks for "frozen <0|1>" line and returns Some(bool), or None if not found.
pub fn parse_frozen(events: &str) -> Option<bool> {
    events.lines().find_map(|l| {
        let rest = l.strip_prefix("frozen ")?;
        Some(rest.trim() == "1")
    })
}

/// Pure parser: extract anon memory value from memory.stat text.
/// Looks for "anon <value>" line and returns the parsed value, or None if not found.
pub fn parse_anon(stat: &str) -> Option<u64> {
    stat.lines()
        .find_map(|l| l.strip_prefix("anon ")?.trim().parse::<u64>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_frozen_reads_events() {
        assert_eq!(parse_frozen("populated 1\nfrozen 0\n"), Some(false));
        assert_eq!(parse_frozen("populated 1\nfrozen 1\n"), Some(true));
        assert_eq!(parse_frozen("populated 1\n"), None);
    }

    #[test]
    fn parse_anon_reads_memory_stat() {
        let stat = "anon 1073741824\nfile 536870912\nkernel 1000\n";
        assert_eq!(parse_anon(stat), Some(1_073_741_824));
        assert_eq!(parse_anon("file 5\n"), None);
    }

    #[test]
    fn pids_under_recurses_into_descendant_directories() {
        // Directory-walk shape test: doesn't need real cgroupfs, just files
        // named `cgroup.procs` nested under a temp tree — collect_pids_recursive
        // only cares about directory structure and file contents, not that
        // it's actually cgroupfs.
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("cgroup.procs"), "111\n222\n").unwrap();

        let child = root.path().join("child");
        fs::create_dir(&child).unwrap();
        fs::write(child.join("cgroup.procs"), "333\n").unwrap();

        let grandchild = child.join("nested");
        fs::create_dir(&grandchild).unwrap();
        fs::write(grandchild.join("cgroup.procs"), "444\n").unwrap();

        // A non-cgroup file alongside the directories must not be descended
        // into or misparsed.
        fs::write(root.path().join("cgroup.controllers"), "cpu memory\n").unwrap();

        let mut out = Vec::new();
        collect_pids_recursive(root.path(), &mut out);
        out.sort_unstable();
        assert_eq!(out, vec![111, 222, 333, 444]);

        // pids_in (non-recursive) sees only the root's own procs.
        let mut root_only = Vec::new();
        if let Ok(content) = fs::read_to_string(root.path().join("cgroup.procs")) {
            root_only.extend(content.lines().filter_map(|l| l.trim().parse::<u32>().ok()));
        }
        root_only.sort_unstable();
        assert_eq!(root_only, vec![111, 222]);
    }

    #[test]
    fn pids_under_tolerates_missing_and_unreadable_dirs() {
        let root = tempfile::tempdir().unwrap();
        // No cgroup.procs at all, no subdirectories — must not panic, just
        // return empty.
        let mut out = Vec::new();
        collect_pids_recursive(root.path(), &mut out);
        assert!(out.is_empty());

        // A path that doesn't exist at all.
        let mut out2 = Vec::new();
        collect_pids_recursive(&root.path().join("does-not-exist"), &mut out2);
        assert!(out2.is_empty());
    }

    /// Integration test: create a real delegated rlm cgroup with a nested
    /// child cgroup holding a process, and confirm `pids_under` sees the
    /// nested process while `pids_in` does not. Requires cgroup v2
    /// delegation, so it's `#[ignore]`d.
    #[test]
    #[ignore = "requires cgroup v2 delegation; run manually"]
    fn pids_under_sees_nested_process_pids_in_does_not() {
        use crate::CgroupManager;
        use common::Limit;
        use std::process::Command;

        let manager = CgroupManager::new().expect("create CgroupManager");
        let abs_path = manager
            .prepare_cgroup("test-pids-under", &Limit::default())
            .expect("create test cgroup");
        let cgroup = format!(
            "/{}",
            abs_path
                .strip_prefix("/sys/fs/cgroup")
                .expect("cgroup under /sys/fs/cgroup")
                .display()
        );

        // A real, undelegated-controller child directory under a delegated
        // cgroup is a plain mkdir — the kernel populates its interface files.
        let child_dir = abs_path.join("child");
        fs::create_dir(&child_dir).expect("mkdir child cgroup");

        let mut child_proc = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child_proc.id();
        // Move the process into the nested child cgroup (writing its own
        // cgroup.procs, not the parent's, is what actually nests it).
        fs::write(child_dir.join("cgroup.procs"), pid.to_string())
            .expect("place pid in nested child cgroup");

        let seen_by_pids_in = pids_in(&cgroup);
        let seen_by_pids_under = pids_under(&cgroup);

        let _ = child_proc.kill();
        let _ = child_proc.wait();
        let _ = fs::remove_dir(&child_dir);
        let _ = manager.cleanup_cgroup("test-pids-under");

        assert!(
            !seen_by_pids_in.contains(&pid),
            "pids_in must not see the nested child's pid (exact-dir semantics)"
        );
        assert!(
            seen_by_pids_under.contains(&pid),
            "pids_under must see the nested child's pid"
        );
    }

    #[test]
    fn abs_handles_absolute_style_paths() {
        // Task 1's Resolution.cgroup produces absolute-style paths (starting with '/')
        // abs() must correctly prefix /sys/fs/cgroup, not drop it via Path::join
        assert_eq!(
            abs("/user.slice/user-1000.slice/user@1000.service/app.slice"),
            PathBuf::from("/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice")
        );
        // Also handles relative paths without leading '/'
        assert_eq!(
            abs("user.slice/foo"),
            PathBuf::from("/sys/fs/cgroup/user.slice/foo")
        );
    }
}

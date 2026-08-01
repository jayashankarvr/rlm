//! Reads memory pressure (PSI) and enumerates eligible processes. Pure reads of
//! `/proc`; no decisions. The parsing is factored into small pure free
//! functions so it can be unit-tested without touching the filesystem.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use super::cgfs;
use super::resolve::{candidate_target, finalize, Resolution};
use super::types::{ProcInfo, Sample};
use common::{GuardConfig, BUILTIN_PROTECT};

/// Samples system pressure and the user's eligible processes.
pub struct Sampler {
    cfg: GuardConfig,
    /// The guard's own PID — always excluded from the eligible set.
    self_pid: u32,
    /// Only processes owned by this uid are eligible.
    uid: u32,
    /// Precomputed protect-set: builtin names ∪ config additions.
    protect: HashSet<String>,
    /// `CgroupManager::base_path()` minus the leading `/sys/fs/cgroup`, e.g.
    /// "/user.slice/user-1000.slice/user@1000.service/rlm". Used to resolve
    /// raw (non-systemd-unit) rlm cgroups as targets. `None` means the strip
    /// failed (see [`strip_cgroup_root`]) — resolution assembly is disabled
    /// entirely rather than risk a bogus permissive match (see [`Sampler::resolve`]).
    rlm_base: Option<String>,
}

/// Strip the `/sys/fs/cgroup` prefix from a `CgroupManager::base_path()` so
/// the result matches the convention `resolve::candidate_target` expects
/// (paths relative to the cgroupfs root). Pure string manipulation.
///
/// Returns `None` if `base_path` isn't valid UTF-8 or doesn't start with
/// `/sys/fs/cgroup` — that's a broken invariant (base_path always comes from
/// `CgroupManager`, which is hardcoded to build under `/sys/fs/cgroup`), and
/// callers must fail closed rather than substitute an empty string: an empty
/// `rlm_base` makes `candidate_target`'s raw-cgroup prefix check `""` (i.e.
/// "/"), which matches almost every absolute cgroup path as a bogus Raw
/// candidate — the dangerous direction for a freeze decision.
pub fn strip_cgroup_root(base_path: &Path) -> Option<String> {
    base_path
        .to_str()?
        .strip_prefix("/sys/fs/cgroup")
        .map(str::to_string)
}

impl Sampler {
    /// `self_pid` is the guard's own PID (always excluded). `uid` is the user
    /// whose processes are eligible. `rlm_base` is
    /// `CgroupManager::base_path()` with the `/sys/fs/cgroup` prefix
    /// stripped (see [`strip_cgroup_root`]); `None` disables resolution
    /// assembly entirely (fail closed — every process reports `resolution:
    /// None`, so the policy engine can never select an escalation victim).
    pub fn new(cfg: GuardConfig, self_pid: u32, uid: u32, rlm_base: Option<String>) -> Self {
        // Merge the baked-in protect-list with the user's additions once, up
        // front, so the per-process scan is a cheap hash lookup.
        let mut protect: HashSet<String> =
            BUILTIN_PROTECT.iter().map(|s| (*s).to_string()).collect();
        protect.extend(cfg.selection.protect.iter().cloned());

        Self {
            cfg,
            self_pid,
            uid,
            protect,
            rlm_base,
        }
    }

    /// Read current pressure. `None` if PSI is unavailable (e.g. the kernel was
    /// built without `CONFIG_PSI`, so `/proc/pressure/memory` doesn't exist).
    pub fn sample(&self) -> Option<Sample> {
        // PSI is the primary signal; if we can't read it, we have no sample.
        let psi = fs::read_to_string("/proc/pressure/memory").ok()?;
        let (some_avg10, full_avg10) = parse_psi(&psi)?;

        // MemAvailable is only a backstop floor. If it can't be read, fall back
        // to u64::MAX so the floor check can never trip spuriously.
        let mem_available_mb = fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|m| parse_mem_available_mb(&m))
            .unwrap_or(u64::MAX);

        Some(Sample {
            some_avg10,
            full_avg10,
            mem_available_mb,
        })
    }

    /// Enumerate eligible processes: owned by `uid`, not protected (builtin +
    /// config protect-list), `rss_kb >= min_rss_mb * 1024`, excluding the guard
    /// itself. Sorted by `rss_kb` descending. Robust to processes vanishing
    /// mid-scan — any unreadable entry is simply skipped.
    ///
    /// Also resolves each surviving process to its freeze/cap target (see
    /// [`ProcInfo::resolution`]). Resolutions are cached per candidate cgroup
    /// for the duration of this call, so N processes sharing one cgroup (e.g.
    /// N Firefox content processes) cost a single member scan.
    pub fn eligible(&self) -> Vec<ProcInfo> {
        let min_rss_kb = self.cfg.selection.min_rss_mb.saturating_mul(1024);

        let entries = match fs::read_dir("/proc") {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        let mut resolved: HashMap<String, Resolution> = HashMap::new();
        let mut out = Vec::new();
        for entry in entries.flatten() {
            // `/proc/<pid>` directories are named by their numeric PID; skip
            // everything else (cpuinfo, self, net, ...).
            let file_name = entry.file_name();
            let name = match file_name.to_str() {
                Some(n) => n,
                None => continue,
            };
            let pid: u32 = match name.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Never act on ourselves.
            if pid == self.self_pid {
                continue;
            }

            // The process may exit between read_dir and now — that's fine, skip.
            let status = match fs::read_to_string(format!("/proc/{pid}/status")) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let (owner_uid, pname, rss_kb) = match parse_proc_status(&status) {
                Some(v) => v,
                None => continue,
            };

            // Only the user's own processes are eligible.
            if owner_uid != self.uid {
                continue;
            }
            // Below the min-RSS threshold — not worth acting on.
            if rss_kb < min_rss_kb {
                continue;
            }
            // Protected by builtin defaults or user config. The exe basename
            // (realpath, full name) is authoritative — it's what avoids the
            // kernel's 15-char `comm` truncation silently missing
            // user-configured names like "gnome-control-center". Comm is
            // kept as a fallback for processes whose /proc/<pid>/exe isn't
            // readable (e.g. already exited, or a kernel thread).
            let protected_by_exe =
                cgfs::exe_basename(pid).is_some_and(|exe| self.protect.contains(&exe));
            if protected_by_exe || self.protect.contains(&pname) {
                continue;
            }

            let resolution = self.resolve(pid, &mut resolved);

            out.push(ProcInfo {
                pid,
                name: pname,
                rss_kb,
                resolution,
            });
        }

        // Biggest memory hog first — that's the victim the engine prefers.
        out.sort_by_key(|p| std::cmp::Reverse(p.rss_kb));
        out
    }

    /// Resolve `pid` to its freeze/cap target, if any. `cache` is keyed by
    /// candidate cgroup so callers in the same eligible-cgroup only pay for
    /// the member scan once. Returns `None` outright if `rlm_base` failed to
    /// compute at startup — see [`strip_cgroup_root`].
    fn resolve(&self, pid: u32, cache: &mut HashMap<String, Resolution>) -> Option<Resolution> {
        let rlm_base = self.rlm_base.as_deref()?;
        let cgroup_file = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
        let victim_cgroup = parse_cgroup_path(&cgroup_file)?;
        let candidate = candidate_target(&victim_cgroup, self.uid, rlm_base)?;

        if let Some(cached) = cache.get(&candidate.cgroup) {
            return Some(cached.clone());
        }

        // Recursive: a protected process nested in a child cgroup (shell in
        // a terminal scope's descendant, nested systemd-run, app-created
        // sub-cgroup) is still within the freeze/stop blast radius, so it
        // must be visible to the protect check even though it isn't a
        // direct member of the candidate cgroup itself.
        let member_exes: Vec<String> = cgfs::pids_under(&candidate.cgroup)
            .into_iter()
            .filter_map(|p| cgfs::exe_basename(p).or_else(|| comm_of(p)))
            .collect();

        let key = candidate.cgroup.clone();
        let resolution = finalize(candidate, &member_exes, &self.protect);
        cache.insert(key, resolution.clone());
        Some(resolution)
    }
}

/// Parse the v2 line of /proc/<pid>/cgroup ("0::<path>"). Hybrid-mode lines
/// for other controllers are noise and skipped.
pub fn parse_cgroup_path(content: &str) -> Option<String> {
    content
        .lines()
        .find_map(|l| l.strip_prefix("0::").map(|p| p.to_string()))
}

/// Fallback comm lookup (`Name:` in /proc/<pid>/status) for member processes
/// whose `/proc/<pid>/exe` isn't readable.
fn comm_of(pid: u32) -> Option<String> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Name:").map(|r| r.trim().to_string()))
}

/// Parse `/proc/pressure/memory`, returning `(some_avg10, full_avg10)`.
///
/// Expected format (the `full` line may be absent on some kernels):
/// ```text
/// some avg10=0.00 avg60=0.00 avg300=0.00 total=12345
/// full avg10=0.00 avg60=0.00 avg300=0.00 total=6789
/// ```
/// Returns `None` if the `some` line or its `avg10` can't be found. A missing
/// `full` line defaults its avg10 to `0.0`.
fn parse_psi(content: &str) -> Option<(f64, f64)> {
    let mut some = None;
    let mut full = 0.0; // default if the `full` line is missing

    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("some ") {
            some = field_f64(rest, "avg10");
        } else if let Some(rest) = line.strip_prefix("full ") {
            if let Some(v) = field_f64(rest, "avg10") {
                full = v;
            }
        }
    }

    some.map(|s| (s, full))
}

/// Find `key=<number>` among space-separated `k=v` tokens and parse the value.
fn field_f64(tokens: &str, key: &str) -> Option<f64> {
    tokens.split_whitespace().find_map(|tok| {
        tok.strip_prefix(key)
            .and_then(|r| r.strip_prefix('='))
            .and_then(|v| v.parse().ok())
    })
}

/// Parse `MemAvailable:` (in kB) from `/proc/meminfo` and convert to MB.
/// Returns `None` if the field is missing or malformed.
fn parse_mem_available_mb(meminfo: &str) -> Option<u64> {
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            // e.g. "   12345678 kB" — first whitespace token is the kB value.
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb / 1024);
        }
    }
    None
}

/// Parse `/proc/<pid>/status`, returning `(real_uid, name, rss_kb)` where
/// `rss_kb = VmRSS + VmSwap`.
///
/// - `Uid:` line is `Uid:\t<real>\t<effective>\t<saved>\t<fs>`; we take the
///   first (real) field.
/// - `Name:` is the comm, truncated to 15 chars by the kernel — that's fine,
///   it matches the protect-list which also compares against comm.
/// - `VmSwap:` may be absent (e.g. kernel thread / no swap) — treated as 0.
///
/// Returns `None` only if the required `Uid:` or `Name:` lines are missing.
fn parse_proc_status(status: &str) -> Option<(u32, String, u64)> {
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

    Some((uid?, name?, vm_rss.saturating_add(vm_swap)))
}

/// Parse the leading integer of a `"   1234 kB"` style value as a kB count.
fn first_kb(rest: &str) -> Option<u64> {
    rest.split_whitespace().next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- parse_cgroup_path ------------------------------------------------

    #[test]
    fn cgroup_path_parses_v2_line() {
        assert_eq!(
            parse_cgroup_path("0::/user.slice/x.scope\n"),
            Some("/user.slice/x.scope".into())
        );
        // Hybrid line noise is skipped; only the "0::" entry counts.
        assert_eq!(
            parse_cgroup_path("1:name=systemd:/foo\n0::/bar\n"),
            Some("/bar".into())
        );
        assert_eq!(parse_cgroup_path(""), None);
    }

    // ---- parse_psi -------------------------------------------------------

    #[test]
    fn psi_parses_some_and_full() {
        let s = "some avg10=12.34 avg60=5.00 avg300=1.00 total=999\n\
                 full avg10=3.21 avg60=2.00 avg300=0.50 total=42\n";
        assert_eq!(parse_psi(s), Some((12.34, 3.21)));
    }

    #[test]
    fn psi_missing_full_line_defaults_to_zero() {
        let s = "some avg10=7.50 avg60=1.00 avg300=0.10 total=10\n";
        assert_eq!(parse_psi(s), Some((7.50, 0.0)));
    }

    #[test]
    fn psi_missing_some_line_is_none() {
        let s = "full avg10=3.00 avg60=1.00 avg300=0.10 total=10\n";
        assert_eq!(parse_psi(s), None);
    }

    #[test]
    fn psi_empty_is_none() {
        assert_eq!(parse_psi(""), None);
    }

    #[test]
    fn psi_malformed_avg10_is_none() {
        let s = "some avg10=NaNNN avg60=1.00 total=5\n";
        assert_eq!(parse_psi(s), None);
    }

    #[test]
    fn psi_zero_values() {
        let s = "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n\
                 full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n";
        assert_eq!(parse_psi(s), Some((0.0, 0.0)));
    }

    #[test]
    fn psi_tolerates_leading_whitespace() {
        let s = "  some avg10=1.00 avg60=0.00 avg300=0.00 total=1\n";
        assert_eq!(parse_psi(s), Some((1.0, 0.0)));
    }

    // ---- parse_mem_available_mb -----------------------------------------

    #[test]
    fn mem_available_basic() {
        // 2_097_152 kB == 2048 MB
        let m = "MemTotal:       16000000 kB\n\
                 MemFree:         1000000 kB\n\
                 MemAvailable:    2097152 kB\n";
        assert_eq!(parse_mem_available_mb(m), Some(2048));
    }

    #[test]
    fn mem_available_missing_is_none() {
        let m = "MemTotal:       16000000 kB\nMemFree: 1000000 kB\n";
        assert_eq!(parse_mem_available_mb(m), None);
    }

    #[test]
    fn mem_available_malformed_is_none() {
        let m = "MemAvailable:    not_a_number kB\n";
        assert_eq!(parse_mem_available_mb(m), None);
    }

    #[test]
    fn mem_available_truncates_down() {
        // 1500 kB -> 1 MB (integer division)
        let m = "MemAvailable:       1500 kB\n";
        assert_eq!(parse_mem_available_mb(m), Some(1));
    }

    // ---- parse_proc_status ----------------------------------------------

    #[test]
    fn status_full_fields() {
        let s = "Name:\tfirefox\n\
                 State:\tS (sleeping)\n\
                 Tgid:\t1234\n\
                 Pid:\t1234\n\
                 Uid:\t1000\t1000\t1000\t1000\n\
                 VmRSS:\t  500000 kB\n\
                 VmSwap:\t   2000 kB\n";
        let (uid, name, rss) = parse_proc_status(s).unwrap();
        assert_eq!(uid, 1000);
        assert_eq!(name, "firefox");
        assert_eq!(rss, 502000); // 500000 + 2000
    }

    #[test]
    fn status_missing_vmswap_defaults_zero() {
        let s = "Name:\tcode\n\
                 Uid:\t1000\t1000\t1000\t1000\n\
                 VmRSS:\t  300000 kB\n";
        let (uid, name, rss) = parse_proc_status(s).unwrap();
        assert_eq!(uid, 1000);
        assert_eq!(name, "code");
        assert_eq!(rss, 300000);
    }

    #[test]
    fn status_missing_vmrss_treated_as_zero() {
        // Kernel threads have no VmRSS line at all.
        let s = "Name:\tkworker/0:0\n\
                 Uid:\t0\t0\t0\t0\n";
        let (uid, name, rss) = parse_proc_status(s).unwrap();
        assert_eq!(uid, 0);
        assert_eq!(name, "kworker/0:0");
        assert_eq!(rss, 0);
    }

    #[test]
    fn status_truncated_name_15_chars() {
        // The kernel truncates comm to 15 chars; we keep it verbatim.
        let s = "Name:\tsome-very-long-\n\
                 Uid:\t1000\t1000\t1000\t1000\n\
                 VmRSS:\t  100000 kB\n";
        let (_, name, _) = parse_proc_status(s).unwrap();
        assert_eq!(name, "some-very-long-");
        assert_eq!(name.len(), 15);
    }

    #[test]
    fn status_takes_real_uid_first_field() {
        // A setuid process: real=1000, effective=0. We must pick the real uid.
        let s = "Name:\tsetuid-proc\n\
                 Uid:\t1000\t0\t0\t1000\n\
                 VmRSS:\t  100000 kB\n";
        let (uid, _, _) = parse_proc_status(s).unwrap();
        assert_eq!(uid, 1000);
    }

    #[test]
    fn status_missing_uid_is_none() {
        let s = "Name:\tfoo\nVmRSS:\t  100000 kB\n";
        assert_eq!(parse_proc_status(s), None);
    }

    #[test]
    fn status_missing_name_is_none() {
        let s = "Uid:\t1000\t1000\t1000\t1000\nVmRSS:\t  100000 kB\n";
        assert_eq!(parse_proc_status(s), None);
    }

    #[test]
    fn status_malformed_rss_is_zero() {
        let s = "Name:\tfoo\n\
                 Uid:\t1000\t1000\t1000\t1000\n\
                 VmRSS:\tbogus kB\n";
        let (_, _, rss) = parse_proc_status(s).unwrap();
        assert_eq!(rss, 0);
    }
}

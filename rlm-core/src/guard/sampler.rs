//! Reads memory pressure (PSI) and enumerates eligible processes. Pure reads of
//! `/proc`; no decisions. The parsing is factored into small pure free
//! functions so it can be unit-tested without touching the filesystem.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use super::cgfs;
use super::resolve::{candidate_target, finalize, Resolution};
use super::types::{ProcInfo, PsiSource, Sample, Target};
use common::GuardConfig;

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
        let protect = common::protect_set(&cfg.selection.protect);

        Self {
            cfg,
            self_pid,
            uid,
            protect,
            rlm_base,
        }
    }

    /// Read current pressure. Prefers the user's app.slice PSI (what the
    /// processes the guard can act on actually feel) and falls back to system
    /// PSI only when that file is missing. `None` if neither is readable (e.g.
    /// a kernel built without `CONFIG_PSI`).
    pub fn sample(&self) -> Option<Sample> {
        let app = fs::read_to_string(app_slice_pressure_path(self.uid)).ok();
        let sys = fs::read_to_string("/proc/pressure/memory").ok();
        let (some_avg10, full_avg10, source) = pick_pressure(app.as_deref(), sys.as_deref())?;

        // Unreadable meminfo reports "plenty available, total unknown", which
        // the policy's scarcity gate treats as not scarce: no action.
        let mem = fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|m| parse_meminfo(&m));

        Some(Sample {
            some_avg10,
            full_avg10,
            mem_available_mb: mem.map_or(u64::MAX, |m| m.available_mb),
            mem_total_mb: mem.map_or(0, |m| m.total_mb),
            source,
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
            let exe = cgfs::exe_basename(pid);
            if common::is_protected(&self.protect, &pname, exe.as_deref()) {
                continue;
            }

            let resolution = self.resolve(pid, &mut resolved);

            // The exe basename names the app: Firefox content processes have
            // comm "Isolated Web Co" but run the `firefox` binary.
            out.push(ProcInfo {
                pid,
                name: exe.unwrap_or(pname),
                rss_kb,
                resolution,
            });
        }

        // Largest first, for stable output.
        out.sort_by_key(|p| std::cmp::Reverse(p.rss_kb));
        out
    }

    /// Every cgroup currently resolved for one of the user's own, live
    /// processes — deliberately with **no** min-RSS or protect filtering
    /// applied (unlike [`Sampler::eligible`]). This is a liveness signal,
    /// not an escalation candidate list: `PolicyEngine::tick` prunes its
    /// interventions against this set rather than against `eligible()`'s
    /// filtered output, because a successful `Cap` sizes off anon+swap while
    /// `memory.high` also bounds file-backed pages — capping a
    /// mapped-file-heavy process can push its `rss_kb` below the min-RSS
    /// floor on the very next tick even though the cgroup, and the process
    /// in it, are both still very much alive (D2 fix).
    ///
    /// Deliberately calls [`candidate_target`] directly rather than
    /// `Self::resolve`: `resolve` (via `finalize`) additionally runs a
    /// recursive `cgfs::pids_under` tree walk plus a `readlink
    /// /proc/<pid>/exe` per member to compute `verdict`/`coverage`, neither
    /// of which this function uses — only `candidate.cgroup` (`finalize`
    /// passes `candidate.cgroup` through unchanged into `Resolution::cgroup`,
    /// so the output is identical). Because this function has no min-RSS
    /// filter (that's the D2 fix above), it runs for every one of the user's
    /// processes on every tick, not just the heavy ones, so the member-scan
    /// work `resolve` does is pure waste here (NEW-3 fix).
    pub fn live_cgroups(&self) -> HashSet<String> {
        let mut live = HashSet::new();

        let Some(rlm_base) = self.rlm_base.as_deref() else {
            return live;
        };

        let Ok(entries) = fs::read_dir("/proc") else {
            return live;
        };
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            if pid == self.self_pid {
                continue;
            }

            let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else {
                continue;
            };
            let Some((owner_uid, _, _)) = parse_proc_status(&status) else {
                continue;
            };
            if owner_uid != self.uid {
                continue;
            }

            let Ok(cgroup_file) = fs::read_to_string(format!("/proc/{pid}/cgroup")) else {
                continue;
            };
            let Some(victim_cgroup) = parse_cgroup_path(&cgroup_file) else {
                continue;
            };
            if let Some(candidate) = candidate_target(&victim_cgroup, self.uid, rlm_base) {
                live.insert(candidate.cgroup);
            }
        }
        live
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

/// Group resolved processes by cgroup into one [`Target`] each. The app is
/// named after the cgroup's largest process, and `current_bytes` reads the
/// cgroup's `memory.current` (injected so tests stay off the real cgroupfs).
/// Unresolved processes are dropped: the guard can't act on them.
pub fn targets_from_procs(
    procs: &[ProcInfo],
    current_bytes: &dyn Fn(&str) -> Option<u64>,
) -> Vec<Target> {
    let mut heaviest: BTreeMap<&str, &ProcInfo> = BTreeMap::new();
    for p in procs {
        let Some(res) = p.resolution.as_ref() else {
            continue;
        };
        let slot = heaviest.entry(res.cgroup.as_str()).or_insert(p);
        if p.rss_kb > slot.rss_kb {
            *slot = p;
        }
    }
    heaviest
        .into_iter()
        .map(|(cg, p)| Target {
            app: p.name.clone(),
            resolution: p.resolution.clone().expect("grouped only resolved procs"),
            rss_kb: p.rss_kb,
            current_bytes: current_bytes(cg),
        })
        .collect()
}

/// Parse the v2 line of /proc/<pid>/cgroup ("0::<path>"). Hybrid-mode lines
/// for other controllers are noise and skipped. Delegates to
/// [`crate::process::parse_cgroup_v2`]; kept under this name for callers.
pub use crate::process::parse_cgroup_v2 as parse_cgroup_path;

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

/// The fields of `/proc/meminfo` the guard uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemInfo {
    pub available_mb: u64,
    pub total_mb: u64,
    pub swap_total_kb: u64,
}

/// Parse `/proc/meminfo`. `MemAvailable` and `MemTotal` are required;
/// a missing `SwapTotal` reads as 0.
pub fn parse_meminfo(s: &str) -> Option<MemInfo> {
    let kb = |key: &str| {
        s.lines()
            .find_map(|l| l.strip_prefix(key))
            .and_then(|r| r.split_whitespace().next()?.parse::<u64>().ok())
    };
    Some(MemInfo {
        available_mb: kb("MemAvailable:")? / 1024,
        total_mb: kb("MemTotal:")? / 1024,
        swap_total_kb: kb("SwapTotal:").unwrap_or(0),
    })
}

/// The memory PSI file of the user's `app.slice`: covers the apps the guard
/// may act on, and excludes rlm's own subtree (`user@UID.service/rlm/`) and
/// `session.slice`.
pub fn app_slice_pressure_path(uid: u32) -> PathBuf {
    PathBuf::from(format!(
        "/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service/app.slice/memory.pressure"
    ))
}

/// Choose the pressure to act on: app.slice PSI when it parses, otherwise
/// system PSI. Returns `(some_avg10, full_avg10, source)`.
pub fn pick_pressure(
    app_slice: Option<&str>,
    system: Option<&str>,
) -> Option<(f64, f64, PsiSource)> {
    if let Some((s, f)) = app_slice.and_then(parse_psi) {
        return Some((s, f, PsiSource::AppSlice));
    }
    system
        .and_then(parse_psi)
        .map(|(s, f)| (s, f, PsiSource::System))
}

/// Parse `/proc/<pid>/status`, returning `(real_uid, name, rss_kb)` where
/// `rss_kb = VmRSS + VmSwap`. Delegates to [`crate::process::parse_status`].
fn parse_proc_status(status: &str) -> Option<(u32, String, u64)> {
    crate::process::parse_status(status).map(|f| (f.uid, f.name, f.rss_kb))
}

#[cfg(test)]
mod tests {
    use super::super::resolve::{Coverage, Mechanism, Verdict};
    use super::*;

    fn pinfo(pid: u32, name: &str, rss_mb: u64, cg: Option<&str>) -> ProcInfo {
        ProcInfo {
            pid,
            name: name.into(),
            rss_kb: rss_mb * 1024,
            resolution: cg.map(|c| Resolution {
                cgroup: c.into(),
                unit: None,
                verdict: Verdict::Freeze,
                coverage: Coverage::Full,
                mechanism: Mechanism::Raw,
            }),
        }
    }

    #[test]
    fn targets_merge_processes_sharing_a_cgroup_and_drop_unresolved() {
        let procs = vec![
            pinfo(10, "firefox", 900, Some("/a.scope")),
            pinfo(11, "firefox", 1200, Some("/a.scope")),
            pinfo(12, "stray", 5000, None),
        ];
        let t = targets_from_procs(&procs, &|_| Some(42));
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].app, "firefox");
        assert_eq!(t[0].rss_kb, 1200 * 1024);
        assert_eq!(t[0].current_bytes, Some(42));
    }

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

    // ---- pick_pressure / parse_meminfo ------------------------------------

    const APP_CALM: &str = "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n";
    const SYS_HOT: &str = "some avg10=60.00 avg60=20.00 avg300=5.00 total=1\nfull avg10=40.00 avg60=10.00 avg300=2.00 total=1\n";

    #[test]
    fn stall_inside_a_limited_rlm_cgroup_does_not_count_as_app_pressure() {
        // Incident replay: a cgroup rlm limited thrashed at its own memory.max;
        // system PSI read 60% while nothing in app.slice was waiting.
        assert_eq!(
            pick_pressure(Some(APP_CALM), Some(SYS_HOT)),
            Some((0.0, 0.0, PsiSource::AppSlice))
        );
    }

    #[test]
    fn falls_back_to_system_psi_when_app_slice_file_missing() {
        assert_eq!(
            pick_pressure(None, Some(SYS_HOT)),
            Some((60.0, 40.0, PsiSource::System))
        );
        assert_eq!(
            pick_pressure(Some("garbage"), Some(SYS_HOT)),
            Some((60.0, 40.0, PsiSource::System))
        );
    }

    #[test]
    fn no_psi_anywhere_is_none() {
        assert_eq!(pick_pressure(None, None), None);
    }

    #[test]
    fn app_slice_pressure_path_is_under_the_user_manager() {
        assert_eq!(
            app_slice_pressure_path(1000),
            std::path::PathBuf::from(
                "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/memory.pressure"
            )
        );
    }

    #[test]
    fn parse_meminfo_reads_available_total_and_swap() {
        let m = "MemTotal:       16384000 kB\nMemFree: 1 kB\nMemAvailable:    2097152 kB\nSwapTotal:       8388604 kB\n";
        assert_eq!(
            parse_meminfo(m),
            Some(MemInfo {
                available_mb: 2048,
                total_mb: 16000,
                swap_total_kb: 8_388_604
            })
        );
    }

    #[test]
    fn parse_meminfo_without_swaptotal_defaults_zero() {
        let m = "MemTotal: 1024000 kB\nMemAvailable: 512000 kB\n";
        assert_eq!(parse_meminfo(m).unwrap().swap_total_kb, 0);
    }

    #[test]
    fn parse_meminfo_requires_available_and_total() {
        assert_eq!(parse_meminfo("MemTotal: 1 kB\n"), None);
        assert_eq!(parse_meminfo("MemAvailable: 1 kB\n"), None);
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

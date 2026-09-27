//! Reads memory pressure (PSI) and picks escalation candidates from a process
//! snapshot. Pure reads; no decisions. The parsing is factored into small pure free
//! functions so it can be unit-tested without touching the filesystem.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use super::cgfs;
use super::resolve::{candidate_target, finalize, Resolution};
use super::types::{ProcInfo, PsiSource, Sample, Target};
use crate::process::ProcessInfo;
use common::GuardConfig;

/// Samples system pressure and the user's eligible processes.
pub struct Sampler {
    cfg: GuardConfig,
    /// The guard's own PID, always excluded from the eligible set.
    self_pid: u32,
    /// Only processes owned by this uid are eligible.
    uid: u32,
    /// Precomputed protect-set: builtin names ∪ config additions.
    protect: HashSet<String>,
    /// `CgroupManager::base_path()` minus the leading `/sys/fs/cgroup`, e.g.
    /// "/user.slice/user-1000.slice/user@1000.service/rlm". Used to resolve
    /// raw (non-systemd-unit) rlm cgroups as targets. `None` means the strip
    /// failed (see [`strip_cgroup_root`]); resolution assembly is disabled
    /// entirely rather than risk a bogus permissive match (see [`Sampler::resolve`]).
    rlm_base: Option<String>,
}

/// Strip the `/sys/fs/cgroup` prefix from a `CgroupManager::base_path()` so
/// the result matches the convention `resolve::candidate_target` expects
/// (paths relative to the cgroupfs root). Pure string manipulation.
///
/// Returns `None` if `base_path` isn't valid UTF-8 or doesn't start with
/// `/sys/fs/cgroup`; that's a broken invariant (base_path always comes from
/// `CgroupManager`, which is hardcoded to build under `/sys/fs/cgroup`), and
/// callers must fail closed rather than substitute an empty string: an empty
/// `rlm_base` makes `candidate_target`'s raw-cgroup prefix check `""` (i.e.
/// "/"), which matches almost every absolute cgroup path as a bogus Raw
/// candidate, the dangerous direction for a freeze decision.
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
    /// assembly entirely (fail closed: every process reports `resolution:
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
    /// PSI when that file is missing OR unreadable/unparseable. `None` if
    /// neither is readable (e.g. a kernel built without `CONFIG_PSI`).
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

    /// The escalation candidates in `snapshot` (normally
    /// `process::list_for_uid(uid)`, taken once per tick and shared with the
    /// rules enforcer): owned by `uid`, not the guard itself, at least
    /// `min_rss_mb`, and not protected (builtin + config protect-list, matched
    /// on comm and on the untruncated exe basename). Sorted by `rss_kb`
    /// descending.
    ///
    /// Each candidate is named by its exe basename (comm fallback): Firefox
    /// content processes have comm "Isolated Web Co" but run `firefox`.
    /// Resolutions are cached per candidate cgroup, so N processes sharing
    /// one cgroup cost a single member scan.
    pub fn candidates(&self, snapshot: &[ProcessInfo]) -> Vec<ProcInfo> {
        let min_rss_kb = self.cfg.selection.min_rss_mb.saturating_mul(1024);
        let mut cache: HashMap<String, Resolution> = HashMap::new();
        let mut out: Vec<ProcInfo> = snapshot
            .iter()
            .filter(|p| p.pid != self.self_pid && p.uid == self.uid && p.rss_kb >= min_rss_kb)
            .filter(|p| !common::is_protected(&self.protect, &p.name, p.exe_name()))
            .map(|p| ProcInfo {
                pid: p.pid,
                name: p.display_name().to_string(),
                rss_kb: p.rss_kb,
                resolution: p
                    .cgroup
                    .as_deref()
                    .and_then(|cg| self.resolve_cgroup(cg, &mut cache)),
            })
            .collect();
        out.sort_by_key(|p| std::cmp::Reverse(p.rss_kb));
        out
    }

    /// Resolve a process's cgroup (the "0::" path) to its freeze/cap target,
    /// if any. `cache` is keyed by candidate cgroup so processes sharing one
    /// only pay for the member scan once. Returns `None` outright if
    /// `rlm_base` failed to compute at startup; see [`strip_cgroup_root`].
    fn resolve_cgroup(
        &self,
        victim_cgroup: &str,
        cache: &mut HashMap<String, Resolution>,
    ) -> Option<Resolution> {
        let rlm_base = self.rlm_base.as_deref()?;
        let candidate = candidate_target(victim_cgroup, self.uid, rlm_base)?;

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

/// The cgroups in `cgroups` that still hold at least one process
/// (`cgroup.events` says `populated 1`). `PolicyEngine::tick` prunes its
/// interventions against this set, so only the cgroups it holds are checked:
/// one small read each, no `/proc` scan. A cgroup whose events file can't be
/// read (removed, or never existed) is not live.
///
/// This is deliberately not derived from the candidate list: a successful
/// `Cap` can push a process below the min-RSS floor while its cgroup, and
/// the process in it, are still alive (D2).
pub fn live_cgroups(cgroups: &[String]) -> HashSet<String> {
    cgroups
        .iter()
        .filter(|cg| cgfs::is_populated(cg) == Some(true))
        .cloned()
        .collect()
}

/// Runtimes, interpreters and shells: many unrelated apps run the same
/// binary, so for these the exe basename alone does not identify an app.
/// Matched exactly, except the [`RUNTIME_PREFIXES`] which match by prefix.
const RUNTIME_EXES: &[&str] = &[
    "java",
    "node",
    "nodejs",
    "python",
    "python2",
    "python3",
    "electron",
    "wine",
    "wine64",
    "wine-preloader",
    "wine64-preloader",
    "gjs-console",
    "bash",
    "sh",
    "dash",
    "zsh",
    "fish",
    "ruby",
    "perl",
    "php",
    "dotnet",
    "mono",
    "deno",
    "bun",
];

/// Versioned interpreters, the dynamic loader, and QEMU system emulators
/// (each user VM is its own app).
const RUNTIME_PREFIXES: &[&str] = &["python2.", "python3.", "ld-linux", "qemu-system-"];

fn is_runtime_exe(name: &str) -> bool {
    RUNTIME_EXES.contains(&name) || RUNTIME_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// The grouping key for a cgroup whose largest process is `name`: the exe
/// basename, so every scope of one browser is one app, except for runtimes,
/// which get `<name>@<cgroup leaf>` so each unit is its own app (a growing
/// Gradle daemon must not take IntelliJ down with it).
fn app_key(name: &str, cgroup: &str) -> String {
    if is_runtime_exe(name) {
        let leaf = cgroup.rsplit('/').next().unwrap_or(cgroup);
        format!("{name}@{leaf}")
    } else {
        name.to_string()
    }
}

/// Group resolved processes by cgroup into one [`Target`] each. The app is
/// named after the cgroup's largest process (see [`app_key`]), and `current_bytes` reads the
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
            app: app_key(&p.name, cg),
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

#[cfg(test)]
mod tests {
    use super::super::resolve::{Coverage, Mechanism, Verdict};
    use super::*;

    /// `(real_uid, name, rss_kb)` from `/proc/<pid>/status` text.
    fn parse_proc_status(status: &str) -> Option<(u32, String, u64)> {
        crate::process::parse_status(status).map(|f| (f.uid, f.name, f.rss_kb))
    }

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

    fn high_sample() -> Sample {
        Sample {
            some_avg10: 50.0,
            full_avg10: 0.0,
            mem_available_mb: 2_000,
            mem_total_mb: 16_000,
            source: PsiSource::AppSlice,
        }
    }

    fn frozen(actions: &[super::super::types::Action]) -> Vec<String> {
        let mut v: Vec<String> = actions
            .iter()
            .filter_map(|a| match a {
                super::super::types::Action::Freeze { res, .. } => Some(res.cgroup.clone()),
                _ => None,
            })
            .collect();
        v.sort();
        v
    }

    fn tick_once(procs: &[ProcInfo]) -> Vec<String> {
        let ts = targets_from_procs(procs, &|_| None);
        let live: HashSet<String> = ts.iter().map(|t| t.resolution.cgroup.clone()).collect();
        let mut e = super::super::PolicyEngine::new(GuardConfig::default());
        frozen(&e.tick(0, high_sample(), &ts, &live))
    }

    const RLM: &str = "/user.slice/user-1000.slice/user@1000.service/rlm";

    fn snap(pid: u32, uid: u32, comm: &str, exe: &str, rss_mb: u64, cg: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            uid,
            name: comm.into(),
            executable: Some(format!("/usr/bin/{exe}").into()),
            rss_kb: rss_mb * 1024,
            cgroup: Some(cg.into()),
            ..Default::default()
        }
    }
    fn app(n: &str) -> String {
        format!("/user.slice/user-1000.slice/user@1000.service/app.slice/app-{n}.scope")
    }

    #[test]
    fn candidates_keep_own_large_unprotected_processes_only() {
        let s = Sampler::new(GuardConfig::default(), 1, 1000, Some(RLM.into()));
        let snapshot = vec![
            snap(1, 1000, "rlm-guard", "rlm-guard", 500, &app("guard")), // the guard itself
            snap(10, 1000, "Isolated Web Co", "firefox", 900, &app("ff")),
            snap(11, 1001, "firefox", "firefox", 900, &app("other")), // another user
            snap(12, 1000, "gnome-shell", "gnome-shell", 900, &app("gs")), // protected
            snap(13, 1000, "tiny", "tiny", 10, &app("tiny")),         // below min_rss
        ];
        let c = s.candidates(&snapshot);
        assert_eq!(c.iter().map(|p| p.pid).collect::<Vec<_>>(), vec![10]);
        assert_eq!(c[0].name, "firefox", "app identity is the exe basename");
        assert!(c[0].resolution.is_some());
    }

    #[test]
    fn session_scope_processes_have_no_resolution() {
        // Review Focus 1: a runaway started from a tty or ssh login lives in session-N.scope.
        let s = Sampler::new(GuardConfig::default(), 1, 1000, Some(RLM.into()));
        let snapshot = vec![snap(
            20,
            1000,
            "python3",
            "python3",
            900,
            "/user.slice/user-1000.slice/session-3.scope",
        )];
        let c = s.candidates(&snapshot);
        assert_eq!(c.len(), 1);
        assert!(
            c[0].resolution.is_none(),
            "outside app.slice and rlm/, never a target"
        );
    }

    #[test]
    fn candidates_name_a_replaced_binary_without_the_deleted_suffix() {
        let s = Sampler::new(GuardConfig::default(), 1, 1000, Some(RLM.into()));
        let mut p = snap(30, 1000, "chrome", "chrome", 900, &app("c"));
        p.executable = Some("/opt/google/chrome/chrome (deleted)".into());
        assert_eq!(s.candidates(&[p])[0].name, "chrome");
    }

    #[test]
    fn two_java_scopes_are_two_apps() {
        let procs = vec![
            pinfo(1, "java", 3000, Some("/app.slice/app-idea-1.scope")),
            pinfo(2, "java", 2000, Some("/app.slice/app-gradle-2.scope")),
        ];
        assert_eq!(tick_once(&procs), vec!["/app.slice/app-idea-1.scope"]);
    }

    #[test]
    fn two_chrome_scopes_are_still_one_app() {
        let procs = vec![
            pinfo(1, "chrome", 3000, Some("/app.slice/app-a-1.scope")),
            pinfo(2, "chrome", 2000, Some("/app.slice/app-b-2.scope")),
        ];
        assert_eq!(
            tick_once(&procs),
            vec!["/app.slice/app-a-1.scope", "/app.slice/app-b-2.scope"]
        );
    }

    #[test]
    fn runtime_binaries_are_keyed_per_unit() {
        let procs = vec![
            pinfo(1, "python3.12", 900, Some("/app.slice/run-u7.service")),
            pinfo(2, "ld-linux-x86-64.so.2", 900, Some("/app.slice/x.scope")),
            pinfo(3, "firefox", 900, Some("/app.slice/ff.scope")),
            pinfo(4, "wine64-preloader", 900, Some("/app.slice/w.scope")),
            pinfo(5, "gjs-console", 900, Some("/app.slice/g.scope")),
            pinfo(6, "python2.7", 900, Some("/app.slice/p2.scope")),
            pinfo(7, "qemu-system-x86_64", 900, Some("/app.slice/vm.scope")),
        ];
        let mut apps: Vec<String> = targets_from_procs(&procs, &|_| None)
            .into_iter()
            .map(|t| t.app)
            .collect();
        apps.sort();
        assert_eq!(
            apps,
            vec![
                "firefox",
                "gjs-console@g.scope",
                "ld-linux-x86-64.so.2@x.scope",
                "python2.7@p2.scope",
                "python3.12@run-u7.service",
                "qemu-system-x86_64@vm.scope",
                "wine64-preloader@w.scope",
            ]
        );
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

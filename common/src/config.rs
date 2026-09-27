use crate::{Error, Limit, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

/// Maximum config file size (1 MB) - prevents YAML bomb DoS attacks
const MAX_CONFIG_SIZE: u64 = 1_048_576;

/// Upper bound for guard sizes given in MB (16 TiB). Far above any real
/// host, and low enough that converting to bytes cannot overflow.
pub const MAX_GUARD_MB: u64 = 16 * 1024 * 1024;
/// Upper bound for guard durations given in seconds (one day).
pub const MAX_GUARD_SECS: u64 = 86_400;

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub profiles: HashMap<String, Profile>,

    /// Freeze-guard daemon configuration. Skipped on serialize when at defaults
    /// so saving profiles doesn't pollute config.yaml with a guard block.
    #[serde(default, skip_serializing_if = "GuardConfig::is_default")]
    pub guard: GuardConfig,

    /// Persistent application limit rules, enforced continuously by rlm-guard.
    /// Keyed by rule name (defaults to the executable basename). Omitted from
    /// serialized output when empty.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub rules: HashMap<String, AppRule>,
}

/// A persistent application limit rule. Instances whose executable basename is
/// in `match_exe` are placed into a shared `app-<name>` cgroup with these limits.
/// Limits are stored inline (a snapshot), not as a reference to a profile.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppRule {
    /// Executable basenames this rule matches.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub match_exe: Vec<String>,

    /// Memory limit (e.g., "4G").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,

    /// CPU limit (e.g., "75%").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<String>,

    /// I/O read bandwidth limit (e.g., "100M").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_read: Option<String>,

    /// I/O write bandwidth limit (e.g., "50M").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_write: Option<String>,
}

impl AppRule {
    pub fn to_limit(&self) -> Result<Limit> {
        use crate::{CpuLimit, IoLimit, MemoryLimit};

        let read_bps = self
            .io_read
            .as_ref()
            .map(|s| IoLimit::parse_bps(s))
            .transpose()?;
        let write_bps = self
            .io_write
            .as_ref()
            .map(|s| IoLimit::parse_bps(s))
            .transpose()?;
        let io = if read_bps.is_some() || write_bps.is_some() {
            Some(IoLimit {
                read_bps,
                write_bps,
            })
        } else {
            None
        };

        Ok(Limit {
            memory: self
                .memory
                .as_ref()
                .map(|s| MemoryLimit::parse(s))
                .transpose()?,
            cpu: self.cpu.as_ref().map(|s| CpuLimit::parse(s)).transpose()?,
            io,
        })
    }
}

/// Configuration for the `rlm-guard` freeze-guard daemon. Every field defaults,
/// so a missing `guard:` section (or any missing key) yields a working setup.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GuardConfig {
    pub enabled: bool,
    pub trigger: GuardTrigger,
    pub timing: GuardTiming,
    pub selection: GuardSelection,
    pub notify: bool,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            trigger: GuardTrigger::default(),
            timing: GuardTiming::default(),
            selection: GuardSelection::default(),
            notify: true,
        }
    }
}

impl GuardConfig {
    pub fn is_default(&self) -> bool {
        *self == GuardConfig::default()
    }

    /// Reject values the guard cannot act on safely. Called by rlm-guard at
    /// startup and by `rlm guard status` / `rlm doctor`.
    pub fn validate(&self) -> Result<()> {
        let bad = |m: &str| Err(Error::Config(format!("guard: {m}")));
        let t = &self.trigger;
        let pct = |v: f64| v > 0.0 && v <= 100.0;
        if !pct(t.psi_some_warn) || !pct(t.psi_some_high) || !pct(t.psi_full_critical) {
            return bad("trigger PSI thresholds must be between 0 (exclusive) and 100");
        }
        if t.psi_some_warn >= t.psi_some_high {
            return bad("trigger.psi_some_warn must be below trigger.psi_some_high");
        }
        if !(1..=100).contains(&t.act_below_available_pct) {
            return bad("trigger.act_below_available_pct must be between 1 and 100");
        }
        if t.mem_available_floor_mb > MAX_GUARD_MB {
            return bad(&format!(
                "trigger.mem_available_floor_mb must be at most {MAX_GUARD_MB}"
            ));
        }
        let tm = &self.timing;
        if !(100..=60_000).contains(&tm.sample_interval_ms) {
            return bad("timing.sample_interval_ms must be between 100 and 60000");
        }
        if !(1..=60).contains(&tm.freeze_hold_secs) {
            return bad("timing.freeze_hold_secs must be between 1 and 60");
        }
        if !(1..=MAX_GUARD_SECS).contains(&tm.calm_hold_secs) {
            return bad(&format!(
                "timing.calm_hold_secs must be between 1 and {MAX_GUARD_SECS}"
            ));
        }
        if tm.freeze_cooldown_secs < tm.freeze_hold_secs {
            return bad("timing.freeze_cooldown_secs must be at least timing.freeze_hold_secs");
        }
        if tm.freeze_cooldown_secs > MAX_GUARD_SECS {
            return bad(&format!(
                "timing.freeze_cooldown_secs must be at most {MAX_GUARD_SECS}"
            ));
        }
        if self.selection.min_rss_mb > MAX_GUARD_MB {
            return bad(&format!(
                "selection.min_rss_mb must be at most {MAX_GUARD_MB}"
            ));
        }
        if self.selection.protect.iter().any(|p| p.trim().is_empty()) {
            return bad("selection.protect must not contain empty names");
        }
        Ok(())
    }
}

/// Pressure thresholds (PSI percentages and a MemAvailable backstop).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GuardTrigger {
    /// PSI `some` avg10 (%) at which to start warning.
    pub psi_some_warn: f64,
    /// PSI `some` avg10 (%) at which to start acting (High).
    pub psi_some_high: f64,
    /// PSI `full` avg10 (%) considered Critical.
    pub psi_full_critical: f64,
    /// Hard floor: act if MemAvailable drops below this many MB.
    pub mem_available_floor_mb: u64,
    /// Act only while MemAvailable is below this percentage of MemTotal (or below the floor).
    pub act_below_available_pct: u64,
}

impl Default for GuardTrigger {
    fn default() -> Self {
        Self {
            psi_some_warn: 10.0,
            psi_some_high: 30.0,
            psi_full_critical: 10.0,
            mem_available_floor_mb: 400,
            act_below_available_pct: 20,
        }
    }
}

/// Timing/hysteresis knobs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GuardTiming {
    /// How long a freeze is held before auto-thaw.
    pub freeze_hold_secs: u64,
    /// How long pressure must stay Calm before caps are lifted.
    pub calm_hold_secs: u64,
    /// Minimum gap before the same PID may be frozen again (else it's capped).
    pub freeze_cooldown_secs: u64,
    /// Sampling interval.
    pub sample_interval_ms: u64,
}

impl Default for GuardTiming {
    fn default() -> Self {
        Self {
            freeze_hold_secs: 5,
            calm_hold_secs: 30,
            freeze_cooldown_secs: 60,
            sample_interval_ms: 1000,
        }
    }
}

/// Victim-selection knobs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GuardSelection {
    /// Ignore processes smaller than this (MB of RSS+swap).
    pub min_rss_mb: u64,
    /// Process names to NEVER act on. These ADD to the built-in protect-list.
    pub protect: Vec<String>,
}

impl Default for GuardSelection {
    fn default() -> Self {
        Self {
            min_rss_mb: 200,
            protect: Vec::new(),
        }
    }
}

/// Process names always protected from the guard, regardless of config.
pub const BUILTIN_PROTECT: &[&str] = &[
    "gnome-shell",
    "kwin_wayland",
    "kwin_x11",
    "plasmashell",
    "sway",
    "Hyprland",
    "Xwayland",
    "Xorg",
    "sshd",
    "systemd",
    "dbus-daemon",
    "pipewire",
    "wireplumber",
    "pulseaudio",
    "rlm-guard",
    "bash",
    "zsh",
    "fish",
];

/// Built-in protect names plus the user's additions from `guard.selection.protect`.
pub fn protect_set(extra: &[String]) -> HashSet<String> {
    BUILTIN_PROTECT
        .iter()
        .map(|s| (*s).to_string())
        .chain(extra.iter().cloned())
        .collect()
}

/// A process is protected if its full executable basename is in `set`, or,
/// when the executable is unreadable, if its comm is. comm is truncated to 15
/// characters by the kernel, so it only matches short names.
pub fn is_protected(set: &HashSet<String>, comm: &str, exe: Option<&str>) -> bool {
    exe.is_some_and(|e| set.contains(e)) || set.contains(comm)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Executables this profile matches
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub match_exe: Vec<String>,

    /// Memory limit (e.g., "2G")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,

    /// CPU limit (e.g., "50%")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<String>,

    /// I/O read bandwidth limit (e.g., "100M")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_read: Option<String>,

    /// I/O write bandwidth limit (e.g., "50M")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_write: Option<String>,
}

impl Profile {
    /// Validate that this profile's limit values parse and that it sets at
    /// least one limit (an all-empty profile is never useful).
    pub fn validate(&self) -> Result<()> {
        let l = self.to_limit()?;
        if l.is_empty() {
            return Err(Error::Config("profile sets no limits".into()));
        }
        Ok(())
    }

    pub fn to_limit(&self) -> Result<Limit> {
        use crate::{CpuLimit, IoLimit, MemoryLimit};

        let read_bps = self
            .io_read
            .as_ref()
            .map(|s| IoLimit::parse_bps(s))
            .transpose()?;
        let write_bps = self
            .io_write
            .as_ref()
            .map(|s| IoLimit::parse_bps(s))
            .transpose()?;
        let io = if read_bps.is_some() || write_bps.is_some() {
            Some(IoLimit {
                read_bps,
                write_bps,
            })
        } else {
            None
        };

        Ok(Limit {
            memory: self
                .memory
                .as_ref()
                .map(|s| MemoryLimit::parse(s))
                .transpose()?,
            cpu: self.cpu.as_ref().map(|s| CpuLimit::parse(s)).transpose()?,
            io,
        })
    }
}

/// Built-in preset profiles
pub fn builtin_presets() -> HashMap<String, Profile> {
    let mut presets = HashMap::new();

    presets.insert(
        "Light".to_string(),
        Profile {
            match_exe: Vec::new(),
            memory: Some("512M".to_string()),
            cpu: Some("25%".to_string()),
            io_read: None,
            io_write: None,
        },
    );

    presets.insert(
        "Medium".to_string(),
        Profile {
            match_exe: Vec::new(),
            memory: Some("2G".to_string()),
            cpu: Some("50%".to_string()),
            io_read: Some("50M".to_string()),
            io_write: Some("25M".to_string()),
        },
    );

    presets.insert(
        "Heavy".to_string(),
        Profile {
            match_exe: Vec::new(),
            memory: Some("4G".to_string()),
            cpu: Some("100%".to_string()),
            io_read: Some("100M".to_string()),
            io_write: Some("50M".to_string()),
        },
    );

    presets.insert(
        "Browser".to_string(),
        Profile {
            match_exe: vec![
                "firefox".to_string(),
                "chrome".to_string(),
                "chromium".to_string(),
            ],
            memory: Some("4G".to_string()),
            cpu: Some("75%".to_string()),
            io_read: None,
            io_write: None,
        },
    );

    presets
}

impl Config {
    /// Load config from default locations (user overrides system)
    pub fn load() -> Result<Self> {
        let mut config = Config::default();

        // System config
        let system_path = PathBuf::from("/etc/rlm/config.yaml");
        if system_path.exists() {
            config.merge_from(&system_path)?;
        }

        // User config
        if let Some(user_path) = Self::user_config_path() {
            if user_path.exists() {
                config.merge_from(&user_path)?;
            }

            // Load profiles from profiles.d/
            let profiles_dir = user_path
                .parent()
                .map(|p| p.join("profiles.d"))
                .unwrap_or_else(|| PathBuf::from("profiles.d"));
            if profiles_dir.exists() {
                config.load_profiles_dir(&profiles_dir)?;
            }
        }

        Ok(config)
    }

    /// `load()` plus guard validation. rlm-guard refuses to start on `Err`.
    pub fn load_validated() -> Result<Self> {
        let c = Self::load()?;
        c.guard.validate()?;
        Ok(c)
    }

    /// Load config from a specific file
    pub fn load_from(path: &Path) -> Result<Self> {
        // Check file size to prevent YAML bomb DoS
        let metadata = fs::metadata(path)?;
        if metadata.len() > MAX_CONFIG_SIZE {
            return Err(Error::Config(format!(
                "config file {} exceeds maximum size of 1MB",
                path.display()
            )));
        }

        let content = fs::read_to_string(path)?;
        serde_yaml_ng::from_str(&content)
            .map_err(|e| Error::Config(format!("failed to parse {}: {e}", path.display())))
    }

    fn merge_from(&mut self, path: &Path) -> Result<()> {
        let other = Self::load_from(path)?;
        self.profiles.extend(other.profiles);
        self.rules.extend(other.rules);
        // A non-default guard block in a loaded file takes effect.
        if !other.guard.is_default() {
            self.guard = other.guard;
        }
        Ok(())
    }

    fn load_profiles_dir(&mut self, dir: &Path) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
                self.merge_from(&path)?;
            }
        }
        Ok(())
    }

    fn user_config_path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("rlm").join("config.yaml"))
    }

    /// Find a profile by name (includes built-in presets): an exact match
    /// wins, otherwise a case-insensitive match is used if exactly one
    /// profile name matches.
    pub fn get_profile(&self, name: &str) -> Option<Profile> {
        let resolved = self.resolve_profile_name(name)?;
        self.all_profiles().get(&resolved).cloned()
    }

    /// Resolve `name` to a real profile name: an exact match wins, otherwise
    /// the single case-insensitive match, or `None` if there is no match or
    /// more than one.
    pub fn resolve_profile_name(&self, name: &str) -> Option<String> {
        let all = self.all_profiles();
        if all.contains_key(name) {
            return Some(name.to_string());
        }
        let mut matches = all.keys().filter(|k| k.eq_ignore_ascii_case(name));
        let first = matches.next()?.clone();
        if matches.next().is_some() {
            None
        } else {
            Some(first)
        }
    }

    /// All profile names (user profiles plus built-in presets), sorted
    /// case-insensitively (ties broken by the name itself).
    pub fn profile_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.all_profiles().into_keys().collect();
        names.sort_by(|a, b| {
            a.to_lowercase()
                .cmp(&b.to_lowercase())
                .then_with(|| a.cmp(b))
        });
        names
    }

    /// Get all profiles including built-in presets (user profiles override)
    pub fn all_profiles(&self) -> HashMap<String, Profile> {
        let mut all = builtin_presets();
        // User profiles override built-in
        for (name, profile) in &self.profiles {
            all.insert(name.clone(), profile.clone());
        }
        all
    }

    /// Add or replace a persistent application rule.
    pub fn add_rule(&mut self, name: impl Into<String>, rule: AppRule) {
        self.rules.insert(name.into(), rule);
    }

    /// Remove a persistent rule by name. Returns true if a rule was removed.
    pub fn remove_rule(&mut self, name: &str) -> bool {
        self.rules.remove(name).is_some()
    }

    /// Save config to user config path (atomic write)
    pub fn save(&self) -> Result<()> {
        let path = Self::user_config_path()
            .ok_or_else(|| Error::Config("No config directory found".into()))?;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let yaml = serde_yaml_ng::to_string(self)
            .map_err(|e| Error::Config(format!("Failed to serialize config: {e}")))?;

        // Atomic write: write to temp file, then rename
        let tmp_path = path.with_extension("yaml.tmp");
        fs::write(&tmp_path, &yaml)?;
        fs::rename(&tmp_path, &path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_rule_to_limit_parses_fields() {
        let rule = AppRule {
            match_exe: vec!["firefox".into()],
            memory: Some("4G".into()),
            cpu: Some("75%".into()),
            io_read: None,
            io_write: None,
        };
        let limit = rule.to_limit().unwrap();
        assert_eq!(limit.memory.unwrap().bytes(), 4 * 1024 * 1024 * 1024);
        assert_eq!(limit.cpu.unwrap().percent(), 75);
        assert!(limit.io.is_none());
    }

    #[test]
    fn app_rule_invalid_limit_errors() {
        let rule = AppRule {
            match_exe: vec!["x".into()],
            memory: Some("notasize".into()),
            ..Default::default()
        };
        assert!(rule.to_limit().is_err());
    }

    #[test]
    fn empty_rules_omitted_from_yaml() {
        let cfg = Config::default();
        let yaml = serde_yaml_ng::to_string(&cfg).unwrap();
        assert!(
            !yaml.contains("rules:"),
            "empty rules must be omitted: {yaml}"
        );
    }

    #[test]
    fn rules_round_trip_through_yaml() {
        let mut cfg = Config::default();
        cfg.add_rule(
            "firefox",
            AppRule {
                match_exe: vec!["firefox".into()],
                memory: Some("4G".into()),
                cpu: Some("75%".into()),
                io_read: None,
                io_write: None,
            },
        );
        let yaml = serde_yaml_ng::to_string(&cfg).unwrap();
        assert!(yaml.contains("rules:"));
        let back: Config = serde_yaml_ng::from_str(&yaml).unwrap();
        let r = back.rules.get("firefox").expect("rule present");
        assert_eq!(r.match_exe, vec!["firefox".to_string()]);
        assert_eq!(r.memory.as_deref(), Some("4G"));
    }

    #[test]
    fn add_and_remove_rule() {
        let mut cfg = Config::default();
        cfg.add_rule("code", AppRule::default());
        assert!(cfg.rules.contains_key("code"));
        assert!(cfg.remove_rule("code"));
        assert!(!cfg.remove_rule("code"));
        assert!(cfg.rules.is_empty());
    }

    #[test]
    fn protect_set_merges_builtin_and_extra() {
        let s = protect_set(&["gnome-control-center".into()]);
        assert!(s.contains("gnome-shell"));
        assert!(s.contains("gnome-control-center"));
    }

    #[test]
    fn is_protected_prefers_full_exe_name_over_truncated_comm() {
        let s = protect_set(&["gnome-control-center".into()]);
        assert!(is_protected(
            &s,
            "gnome-control-c",
            Some("gnome-control-center")
        ));
        assert!(
            !is_protected(&s, "gnome-control-c", None),
            "truncated comm alone cannot match"
        );
        assert!(is_protected(&s, "bash", None));
        assert!(!is_protected(&s, "firefox", Some("firefox")));
    }

    #[test]
    fn readme_guard_example_parses_and_validates() {
        let yaml = "guard:\n  enabled: true\n  trigger:   { psi_some_warn: 10, psi_some_high: 30, psi_full_critical: 10, mem_available_floor_mb: 400 }\n  timing:    { freeze_hold_secs: 5, calm_hold_secs: 30, freeze_cooldown_secs: 60, sample_interval_ms: 1000 }\n  selection: { min_rss_mb: 200, protect: [] }\n  notify: true\n";
        let cfg: Config = serde_yaml_ng::from_str(yaml).unwrap();
        cfg.guard.validate().unwrap();
        assert_eq!(cfg.guard.trigger.act_below_available_pct, 20);
    }

    #[test]
    fn unknown_guard_key_is_an_error() {
        let err = serde_yaml_ng::from_str::<Config>("guard:\n  selection: { min_rss: 100 }\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("min_rss"), "{err}");
    }

    #[test]
    fn unknown_top_level_and_profile_keys_are_errors() {
        assert!(serde_yaml_ng::from_str::<Config>("gaurd:\n  enabled: false\n").is_err());
        assert!(serde_yaml_ng::from_str::<Config>("profiles:\n  a: { memroy: 2G }\n").is_err());
    }

    #[test]
    fn claude_md_profile_example_still_parses() {
        let yaml = "profiles:\n  browser:\n    match_exe: [firefox, chrome]\n    memory: \"4G\"\n    cpu: \"75%\"\n    io_read: \"100M\"\n    io_write: \"50M\"\n";
        let cfg: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(cfg.profiles["browser"].memory.as_deref(), Some("4G"));
    }

    #[test]
    fn default_guard_config_validates() {
        GuardConfig::default().validate().unwrap();
    }

    #[test]
    #[allow(clippy::type_complexity)]
    fn validate_rejects_bad_values() {
        let bad: Vec<Box<dyn Fn(&mut GuardConfig)>> = vec![
            Box::new(|c| {
                c.trigger.psi_some_warn = 40.0;
                c.trigger.psi_some_high = 30.0
            }),
            Box::new(|c| c.trigger.psi_full_critical = 0.0),
            Box::new(|c| c.trigger.psi_some_high = f64::NAN),
            Box::new(|c| c.trigger.act_below_available_pct = 0),
            Box::new(|c| c.trigger.act_below_available_pct = 101),
            Box::new(|c| c.timing.sample_interval_ms = 0),
            Box::new(|c| c.timing.freeze_hold_secs = 0),
            Box::new(|c| c.timing.calm_hold_secs = 0),
            Box::new(|c| c.timing.freeze_cooldown_secs = 1),
            Box::new(|c| c.selection.protect = vec!["  ".into()]),
        ];
        for (i, f) in bad.iter().enumerate() {
            let mut c = GuardConfig::default();
            f(&mut c);
            assert!(c.validate().is_err(), "case {i} should be rejected");
        }
    }

    /// Every size and duration has an upper bound: the bound itself is
    /// accepted, one past it is rejected with a message naming the field.
    #[test]
    #[allow(clippy::type_complexity)]
    fn validate_enforces_upper_bounds() {
        let cases: Vec<(&str, Box<dyn Fn(&mut GuardConfig, u64)>, u64)> = vec![
            (
                "trigger.mem_available_floor_mb",
                Box::new(|c, v| c.trigger.mem_available_floor_mb = v),
                MAX_GUARD_MB,
            ),
            (
                "timing.calm_hold_secs",
                Box::new(|c, v| c.timing.calm_hold_secs = v),
                MAX_GUARD_SECS,
            ),
            (
                "timing.freeze_cooldown_secs",
                Box::new(|c, v| c.timing.freeze_cooldown_secs = v),
                MAX_GUARD_SECS,
            ),
            (
                "selection.min_rss_mb",
                Box::new(|c, v| c.selection.min_rss_mb = v),
                MAX_GUARD_MB,
            ),
            (
                "timing.freeze_hold_secs",
                Box::new(|c, v| c.timing.freeze_hold_secs = v),
                60,
            ),
            (
                "timing.sample_interval_ms",
                Box::new(|c, v| c.timing.sample_interval_ms = v),
                60_000,
            ),
            (
                "trigger.act_below_available_pct",
                Box::new(|c, v| c.trigger.act_below_available_pct = v),
                100,
            ),
        ];
        for (field, set, max) in &cases {
            let mut c = GuardConfig::default();
            set(&mut c, *max);
            c.validate()
                .unwrap_or_else(|e| panic!("{field} = {max} must be accepted: {e}"));
            for v in [max + 1, u64::MAX] {
                let mut c = GuardConfig::default();
                set(&mut c, v);
                let err = c.validate().expect_err(field).to_string();
                assert!(err.contains(field), "{field} = {v}: {err}");
            }
        }
    }

    #[test]
    fn profile_lookup_is_case_insensitive_when_unique() {
        let cfg = Config::default();
        assert!(cfg.get_profile("browser").is_some());
        assert!(cfg.get_profile("MEDIUM").is_some());
        assert!(cfg.get_profile("nope").is_none());
    }

    #[test]
    fn exact_profile_name_wins_and_ambiguity_is_refused() {
        let mut cfg = Config::default();
        cfg.profiles.insert(
            "browser".into(),
            Profile {
                memory: Some("1G".into()),
                ..Default::default()
            },
        );
        assert_eq!(
            cfg.get_profile("browser").unwrap().memory.as_deref(),
            Some("1G")
        );
        assert_eq!(
            cfg.get_profile("Browser").unwrap().memory.as_deref(),
            Some("4G")
        );
        assert!(
            cfg.get_profile("BROWSER").is_none(),
            "two case-insensitive matches"
        );
    }

    #[test]
    fn profile_names_are_sorted_case_insensitively() {
        let mut cfg = Config::default();
        cfg.profiles.insert(
            "aaa".into(),
            Profile {
                cpu: Some("10%".into()),
                ..Default::default()
            },
        );
        assert_eq!(
            cfg.profile_names(),
            vec!["aaa", "Browser", "Heavy", "Light", "Medium"]
        );
    }

    #[test]
    fn profile_validate_rejects_empty_and_invalid() {
        assert!(Profile::default().validate().is_err());
        assert!(Profile {
            memory: Some("lots".into()),
            ..Default::default()
        }
        .validate()
        .is_err());
        assert!(Profile {
            cpu: Some("50%".into()),
            ..Default::default()
        }
        .validate()
        .is_ok());
    }

    #[test]
    fn load_from_names_the_file_on_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("config.yaml");
        std::fs::write(&p, "profiles: [\n").unwrap();
        let err = Config::load_from(&p).unwrap_err().to_string();
        assert!(err.contains("config.yaml"), "{err}");
    }
}

use crate::{Error, Limit, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Maximum config file size (1 MB) - prevents YAML bomb DoS attacks
const MAX_CONFIG_SIZE: u64 = 1_048_576;

#[derive(Debug, Default, Serialize, Deserialize)]
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
#[serde(default)]
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
}

/// Pressure thresholds (PSI percentages and a MemAvailable backstop).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GuardTrigger {
    /// PSI `some` avg10 (%) at which to start warning.
    pub psi_some_warn: f64,
    /// PSI `some` avg10 (%) at which to start acting (High).
    pub psi_some_high: f64,
    /// PSI `full` avg10 (%) considered Critical.
    pub psi_full_critical: f64,
    /// Hard floor: act if MemAvailable drops below this many MB.
    pub mem_available_floor_mb: u64,
}

impl Default for GuardTrigger {
    fn default() -> Self {
        Self {
            psi_some_warn: 10.0,
            psi_some_high: 30.0,
            psi_full_critical: 10.0,
            mem_available_floor_mb: 400,
        }
    }
}

/// Timing/hysteresis knobs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
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
#[serde(default)]
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

    /// Find a profile by name (includes built-in presets)
    pub fn get_profile(&self, name: &str) -> Option<Profile> {
        // User profiles override built-in presets
        if let Some(p) = self.profiles.get(name) {
            return Some(p.clone());
        }
        builtin_presets().get(name).cloned()
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
}

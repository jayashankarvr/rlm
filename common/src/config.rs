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
}

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

    /// Find a profile that matches an executable name
    pub fn find_profile_for_exe(&self, exe: &str) -> Option<&Profile> {
        self.profiles
            .values()
            .find(|p| p.match_exe.iter().any(|m| m == exe))
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

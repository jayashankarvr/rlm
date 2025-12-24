use common::Result;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Desktop application entry
#[derive(Clone)]
pub struct DesktopApp {
    pub name: String,
    pub exec: String,
    pub is_cli: bool,
}

/// List installed applications from .desktop files
pub fn list_applications() -> Result<Vec<DesktopApp>> {
    let mut apps = Vec::new();
    let dirs = [
        "/usr/share/applications",
        "/usr/local/share/applications",
        "/var/lib/flatpak/exports/share/applications",
    ];

    // Also check user's local applications
    let home_apps = dirs::data_dir().map(|d| d.join("applications"));

    for dir in dirs.iter().map(Path::new).chain(home_apps.as_deref()) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "desktop") {
                    if let Some(app) = parse_desktop_file(&path) {
                        apps.push(app);
                    }
                }
            }
        }
    }

    apps.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    apps.dedup_by(|a, b| a.name == b.name);
    Ok(apps)
}

fn parse_desktop_file(path: &Path) -> Option<DesktopApp> {
    let content = fs::read_to_string(path).ok()?;
    let mut name = None;
    let mut exec = None;
    let mut no_display = false;
    let mut in_desktop_entry = false;

    for line in content.lines() {
        let line = line.trim();

        if line.starts_with('[') {
            in_desktop_entry = line == "[Desktop Entry]";
            continue;
        }

        if !in_desktop_entry {
            continue;
        }

        if line.starts_with("Name=") && name.is_none() {
            name = Some(line[5..].to_string());
        } else if line.starts_with("Exec=") && exec.is_none() {
            // Extract command, stripping field codes (%u, %F, etc.) but keeping arguments
            let cmd_line = &line[5..];
            let filtered: Vec<&str> = cmd_line
                .split_whitespace()
                .map(|arg| arg.trim_matches('"'))
                .filter(|arg| !arg.is_empty() && !arg.starts_with('%'))
                .collect();

            // Handle env wrappers (e.g., "env VAR=val app args")
            let command = if filtered.first() == Some(&"env") {
                // Skip env and any VAR=val pairs
                filtered
                    .iter()
                    .skip(1)
                    .skip_while(|arg| arg.contains('='))
                    .copied()
                    .collect::<Vec<_>>()
                    .join(" ")
            } else {
                filtered.join(" ")
            };

            if !command.is_empty() {
                exec = Some(command);
            }
        } else if line == "NoDisplay=true" || line == "Hidden=true" {
            no_display = true;
        } else if line.starts_with("Type=") && line != "Type=Application" {
            return None;
        }
    }

    if no_display {
        return None;
    }

    Some(DesktopApp {
        name: name?,
        exec: exec?,
        is_cli: false,
    })
}

/// Search PATH for executables matching a query
pub fn search_cli_apps(query: &str) -> Vec<DesktopApp> {
    if query.len() < 2 {
        return Vec::new();
    }

    let query_lower = query.to_lowercase();
    let mut apps = Vec::new();

    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            let dir_path = Path::new(dir);
            if let Ok(entries) = fs::read_dir(dir_path) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if !name.to_lowercase().contains(&query_lower) {
                        continue;
                    }

                    // Check if executable
                    if let Ok(meta) = entry.metadata() {
                        if meta.is_file() && (meta.permissions().mode() & 0o111 != 0) {
                            apps.push(DesktopApp {
                                name: format!("{} (CLI)", name),
                                exec: name,
                                is_cli: true,
                            });
                        }
                    }
                }
            }
        }
    }

    apps.sort_by(|a, b| a.name.cmp(&b.name));
    apps.dedup_by(|a, b| a.exec == b.exec);
    apps
}

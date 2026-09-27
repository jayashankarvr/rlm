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

    apps.sort_by_key(|a| a.name.to_lowercase());
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
            exec = exec_command(&line[5..]);
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

/// Turn a desktop file `Exec` value into a shell-quoted command line: field
/// codes (%u, %F, ...) removed and each argument quoted when it holds spaces
/// or shell characters, so a shell-style split gives back the same
/// arguments. An `env VAR=value app` wrapper is kept whole, with `env` as
/// the program, so the app still gets its variables. `None` if nothing is
/// left, an `env` wrapper names no program, or a quote is not closed.
pub fn exec_command(value: &str) -> Option<String> {
    let args = split_exec(&unescape_value(value))?;
    let args: Vec<String> = args.into_iter().filter_map(expand_field_codes).collect();
    if args.is_empty() {
        return None;
    }
    if args[0] == "env" && !env_runs_a_program(&args[1..]) {
        return None;
    }
    Some(
        args.iter()
            .map(|a| shell_quote(a))
            .collect::<Vec<_>>()
            .join(" "),
    )
}

/// Whether the arguments after `env` name a program to run, rather than only
/// settings (`VAR=value`, `-u NAME`, `-i`, ...), in which case `env` would
/// just print the environment.
fn env_runs_a_program(args: &[String]) -> bool {
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            // These take the next argument as their value.
            "-u" | "--unset" | "-C" | "--chdir" => {
                args.next();
            }
            // The string holds the command line itself.
            "-S" | "--split-string" => return args.next().is_some(),
            "--" => return args.next().is_some(),
            a if a.starts_with("-S") && a.len() > 2 => return true,
            a if a.starts_with('-') => {}
            a if a.contains('=') => {}
            _ => return true,
        }
    }
    false
}

/// Undo the escapes every desktop file string value may use: \s, \n, \t,
/// \r and \\.
fn unescape_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('s') => out.push(' '),
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('\\') => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// Split an Exec value into arguments. Double quotes group an argument;
/// inside them a backslash escapes `"`, `` ` ``, `$` and `\`. `None` when
/// a quote is left open.
fn split_exec(value: &str) -> Option<Vec<String>> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_arg = false;
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                in_arg = true;
                loop {
                    match chars.next()? {
                        '"' => break,
                        '\\' => match chars.next()? {
                            e @ ('"' | '`' | '$' | '\\') => current.push(e),
                            other => {
                                current.push('\\');
                                current.push(other);
                            }
                        },
                        other => current.push(other),
                    }
                }
            }
            c if c.is_whitespace() => {
                if in_arg {
                    args.push(std::mem::take(&mut current));
                    in_arg = false;
                }
            }
            c => {
                in_arg = true;
                current.push(c);
            }
        }
    }
    if in_arg {
        args.push(current);
    }
    Some(args)
}

/// Remove field codes from one argument: an argument that is only a code
/// (such as %U) is dropped, `%%` becomes `%`, and codes inside an argument
/// are removed.
fn expand_field_codes(arg: String) -> Option<String> {
    if arg.len() == 2 && arg.starts_with('%') && arg != "%%" {
        return None;
    }
    let mut out = String::with_capacity(arg.len());
    let mut chars = arg.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
        } else if let Some(next) = chars.next() {
            if next == '%' {
                out.push('%');
            }
        }
    }
    Some(out)
}

/// Quote `arg` for a POSIX shell-style split, leaving plain words as they
/// are.
fn shell_quote(arg: &str) -> String {
    let plain = !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c));
    if plain {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', r"'\''"))
    }
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
                                // Quoted, since a file name may hold spaces or
                                // shell characters and the command is split
                                // like a shell line.
                                exec: shell_quote(&name),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_drops_field_codes_and_keeps_arguments() {
        assert_eq!(exec_command("firefox %u").as_deref(), Some("firefox"));
        assert_eq!(
            exec_command("code --new-window %F").as_deref(),
            Some("code --new-window")
        );
        assert_eq!(
            exec_command("app --pct=100%%").as_deref(),
            Some("app --pct=100%")
        );
        assert_eq!(
            exec_command("app --file=%f").as_deref(),
            Some("app --file=")
        );
    }

    #[test]
    fn exec_keeps_quoted_arguments_together() {
        assert_eq!(
            exec_command(r#""/opt/My App/app" --flag %U"#).as_deref(),
            Some("'/opt/My App/app' --flag")
        );
        assert_eq!(
            exec_command(r#"sh -c "echo hi; sleep 1""#).as_deref(),
            Some("sh -c 'echo hi; sleep 1'")
        );
        // Inside quotes a backslash escapes ", `, $ and \. The file itself
        // writes a backslash as \\, so \\\\ in the file is one backslash.
        assert_eq!(
            exec_command(r#"app "say \\"hi\\"" "c:\\\\dir""#).as_deref(),
            Some(r#"app 'say "hi"' 'c:\dir'"#)
        );
        assert_eq!(
            exec_command("app \"it's\"").as_deref(),
            Some(r"app 'it'\''s'")
        );
        // \s is unescaped before splitting, so it separates words.
        assert_eq!(exec_command(r"my\sapp").as_deref(), Some("my app"));
    }

    #[test]
    fn exec_keeps_env_wrappers_and_their_variables() {
        assert_eq!(
            exec_command("env FOO=1 BAR=\"a b\" app --x %f").as_deref(),
            Some("env FOO=1 'BAR=a b' app --x")
        );
        assert_eq!(
            exec_command("env -u GTK_THEME app").as_deref(),
            Some("env -u GTK_THEME app")
        );
        assert_eq!(
            exec_command("env -i -- app").as_deref(),
            Some("env -i -- app")
        );
        assert_eq!(exec_command("env -u X"), None);
        assert_eq!(exec_command("env -i"), None);
    }

    #[test]
    fn cli_app_names_are_quoted() {
        assert_eq!(shell_quote("my tool"), "'my tool'");
        assert_eq!(shell_quote("rg"), "rg");
        assert_eq!(shell_quote("a$b"), "'a$b'");
    }

    #[test]
    fn exec_rejects_empty_or_unterminated_lines() {
        assert_eq!(exec_command("%U"), None);
        assert_eq!(exec_command("   "), None);
        assert_eq!(exec_command("env A=1"), None);
        assert_eq!(exec_command(r#"app "open"#), None);
    }
}

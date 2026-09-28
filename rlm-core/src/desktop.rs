use common::Result;
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Desktop application entry
#[derive(Clone)]
pub struct DesktopApp {
    pub name: String,
    pub exec: String,
    pub is_cli: bool,
}

/// Directories searched for `.desktop` files: the system ones, then the
/// user's own.
fn desktop_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = [
        "/usr/share/applications",
        "/usr/local/share/applications",
        "/var/lib/flatpak/exports/share/applications",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    dirs.extend(dirs::data_dir().map(|d| d.join("applications")));
    dirs
}

/// Every shown application entry in [`desktop_dirs`].
fn desktop_entries() -> Vec<Entry> {
    let mut out = Vec::new();
    for dir in desktop_dirs() {
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "desktop") {
                    if let Some(e) = read_entry(&path) {
                        out.push(e);
                    }
                }
            }
        }
    }
    out
}

/// List installed applications from .desktop files
pub fn list_applications() -> Result<Vec<DesktopApp>> {
    let mut apps: Vec<DesktopApp> = desktop_entries()
        .into_iter()
        .filter_map(|e| {
            Some(DesktopApp {
                exec: exec_command(&e.exec)?,
                name: e.name,
                is_cli: false,
            })
        })
        .collect();
    apps.sort_by_key(|a| a.name.to_lowercase());
    apps.dedup_by(|a, b| a.name == b.name);
    Ok(apps)
}

/// Installed application names keyed by the basename of the program their
/// `Exec` runs (`firefox` to `Firefox`). When several entries run the same
/// program, the shortest name wins.
pub fn names_by_program() -> HashMap<String, String> {
    let mut names: HashMap<String, String> = HashMap::new();
    for e in desktop_entries() {
        let Some(program) = exec_program(&e.exec) else {
            continue;
        };
        let better = names
            .get(&program)
            .is_none_or(|old| (e.name.len(), &e.name) < (old.len(), old));
        if better {
            names.insert(program, e.name);
        }
    }
    names
}

/// The basename of the program a raw desktop file `Exec` value runs, looking
/// past an `env VAR=value` wrapper. `None` if there is none.
pub fn exec_program(value: &str) -> Option<String> {
    let args = split_exec(&unescape_value(value))?;
    let mut args = args.into_iter().filter_map(expand_field_codes);
    let mut program = args.next()?;
    if program == "env" {
        program = loop {
            let arg = args.next()?;
            match arg.as_str() {
                "-u" | "--unset" | "-C" | "--chdir" => {
                    args.next();
                }
                "--" => break args.next()?,
                a if a.starts_with('-') || a.contains('=') => {}
                _ => break arg,
            }
        };
    }
    let base = program.rsplit('/').next().unwrap_or(&program);
    (!base.is_empty()).then(|| base.to_string())
}

/// A shown application entry: its `Name` and raw `Exec` value.
struct Entry {
    name: String,
    exec: String,
}

/// Read the `[Desktop Entry]` group of one file. `None` for a hidden entry,
/// a non-application, or one without a usable `Name` and `Exec`.
fn read_entry(path: &Path) -> Option<Entry> {
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

        if let Some(value) = line.strip_prefix("Name=") {
            if name.is_none() {
                name = Some(value.to_string());
            }
        } else if let Some(value) = line.strip_prefix("Exec=") {
            if exec.is_none() && exec_command(value).is_some() {
                exec = Some(value.to_string());
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

    Some(Entry {
        name: name?,
        exec: exec?,
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

    #[test]
    fn exec_program_is_the_basename_past_env() {
        assert_eq!(exec_program("firefox %u").as_deref(), Some("firefox"));
        assert_eq!(
            exec_program("/usr/bin/google-chrome-stable %U").as_deref(),
            Some("google-chrome-stable")
        );
        assert_eq!(
            exec_program(r#""/opt/My App/app" --flag"#).as_deref(),
            Some("app")
        );
        assert_eq!(
            exec_program("env FOO=1 -u X /snap/bin/code --new-window").as_deref(),
            Some("code")
        );
        assert_eq!(exec_program("env -i -- app").as_deref(), Some("app"));
        assert_eq!(exec_program("env A=1"), None);
        assert_eq!(exec_program("%U"), None);
    }
}

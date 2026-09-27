//! Shared tracing setup for the CLI, GUI, and guard daemon: logs go to
//! stderr (so stdout stays script-clean), colored only when stderr is a
//! terminal, filtered by `RUST_LOG` when set, else by a per-binary default.

use std::io::IsTerminal;
use tracing_subscriber::EnvFilter;

/// The env-filter directive string: `env` when it holds a non-blank value,
/// else `default_level` lowercased (e.g. "warn"). A blank `RUST_LOG=""` is
/// treated the same as unset, rather than as an empty (match-nothing) filter.
pub fn filter_spec(env: Option<&str>, default_level: tracing::Level) -> String {
    match env {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => default_level.as_str().to_lowercase(),
    }
}

/// Install the global tracing subscriber. Writes to stderr, with ANSI colors
/// only when stderr is a terminal, filtered by `RUST_LOG` (or
/// `default_level` when it is unset or blank). Safe to call more than once;
/// later calls are silently ignored.
pub fn init(default_level: tracing::Level) {
    let spec = filter_spec(std::env::var("RUST_LOG").ok().as_deref(), default_level);
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(spec))
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_overrides_default_and_blank_env_is_ignored() {
        assert_eq!(filter_spec(None, tracing::Level::WARN), "warn");
        assert_eq!(filter_spec(Some(""), tracing::Level::INFO), "info");
        assert_eq!(
            filter_spec(Some("rlm=debug"), tracing::Level::WARN),
            "rlm=debug"
        );
    }
}

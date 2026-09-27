//! Intervention history: an append-only JSONL log of what the guard actually
//! did (freeze/thaw/cap/lift, and failed attempts), separate from the
//! write-ahead restore [`super::journal::Journal`]. The journal exists to
//! make crash-restore correct; this log exists so a human can see what
//! happened, via `rlm guard history` (and, later, the GUI).

use super::resolve::Resolution;
use super::types::Action;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Owner-only permissions for the history log: entries record app names and
/// cgroup paths, so the file is created `0600` rather than inheriting the
/// process umask. Only takes effect when this call actually creates the
/// file (`O_CREAT`); an already-existing file's mode is left as-is.
const HISTORY_FILE_MODE: u32 = 0o600;

/// Rotate the log once it reaches this size: the current file is renamed to
/// `guard-history.jsonl.1` (overwriting any previous rotation) and a fresh
/// file is started. Keeps the log bounded without needing a background
/// compaction task.
pub const MAX_HISTORY_BYTES: u64 = 256 * 1024;

/// What kind of event one [`HistoryEvent`] records. Serialized in lowercase
/// to keep the on-disk JSONL readable without a decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HistoryKind {
    Freeze,
    Thaw,
    Cap,
    Lift,
    Failed,
}

impl HistoryKind {
    /// The lowercase word used in `rlm guard history`'s output, matching the
    /// serde rename so the log and the CLI never disagree.
    pub fn word(self) -> &'static str {
        match self {
            HistoryKind::Freeze => "freeze",
            HistoryKind::Thaw => "thaw",
            HistoryKind::Cap => "cap",
            HistoryKind::Lift => "lift",
            HistoryKind::Failed => "failed",
        }
    }
}

/// One recorded intervention (or failed attempt).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEvent {
    /// Unix seconds when the action was applied.
    pub ts: u64,
    pub kind: HistoryKind,
    /// The app the action targeted (see [`super::types::Target::app`]).
    pub app: String,
    /// The cgroup the action acted on.
    pub cgroup: String,
    /// A short human-readable description of what happened.
    pub detail: String,
}

/// Path of the intervention history log, `<state_dir>/rlm/guard-history.jsonl`,
/// with the same per-user fallback as the journal (see [`super::guard_file`]).
/// `None` when no per-user dir is known; history is then not recorded.
pub fn try_history_path() -> Option<PathBuf> {
    super::guard_file("guard-history.jsonl")
}

/// [`try_history_path`] for read-only callers. Returns an empty path when no
/// per-user dir is known; [`read_recent`] then finds nothing.
pub fn history_path() -> PathBuf {
    try_history_path().unwrap_or_default()
}

/// The app name to record for an action that only carries a [`Resolution`]
/// (`Thaw`/`LiftCap`): the resolved systemd unit if there is one, else the
/// cgroup path's last component.
fn unit_or_leaf(res: &Resolution) -> String {
    res.unit.clone().unwrap_or_else(|| {
        res.cgroup
            .rsplit('/')
            .next()
            .unwrap_or(&res.cgroup)
            .to_string()
    })
}

/// Turn an applied [`Action`] and its result into a [`HistoryEvent`], if the
/// action is one worth recording. `Notify` is best-effort UI noise, not an
/// intervention, so it never produces an event.
pub fn event_for(
    action: &Action,
    result: &std::result::Result<(), String>,
    ts: u64,
) -> Option<HistoryEvent> {
    let (kind, app, cgroup, detail, verb) = match action {
        Action::Notify { .. } => return None,
        Action::Freeze { res, name } => (
            HistoryKind::Freeze,
            name.clone(),
            res.cgroup.clone(),
            "froze the app's cgroup".to_string(),
            "freeze",
        ),
        Action::Thaw { res } => (
            HistoryKind::Thaw,
            unit_or_leaf(res),
            res.cgroup.clone(),
            "thawed".to_string(),
            "thaw",
        ),
        Action::Cap { res, name } => (
            HistoryKind::Cap,
            name.clone(),
            res.cgroup.clone(),
            "set a soft limit (memory.high)".to_string(),
            "cap",
        ),
        Action::LiftCap { res } => (
            HistoryKind::Lift,
            unit_or_leaf(res),
            res.cgroup.clone(),
            "removed the soft limit".to_string(),
            "lift cap",
        ),
    };
    match result {
        Ok(()) => Some(HistoryEvent {
            ts,
            kind,
            app,
            cgroup,
            detail,
        }),
        Err(e) => Some(HistoryEvent {
            ts,
            kind: HistoryKind::Failed,
            app,
            cgroup,
            detail: format!("{verb} failed: {e}"),
        }),
    }
}

/// Append one event, creating the parent directory and file as needed.
/// Rotates the current file to `.jsonl.1` first when it has reached
/// [`MAX_HISTORY_BYTES`], so the log never grows without bound.
pub fn append(path: &Path, ev: &HistoryEvent) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Ok(meta) = fs::metadata(path) {
        if meta.len() >= MAX_HISTORY_BYTES {
            fs::rename(path, path.with_extension("jsonl.1"))?;
        }
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(HISTORY_FILE_MODE)
        .open(path)?;
    let line = serde_json::to_string(ev)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    writeln!(file, "{line}")?;
    Ok(())
}

/// The last `n` events, oldest of the returned set first, reading the
/// rotated file (`.jsonl.1`) before the current one so a request spanning a
/// rotation still returns them in chronological order. Lines that fail to
/// deserialize (a torn write, or a rotation's now-truncated tail) are
/// silently skipped rather than treated as fatal.
pub fn read_recent(path: &Path, n: usize) -> Vec<HistoryEvent> {
    let mut events = Vec::new();
    for p in [path.with_extension("jsonl.1"), path.to_path_buf()] {
        if let Ok(contents) = fs::read_to_string(&p) {
            events.extend(
                contents
                    .lines()
                    .filter_map(|l| serde_json::from_str::<HistoryEvent>(l).ok()),
            );
        }
    }
    let start = events.len().saturating_sub(n);
    events.split_off(start)
}

/// A short, human-readable age like `"45s ago"`, `"12m ago"`, `"3h ago"`, or
/// `"2d ago"`. `ts >= now` (clock skew, or an event from this same instant)
/// reads as `"just now"` rather than an underflowing subtraction.
pub fn format_age(now: u64, ts: u64) -> String {
    if ts >= now {
        return "just now".to_string();
    }
    let diff = now - ts;
    if diff < 60 {
        format!("{diff}s ago")
    } else if diff < 3600 {
        format!("{}m ago", diff / 60)
    } else if diff < 86_400 {
        format!("{}h ago", diff / 3600)
    } else {
        format!("{}d ago", diff / 86_400)
    }
}

/// Current wall-clock time in Unix seconds. `0` on the essentially
/// impossible case that the system clock reads before the epoch.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::resolve::{Coverage, Mechanism, Resolution, Verdict};

    #[test]
    fn reader_path_without_a_dir_reads_nothing_and_is_not_tmp() {
        assert!(!history_path().starts_with("/tmp"));
        assert!(read_recent(&PathBuf::new(), 5).is_empty());
    }

    fn res() -> Resolution {
        Resolution {
            cgroup: "/u/app.slice/app-firefox-1.scope".into(),
            unit: Some("app-firefox-1.scope".into()),
            verdict: Verdict::Freeze,
            coverage: Coverage::Full,
            mechanism: Mechanism::Unit,
        }
    }

    #[test]
    fn events_for_each_action() {
        let f = event_for(
            &Action::Freeze {
                res: res(),
                name: "firefox".into(),
            },
            &Ok(()),
            10,
        )
        .unwrap();
        assert_eq!(
            (f.kind, f.app.as_str(), f.ts),
            (HistoryKind::Freeze, "firefox", 10)
        );
        let t = event_for(&Action::Thaw { res: res() }, &Ok(()), 11).unwrap();
        assert_eq!(
            (t.kind, t.app.as_str()),
            (HistoryKind::Thaw, "app-firefox-1.scope")
        );
        let e = event_for(
            &Action::Cap {
                res: res(),
                name: "firefox".into(),
            },
            &Err("EBUSY".into()),
            12,
        )
        .unwrap();
        assert_eq!(e.kind, HistoryKind::Failed);
        assert!(e.detail.contains("EBUSY"));
        assert!(event_for(
            &Action::Notify {
                message: "x".into()
            },
            &Ok(()),
            13
        )
        .is_none());
    }

    #[test]
    fn append_and_read_recent_round_trip_newest_last() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("h.jsonl");
        for ts in 0..5 {
            let ev = HistoryEvent {
                ts,
                kind: HistoryKind::Cap,
                app: "a".into(),
                cgroup: "/c".into(),
                detail: String::new(),
            };
            append(&p, &ev).unwrap();
        }
        let got: Vec<u64> = read_recent(&p, 3).iter().map(|e| e.ts).collect();
        assert_eq!(got, vec![2, 3, 4]);
    }

    #[test]
    fn rotation_keeps_one_old_file_and_reads_across_it() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("h.jsonl");
        std::fs::write(&p, "x".repeat(MAX_HISTORY_BYTES as usize)).unwrap();
        let ev = HistoryEvent {
            ts: 1,
            kind: HistoryKind::Lift,
            app: "a".into(),
            cgroup: "/c".into(),
            detail: String::new(),
        };
        append(&p, &ev).unwrap();
        assert!(p.with_extension("jsonl.1").exists());
        assert_eq!(
            read_recent(&p, 10),
            vec![ev],
            "corrupt old lines are skipped"
        );
    }

    /// Fix round 1, ruling R15: the history log records app names and cgroup
    /// paths, so both the live file and its rotated `.jsonl.1` predecessor
    /// must be owner-only (`0600`), not whatever the process umask would
    /// otherwise give a newly created file.
    #[test]
    fn history_file_and_rotation_are_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("h.jsonl");
        let ev = HistoryEvent {
            ts: 1,
            kind: HistoryKind::Freeze,
            app: "a".into(),
            cgroup: "/c".into(),
            detail: String::new(),
        };
        append(&p, &ev).unwrap();
        let mode_of = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode_of(&p), 0o600, "history file must be created 0600");

        // Grow the file past the rotation threshold without ever recreating
        // it (a bare append, not our `append()`, so its existing mode is
        // untouched), then append once more through `append()` to trigger
        // rotation.
        {
            let mut f = OpenOptions::new().append(true).open(&p).unwrap();
            f.write_all(&vec![b'x'; MAX_HISTORY_BYTES as usize])
                .unwrap();
        }
        append(&p, &ev).unwrap();

        let rotated = p.with_extension("jsonl.1");
        assert!(rotated.exists());
        assert_eq!(
            mode_of(&rotated),
            0o600,
            "rotated file must stay owner-only"
        );
        assert_eq!(
            mode_of(&p),
            0o600,
            "fresh file after rotation must also be 0600"
        );
    }

    #[test]
    fn ages_are_short_and_readable() {
        assert_eq!(format_age(100, 55), "45s ago");
        assert_eq!(format_age(10_000, 10_000 - 720), "12m ago");
        assert_eq!(format_age(100_000, 100_000 - 3 * 3600), "3h ago");
        assert_eq!(format_age(1_000_000, 1_000_000 - 2 * 86_400), "2d ago");
        assert_eq!(format_age(5, 9), "just now");
    }
}

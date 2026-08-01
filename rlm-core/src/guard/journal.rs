//! Write-ahead restore journal for freeze-guard interventions.
//!
//! Records all freeze/cap actions with boot_id, inode, and value guards to safely restore
//! memory.high on process restart or boot. Uses append-only JSON lines with a boot_id header;
//! stale entries are discarded on boot mismatch.

use common::Error;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

/// Action recorded in the journal: freeze or soft cap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JournalAction {
    Freeze,
    Cap,
}

/// One restore entry: identifies a cgroup and the action taken, with guards for safe restoration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    /// Relative cgroupfs path, e.g., "/user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox-12.scope"
    pub cgroup: String,
    /// Directory inode at time of action (used to detect cgroup recreation).
    pub inode: u64,
    /// Systemd unit name if applicable.
    pub unit: Option<String>,
    /// Action taken: Freeze or Cap.
    pub action: JournalAction,
    /// Cap only: memory.high value before we modified it.
    pub prev_high: Option<String>,
    /// Cap only: memory.high value we wrote.
    pub our_high: Option<String>,
}

/// Write-ahead restore journal: crash-safe record of freeze/cap interventions.
pub struct Journal {
    path: PathBuf,
    boot_id: String,
}

impl Journal {
    /// Opens the journal file, creating parent directories if needed.
    ///
    /// If the file exists and its boot_id header differs from the provided `boot_id`,
    /// the file is truncated (entries from a prior boot are discarded).
    ///
    /// # Arguments
    /// * `path` - Path to the journal file
    /// * `boot_id` - Current boot identifier (passed by caller, not read from cgfs)
    pub fn open(path: PathBuf, boot_id: String) -> common::Result<Self> {
        // Create parent directories if they don't exist.
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let journal = Journal {
            path: path.clone(),
            boot_id: boot_id.clone(),
        };

        // If file exists, check boot_id header.
        if path.exists() {
            let file = File::open(&path)?;
            let reader = BufReader::new(file);
            let mut lines = reader.lines();

            // Read first line (header).
            if let Some(Ok(header_line)) = lines.next() {
                if let Ok(header) = serde_json::from_str::<serde_json::Value>(&header_line) {
                    if let Some(stored_boot_id) = header.get("boot_id").and_then(|v| v.as_str()) {
                        if stored_boot_id != boot_id {
                            // Boot ID mismatch: truncate file and write new header.
                            journal.write_header()?;
                            return Ok(journal);
                        }
                        // Boot ID matches: file is valid.
                        return Ok(journal);
                    }
                }
            }

            // Header missing or invalid: rewrite.
            journal.write_header()?;
        } else {
            // File doesn't exist: create with header.
            journal.write_header()?;
        }

        Ok(journal)
    }

    /// Write the journal header (boot_id line) and fsync.
    fn write_header(&self) -> common::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.path)?;

        let header = serde_json::json!({ "boot_id": self.boot_id });
        writeln!(file, "{}", header)?;
        file.sync_data()?;

        Ok(())
    }

    /// Append a journal entry (write-ahead: fsyncs before returning).
    pub fn append(&self, e: &JournalEntry) -> common::Result<()> {
        let mut file = OpenOptions::new().append(true).open(&self.path)?;

        let json_line = serde_json::to_string(e)
            .map_err(|err| Error::Cgroup(format!("journal serialization error: {}", err)))?;
        writeln!(file, "{}", json_line)?;
        file.sync_data()?;

        Ok(())
    }

    /// Retrieve all valid entries from the current boot.
    pub fn entries(&self) -> Vec<JournalEntry> {
        let Ok(file) = File::open(&self.path) else {
            return vec![];
        };

        let reader = BufReader::new(file);
        let mut entries = vec![];

        for (idx, line) in reader.lines().enumerate() {
            if idx == 0 {
                // Skip header.
                continue;
            }

            if let Ok(line) = line {
                if let Ok(entry) = serde_json::from_str::<JournalEntry>(&line) {
                    entries.push(entry);
                } else {
                    // Corrupt line: skip silently.
                    tracing::warn!("Journal: skipping corrupt line {}", idx);
                }
            }
        }

        entries
    }

    /// Remove all entries matching the given cgroup (atomic rewrite: temp file + rename + fsync).
    pub fn remove(&self, cgroup: &str) -> common::Result<()> {
        let entries = self
            .entries()
            .into_iter()
            .filter(|e| e.cgroup != cgroup)
            .collect::<Vec<_>>();

        self.write_entries(&entries)?;
        Ok(())
    }

    /// Clear all entries, leaving only the header (clean shutdown compaction).
    pub fn clear(&self) -> common::Result<()> {
        self.write_entries(&[])?;
        Ok(())
    }

    /// Rewrite the journal with a new set of entries (atomic: temp file + rename + fsync).
    fn write_entries(&self, entries: &[JournalEntry]) -> common::Result<()> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| common::Error::Cgroup("Journal path has no parent".to_string()))?;

        // Create temp file in the same directory (atomic rename).
        let temp_path = parent.join(format!(".journal-tmp-{}", std::process::id()));

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)?;

        // Write header.
        let header = serde_json::json!({ "boot_id": self.boot_id });
        writeln!(file, "{}", header)?;

        // Write entries.
        for entry in entries {
            let json_line = serde_json::to_string(entry)
                .map_err(|err| Error::Cgroup(format!("journal serialization error: {}", err)))?;
            writeln!(file, "{}", json_line)?;
        }

        // Fsync before rename.
        file.sync_data()?;
        drop(file);

        // Atomic rename.
        fs::rename(&temp_path, &self.path)?;

        // Fsync parent directory (best-effort on supported systems).
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }

        Ok(())
    }
}

/// Determine whether a journal entry's memory.high should be restored.
///
/// Returns true if:
/// - The inode matches the current cgroup inode (cgroup hasn't been recreated), AND
/// - For Cap entries: current memory.high matches our_high (no one else changed it), OR
/// - For Freeze entries: inode alone is sufficient
pub fn should_restore(
    e: &JournalEntry,
    current_inode: Option<u64>,
    current_high: Option<&str>,
) -> bool {
    if current_inode != Some(e.inode) {
        return false;
    }

    match e.action {
        JournalAction::Freeze => true,
        JournalAction::Cap => e.our_high.as_deref() == current_high,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(cg: &str) -> JournalEntry {
        JournalEntry {
            cgroup: cg.into(),
            inode: 42,
            unit: None,
            action: JournalAction::Cap,
            prev_high: Some("max".into()),
            our_high: Some("1000000".into()),
        }
    }

    #[test]
    fn append_then_entries_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::open(dir.path().join("j.jsonl"), "boot-a".into()).unwrap();
        j.append(&entry("/x/a")).unwrap();
        j.append(&entry("/x/b")).unwrap();
        assert_eq!(j.entries().len(), 2);
        assert_eq!(j.entries()[0].cgroup, "/x/a");
    }

    #[test]
    fn stale_boot_id_truncates() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("j.jsonl");
        let j = Journal::open(p.clone(), "boot-a".into()).unwrap();
        j.append(&entry("/x/a")).unwrap();
        drop(j);
        let j2 = Journal::open(p, "boot-b".into()).unwrap();
        assert!(
            j2.entries().is_empty(),
            "prior-boot entries must be discarded"
        );
    }

    #[test]
    fn remove_deletes_only_matching_cgroup() {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::open(dir.path().join("j.jsonl"), "b".into()).unwrap();
        j.append(&entry("/x/a")).unwrap();
        j.append(&entry("/x/b")).unwrap();
        j.remove("/x/a").unwrap();
        let e = j.entries();
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].cgroup, "/x/b");
    }

    #[test]
    fn clear_leaves_header_only() {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::open(dir.path().join("j.jsonl"), "b".into()).unwrap();
        j.append(&entry("/x/a")).unwrap();
        j.clear().unwrap();
        assert!(j.entries().is_empty());
    }

    #[test]
    fn corrupt_lines_are_skipped_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("j.jsonl");
        let j = Journal::open(p.clone(), "b".into()).unwrap();
        j.append(&entry("/x/a")).unwrap();
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        writeln!(f, "{{garbage").unwrap();
        assert_eq!(j.entries().len(), 1);
    }

    #[test]
    fn should_restore_guards() {
        let e = entry("/x/a"); // inode 42, our_high "1000000"
        assert!(should_restore(&e, Some(42), Some("1000000")));
        assert!(
            !should_restore(&e, Some(43), Some("1000000")),
            "inode mismatch → skip"
        );
        assert!(
            !should_restore(&e, None, Some("1000000")),
            "cgroup gone → skip"
        );
        assert!(
            !should_restore(&e, Some(42), Some("999")),
            "someone changed high → skip"
        );
        let f = JournalEntry {
            action: JournalAction::Freeze,
            prev_high: None,
            our_high: None,
            ..e
        };
        assert!(
            should_restore(&f, Some(42), None),
            "freeze entries only need inode"
        );
    }
}

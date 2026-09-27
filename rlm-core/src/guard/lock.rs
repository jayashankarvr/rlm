//! Single-instance lock for `rlm-guard`. Two guards would each sweep and
//! rewrite the same journal and each hold up to `MAX_HELD_APPS` apps, so a
//! second one must stop before it touches anything.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

/// Take an exclusive, non-blocking `flock` on `path`, creating the file
/// (mode 0600) and its parent directory when missing.
///
/// Returns `Ok(Some(file))` when this process now holds the lock; keep the
/// file open for as long as the lock must be held (the kernel drops it when
/// the process exits). Returns `Ok(None)` when another process holds it.
pub fn try_lock(path: &Path) -> io::Result<Option<File>> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(path)?;
    // SAFETY: flock only reads the descriptor, which `file` keeps open.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        return Ok(Some(file));
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
        Ok(None)
    } else {
        Err(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_lock_is_refused_until_the_first_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("rlm-guard.lock");
        let first = try_lock(&path).unwrap();
        assert!(first.is_some(), "first lock must succeed");
        assert!(
            try_lock(&path).unwrap().is_none(),
            "a second holder must be refused"
        );
        drop(first);
        assert!(
            try_lock(&path).unwrap().is_some(),
            "lock must be free again once the holder is gone"
        );
    }
}

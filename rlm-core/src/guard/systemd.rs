//! Blocking systemd user-bus (`org.freedesktop.systemd1`) client used on the
//! freeze-guard's storm path as an alternative to fork+exec'ing `systemctl`.
//!
//! The connection is established once at daemon startup (pre-storm, when a
//! slow session-bus handshake doesn't matter) and reused for every call. Each
//! individual call still gets its own hard timeout: zbus's own blocking calls
//! default to a 25s method-call timeout, which is far too long for a path that
//! exists specifically to react before the system locks up. We enforce our own
//! deadline by running the call on a spawned thread and waiting on it via
//! `mpsc::Receiver::recv_timeout`. If the deadline passes first we return
//! `Err` immediately; the spawned thread is left to finish (or never finish,
//! if the bus is wedged) in the background and its result is dropped. This is
//! a bounded leak — one thread per timed-out call — accepted because the
//! storm path always falls back to raw cgroup writes on `Err`, so a wedged
//! D-Bus call never blocks the daemon itself.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use common::{Error, Result};
use zbus::blocking::Connection;
use zbus::zvariant::Value;

const DESTINATION: &str = "org.freedesktop.systemd1";
const PATH: &str = "/org/freedesktop/systemd1";
const INTERFACE: &str = "org.freedesktop.systemd1.Manager";

/// Blocking client for the systemd user-session D-Bus manager.
pub struct SystemdUser {
    conn: Connection,
}

impl SystemdUser {
    /// Connect to the session bus at daemon startup. Returns `None` if no
    /// session bus is available (e.g. headless, no `DBUS_SESSION_BUS_ADDRESS`)
    /// — callers then fall back to raw cgroup operations everywhere.
    pub fn connect() -> Option<Self> {
        Connection::session().ok().map(|conn| Self { conn })
    }

    /// `FreezeUnit(name)`. Returns `Err` on failure OR timeout; the caller
    /// falls back to a raw cgroup freeze.
    pub fn freeze_unit(&self, unit: &str, timeout: Duration) -> Result<()> {
        let unit = unit.to_string();
        self.call_with_timeout(timeout, move |conn| {
            conn.call_method(
                Some(DESTINATION),
                PATH,
                Some(INTERFACE),
                "FreezeUnit",
                &(unit.as_str(),),
            )
            .map(|_| ())
            .map_err(|e| Error::Cgroup(format!("FreezeUnit({unit}) failed: {e}")))
        })
    }

    /// `ThawUnit(name)`. Returns `Err` on failure OR timeout; the caller falls
    /// back to a raw cgroup thaw.
    pub fn thaw_unit(&self, unit: &str, timeout: Duration) -> Result<()> {
        let unit = unit.to_string();
        self.call_with_timeout(timeout, move |conn| {
            conn.call_method(
                Some(DESTINATION),
                PATH,
                Some(INTERFACE),
                "ThawUnit",
                &(unit.as_str(),),
            )
            .map(|_| ())
            .map_err(|e| Error::Cgroup(format!("ThawUnit({unit}) failed: {e}")))
        })
    }

    /// `SetUnitProperties(name, runtime=true, [("MemoryHigh", u64)])`.
    /// `bytes = u64::MAX` means "max" (systemd's infinity convention).
    pub fn set_memory_high(&self, unit: &str, bytes: u64, timeout: Duration) -> Result<()> {
        let unit = unit.to_string();
        self.call_with_timeout(timeout, move |conn| {
            let props = vec![("MemoryHigh", Value::from(bytes))];
            conn.call_method(
                Some(DESTINATION),
                PATH,
                Some(INTERFACE),
                "SetUnitProperties",
                &(unit.as_str(), true, props),
            )
            .map(|_| ())
            .map_err(|e| Error::Cgroup(format!("SetUnitProperties({unit}) failed: {e}")))
        })
    }

    /// Run `f` against a clone of the connection on a spawned thread, and
    /// enforce `timeout` ourselves rather than trusting zbus's own (25s)
    /// default. See [`run_with_timeout`] for the timeout mechanics.
    fn call_with_timeout(
        &self,
        timeout: Duration,
        f: impl FnOnce(&Connection) -> Result<()> + Send + 'static,
    ) -> Result<()> {
        let conn = self.conn.clone();
        run_with_timeout(timeout, move || f(&conn))
    }
}

/// Run `f` on a spawned thread and wait for it via
/// `mpsc::Receiver::recv_timeout(timeout)` instead of trusting the callee's
/// own notion of a deadline. On timeout, returns `Err` immediately; the
/// spawned thread is detached and left to finish (or never finish) in the
/// background, with its eventual result silently dropped on send. This is a
/// bounded leak — one thread per timed-out call — accepted because callers
/// always treat `Err` as "fall back to raw cgroup ops", so a wedged call
/// never blocks the daemon itself.
fn run_with_timeout<T: Send + 'static>(
    timeout: Duration,
    f: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        // Ignore send errors: the receiver may already have timed out and
        // been dropped, in which case there's nothing left to notify.
        let _ = tx.send(f());
    });
    rx.recv_timeout(timeout).unwrap_or_else(|_| {
        Err(Error::Cgroup(format!(
            "D-Bus call timed out after {timeout:?}"
        )))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pure test of the timeout wrapper: a closure that outlives the deadline
    /// must cause `run_with_timeout` to return `Err` promptly, without
    /// requiring a real session bus.
    #[test]
    fn run_with_timeout_returns_err_on_timeout() {
        let result: Result<()> = run_with_timeout(Duration::from_millis(50), || {
            thread::sleep(Duration::from_secs(5));
            Ok(())
        });
        assert!(result.is_err(), "expected a timeout error");
    }

    /// A closure that finishes well within the deadline should return its
    /// own `Ok` value through unchanged.
    #[test]
    fn run_with_timeout_returns_ok_when_fast() {
        let result: Result<u32> = run_with_timeout(Duration::from_secs(2), || Ok(42));
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    #[ignore = "requires a session bus and a running user unit; run manually"]
    fn freeze_thaw_transient_unit_roundtrip() {
        // systemd-run --user --unit=rlm-dbus-test sleep 30 must be running.
        let s = SystemdUser::connect().expect("session bus");
        s.freeze_unit("rlm-dbus-test.service", Duration::from_secs(2))
            .expect("freeze");
        s.thaw_unit("rlm-dbus-test.service", Duration::from_secs(2))
            .expect("thaw");
    }
}

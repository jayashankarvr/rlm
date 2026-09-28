//! Desktop notifications for guard interventions.
//!
//! The daemon loop hands every applied [`Action`] to a [`Notifier`], which
//! keeps one notification per app: "<App> paused" after a freeze, replaced
//! in place by "<App> slowed down" after a cap, and closed when the app is
//! released. Failed freezes and caps show nothing (they are in the history
//! and the journal). An optional early warning ("Memory is running low")
//! is sent at most once a minute while pressure is High or Critical and no
//! app is held.
//!
//! Notifications never feed back into guard decisions: the [`Notifier`]
//! only reads what the effector already did. The desktop transport,
//! [`DesktopSink`], runs on its own thread so a slow or missing
//! notification server can never hold up the guard loop.

use super::effector::Applied;
use super::policy::is_scarce;
use super::types::{Action, Level, Sample};
use common::GuardConfig;
use std::collections::{HashMap, HashSet};
use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;

/// Icon and desktop entry the notifications carry (the GTK app's).
pub const APP_ID: &str = "io.github.rlm.gtk";
/// Application name shown by the notification server.
pub const APP_NAME: &str = "rlm";

/// Title and body of the early warning.
pub const PRESSURE_TITLE: &str = "Memory is running low";
pub const PRESSURE_BODY: &str = "rlm will step in if an app keeps growing.";

/// At most one early warning per this many ms.
pub const PRESSURE_INTERVAL_MS: u64 = 60_000;

/// Sink key of the early warning. App keys are exe basenames, which never
/// contain a `/`, so this cannot collide with one.
pub const PRESSURE_KEY: &str = "/pressure";

/// How the memory looked on one tick, for the early warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Memory {
    /// The policy did not run this tick.
    Unknown,
    /// Not both under High or Critical pressure and short of memory.
    Fine,
    /// Pressure is High or Critical and memory is short, as the policy
    /// judges it before acting ([`is_scarce`]).
    Low,
}

/// [`Memory`] for a tick whose policy computed `level` from `sample`.
pub fn memory_state(level: Level, sample: &Sample, trigger: &common::GuardTrigger) -> Memory {
    if matches!(level, Level::High | Level::Critical) && is_scarce(sample, trigger) {
        Memory::Low
    } else {
        Memory::Fine
    }
}

/// Where notifications go. `key` names one notification: a second `show`
/// with the same key replaces it in place, `close` removes it.
pub trait NotifySink {
    fn show(&mut self, key: &str, title: &str, body: &str);
    fn close(&mut self, key: &str);
}

/// Title and body for an app that was just frozen for `hold_secs`.
pub fn paused_text(app: &str, hold_secs: u64) -> (String, String) {
    let unit = if hold_secs == 1 { "second" } else { "seconds" };
    (
        format!("{app} paused"),
        // GNOME shows one line of body text in the popup, so keep it short;
        // the title already names the app.
        format!("Paused for {hold_secs} {unit} while memory is low."),
    )
}

/// Title and body for an app held under a `memory.high` of `cap_bytes`.
pub fn slowed_text(app: &str, cap_bytes: u64) -> (String, String) {
    (
        format!("{app} slowed down"),
        format!(
            "Held to about {} until memory frees up.",
            format_size(cap_bytes)
        ),
    )
}

/// A byte count in the decimal units desktops show: "3.2 GB", "512 MB".
pub fn format_size(bytes: u64) -> String {
    const GB: f64 = 1e9;
    const MB: f64 = 1e6;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.1} GB", b / GB)
    } else {
        format!("{:.0} MB", (b / MB).max(1.0))
    }
}

/// A friendly name for the app key the guard uses (an exe basename, or
/// `<basename>@<cgroup leaf>` for runtimes). In order: the `Name` of an
/// installed desktop entry that runs this program (`desktop` maps program
/// basename to name), else the process name `comm` when the basename has no
/// letters (a versioned binary such as `2.1.283`), else the basename with its
/// first letter upper-cased. The `@leaf` suffix is never shown.
pub fn display_name(key: &str, desktop: &HashMap<String, String>, comm: Option<&str>) -> String {
    let base = key.split('@').next().unwrap_or(key);
    let has_letters = |s: &str| s.chars().any(char::is_alphabetic);
    let program = match comm {
        Some(c) if !has_letters(base) && has_letters(c) => c.trim(),
        _ => base,
    };
    if let Some(name) = desktop.get(program).or_else(|| desktop.get(base)) {
        return name.clone();
    }
    if program.is_empty() {
        return "An app".to_string();
    }
    let mut chars = program.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// Resolves app keys to [`display_name`]s from the system: installed
/// desktop entries (read once) and, for versioned binaries, the process name
/// of a member of the cgroup.
pub struct AppNames {
    desktop: HashMap<String, String>,
    /// Desktop entries still being read on a background thread.
    loading: Option<mpsc::Receiver<HashMap<String, String>>>,
}

impl AppNames {
    /// Read the desktop entries now.
    pub fn new() -> Self {
        Self {
            desktop: crate::desktop::names_by_program(),
            loading: None,
        }
    }

    /// Read the desktop entries on a background thread, so the caller (the
    /// guard loop) never waits on the disk. Until they are read, names fall
    /// back to the basename rules of [`display_name`].
    pub fn in_background() -> Self {
        let (tx, rx) = mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("rlm-app-names".into())
            .spawn(move || {
                let _ = tx.send(crate::desktop::names_by_program());
            });
        Self {
            desktop: HashMap::new(),
            loading: spawned.ok().map(|_| rx),
        }
    }

    /// The display name of `key`, whose processes live under `cgroup`.
    pub fn name(&mut self, key: &str, cgroup: &str) -> String {
        if let Some(rx) = &self.loading {
            match rx.try_recv() {
                Ok(desktop) => {
                    self.desktop = desktop;
                    self.loading = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => self.loading = None,
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        let base = key.split('@').next().unwrap_or(key);
        let comm = if base.chars().any(char::is_alphabetic) {
            None
        } else {
            comm_in(cgroup, base)
        };
        display_name(key, &self.desktop, comm.as_deref())
    }
}

impl Default for AppNames {
    fn default() -> Self {
        Self::new()
    }
}

/// The process name of the first process under `cgroup` running `exe`.
fn comm_in(cgroup: &str, exe: &str) -> Option<String> {
    super::cgfs::pids_under(cgroup)
        .into_iter()
        .find(|&p| super::cgfs::exe_basename(p).as_deref() == Some(exe))
        .and_then(|p| std::fs::read_to_string(format!("/proc/{p}/comm")).ok())
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
}

/// The two notification settings, the only ones the guard applies live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotifyFlags {
    /// `guard.notify`: send notifications at all.
    pub notify: bool,
    /// `guard.notify_pressure`: also send the early warning.
    pub pressure: bool,
}

impl NotifyFlags {
    pub fn from_config(g: &GuardConfig) -> Self {
        Self {
            notify: g.notify,
            pressure: g.notify_pressure,
        }
    }
}

/// The flags to use after the config file changed on disk: the reloaded
/// file's two notification flags when it is valid, else the `current` ones.
/// Nothing else in the reloaded config is used.
pub fn flags_after_reload(
    current: NotifyFlags,
    reloaded: std::result::Result<&GuardConfig, &common::Error>,
) -> NotifyFlags {
    match reloaded {
        Ok(g) => NotifyFlags::from_config(g),
        Err(_) => current,
    }
}

/// One cgroup the guard holds, as far as notifications care.
#[derive(Debug, Clone)]
struct Held {
    app: String,
    /// `Some` once capped: the `memory.high` written, in bytes.
    cap_bytes: Option<u64>,
}

/// Keeps one notification per held app in step with what the effector did.
///
/// Call [`record`](Self::record) for every applied action, then
/// [`end_tick`](Self::end_tick) once per loop iteration; notifications are
/// only sent from `end_tick`, so a thaw and a cap of the same app in one tick
/// replace the notification instead of closing and reopening it. A release
/// by thaw also waits one more tick before closing, since the policy caps a
/// still-hot app on the tick after its thaw.
pub struct Notifier<S: NotifySink> {
    sink: S,
    flags: NotifyFlags,
    freeze_hold_secs: u64,
    /// Held cgroups, keyed by cgroup path.
    held: HashMap<String, Held>,
    /// Display name of each held or shown app, keyed by app.
    names: HashMap<String, String>,
    /// What each app's notification shows now, keyed by app.
    shown: HashMap<String, (String, String)>,
    /// Apps released by a thaw during the current tick.
    thawed: HashSet<String>,
    pressure_shown: bool,
    last_pressure_ms: Option<u64>,
}

impl<S: NotifySink> Notifier<S> {
    pub fn new(sink: S, cfg: &GuardConfig) -> Self {
        Self {
            sink,
            flags: NotifyFlags::from_config(cfg),
            freeze_hold_secs: cfg.timing.freeze_hold_secs,
            held: HashMap::new(),
            names: HashMap::new(),
            shown: HashMap::new(),
            thawed: HashSet::new(),
            pressure_shown: false,
            last_pressure_ms: None,
        }
    }

    pub fn sink(&self) -> &S {
        &self.sink
    }

    pub fn flags(&self) -> NotifyFlags {
        self.flags
    }

    /// Apply new notification settings. Turning `notify` off closes what is
    /// shown; turning the early warning off closes it.
    pub fn set_flags(&mut self, flags: NotifyFlags) {
        if !flags.notify {
            self.close_all();
        } else if !flags.pressure {
            self.close_pressure();
        }
        self.flags = flags;
    }

    /// Note one action the effector applied. `applied` is `None` when it
    /// failed. Cheap: nothing is sent or looked up until
    /// [`end_tick`](Self::end_tick).
    pub fn record(&mut self, action: &Action, applied: Option<Applied>) {
        match action {
            Action::Freeze { res, name: app } | Action::Cap { res, name: app } => {
                let Some(applied) = applied else {
                    return;
                };
                let cap_bytes = match action {
                    Action::Cap { .. } => Some(applied.cap_bytes.unwrap_or(0)),
                    _ => None,
                };
                self.held.insert(
                    res.cgroup.clone(),
                    Held {
                        app: app.clone(),
                        cap_bytes,
                    },
                );
            }
            // A release closes the notification even if the undo reported
            // an error: the guard no longer holds the cgroup either way.
            Action::Thaw { res } => {
                if let Some(h) = self.held.remove(&res.cgroup) {
                    self.thawed.insert(h.app);
                }
            }
            Action::LiftCap { res } => {
                self.held.remove(&res.cgroup);
            }
        }
    }

    /// Send what changed this tick. `memory` is how the memory looked on this
    /// tick (see [`memory_state`]). `name` maps an app key
    /// and one of its cgroups to a display name; it is called once per newly
    /// held app, after every action of the tick was applied.
    pub fn end_tick(
        &mut self,
        now_ms: u64,
        memory: Memory,
        name: &mut dyn FnMut(&str, &str) -> String,
    ) {
        let thawed = std::mem::take(&mut self.thawed);
        if !self.flags.notify {
            return;
        }

        let mut held: Vec<(&String, &Held)> = self.held.iter().collect();
        held.sort_by(|a, b| a.0.cmp(b.0));
        for (cgroup, h) in &held {
            if !self.names.contains_key(&h.app) {
                self.names.insert(h.app.clone(), name(&h.app, cgroup));
            }
        }
        let mut want: HashMap<String, (String, String)> = HashMap::new();
        for (_, h) in held {
            let display = self
                .names
                .get(&h.app)
                .map_or(h.app.as_str(), |n| n.as_str());
            let capped: u64 = self
                .held
                .values()
                .filter(|o| o.app == h.app)
                .filter_map(|o| o.cap_bytes)
                .sum();
            let any_capped = self
                .held
                .values()
                .any(|o| o.app == h.app && o.cap_bytes.is_some());
            let text = if any_capped {
                slowed_text(display, capped)
            } else {
                paused_text(display, self.freeze_hold_secs)
            };
            want.entry(h.app.clone()).or_insert(text);
        }

        let mut gone: Vec<String> = self
            .shown
            .keys()
            .filter(|app| !want.contains_key(*app) && !thawed.contains(*app))
            .cloned()
            .collect();
        gone.sort();
        for app in gone {
            self.sink.close(&app);
            self.shown.remove(&app);
        }
        let (held, shown) = (&self.held, &self.shown);
        self.names
            .retain(|app, _| shown.contains_key(app) || held.values().any(|h| h.app == *app));
        let mut changed: Vec<(String, (String, String))> = want
            .into_iter()
            .filter(|(app, text)| self.shown.get(app) != Some(text))
            .collect();
        changed.sort();
        for (app, (title, body)) in changed {
            self.sink.show(&app, &title, &body);
            self.shown.insert(app, (title, body));
        }

        let pressing = memory == Memory::Low;
        if self.held.is_empty() && self.shown.is_empty() && pressing {
            let due = self
                .last_pressure_ms
                .is_none_or(|last| now_ms.saturating_sub(last) >= PRESSURE_INTERVAL_MS);
            if self.flags.pressure && due {
                self.sink.show(PRESSURE_KEY, PRESSURE_TITLE, PRESSURE_BODY);
                self.pressure_shown = true;
                self.last_pressure_ms = Some(now_ms);
            }
        } else if memory != Memory::Unknown || !self.held.is_empty() {
            self.close_pressure();
        }
    }

    /// Close every notification this notifier has open (guard shutdown).
    pub fn close_all(&mut self) {
        let mut apps: Vec<String> = self.shown.drain().map(|(app, _)| app).collect();
        apps.sort();
        for app in apps {
            self.sink.close(&app);
        }
        self.close_pressure();
    }

    fn close_pressure(&mut self) {
        if self.pressure_shown {
            self.sink.close(PRESSURE_KEY);
            self.pressure_shown = false;
        }
    }
}

/// Longest wait for one call to the notification server.
const CALL_TIMEOUT: Duration = Duration::from_secs(2);

/// The `expire_timeout` sent with every notification: -1, the server's
/// default. A finite value is the popup's on-screen lifetime on KDE, dunst,
/// mako and xfce4-notifyd, and a cap can outlast any fixed limit; the guard
/// closes its notifications itself when it releases an app.
const EXPIRE_TIMEOUT: i32 = -1;
/// Requests queued for the sender thread; more are dropped.
const QUEUE: usize = 64;

const NOTIFY_DEST: &str = "org.freedesktop.Notifications";
const NOTIFY_PATH: &str = "/org/freedesktop/Notifications";

enum Cmd {
    Show {
        key: String,
        title: String,
        body: String,
    },
    Close {
        key: String,
    },
    Flush(mpsc::Sender<()>),
}

/// Sends notifications to the desktop from a background thread, through the
/// freedesktop Notifications D-Bus API on the session bus (`Notify` with
/// `replaces_id` to update in place, `CloseNotification` to clear). The
/// thread keeps the server's notification id per key. Without a session
/// bus it falls back to `notify-send`, which can neither update nor close.
/// Requests never block the caller: they are queued, and dropped when the
/// queue is full. Every failure is logged at debug and otherwise ignored.
pub struct DesktopSink {
    tx: Option<mpsc::SyncSender<Cmd>>,
}

impl DesktopSink {
    /// Start the sender thread. It connects to the session bus on the first
    /// request, so a guard that never notifies never connects.
    pub fn spawn() -> Self {
        let (tx, rx) = mpsc::sync_channel(QUEUE);
        let started = std::thread::Builder::new()
            .name("rlm-notify".into())
            .spawn(move || sender(rx));
        match started {
            Ok(_) => Self { tx: Some(tx) },
            Err(e) => {
                tracing::debug!(error = %e, "cannot start the notification thread");
                Self { tx: None }
            }
        }
    }

    /// Wait up to `timeout` for every queued request to be sent. Returns
    /// false on timeout.
    pub fn flush(&self, timeout: Duration) -> bool {
        let (done, wait) = mpsc::channel();
        if !self.send(Cmd::Flush(done)) {
            return false;
        }
        wait.recv_timeout(timeout).is_ok()
    }

    fn send(&self, cmd: Cmd) -> bool {
        match &self.tx {
            Some(tx) => match tx.try_send(cmd) {
                Ok(()) => true,
                Err(e) => {
                    tracing::debug!(error = %e, "notification dropped");
                    false
                }
            },
            None => false,
        }
    }
}

impl NotifySink for DesktopSink {
    fn show(&mut self, key: &str, title: &str, body: &str) {
        self.send(Cmd::Show {
            key: key.to_string(),
            title: title.to_string(),
            body: body.to_string(),
        });
    }

    fn close(&mut self, key: &str) {
        self.send(Cmd::Close {
            key: key.to_string(),
        });
    }
}

/// The sender thread: owns the bus connection and the id of each shown
/// notification.
fn sender(rx: mpsc::Receiver<Cmd>) {
    let mut conn: Option<Option<zbus::blocking::Connection>> = None;
    let mut ids: HashMap<String, u32> = HashMap::new();
    for cmd in rx {
        if let Cmd::Flush(done) = cmd {
            let _ = done.send(());
            continue;
        }
        let conn = conn.get_or_insert_with(connect).as_ref();
        match (cmd, conn) {
            (Cmd::Show { key, title, body }, Some(c)) => {
                let replaces = ids.get(&key).copied().unwrap_or(0);
                match dbus_notify(c, replaces, &title, &body, EXPIRE_TIMEOUT) {
                    Ok(id) => {
                        ids.insert(key, id);
                    }
                    Err(e) => tracing::debug!(error = %e, "Notify failed"),
                }
            }
            (Cmd::Show { title, body, .. }, None) => notify_send(&title, &body),
            (Cmd::Close { key }, Some(c)) => {
                if let Some(id) = ids.remove(&key) {
                    if let Err(e) = c.call_method(
                        Some(NOTIFY_DEST),
                        NOTIFY_PATH,
                        Some(NOTIFY_DEST),
                        "CloseNotification",
                        &(id,),
                    ) {
                        tracing::debug!(error = %e, "CloseNotification failed");
                    }
                }
            }
            (Cmd::Close { .. }, None) | (Cmd::Flush(_), _) => {}
        }
    }
}

/// Connect to the session bus, giving up after [`CALL_TIMEOUT`] so a
/// wedged bus cannot stall the sender; `None` means use `notify-send`.
fn connect() -> Option<zbus::blocking::Connection> {
    let conn = within(CALL_TIMEOUT, || {
        zbus::blocking::connection::Builder::session()
            .map(|b| b.method_timeout(CALL_TIMEOUT))
            .and_then(|b| b.build())
            .map_err(|e| tracing::debug!(error = %e, "cannot connect to the session bus"))
            .ok()
    });
    if conn.is_none() {
        tracing::debug!("no session bus; notifications use notify-send");
    }
    conn
}

/// Run `f` on a helper thread and wait at most `timeout` for it. On timeout
/// the thread is left to finish on its own and its result is dropped.
fn within<T: Send + 'static>(
    timeout: Duration,
    f: impl FnOnce() -> Option<T> + Send + 'static,
) -> Option<T> {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("rlm-notify-connect".into())
        .spawn(move || {
            let _ = tx.send(f());
        })
        .ok()?;
    rx.recv_timeout(timeout).ok().flatten()
}

fn dbus_notify(
    conn: &zbus::blocking::Connection,
    replaces_id: u32,
    title: &str,
    body: &str,
    expire_timeout: i32,
) -> zbus::Result<u32> {
    use zbus::zvariant::Value;
    let mut hints: HashMap<&str, Value<'_>> = HashMap::new();
    hints.insert("desktop-entry", Value::from(APP_ID));
    // Urgency normal.
    hints.insert("urgency", Value::U8(1));
    let actions: Vec<&str> = Vec::new();
    let reply = conn.call_method(
        Some(NOTIFY_DEST),
        NOTIFY_PATH,
        Some(NOTIFY_DEST),
        "Notify",
        &(
            APP_NAME,
            replaces_id,
            APP_ID,
            title,
            body,
            actions,
            hints,
            expire_timeout,
        ),
    )?;
    reply.body().deserialize::<u32>()
}

/// Fallback without a session bus: a plain `notify-send`, reaped on its own
/// thread so a hung one cannot stall the sender.
fn notify_send(title: &str, body: &str) {
    match Command::new("notify-send")
        .args(["-a", APP_NAME, "-i", APP_ID, title, body])
        .spawn()
    {
        Ok(mut child) => {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
        Err(e) => tracing::debug!(error = %e, "notify-send unavailable; skipping notification"),
    }
}

#[cfg(test)]
mod tests {
    use super::super::resolve::{Coverage, Mechanism, Resolution, Verdict};
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        Show(String, String, String),
        Close(String),
    }

    #[derive(Default)]
    struct Fake(Vec<Call>);

    impl NotifySink for Fake {
        fn show(&mut self, key: &str, title: &str, body: &str) {
            self.0
                .push(Call::Show(key.into(), title.into(), body.into()));
        }
        fn close(&mut self, key: &str) {
            self.0.push(Call::Close(key.into()));
        }
    }

    impl Notifier<Fake> {
        fn take(&mut self) -> Vec<Call> {
            std::mem::take(&mut self.sink.0)
        }
    }

    const GB: u64 = 1_000_000_000;

    fn res(cg: &str) -> Resolution {
        Resolution {
            cgroup: cg.into(),
            unit: None,
            verdict: Verdict::Freeze,
            coverage: Coverage::Full,
            mechanism: Mechanism::Raw,
        }
    }

    fn freeze(cg: &str) -> Action {
        Action::Freeze {
            res: res(cg),
            name: "firefox".into(),
        }
    }

    fn cap(cg: &str) -> Action {
        Action::Cap {
            res: res(cg),
            name: "firefox".into(),
        }
    }

    fn ok() -> Option<Applied> {
        Some(Applied { cap_bytes: None })
    }

    fn capped(bytes: u64) -> Option<Applied> {
        Some(Applied {
            cap_bytes: Some(bytes),
        })
    }

    fn notifier(notify: bool, pressure: bool) -> Notifier<Fake> {
        let cfg = GuardConfig {
            notify,
            notify_pressure: pressure,
            ..GuardConfig::default()
        };
        Notifier::new(Fake::default(), &cfg)
    }

    fn names(key: &str, _cg: &str) -> String {
        display_name(key, &HashMap::new(), None)
    }

    fn paused() -> Call {
        let (t, b) = paused_text("Firefox", 5);
        Call::Show("firefox".into(), t, b)
    }

    fn slowed(bytes: u64) -> Call {
        let (t, b) = slowed_text("Firefox", bytes);
        Call::Show("firefox".into(), t, b)
    }

    #[test]
    fn texts_read_as_specified() {
        assert_eq!(
            paused_text("Firefox", 5),
            (
                "Firefox paused".to_string(),
                "Paused for 5 seconds while memory is low.".to_string()
            )
        );
        assert_eq!(
            slowed_text("Firefox", 3_200_000_000),
            (
                "Firefox slowed down".to_string(),
                "Held to about 3.2 GB until memory frees up.".to_string()
            )
        );
        assert!(paused_text("X", 1).1.contains("for 1 second while"));
        assert_eq!(format_size(512_000_000), "512 MB");
        assert_eq!(format_size(268_435_456), "268 MB");
    }

    #[test]
    fn freeze_shows_paused_once_for_all_of_an_apps_cgroups() {
        let mut n = notifier(true, false);
        n.record(&freeze("/a"), ok());
        n.record(&freeze("/b"), ok());
        n.end_tick(0, Memory::Low, &mut names);
        assert_eq!(n.take(), vec![paused()]);
        n.end_tick(1_000, Memory::Low, &mut names);
        assert!(n.take().is_empty(), "nothing changed, nothing sent");
    }

    #[test]
    fn thaw_then_cap_in_one_tick_replaces_without_close() {
        let mut n = notifier(true, false);
        n.record(&freeze("/a"), ok());
        n.end_tick(0, Memory::Low, &mut names);
        n.take();
        n.record(&Action::Thaw { res: res("/a") }, ok());
        n.record(&cap("/a"), capped(3 * GB));
        n.end_tick(5_000, Memory::Low, &mut names);
        assert_eq!(n.take(), vec![slowed(3 * GB)]);
    }

    #[test]
    fn cap_on_the_tick_after_a_thaw_still_replaces() {
        let mut n = notifier(true, false);
        n.record(&freeze("/a"), ok());
        n.end_tick(0, Memory::Low, &mut names);
        n.take();
        n.record(&Action::Thaw { res: res("/a") }, ok());
        n.end_tick(5_000, Memory::Low, &mut names);
        assert!(n.take().is_empty(), "the close waits a tick");
        n.record(&cap("/a"), capped(2 * GB));
        n.end_tick(6_000, Memory::Low, &mut names);
        assert_eq!(n.take(), vec![slowed(2 * GB)]);
    }

    #[test]
    fn thaw_alone_closes() {
        let mut n = notifier(true, false);
        n.record(&freeze("/a"), ok());
        n.end_tick(0, Memory::Low, &mut names);
        n.take();
        n.record(&Action::Thaw { res: res("/a") }, ok());
        n.end_tick(5_000, Memory::Fine, &mut names);
        n.end_tick(6_000, Memory::Fine, &mut names);
        assert_eq!(n.take(), vec![Call::Close("firefox".into())]);
    }

    #[test]
    fn lift_closes_in_the_same_tick() {
        let mut n = notifier(true, false);
        n.record(&cap("/a"), capped(GB));
        n.end_tick(0, Memory::Low, &mut names);
        assert_eq!(n.take(), vec![slowed(GB)]);
        n.record(&Action::LiftCap { res: res("/a") }, ok());
        n.end_tick(40_000, Memory::Fine, &mut names);
        assert_eq!(n.take(), vec![Call::Close("firefox".into())]);
    }

    #[test]
    fn a_release_that_reported_an_error_still_closes() {
        let mut n = notifier(true, false);
        n.record(&cap("/a"), capped(GB));
        n.end_tick(0, Memory::Low, &mut names);
        n.take();
        n.record(&Action::LiftCap { res: res("/a") }, None);
        n.end_tick(1_000, Memory::Fine, &mut names);
        assert_eq!(n.take(), vec![Call::Close("firefox".into())]);
    }

    #[test]
    fn failed_interventions_send_nothing() {
        let mut n = notifier(true, false);
        n.record(&freeze("/a"), None);
        n.record(&cap("/b"), None);
        n.end_tick(0, Memory::Low, &mut names);
        assert!(n.take().is_empty());
    }

    #[test]
    fn caps_of_one_app_add_up() {
        let mut n = notifier(true, false);
        n.record(&cap("/a"), capped(GB));
        n.record(&cap("/b"), capped(2 * GB));
        n.end_tick(0, Memory::Low, &mut names);
        assert_eq!(n.take(), vec![slowed(3 * GB)]);
        n.record(&Action::LiftCap { res: res("/a") }, ok());
        n.end_tick(1_000, Memory::Low, &mut names);
        assert_eq!(n.take(), vec![slowed(2 * GB)], "updated, not closed");
    }

    #[test]
    fn disabled_notify_sends_nothing() {
        let mut n = notifier(false, true);
        n.record(&freeze("/a"), ok());
        n.end_tick(0, Memory::Low, &mut names);
        n.record(&Action::Thaw { res: res("/a") }, ok());
        n.end_tick(5_000, Memory::Low, &mut names);
        n.end_tick(6_000, Memory::Low, &mut names);
        n.close_all();
        assert!(n.take().is_empty());
    }

    #[test]
    fn turning_notify_off_clears_what_is_shown() {
        let mut n = notifier(true, false);
        n.record(&freeze("/a"), ok());
        n.end_tick(0, Memory::Low, &mut names);
        n.take();
        n.set_flags(NotifyFlags {
            notify: false,
            pressure: false,
        });
        assert_eq!(n.take(), vec![Call::Close("firefox".into())]);
        n.end_tick(1_000, Memory::Low, &mut names);
        assert!(n.take().is_empty());
    }

    #[test]
    fn close_all_closes_every_app() {
        let mut n = notifier(true, false);
        n.record(&freeze("/a"), ok());
        n.end_tick(0, Memory::Low, &mut names);
        n.take();
        n.close_all();
        assert_eq!(n.take(), vec![Call::Close("firefox".into())]);
    }

    fn warning() -> Call {
        Call::Show(
            PRESSURE_KEY.into(),
            PRESSURE_TITLE.into(),
            PRESSURE_BODY.into(),
        )
    }

    #[test]
    fn pressure_warning_is_off_by_default() {
        let mut n = Notifier::new(Fake::default(), &GuardConfig::default());
        n.end_tick(0, Memory::Low, &mut names);
        assert!(n.take().is_empty());
    }

    #[test]
    fn pressure_warning_is_rate_limited_and_only_at_high() {
        let mut n = notifier(true, true);
        n.end_tick(0, Memory::Fine, &mut names);
        assert!(n.take().is_empty(), "Warn is not enough");
        n.end_tick(1_000, Memory::Low, &mut names);
        assert_eq!(n.take(), vec![warning()]);
        n.end_tick(30_000, Memory::Low, &mut names);
        assert!(n.take().is_empty(), "at most once a minute");
        n.end_tick(61_000, Memory::Low, &mut names);
        assert_eq!(n.take(), vec![warning()]);
    }

    #[test]
    fn memory_is_low_only_when_pressure_is_high_and_memory_short() {
        let t = common::GuardTrigger::default();
        let sample = |avail| Sample {
            some_avg10: 40.0,
            full_avg10: 0.0,
            mem_available_mb: avail,
            mem_total_mb: 16_000,
            source: super::super::types::PsiSource::AppSlice,
        };
        assert_eq!(memory_state(Level::High, &sample(1_000), &t), Memory::Low);
        assert_eq!(
            memory_state(Level::High, &sample(8_000), &t),
            Memory::Fine,
            "a stall with half the RAM free is not low memory"
        );
        assert_eq!(memory_state(Level::Warn, &sample(1_000), &t), Memory::Fine);
        assert_eq!(memory_state(Level::Critical, &sample(300), &t), Memory::Low);
    }

    #[test]
    fn pressure_warning_gives_way_to_an_intervention() {
        let mut n = notifier(true, true);
        n.end_tick(0, Memory::Low, &mut names);
        n.take();
        n.record(&freeze("/a"), ok());
        n.end_tick(1_000, Memory::Low, &mut names);
        assert_eq!(n.take(), vec![paused(), Call::Close(PRESSURE_KEY.into())]);
        n.end_tick(70_000, Memory::Low, &mut names);
        assert!(n.take().is_empty(), "no warning while an app is held");
    }

    #[test]
    fn pressure_warning_needs_notify() {
        let mut n = notifier(false, true);
        n.end_tick(0, Memory::Low, &mut names);
        assert!(n.take().is_empty());
    }

    #[test]
    fn reload_takes_only_valid_notification_flags() {
        let current = NotifyFlags {
            notify: true,
            pressure: false,
        };
        let mut changed = GuardConfig {
            notify_pressure: true,
            enabled: false,
            ..GuardConfig::default()
        };
        changed.timing.freeze_hold_secs = 30;
        assert_eq!(
            flags_after_reload(current, Ok(&changed)),
            NotifyFlags {
                notify: true,
                pressure: true
            }
        );
        let err = common::Error::Config("bad".into());
        assert_eq!(flags_after_reload(current, Err(&err)), current);
    }

    #[test]
    fn a_slow_connect_gives_up() {
        let start = std::time::Instant::now();
        let got = within(Duration::from_millis(50), || {
            std::thread::sleep(Duration::from_secs(5));
            Some(1)
        });
        assert_eq!(got, None);
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(within(Duration::from_secs(2), || Some(7)), Some(7));
    }

    #[test]
    fn notifications_use_the_server_default_lifetime() {
        assert_eq!(EXPIRE_TIMEOUT, -1);
    }

    #[test]
    fn display_names() {
        let mut desktop = HashMap::new();
        desktop.insert("code".to_string(), "Visual Studio Code".to_string());
        desktop.insert("claude".to_string(), "Claude".to_string());
        assert_eq!(display_name("code", &desktop, None), "Visual Studio Code");
        assert_eq!(display_name("firefox", &desktop, None), "Firefox");
        assert_eq!(display_name("node@app-x.scope", &desktop, None), "Node");
        assert_eq!(
            display_name("python3@run-u12.service", &desktop, None),
            "Python3"
        );
        assert_eq!(
            display_name("2.1.283", &HashMap::new(), Some("claude")),
            "Claude"
        );
        assert_eq!(display_name("2.1.283", &desktop, Some("claude")), "Claude");
        assert_eq!(display_name("2.1.283", &desktop, None), "2.1.283");
        assert_eq!(
            display_name("firefox", &desktop, Some("Isolated Web Co")),
            "Firefox",
            "comm is only used when the basename has no letters"
        );
        assert_eq!(display_name("élan", &desktop, None), "Élan");
        assert_eq!(display_name("", &desktop, None), "An app");
    }
}

//! Desktop notifications for guard interventions.
//!
//! The daemon loop hands every applied [`Action`] to a [`Notifier`], which
//! keeps one notification per app: "<App> paused" after a freeze, replaced
//! in place by "<App> slowed down" after a cap, and closed when the app is
//! released. A thaw that fails replaces it with "<App> could not be
//! resumed", which stays until a later release of that cgroup succeeds, the
//! cgroup is gone, or the guard shuts down. Failed freezes and caps show
//! nothing (they are in the history and the journal). An optional early
//! warning ("Memory is running low") is sent at most once a minute while
//! pressure is High or Critical and no app is held.
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
use std::time::{Duration, Instant};

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

/// Title and body for an app whose thaw failed, so it may still be frozen.
pub fn failed_resume_text(app: &str) -> (String, String) {
    (
        format!("{app} could not be resumed"),
        "It may stay paused. Run rlm guard status for details.".to_string(),
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
    /// Cgroups whose thaw failed, so they may still be frozen, with their app.
    stuck: HashMap<String, String>,
    /// Whether a cgroup directory still exists. A `stuck` entry whose
    /// cgroup is gone is dropped: nothing is left that could stay frozen.
    cgroup_exists: Box<dyn Fn(&str) -> bool>,
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
            stuck: HashMap::new(),
            cgroup_exists: Box::new(|cg| super::cgfs::abs(cg).is_dir()),
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
            // A failed thaw may leave the app frozen, so its notification
            // says so instead of closing.
            Action::Thaw { res } => {
                if let Some(h) = self.held.remove(&res.cgroup) {
                    if applied.is_some() {
                        self.thawed.insert(h.app);
                    } else {
                        self.stuck.insert(res.cgroup.clone(), h.app);
                    }
                }
                if applied.is_some() {
                    self.stuck.remove(&res.cgroup);
                }
            }
            // A cap lift closes the notification even if it reported an
            // error: the guard no longer holds the cgroup either way.
            Action::LiftCap { res } => {
                self.held.remove(&res.cgroup);
                if applied.is_some() {
                    self.stuck.remove(&res.cgroup);
                }
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
        // The policy has dropped a cgroup whose thaw failed, so no later
        // release will clear it; stop saying it may be paused once it is gone.
        let exists = &self.cgroup_exists;
        self.stuck.retain(|cg, _| exists(cg));
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
        let mut stuck: Vec<(&String, &String)> = self.stuck.iter().collect();
        stuck.sort();
        for (cgroup, app) in stuck {
            if !self.names.contains_key(app) {
                self.names.insert(app.clone(), name(app, cgroup));
            }
            let display = self.names.get(app).map_or(app.as_str(), |n| n.as_str());
            want.entry(app.clone())
                .or_insert_with(|| failed_resume_text(display));
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
        let (held, shown, stuck) = (&self.held, &self.shown, &self.stuck);
        self.names.retain(|app, _| {
            shown.contains_key(app)
                || held.values().any(|h| h.app == *app)
                || stuck.values().any(|a| a == app)
        });
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
        self.stuck.clear();
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
/// bus it falls back to `notify-send`, which can neither update nor close,
/// and tries the bus again after 30 s; a connection that breaks is dropped
/// and rebuilt on the next request. Requests never block the caller: they are queued, and dropped when the
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

/// The sender thread: hands every request to a [`Sender`] over the real
/// session bus.
fn sender(rx: mpsc::Receiver<Cmd>) {
    let mut sender = Sender::new(SessionBus);
    for cmd in rx {
        sender.handle(cmd, Instant::now());
    }
}

/// How long a failed connect is remembered before the next request tries
/// again. Requests in between use `notify-send`.
const RECONNECT_AFTER: Duration = Duration::from_secs(30);

/// Why a call to the notification server failed.
#[derive(Debug)]
enum BusError {
    /// The connection or the server is gone: reconnect, and forget the ids.
    Gone(String),
    /// Only this call failed (for example it timed out).
    Call(String),
}

/// One live connection to the notification server.
trait Bus {
    fn notify(&self, replaces_id: u32, title: &str, body: &str) -> Result<u32, BusError>;
    fn close(&self, id: u32) -> Result<(), BusError>;
}

/// Makes [`Bus`] connections, and sends without one.
trait Connector {
    type Bus: Bus;
    fn connect(&mut self) -> Option<Self::Bus>;
    /// Show a notification without a bus (it cannot be updated or closed).
    fn fallback(&mut self, title: &str, body: &str);
}

/// The sender's state: the connection (or when to retry one) and the
/// server's id for each shown notification.
struct Sender<C: Connector> {
    connector: C,
    bus: Option<C::Bus>,
    /// After a failed connect: no new attempt before this instant.
    retry_at: Option<Instant>,
    ids: HashMap<String, u32>,
}

impl<C: Connector> Sender<C> {
    fn new(connector: C) -> Self {
        Self {
            connector,
            bus: None,
            retry_at: None,
            ids: HashMap::new(),
        }
    }

    /// Connect if there is no connection and the retry delay has passed.
    fn ensure_bus(&mut self, now: Instant) {
        if self.bus.is_some() || self.retry_at.is_some_and(|t| now < t) {
            return;
        }
        self.bus = self.connector.connect();
        self.retry_at = if self.bus.is_none() {
            Some(now + RECONNECT_AFTER)
        } else {
            None
        };
    }

    /// Drop a connection that is gone. The ids belonged to it (or to a
    /// server that is gone), so they are forgotten too.
    fn reset(&mut self, why: &str) {
        tracing::debug!(error = why, "notification connection lost; reconnecting");
        self.bus = None;
        self.retry_at = None;
        self.ids.clear();
    }

    fn handle(&mut self, cmd: Cmd, now: Instant) {
        if let Cmd::Flush(done) = cmd {
            let _ = done.send(());
            return;
        }
        self.ensure_bus(now);
        match cmd {
            Cmd::Show { key, title, body } => {
                let Some(bus) = &self.bus else {
                    self.connector.fallback(&title, &body);
                    return;
                };
                let replaces = self.ids.get(&key).copied().unwrap_or(0);
                match bus.notify(replaces, &title, &body) {
                    Ok(id) => {
                        self.ids.insert(key, id);
                    }
                    Err(BusError::Gone(e)) => {
                        self.reset(&e);
                        // Show it anyway, on a new connection if one comes up.
                        self.ensure_bus(now);
                        match &self.bus {
                            Some(bus) => match bus.notify(0, &title, &body) {
                                Ok(id) => {
                                    self.ids.insert(key, id);
                                }
                                Err(e) => tracing::debug!(error = ?e, "Notify failed"),
                            },
                            None => self.connector.fallback(&title, &body),
                        }
                    }
                    Err(BusError::Call(e)) => tracing::debug!(error = e, "Notify failed"),
                }
            }
            Cmd::Close { key } => {
                let (Some(bus), Some(id)) = (&self.bus, self.ids.remove(&key)) else {
                    return;
                };
                match bus.close(id) {
                    Ok(()) => {}
                    Err(BusError::Gone(e)) => self.reset(&e),
                    Err(BusError::Call(e)) => {
                        tracing::debug!(error = e, "CloseNotification failed")
                    }
                }
            }
            Cmd::Flush(_) => {}
        }
    }
}

/// The real [`Connector`]: the session bus, with `notify-send` as fallback.
struct SessionBus;

impl Connector for SessionBus {
    type Bus = zbus::blocking::Connection;

    fn connect(&mut self) -> Option<Self::Bus> {
        connect()
    }

    fn fallback(&mut self, title: &str, body: &str) {
        notify_send(title, body);
    }
}

impl Bus for zbus::blocking::Connection {
    fn notify(&self, replaces_id: u32, title: &str, body: &str) -> Result<u32, BusError> {
        dbus_notify(self, replaces_id, title, body, EXPIRE_TIMEOUT).map_err(classify)
    }

    fn close(&self, id: u32) -> Result<(), BusError> {
        self.call_method(
            Some(NOTIFY_DEST),
            NOTIFY_PATH,
            Some(NOTIFY_DEST),
            "CloseNotification",
            &(id,),
        )
        .map(|_| ())
        .map_err(classify)
    }
}

/// Sort a zbus error: an I/O failure other than a timeout means the
/// connection is broken, and a missing or disconnected service means the
/// notification server went away; both are [`BusError::Gone`]. Anything
/// else, including a call that timed out, fails only that call.
fn classify(e: zbus::Error) -> BusError {
    let gone = match &e {
        zbus::Error::InputOutput(io) => io.kind() != std::io::ErrorKind::TimedOut,
        zbus::Error::MethodError(name, _, _) => matches!(
            name.as_str(),
            "org.freedesktop.DBus.Error.ServiceUnknown"
                | "org.freedesktop.DBus.Error.Disconnected"
                | "org.freedesktop.DBus.Error.NoServer"
        ),
        _ => false,
    };
    if gone {
        BusError::Gone(e.to_string())
    } else {
        BusError::Call(e.to_string())
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
        let mut n = Notifier::new(Fake::default(), &cfg);
        n.cgroup_exists = Box::new(|_| true);
        n
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

    fn not_resumed() -> Call {
        let (t, b) = failed_resume_text("Firefox");
        Call::Show("firefox".into(), t, b)
    }

    #[test]
    fn a_failed_thaw_replaces_the_notification_instead_of_closing() {
        assert_eq!(
            failed_resume_text("Firefox"),
            (
                "Firefox could not be resumed".to_string(),
                "It may stay paused. Run rlm guard status for details.".to_string()
            )
        );
        let mut n = notifier(true, false);
        n.record(&freeze("/a"), ok());
        n.end_tick(0, Memory::Low, &mut names);
        n.take();
        n.record(&Action::Thaw { res: res("/a") }, None);
        n.end_tick(5_000, Memory::Fine, &mut names);
        assert_eq!(n.take(), vec![not_resumed()]);
        n.end_tick(6_000, Memory::Fine, &mut names);
        assert!(n.take().is_empty(), "stays up");
        n.close_all();
        assert_eq!(n.take(), vec![Call::Close("firefox".into())]);
    }

    #[test]
    fn a_failed_thaw_notice_closes_once_its_cgroup_is_gone() {
        let exists = std::rc::Rc::new(std::cell::Cell::new(true));
        let mut n = notifier(true, false);
        let e = exists.clone();
        n.cgroup_exists = Box::new(move |cg| cg != "/a" || e.get());
        n.record(&freeze("/a"), ok());
        n.end_tick(0, Memory::Low, &mut names);
        n.record(&Action::Thaw { res: res("/a") }, None);
        n.end_tick(5_000, Memory::Fine, &mut names);
        assert_eq!(n.take(), vec![paused(), not_resumed()]);
        exists.set(false);
        n.end_tick(6_000, Memory::Fine, &mut names);
        assert_eq!(n.take(), vec![Call::Close("firefox".into())]);
        n.end_tick(7_000, Memory::Fine, &mut names);
        assert!(n.take().is_empty());
    }

    #[test]
    fn a_later_successful_release_closes_the_failed_thaw_notice() {
        let mut n = notifier(true, false);
        n.record(&freeze("/a"), ok());
        n.end_tick(0, Memory::Low, &mut names);
        n.record(&Action::Thaw { res: res("/a") }, None);
        n.end_tick(5_000, Memory::Low, &mut names);
        n.take();
        n.record(&freeze("/a"), ok());
        n.end_tick(6_000, Memory::Low, &mut names);
        assert_eq!(n.take(), vec![paused()]);
        n.record(&Action::Thaw { res: res("/a") }, ok());
        n.end_tick(11_000, Memory::Fine, &mut names);
        n.end_tick(12_000, Memory::Fine, &mut names);
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

    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    /// What the fake bus and connector saw, shared with the test.
    #[derive(Default)]
    struct Log {
        calls: RefCell<Vec<String>>,
        /// Answers for the next connect attempts; `true` connects. Empty
        /// means connect.
        connects: RefCell<Vec<bool>>,
        /// When set, the next bus call fails with this.
        fail_next: RefCell<Option<BusError>>,
        next_id: Cell<u32>,
    }

    struct FakeBus(Rc<Log>, u32);

    impl Bus for FakeBus {
        fn notify(&self, replaces_id: u32, title: &str, _body: &str) -> Result<u32, BusError> {
            if let Some(e) = self.0.fail_next.borrow_mut().take() {
                return Err(e);
            }
            let id = if replaces_id == 0 {
                self.0.next_id.set(self.0.next_id.get() + 1);
                self.0.next_id.get()
            } else {
                replaces_id
            };
            self.0
                .calls
                .borrow_mut()
                .push(format!("conn{} notify {replaces_id}->{id} {title}", self.1));
            Ok(id)
        }

        fn close(&self, id: u32) -> Result<(), BusError> {
            if let Some(e) = self.0.fail_next.borrow_mut().take() {
                return Err(e);
            }
            self.0
                .calls
                .borrow_mut()
                .push(format!("conn{} close {id}", self.1));
            Ok(())
        }
    }

    struct FakeConnector(Rc<Log>, u32);

    impl Connector for FakeConnector {
        type Bus = FakeBus;

        fn connect(&mut self) -> Option<FakeBus> {
            let ok = {
                let mut answers = self.0.connects.borrow_mut();
                if answers.is_empty() {
                    true
                } else {
                    answers.remove(0)
                }
            };
            self.0
                .calls
                .borrow_mut()
                .push(format!("connect {}", if ok { "ok" } else { "failed" }));
            ok.then(|| {
                self.1 += 1;
                FakeBus(Rc::clone(&self.0), self.1)
            })
        }

        fn fallback(&mut self, title: &str, _body: &str) {
            self.0
                .calls
                .borrow_mut()
                .push(format!("notify-send {title}"));
        }
    }

    fn show(key: &str, title: &str) -> Cmd {
        Cmd::Show {
            key: key.into(),
            title: title.into(),
            body: String::new(),
        }
    }

    fn sender_with(log: &Rc<Log>) -> Sender<FakeConnector> {
        Sender::new(FakeConnector(Rc::clone(log), 0))
    }

    fn take(log: &Log) -> Vec<String> {
        std::mem::take(&mut *log.calls.borrow_mut())
    }

    #[test]
    fn a_failed_connect_is_retried_after_the_backoff() {
        let log = Rc::new(Log::default());
        log.connects.borrow_mut().push(false);
        let mut s = sender_with(&log);
        let t0 = Instant::now();
        s.handle(show("a", "A paused"), t0);
        s.handle(show("a", "A slowed"), t0 + Duration::from_secs(10));
        assert_eq!(
            take(&log),
            [
                "connect failed",
                "notify-send A paused",
                "notify-send A slowed"
            ],
            "no new attempt during the backoff"
        );
        s.handle(show("a", "A slowed"), t0 + RECONNECT_AFTER);
        s.handle(show("a", "A slowed again"), t0 + RECONNECT_AFTER);
        s.handle(
            Cmd::Close { key: "a".into() },
            t0 + RECONNECT_AFTER + Duration::from_secs(1),
        );
        assert_eq!(
            take(&log),
            [
                "connect ok",
                "conn1 notify 0->1 A slowed",
                "conn1 notify 1->1 A slowed again",
                "conn1 close 1"
            ]
        );
    }

    #[test]
    fn a_broken_connection_is_dropped_and_rebuilt() {
        let log = Rc::new(Log::default());
        let mut s = sender_with(&log);
        let t0 = Instant::now();
        s.handle(show("a", "A paused"), t0);
        take(&log);
        *log.fail_next.borrow_mut() = Some(BusError::Gone("broken pipe".into()));
        s.handle(show("a", "A slowed"), t0);
        assert_eq!(
            take(&log),
            ["connect ok", "conn2 notify 0->2 A slowed"],
            "reconnects and shows it as a new notification"
        );
        *log.fail_next.borrow_mut() = Some(BusError::Gone("gone".into()));
        s.handle(Cmd::Close { key: "a".into() }, t0);
        s.handle(show("b", "B paused"), t0);
        assert_eq!(
            take(&log),
            ["connect ok", "conn3 notify 0->3 B paused"],
            "a failed close also resets"
        );
    }

    #[test]
    fn a_timed_out_call_keeps_the_connection() {
        let log = Rc::new(Log::default());
        let mut s = sender_with(&log);
        let t0 = Instant::now();
        s.handle(show("a", "A paused"), t0);
        *log.fail_next.borrow_mut() = Some(BusError::Call("timed out".into()));
        s.handle(show("a", "A slowed"), t0);
        s.handle(show("a", "A slowed"), t0);
        assert_eq!(
            take(&log),
            [
                "connect ok",
                "conn1 notify 0->1 A paused",
                "conn1 notify 1->1 A slowed"
            ]
        );
    }

    #[test]
    fn io_errors_other_than_timeouts_mean_the_connection_is_gone() {
        let io = |kind| zbus::Error::InputOutput(std::sync::Arc::new(std::io::Error::from(kind)));
        assert!(matches!(
            classify(io(std::io::ErrorKind::BrokenPipe)),
            BusError::Gone(_)
        ));
        assert!(matches!(
            classify(io(std::io::ErrorKind::TimedOut)),
            BusError::Call(_)
        ));
        assert!(matches!(
            classify(zbus::Error::InvalidReply),
            BusError::Call(_)
        ));
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

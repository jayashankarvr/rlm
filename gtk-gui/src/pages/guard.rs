//! GTK4/libadwaita Guard page: the `rlm-guard` freeze guard's state. The
//! intervention and history lines reuse `rlm_core::guard::report`'s text, so
//! they match `rlm guard status` and `rlm guard history`. The Pressure, Config
//! and Policy rows are put in plain words here; the CLI's pressure line, with
//! the raw PSI numbers, is the Pressure row's tooltip.
//!
//! The only thing the page changes is whether the service runs: its switch
//! runs `rlm guard enable` or `rlm guard disable`, the same code path as the
//! CLI. Everything else is read from systemd state, the config, a pressure
//! sample, the write-ahead journal and the intervention history log.

use crate::widgets::icon_button;
use adw::prelude::*;
use common::{Config, GuardConfig, GuardTrigger, BUILTIN_PROTECT};
use gtk::glib;
use rlm_core::guard::history::{history_path, read_recent, unix_now, HistoryEvent};
use rlm_core::guard::journal::JournalEntry;
use rlm_core::guard::policy::rise_level;
use rlm_core::guard::report::{
    config_error_line, config_error_path, history_line, intervention_line, pressure_line,
    pressure_unavailable,
};
use rlm_core::guard::service::{describe, query, ServiceState};
use rlm_core::guard::{cgfs, journal_path, Journal, Level, Sample, Sampler};
use rlm_core::process::current_uid;
use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How many recent history entries a refresh fetches and shows.
const HISTORY_SHOWN: usize = 20;

/// `service::query` spawns two `systemctl --user` calls, each with its own
/// 1s timeout (see `rlm_core::guard::service::SYSTEMCTL_TIMEOUT`); cheap
/// once, but the auto-refresh timer (`window.rs`) calls `refresh` every 2s,
/// which would otherwise spawn `systemctl` every 2s on the GTK main thread.
/// Cache the service state and only re-query every `SERVICE_QUERY_INTERVAL`;
/// pressure and history still refresh on the full 2s cadence.
const SERVICE_QUERY_INTERVAL: Duration = Duration::from_secs(10);

static SERVICE_CACHE: Mutex<Option<(Instant, ServiceState)>> = Mutex::new(None);

/// The guard's systemd state, re-read at most once every
/// [`SERVICE_QUERY_INTERVAL`]; a cached value is returned in between. The
/// lock is not held while `query` runs, so a slow systemctl never blocks
/// [`invalidate_service_cache`].
fn cached_service_state() -> ServiceState {
    if let Some((last, state)) = service_cache().as_ref() {
        if last.elapsed() < SERVICE_QUERY_INTERVAL {
            return state.clone();
        }
    }
    let state = query();
    *service_cache() = Some((Instant::now(), state.clone()));
    state
}

/// Whether `rlm-guard` is running, from the cached service state.
pub(crate) fn guard_running() -> bool {
    cached_service_state().active == "active"
}

/// The cache, recovered rather than panicking if a previous holder panicked:
/// it only ever holds a complete value, so a poisoned lock is still usable.
fn service_cache() -> std::sync::MutexGuard<'static, Option<(Instant, ServiceState)>> {
    SERVICE_CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Drop the cached service state so the next read queries systemd.
fn invalidate_service_cache() {
    *service_cache() = None;
}

/// Whether the switch should show the guard as on, or `None` when systemd
/// gave no usable answer and the switch should stay where it is.
pub fn switch_on(s: &ServiceState) -> Option<bool> {
    if s.active == "unknown" || s.active == "timeout" {
        return None;
    }
    Some(s.enabled == "enabled" || s.active == "active")
}

const SWITCH_SUBTITLE: &str =
    "Starts now and at every login; freezes or caps a runaway app under memory pressure";

thread_local! {
    /// Set while `populate` moves the switch, so that change does not run
    /// `rlm guard enable`/`disable` as if the user had flipped it.
    static SYNCING_SWITCH: Cell<bool> = const { Cell::new(false) };
    /// The last failed toggle: the state it asked for and the error. Shown
    /// under the switch until the service reaches that state.
    static TOGGLE_ERROR: std::cell::RefCell<Option<(bool, String)>> =
        const { std::cell::RefCell::new(None) };
}

/// The `rlm` binary to run: the one next to `rlm-gtk` if present (they are
/// installed together), otherwise whatever `rlm` is on PATH.
fn rlm_binary() -> PathBuf {
    rlm_binary_for(std::env::current_exe().ok().as_deref())
}

/// [`rlm_binary`] for a given `rlm-gtk` path. The sibling must be an
/// executable file, not just any file named `rlm`.
fn rlm_binary_for(current_exe: Option<&std::path::Path>) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    current_exe
        .and_then(|exe| exe.parent().map(|dir| dir.join("rlm")))
        .filter(|p| {
            std::fs::metadata(p)
                .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        })
        .unwrap_or_else(|| PathBuf::from("rlm"))
}

/// How long the switch waits for `rlm guard enable`/`disable` before killing
/// it. The command talks to systemd, which can hang on a wedged D-Bus; the
/// switch would otherwise stay greyed out forever.
const GUARD_VERB_TIMEOUT: Duration = Duration::from_secs(30);

/// Run `cmd` with stdin and stdout closed and return its exit status and
/// stderr, or `None` if it did not exit within `timeout` (it is then killed
/// and reaped). stderr is drained on a separate thread so a chatty child
/// cannot block on a full pipe; after exit we wait at most a second for it,
/// since a grandchild may still hold the pipe open.
fn output_with_timeout(
    mut cmd: std::process::Command,
    timeout: Duration,
) -> std::io::Result<Option<(std::process::ExitStatus, String)>> {
    use std::io::Read;
    use std::process::Stdio;
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let stderr = child.stderr.take();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut text = String::new();
        if let Some(mut e) = stderr {
            let _ = e.read_to_string(&mut text);
        }
        let _ = tx.send(text);
    });
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            let text = rx.recv_timeout(Duration::from_secs(1)).unwrap_or_default();
            return Ok(Some((status, text)));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Run `rlm guard <verb>` and return its error text on failure.
fn run_guard_verb(verb: &str) -> std::result::Result<(), String> {
    let mut cmd = std::process::Command::new(rlm_binary());
    cmd.args(["guard", verb]);
    let (status, stderr) = output_with_timeout(cmd, GUARD_VERB_TIMEOUT)
        .map_err(|e| format!("could not run rlm: {e}"))?
        .ok_or_else(|| {
            format!(
                "rlm guard {verb} did not finish in {} s",
                GUARD_VERB_TIMEOUT.as_secs()
            )
        })?;
    if status.success() {
        return Ok(());
    }
    let text = stderr.trim();
    Err(if text.is_empty() {
        format!("rlm guard {verb} failed ({status})")
    } else {
        text.to_string()
    })
}

/// A memory size in MB as people read it: GB with one decimal from 1 GB up.
fn mb_text(mb: u64) -> String {
    if mb >= 1024 {
        format!("{:.1} GB", mb as f64 / 1024.0)
    } else {
        format!("{mb} MB")
    }
}

/// How much memory pressure a sample shows, judged by the level the guard
/// would rise to for it ([`rise_level`]). That check has no memory of earlier
/// samples, while the guard only steps back down once pressure falls to half
/// its thresholds, so with `acting` (the guard has apps frozen or capped) a
/// calm sample reads "pressure easing" rather than "no memory pressure".
pub fn pressure_words(s: &Sample, t: &GuardTrigger, acting: bool) -> &'static str {
    match rise_level(s, t) {
        Level::Critical | Level::High => "high memory pressure",
        Level::Warn => "some memory pressure",
        Level::Calm if acting => "pressure easing",
        Level::Calm => "no memory pressure",
    }
}

/// The Pressure row in plain words, such as "9.8 GB of 14.8 GB free, no
/// memory pressure". `acting` is as for [`pressure_words`]. The raw PSI
/// numbers go in the row's tooltip.
pub fn pressure_summary(sample: Option<&Sample>, t: &GuardTrigger, acting: bool) -> String {
    let Some(s) = sample else {
        return "Cannot read memory pressure on this system".to_string();
    };
    let words = pressure_words(s, t, acting);
    if s.mem_available_mb == u64::MAX || s.mem_total_mb == 0 {
        format!("Free memory unknown, {words}")
    } else {
        format!(
            "{} of {} free, {words}",
            mb_text(s.mem_available_mb),
            mb_text(s.mem_total_mb)
        )
    }
}

/// The Policy row in plain words, from the guard config. Below the free
/// memory floor the guard acts without waiting for stalls (the level is
/// Critical there), so the wording does not claim stalls are always needed.
pub fn policy_summary(g: &GuardConfig) -> String {
    if !g.enabled {
        return "Freezing and capping are off (guard.enabled is false); saved rules still apply"
            .to_string();
    }
    let t = &g.trigger;
    format!(
        "Steps in when apps stall and free memory is below {}%, or at once below {}",
        t.act_below_available_pct,
        mb_text(t.mem_available_floor_mb)
    )
}

/// `text` with its first letter in upper case.
fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// Everything the Guard page renders, computed once from plain data so it
/// can be unit-tested without a display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardView {
    pub service: String,
    pub switch_on: Option<bool>,
    pub failed: bool,
    pub config: std::result::Result<(), String>,
    /// Plain-language pressure, see [`pressure_summary`].
    pub pressure: String,
    /// The CLI's pressure line with the raw PSI numbers.
    pub pressure_detail: String,
    pub policy: String,
    /// Protected process names paired with where they came from: `"built-in"`
    /// or `"your config"`. Sorted case-insensitively by name.
    pub protect: Vec<(String, &'static str)>,
    pub interventions: Vec<String>,
    /// Newest first.
    pub history: Vec<String>,
}

/// Build a [`GuardView`] from plain inputs. `now` is Unix seconds, passed in
/// (rather than read here) so history ages are testable without a clock.
pub fn build_view(
    service: &ServiceState,
    cfg: &std::result::Result<GuardConfig, String>,
    sample: Option<Sample>,
    entries: &[JournalEntry],
    history: &[HistoryEvent],
    now: u64,
) -> GuardView {
    let service_desc = capitalize(&describe(service));
    let config = cfg.as_ref().map(|_| ()).map_err(Clone::clone);
    let trigger = cfg.as_ref().map(|c| c.trigger.clone()).unwrap_or_default();
    let pressure = pressure_summary(sample.as_ref(), &trigger, !entries.is_empty());
    let pressure_detail =
        sample.map_or_else(|| pressure_unavailable().to_string(), |s| pressure_line(&s));
    let policy = cfg.as_ref().map_or_else(
        |_| "The guard will not start until the config is fixed".to_string(),
        policy_summary,
    );

    let mut protect: Vec<(String, &'static str)> = BUILTIN_PROTECT
        .iter()
        .map(|s| ((*s).to_string(), "built-in"))
        .collect();
    if let Ok(c) = cfg {
        for name in &c.selection.protect {
            if !BUILTIN_PROTECT.contains(&name.as_str()) {
                protect.push((name.clone(), "your config"));
            }
        }
    }
    protect.sort_by_key(|(name, _)| name.to_lowercase());

    let interventions = entries.iter().map(intervention_line).collect();
    let history = history.iter().rev().map(|e| history_line(e, now)).collect();

    GuardView {
        service: service_desc,
        switch_on: switch_on(service),
        failed: service.active == "failed",
        config,
        pressure,
        pressure_detail,
        policy,
        protect,
        interventions,
        history,
    }
}

/// Read the guard's current state from the system: `systemctl` state, config,
/// a pressure sample, active-intervention journal entries and recent
/// history. Every call here is read-only.
fn gather() -> GuardView {
    let service = cached_service_state();
    let cfg = match Config::load_validated() {
        Ok(c) => Ok(c.guard),
        Err(e) => Err(config_error_line(&config_error_path(), &e)),
    };
    let sampler_cfg = cfg.clone().unwrap_or_default();
    let sample = Sampler::new(sampler_cfg, std::process::id(), current_uid(), None).sample();
    let entries = Journal::read_entries(&journal_path(), &cgfs::boot_id());
    let history = read_recent(&history_path(), HISTORY_SHOWN);
    let now = unix_now();
    build_view(&service, &cfg, sample, &entries, &history, now)
}

/// Make `list_box` show `rows` as (title, subtitle) pairs. With the same
/// number of rows the existing ones are updated in place, so keyboard focus
/// and scroll position survive; otherwise the list is rebuilt. Titles are
/// plain text, never markup.
fn sync_rows(list_box: &gtk::ListBox, rows: &[(&str, Option<&str>)]) {
    let mut existing = Vec::new();
    let mut child = list_box.first_child();
    while let Some(c) = child {
        child = c.next_sibling();
        if let Ok(row) = c.downcast::<adw::ActionRow>() {
            existing.push(row);
        }
    }
    if existing.len() == rows.len() {
        for (row, (title, subtitle)) in existing.iter().zip(rows) {
            if row.title() != *title {
                row.set_title(title);
            }
            let subtitle = subtitle.unwrap_or("");
            if row.subtitle().as_deref().unwrap_or("") != subtitle {
                row.set_subtitle(subtitle);
            }
        }
        return;
    }
    for row in existing {
        list_box.remove(&row);
    }
    for (title, subtitle) in rows {
        let row = adw::ActionRow::new();
        row.set_use_markup(false);
        row.set_title(title);
        if let Some(subtitle) = subtitle {
            row.set_subtitle(subtitle);
        }
        list_box.append(&row);
    }
}

fn new_list_box(placeholder: Option<&str>) -> gtk::ListBox {
    let list_box = gtk::ListBox::new();
    list_box.set_selection_mode(gtk::SelectionMode::None);
    list_box.add_css_class("boxed-list");
    if let Some(text) = placeholder {
        let label = gtk::Label::new(Some(text));
        label.add_css_class("dim-label");
        label.set_margin_top(12);
        label.set_margin_bottom(12);
        list_box.set_placeholder(Some(&label));
    }
    list_box
}

/// A status row whose subtitle is updated on every refresh.
fn status_row(list_box: &gtk::ListBox, title: &str) -> adw::ActionRow {
    let row = adw::ActionRow::new();
    row.set_title(title);
    row.set_use_markup(false);
    list_box.append(&row);
    row
}

pub struct GuardPage {
    widget: gtk::Widget,
    switch: adw::SwitchRow,
    service_row: adw::ActionRow,
    config_row: adw::ActionRow,
    config_icon: gtk::Image,
    pressure_row: adw::ActionRow,
    policy_row: adw::ActionRow,
    interventions_list: gtk::ListBox,
    history_list: gtk::ListBox,
    protect_list: gtk::ListBox,
    /// What the lists showed after the last refresh; a list is only touched
    /// when its part of the view changed.
    last: RefCell<Option<GuardView>>,
}

impl GuardPage {
    pub fn new() -> Rc<Self> {
        let page = adw::PreferencesPage::new();

        // The on/off switch is a control, not part of the status readout, so it
        // gets its own group (and the spacing that comes with it).
        let control_group = adw::PreferencesGroup::new();
        let switch = adw::SwitchRow::new();
        switch.set_title("Run the guard");
        switch.set_subtitle(SWITCH_SUBTITLE);
        control_group.add(&switch);
        page.add(&control_group);

        let status_group = adw::PreferencesGroup::new();
        status_group.set_title("Status");
        status_group.set_description(Some(
            "Service and config state, memory pressure, and when the guard acts",
        ));
        let refresh_btn = icon_button("view-refresh-symbolic", "Refresh guard status");
        status_group.set_header_suffix(Some(&refresh_btn));
        let status_list = new_list_box(None);
        let service_row = status_row(&status_list, "Service");
        let config_row = status_row(&status_list, "Config");
        let config_icon = gtk::Image::from_icon_name("dialog-warning-symbolic");
        let pressure_row = status_row(&status_list, "Pressure");
        let policy_row = status_row(&status_list, "Policy");
        status_group.add(&status_list);
        page.add(&status_group);

        let interventions_group = adw::PreferencesGroup::new();
        interventions_group.set_title("Active interventions");
        interventions_group.set_description(Some(
            "Apps the guard has frozen or capped right now. They are restored when pressure eases or the guard stops.",
        ));
        let interventions_list = new_list_box(Some("Nothing is frozen or capped"));
        interventions_group.add(&interventions_list);
        page.add(&interventions_group);

        let history_group = adw::PreferencesGroup::new();
        history_group.set_title("Recent activity");
        history_group.set_description(Some(
            "Full history: rlm guard history, or journalctl --user -u rlm-guard",
        ));
        let history_list = new_list_box(Some("No activity yet"));
        history_group.add(&history_list);
        page.add(&history_group);

        let protect_group = adw::PreferencesGroup::new();
        protect_group.set_title("Protected processes");
        protect_group.set_description(Some(
            "The guard never freezes these; an app that shares a scope with one can only be capped. Add names under guard.selection.protect in ~/.config/rlm/config.yaml.",
        ));
        let protect_list = new_list_box(None);
        // The built-in list alone is 40+ names; scroll inside a fixed-height box
        // so it does not push the rest of the page down.
        let protect_scroll = gtk::ScrolledWindow::new();
        protect_scroll.set_hscrollbar_policy(gtk::PolicyType::Never);
        protect_scroll.set_min_content_height(240);
        protect_scroll.set_max_content_height(240);
        protect_scroll.set_child(Some(&protect_list));
        protect_group.add(&protect_scroll);
        page.add(&protect_group);

        let this = Rc::new(Self {
            widget: page.upcast(),
            switch,
            service_row,
            config_row,
            config_icon,
            pressure_row,
            policy_row,
            interventions_list,
            history_list,
            protect_list,
            last: RefCell::new(None),
        });
        this.refresh();

        let weak = Rc::downgrade(&this);
        refresh_btn.connect_clicked(move |_| {
            if let Some(page) = weak.upgrade() {
                page.refresh();
            }
        });

        let weak = Rc::downgrade(&this);
        this.switch.connect_active_notify(move |row| {
            if SYNCING_SWITCH.with(Cell::get) {
                return;
            }
            let verb = if row.is_active() { "enable" } else { "disable" };
            row.set_sensitive(false);
            row.set_subtitle(if verb == "enable" {
                "Turning on..."
            } else {
                "Turning off..."
            });
            let row = row.clone();
            let weak = weak.clone();
            glib::MainContext::default().spawn_local(async move {
                let result = gtk::gio::spawn_blocking(move || run_guard_verb(verb))
                    .await
                    .unwrap_or_else(|_| Err("rlm guard command panicked".to_string()));
                invalidate_service_cache();
                row.set_sensitive(true);
                let want = verb == "enable";
                TOGGLE_ERROR.with(|slot| {
                    *slot.borrow_mut() = result
                        .err()
                        .map(|e| (want, format!("Could not {verb} the guard: {e}")));
                });
                if let Some(page) = weak.upgrade() {
                    page.refresh();
                }
            });
        });

        this
    }

    pub fn widget(&self) -> gtk::Widget {
        self.widget.clone()
    }

    /// Re-read the guard's state, sync the switch and update what changed.
    /// Moving the switch here never runs `rlm guard enable`/`disable`.
    pub fn refresh(&self) {
        self.apply(&gather());
    }

    fn apply(&self, view: &GuardView) {
        self.sync_switch(view);

        self.service_row.set_subtitle(&view.service);
        match &view.config {
            Ok(()) => {
                self.config_row.set_subtitle("Valid");
                if self.config_icon.parent().is_some() {
                    self.config_row.remove(&self.config_icon);
                }
            }
            Err(e) => {
                self.config_row.set_subtitle(e);
                if self.config_icon.parent().is_none() {
                    self.config_row.add_prefix(&self.config_icon);
                }
            }
        }
        self.pressure_row.set_subtitle(&view.pressure);
        self.pressure_row
            .set_tooltip_text(Some(&view.pressure_detail));
        self.policy_row.set_subtitle(&view.policy);

        let last = self.last.borrow().clone();
        let changed = |part: fn(&GuardView) -> &Vec<String>| {
            last.as_ref().is_none_or(|l| part(l) != part(view))
        };
        if changed(|v| &v.interventions) {
            let rows: Vec<_> = view
                .interventions
                .iter()
                .map(|l| (l.as_str(), None))
                .collect();
            sync_rows(&self.interventions_list, &rows);
        }
        if changed(|v| &v.history) {
            let rows: Vec<_> = view.history.iter().map(|l| (l.as_str(), None)).collect();
            sync_rows(&self.history_list, &rows);
        }
        if last.as_ref().is_none_or(|l| l.protect != view.protect) {
            let rows: Vec<_> = view
                .protect
                .iter()
                .map(|(name, source)| (name.as_str(), Some(*source)))
                .collect();
            sync_rows(&self.protect_list, &rows);
        }
        self.last.replace(Some(view.clone()));
    }

    fn sync_switch(&self, view: &GuardView) {
        let switch = &self.switch;
        if !switch.is_sensitive() {
            return;
        }
        if let Some(on) = view.switch_on {
            if switch.is_active() != on {
                SYNCING_SWITCH.with(|f| f.set(true));
                switch.set_active(on);
                SYNCING_SWITCH.with(|f| f.set(false));
            }
        }
        let error = TOGGLE_ERROR.with(|e| {
            let mut e = e.borrow_mut();
            if matches!((&*e, view.switch_on), (Some((want, _)), Some(on)) if *want == on) {
                *e = None;
            }
            e.as_ref().map(|(_, msg)| msg.clone())
        });
        let subtitle = match error {
            Some(msg) => msg,
            None if view.failed => {
                "The guard is not running: its last start failed (see Service)".to_string()
            }
            None => SWITCH_SUBTITLE.to_string(),
        };
        if switch.subtitle().as_deref() != Some(subtitle.as_str()) {
            switch.set_subtitle(&subtitle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rlm_core::guard::history::{HistoryEvent, HistoryKind};

    fn sh(script: &str) -> std::process::Command {
        let mut cmd = std::process::Command::new("sh");
        cmd.args(["-c", script]);
        cmd
    }

    #[test]
    fn a_poisoned_service_cache_is_recovered() {
        let _ = std::thread::spawn(|| {
            let _guard = SERVICE_CACHE.lock().unwrap();
            panic!("poison the cache");
        })
        .join();
        assert!(SERVICE_CACHE.is_poisoned());
        invalidate_service_cache();
        assert!(service_cache().is_none());
    }

    #[test]
    fn rlm_binary_needs_an_executable_sibling() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let gtk = d.path().join("rlm-gtk");
        assert_eq!(rlm_binary_for(Some(&gtk)), PathBuf::from("rlm"));
        let rlm = d.path().join("rlm");
        std::fs::write(&rlm, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&rlm, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(rlm_binary_for(Some(&gtk)), PathBuf::from("rlm"));
        std::fs::set_permissions(&rlm, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(rlm_binary_for(Some(&gtk)), rlm);
        assert_eq!(rlm_binary_for(None), PathBuf::from("rlm"));
    }

    #[test]
    fn output_with_timeout_returns_status_and_stderr() {
        let (status, err) = output_with_timeout(
            sh("echo out; echo oops >&2; exit 3"),
            Duration::from_secs(10),
        )
        .unwrap()
        .unwrap();
        assert_eq!(status.code(), Some(3));
        assert_eq!(err.trim(), "oops");
    }

    #[test]
    fn output_with_timeout_kills_a_hung_child() {
        let start = Instant::now();
        let r = output_with_timeout(sh("exec sleep 30"), Duration::from_millis(200)).unwrap();
        assert!(r.is_none());
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    fn svc(a: &str, e: &str) -> ServiceState {
        ServiceState {
            active: a.into(),
            enabled: e.into(),
        }
    }

    #[test]
    fn view_lists_builtin_and_user_protect_names_sorted() {
        let mut cfg = GuardConfig::default();
        cfg.selection.protect = vec!["obs".into()];
        let v = build_view(&svc("active", "enabled"), &Ok(cfg), None, &[], &[], 100);
        assert_eq!(v.service, "Running (starts at login)");
        assert!(v.protect.contains(&("gnome-shell".to_string(), "built-in")));
        assert!(v.protect.contains(&("obs".to_string(), "your config")));
        let names: Vec<&String> = v.protect.iter().map(|(n, _)| n).collect();
        let mut sorted = names.clone();
        sorted.sort_by_key(|n| n.to_lowercase());
        assert_eq!(names, sorted);
        assert_eq!(v.pressure_detail, pressure_unavailable());
        assert_eq!(v.pressure, "Cannot read memory pressure on this system");
    }

    #[test]
    fn invalid_config_is_shown_and_builtins_still_listed() {
        let v = build_view(
            &svc("failed", "enabled"),
            &Err("guard: bad".into()),
            None,
            &[],
            &[],
            0,
        );
        assert_eq!(v.config, Err("guard: bad".into()));
        assert!(v.protect.iter().all(|(_, src)| *src == "built-in"));
    }

    #[test]
    fn switch_is_on_when_enabled_or_running() {
        assert_eq!(switch_on(&svc("active", "enabled")), Some(true));
        assert_eq!(switch_on(&svc("active", "disabled")), Some(true));
        assert_eq!(switch_on(&svc("inactive", "enabled")), Some(true));
        assert_eq!(switch_on(&svc("inactive", "disabled")), Some(false));
        assert_eq!(switch_on(&svc("inactive", "not-found")), Some(false));
        assert_eq!(switch_on(&svc("unknown", "unknown")), None);
        assert_eq!(switch_on(&svc("timeout", "timeout")), None);
    }

    #[test]
    fn history_is_newest_first() {
        let ev = |ts| HistoryEvent {
            ts,
            kind: HistoryKind::Cap,
            app: "a".into(),
            cgroup: "/c".into(),
            detail: "d".into(),
        };
        let v = build_view(
            &svc("active", "enabled"),
            &Ok(GuardConfig::default()),
            None,
            &[],
            &[ev(10), ev(90)],
            100,
        );
        assert!(v.history[0].contains("10s ago"), "{:?}", v.history);
    }

    fn sample(some: f64, full: f64, avail: u64, total: u64) -> Sample {
        Sample {
            some_avg10: some,
            full_avg10: full,
            mem_available_mb: avail,
            mem_total_mb: total,
            source: rlm_core::guard::PsiSource::AppSlice,
        }
    }

    #[test]
    fn pressure_in_plain_words() {
        let t = GuardTrigger::default();
        assert_eq!(
            pressure_summary(Some(&sample(0.4, 0.0, 10035, 15155)), &t, false),
            "9.8 GB of 14.8 GB free, no memory pressure"
        );
        assert_eq!(
            pressure_summary(Some(&sample(12.0, 0.0, 900, 15155)), &t, false),
            "900 MB of 14.8 GB free, some memory pressure"
        );
        assert_eq!(
            pressure_summary(Some(&sample(31.0, 0.0, 900, 15155)), &t, false),
            "900 MB of 14.8 GB free, high memory pressure"
        );
        assert_eq!(
            pressure_summary(Some(&sample(1.0, 10.0, 900, 15155)), &t, false),
            "900 MB of 14.8 GB free, high memory pressure"
        );
        assert_eq!(
            pressure_summary(Some(&sample(0.0, 0.0, u64::MAX, 0)), &t, false),
            "Free memory unknown, no memory pressure"
        );
        assert_eq!(
            pressure_summary(None, &t, false),
            "Cannot read memory pressure on this system"
        );
    }

    #[test]
    fn pressure_words_agree_with_the_guard() {
        let t = GuardTrigger::default();
        // PSI full at 4 enters High in the guard even with low `some`.
        assert_ne!(
            pressure_summary(Some(&sample(5.0, 4.0, 2000, 15155)), &t, false),
            "2.0 GB of 14.8 GB free, no memory pressure"
        );
        assert_ne!(
            pressure_words(&sample(5.0, 4.0, 2000, 15155), &t, false),
            "no memory pressure"
        );
        // Below the free-memory floor the guard is Critical with no PSI at all.
        assert_eq!(
            pressure_words(&sample(0.0, 0.0, 300, 15155), &t, false),
            "high memory pressure"
        );
    }

    #[test]
    fn pressure_follows_the_configured_thresholds() {
        let t = GuardTrigger {
            psi_some_warn: 1.0,
            psi_some_high: 2.0,
            ..GuardTrigger::default()
        };
        assert_eq!(
            pressure_words(&sample(1.5, 0.0, 8000, 16000), &t, false),
            "some memory pressure"
        );
        assert_eq!(
            pressure_words(&sample(2.0, 0.0, 8000, 16000), &t, false),
            "high memory pressure"
        );
    }

    #[test]
    fn calm_sample_reads_easing_while_the_guard_acts() {
        let t = GuardTrigger::default();
        let calm = sample(0.4, 0.0, 10035, 15155);
        assert_eq!(pressure_words(&calm, &t, false), "no memory pressure");
        assert_eq!(pressure_words(&calm, &t, true), "pressure easing");
        assert_eq!(
            pressure_summary(Some(&calm), &t, true),
            "9.8 GB of 14.8 GB free, pressure easing"
        );
        // Real pressure is still named as such while acting.
        assert_eq!(
            pressure_words(&sample(31.0, 0.0, 900, 15155), &t, true),
            "high memory pressure"
        );
    }

    #[test]
    fn policy_and_config_in_plain_words() {
        assert_eq!(
            policy_summary(&GuardConfig::default()),
            "Steps in when apps stall and free memory is below 20%, or at once below 400 MB"
        );
        let off = GuardConfig {
            enabled: false,
            ..GuardConfig::default()
        };
        assert_eq!(
            policy_summary(&off),
            "Freezing and capping are off (guard.enabled is false); saved rules still apply"
        );
        let s = sample(0.0, 0.0, 8000, 16000);
        let v = build_view(
            &svc("active", "enabled"),
            &Ok(GuardConfig::default()),
            Some(s),
            &[],
            &[],
            0,
        );
        assert_eq!(v.config, Ok(()));
        assert_eq!(v.pressure_detail, pressure_line(&s));
        let bad = build_view(
            &svc("failed", "enabled"),
            &Err("guard: bad".into()),
            None,
            &[],
            &[],
            0,
        );
        assert_eq!(
            bad.policy,
            "The guard will not start until the config is fixed"
        );
    }
}

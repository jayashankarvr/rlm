//! GTK4/libadwaita Guard page: a read-only view of the `rlm-guard` freeze
//! guard's state, reusing `rlm_core::guard::report`'s text so the CLI
//! (`rlm guard status`/`rlm guard history`) and this page never disagree.
//!
//! This page never starts, stops, enables, disables or otherwise configures
//! the guard service; it only reads systemd state, the config, a pressure
//! sample, the write-ahead journal and the intervention history log.

use adw::prelude::*;
use common::{Config, GuardConfig, BUILTIN_PROTECT};
use rlm_core::guard::history::{history_path, read_recent, unix_now, HistoryEvent};
use rlm_core::guard::journal::JournalEntry;
use rlm_core::guard::report::{
    config_error_line, config_error_path, history_line, intervention_line, pressure_line,
    pressure_unavailable, trigger_line,
};
use rlm_core::guard::service::{describe, query, ServiceState};
use rlm_core::guard::{cgfs, journal_path, Journal, Sample, Sampler};
use rlm_core::process::current_uid;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How many recent history entries `refresh`/`create` fetch and show.
const HISTORY_SHOWN: usize = 20;

/// `service::query` spawns two `systemctl --user` calls, each with its own
/// 1s timeout (see `rlm_core::guard::service::SYSTEMCTL_TIMEOUT`) — cheap
/// once, but the auto-refresh timer (`window.rs`) calls `refresh` every 2s,
/// which would otherwise spawn `systemctl` every 2s on the GTK main thread.
/// Cache the service state and only re-query every `SERVICE_QUERY_INTERVAL`;
/// pressure and history still refresh on the full 2s cadence.
const SERVICE_QUERY_INTERVAL: Duration = Duration::from_secs(10);

static SERVICE_CACHE: Mutex<Option<(Instant, ServiceState)>> = Mutex::new(None);

/// The guard's systemd state, re-read at most once every
/// [`SERVICE_QUERY_INTERVAL`]; a cached value is returned in between.
fn cached_service_state() -> ServiceState {
    let mut cache = SERVICE_CACHE.lock().unwrap();
    if let Some((last, state)) = cache.as_ref() {
        if last.elapsed() < SERVICE_QUERY_INTERVAL {
            return state.clone();
        }
    }
    let state = query();
    *cache = Some((Instant::now(), state.clone()));
    state
}

/// Everything the Guard page renders, computed once from plain data so it
/// can be unit-tested without a display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardView {
    pub service: String,
    pub config: std::result::Result<(), String>,
    pub pressure: String,
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
    let service_desc = describe(service);
    let config = cfg.as_ref().map(|_| ()).map_err(Clone::clone);
    let pressure = sample.map_or_else(|| pressure_unavailable().to_string(), |s| pressure_line(&s));
    let policy = cfg.as_ref().map_or_else(
        |_| "guard config invalid; the guard will not start".to_string(),
        |c| trigger_line(&c.trigger),
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
        config,
        pressure,
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

/// Remove every child of `list_box`, so it can be rebuilt from scratch.
fn clear(list_box: &gtk::ListBox) {
    while let Some(child) = list_box.first_child() {
        list_box.remove(&child);
    }
}

fn add_row(list_box: &gtk::ListBox, title: &str, subtitle: Option<&str>) -> adw::ActionRow {
    let row = adw::ActionRow::new();
    row.set_title(title);
    if let Some(subtitle) = subtitle {
        row.set_subtitle(subtitle);
    }
    list_box.append(&row);
    row
}

/// Rebuild the four list boxes from a freshly gathered [`GuardView`].
fn populate(
    view: &GuardView,
    status_list: &gtk::ListBox,
    interventions_list: &gtk::ListBox,
    history_list: &gtk::ListBox,
    protect_list: &gtk::ListBox,
) {
    clear(status_list);
    add_row(status_list, "Service", Some(&view.service));
    match &view.config {
        Ok(()) => {
            add_row(status_list, "Config", Some("ok"));
        }
        Err(e) => {
            let row = add_row(status_list, "Config", Some(e));
            row.add_prefix(&gtk::Image::from_icon_name("dialog-warning-symbolic"));
        }
    }
    add_row(status_list, "Pressure", Some(&view.pressure));
    add_row(status_list, "Policy", Some(&view.policy));
    if view.service.contains("not installed") || view.service.contains("stopped") {
        add_row(status_list, "Turn on with: rlm guard enable", None);
    }

    clear(interventions_list);
    if view.interventions.is_empty() {
        add_row(interventions_list, "None", None);
    } else {
        for line in &view.interventions {
            add_row(interventions_list, line, None);
        }
    }

    clear(history_list);
    if view.history.is_empty() {
        add_row(history_list, "Nothing recorded yet", None);
    } else {
        for line in &view.history {
            add_row(history_list, line, None);
        }
    }

    clear(protect_list);
    for (name, source) in &view.protect {
        add_row(protect_list, name, Some(source));
    }
}

fn find_widget_by_name(widget: &gtk::Widget, name: &str) -> Option<gtk::Widget> {
    if widget.widget_name() == name {
        return Some(widget.clone());
    }
    let mut child = widget.first_child();
    while let Some(c) = child {
        if let Some(found) = find_widget_by_name(&c, name) {
            return Some(found);
        }
        child = c.next_sibling();
    }
    None
}

fn list_box_named(widget: &gtk::Widget, name: &str) -> Option<gtk::ListBox> {
    find_widget_by_name(widget, name).and_then(|w| w.downcast::<gtk::ListBox>().ok())
}

fn new_list_box(name: &str) -> gtk::ListBox {
    let list_box = gtk::ListBox::new();
    list_box.set_selection_mode(gtk::SelectionMode::None);
    list_box.add_css_class("boxed-list");
    list_box.set_widget_name(name);
    list_box
}

pub fn create() -> gtk::Widget {
    let page = adw::PreferencesPage::new();
    page.set_title("Guard");
    page.set_icon_name(Some("security-high-symbolic"));

    let status_group = adw::PreferencesGroup::new();
    status_group.set_title("Status");
    let refresh_btn = gtk::Button::from_icon_name("view-refresh-symbolic");
    refresh_btn.add_css_class("flat");
    refresh_btn.set_tooltip_text(Some("Refresh"));
    status_group.set_header_suffix(Some(&refresh_btn));
    let status_list = new_list_box("guard-status-list");
    status_group.add(&status_list);
    page.add(&status_group);

    let interventions_group = adw::PreferencesGroup::new();
    interventions_group.set_title("Active interventions");
    let interventions_list = new_list_box("guard-interventions-list");
    interventions_group.add(&interventions_list);
    page.add(&interventions_group);

    let history_group = adw::PreferencesGroup::new();
    history_group.set_title("Recent activity");
    history_group.set_description(Some(
        "Full history: rlm guard history, or journalctl --user -u rlm-guard",
    ));
    let history_list = new_list_box("guard-history-list");
    history_group.add(&history_list);
    page.add(&history_group);

    let protect_group = adw::PreferencesGroup::new();
    protect_group.set_title("Protected processes");
    protect_group.set_description(Some(
        "The guard never freezes or caps these. Add names under guard.selection.protect in ~/.config/rlm/config.yaml.",
    ));
    let protect_list = new_list_box("guard-protect-list");
    protect_group.add(&protect_list);
    page.add(&protect_group);

    let widget = page.upcast::<gtk::Widget>();
    populate(
        &gather(),
        &status_list,
        &interventions_list,
        &history_list,
        &protect_list,
    );

    let widget_for_btn = widget.clone();
    refresh_btn.connect_clicked(move |_| {
        refresh(&widget_for_btn);
    });

    widget
}

/// Re-read the guard's state and rebuild the page's list boxes. Read-only:
/// never starts, stops or configures the service.
pub fn refresh(widget: &gtk::Widget) {
    let status_list = list_box_named(widget, "guard-status-list");
    let interventions_list = list_box_named(widget, "guard-interventions-list");
    let history_list = list_box_named(widget, "guard-history-list");
    let protect_list = list_box_named(widget, "guard-protect-list");
    if let (Some(status), Some(interventions), Some(history), Some(protect)) =
        (status_list, interventions_list, history_list, protect_list)
    {
        populate(&gather(), &status, &interventions, &history, &protect);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rlm_core::guard::history::{HistoryEvent, HistoryKind};

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
        assert_eq!(v.service, "running (starts at login)");
        assert!(v.protect.contains(&("gnome-shell".to_string(), "built-in")));
        assert!(v.protect.contains(&("obs".to_string(), "your config")));
        let names: Vec<&String> = v.protect.iter().map(|(n, _)| n).collect();
        let mut sorted = names.clone();
        sorted.sort_by_key(|n| n.to_lowercase());
        assert_eq!(names, sorted);
        assert_eq!(v.pressure, pressure_unavailable());
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
}

//! Managed Processes page: the cgroups rlm has limited, with a button to
//! remove each limit.
//!
//! The page is rebuilt only when what it would show changes ([`StatusView`]),
//! so the 2 s auto-refresh never steals keyboard focus or scroll position.

use crate::pages::guard::guard_running;
use crate::pages::{gui_error, plain_toast, show_toast};
use crate::widgets::icon_button;
use adw::prelude::*;
use common::{build_limit, format_bytes, AppRule, Config, Limit};
use gtk::glib;
use rlm_core::process::start_time;
use rlm_core::rules::cgroup_name_for;
use rlm_core::status::ProcessStatus;
use rlm_core::CgroupManager;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

/// How long the Undo and Forget rule toasts stay up, in seconds.
const ACTION_TOAST_SECS: u32 = 10;

/// One limited cgroup as the page shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowView {
    pub cgroup: String,
    /// The app's friendly name, as plain text.
    pub name: String,
    /// Row title, markup-escaped.
    pub title: String,
    /// Row subtitle, markup-escaped.
    pub subtitle: String,
    pub memory_max: Option<u64>,
    pub cpu_percent: Option<u32>,
    pub io_read_bps: Option<u64>,
    pub io_write_bps: Option<u64>,
}

/// Everything the page shows, so a refresh can tell whether anything changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusView {
    /// There is no cgroup manager; the window's banner says why.
    Unavailable,
    Error(String),
    Empty,
    Rows(Vec<RowView>),
}

/// "1 process" or "N processes".
pub fn processes_text(count: usize) -> String {
    let noun = if count == 1 { "process" } else { "processes" };
    format!("{count} {noun}")
}

/// The friendly name of the app in a cgroup, from its first process: the
/// installed desktop entry's name when there is one, else the program name.
pub fn app_name(p: &ProcessStatus) -> String {
    let comm = (p.name != "?").then_some(p.name.as_str());
    let exe = rlm_core::appname::exe_of_pid(p.pid);
    match exe.as_deref().or(comm) {
        Some(program) => {
            let dir = rlm_core::appname::exe_dir_of_pid(p.pid);
            rlm_core::appname::friendly_name(program, comm, dir.as_deref())
        }
        None => p.name.clone(),
    }
}

/// The row for `p`, whose app is called `app` (see [`app_name`]).
pub fn row_view(p: &ProcessStatus, app: &str) -> RowView {
    let who = match (p.is_shared, p.process_count) {
        (true, Some(count)) => format!("PID {}, {}", p.pid, processes_text(count)),
        (true, None) => format!("PID {}, shared", p.pid),
        (false, _) => format!("PID {}", p.pid),
    };

    let mut limits = Vec::new();
    if let Some(mem) = p.memory_max {
        limits.push(format!("Memory: {}", format_bytes(mem)));
    }
    if let Some(cpu) = p.cpu_quota {
        limits.push(format!("CPU: {cpu}%"));
    }
    if let Some(r) = p.io_read_bps {
        limits.push(format!("I/O Read: {}/s", format_bytes(r)));
    }
    if let Some(w) = p.io_write_bps {
        limits.push(format!("I/O Write: {}/s", format_bytes(w)));
    }
    let mut subtitle = if limits.is_empty() {
        format!("{who} | No limits set")
    } else {
        format!("{who} | {}", limits.join(" | "))
    };
    if p.is_shared {
        subtitle.push_str(" (shared among all processes)");
    }

    RowView {
        cgroup: p.cgroup_name.clone(),
        name: app.to_string(),
        title: glib::markup_escape_text(app).to_string(),
        subtitle: glib::markup_escape_text(&subtitle).to_string(),
        memory_max: p.memory_max,
        cpu_percent: p.cpu_quota,
        io_read_bps: p.io_read_bps,
        io_write_bps: p.io_write_bps,
    }
}

/// The page's view from the result of reading rlm's cgroups, or `None` when
/// there is no cgroup manager. `name` gives each cgroup's app name.
pub fn build_view(
    result: Option<common::Result<Vec<ProcessStatus>>>,
    name: impl Fn(&ProcessStatus) -> String,
) -> StatusView {
    match result {
        None => StatusView::Unavailable,
        Some(Err(e)) => StatusView::Error(e.to_string()),
        Some(Ok(procs)) if procs.is_empty() => StatusView::Empty,
        Some(Ok(procs)) => StatusView::Rows(procs.iter().map(|p| row_view(p, &name(p))).collect()),
    }
}

/// The limits a row shows, as a [`Limit`] that can be applied again. A CPU
/// quota that rounded down to 0% is left out.
pub fn restore_limit(row: &RowView) -> common::Result<Limit> {
    let memory = row.memory_max.map(|b| b.to_string());
    let cpu = row.cpu_percent.filter(|p| *p > 0).map(|p| format!("{p}%"));
    let io_read = row.io_read_bps.map(|b| b.to_string());
    let io_write = row.io_write_bps.map(|b| b.to_string());
    build_limit(
        memory.as_deref(),
        cpu.as_deref(),
        io_read.as_deref(),
        io_write.as_deref(),
    )
}

/// The PIDs of `recorded` (PID, start time at removal) that still name the
/// same process: `now` gives a PID's current start time. A PID that has
/// exited, or was reused by a process that started later, is left out, as is
/// one whose start time could not be read at removal.
pub fn still_running(
    recorded: &[(u32, Option<u64>)],
    now: impl Fn(u32) -> Option<u64>,
) -> Vec<u32> {
    recorded
        .iter()
        .filter(|(pid, then)| then.is_some() && now(*pid) == *then)
        .map(|(pid, _)| *pid)
        .collect()
}

/// Whether every process in a cgroup now (`current`, each PID with its
/// start time) is one of those `removed` from it, so putting them back can
/// only have been the guard's rule. A process that was not there at
/// removal, or whose start time cannot be read, means someone limited the
/// cgroup again since, and that limit must be left alone. An empty cgroup
/// counts as unchanged.
pub fn only_removed_processes(
    removed: &[(u32, Option<u64>)],
    current: &[(u32, Option<u64>)],
) -> bool {
    current.iter().all(|p| p.1.is_some() && removed.contains(p))
}

/// The saved rules that own `cgroup`, sorted: rlm-guard keeps each rule's
/// processes in `app-<rule name>`, so removing that cgroup's limit only
/// lasts until the guard's next pass. Names that differ only in `/` or a
/// space ("my app" and "my_app") share one cgroup, so there can be several.
pub fn rules_for_cgroup(rules: &HashMap<String, AppRule>, cgroup: &str) -> Vec<String> {
    let mut names: Vec<String> = rules
        .keys()
        .filter(|n| cgroup_name_for(n) == cgroup)
        .cloned()
        .collect();
    names.sort();
    names
}

/// Rule names as "'a'", "'a' and 'b'" or "'a', 'b' and 'c'".
fn quoted_names(names: &[String]) -> String {
    let quoted: Vec<String> = names.iter().map(|n| format!("'{n}'")).collect();
    match quoted.split_last() {
        None => String::new(),
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
    }
}

/// "rule 'a'" or "rules 'a' and 'b'".
fn rules_phrase(names: &[String]) -> String {
    let noun = if names.len() == 1 { "rule" } else { "rules" };
    format!("{noun} {}", quoted_names(names))
}

/// The toast after removing a limit that saved rules own. Only a running
/// guard puts the limit back, so only then is that said.
pub fn rule_kept_text(app: &str, rules: &[String], guard_running: bool) -> String {
    let phrase = rules_phrase(rules);
    if guard_running {
        let (verb, it) = if rules.len() == 1 {
            ("is", "it")
        } else {
            ("are", "them")
        };
        format!(
            "{} {verb} still saved; rlm-guard will apply {it} again",
            capitalize(&phrase)
        )
    } else {
        format!("Removed the limit from {app}; {phrase} still saved")
    }
}

/// The toast after forgetting `rules`. A running guard loaded its rules at
/// start and keeps applying them until it restarts.
pub fn forgot_text(rules: &[String], guard_running: bool) -> String {
    let mut text = format!("Forgot {}.", rules_phrase(rules));
    if guard_running {
        text.push_str(if rules.len() == 1 {
            " Restart rlm-guard to stop it applying the rule."
        } else {
            " Restart rlm-guard to stop it applying the rules."
        });
    }
    text
}

fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// Remove the saved rules `names`, as `rlm unlimit --application <name>
/// --forget` does for one.
fn forget_rules(names: &[String]) -> common::Result<()> {
    let mut config = Config::load()?;
    let mut removed = false;
    for name in names {
        removed |= config.remove_rule(name);
    }
    if removed {
        config.save()?;
    }
    Ok(())
}

pub struct StatusPage {
    stack: gtk::Stack,
    list_box: gtk::ListBox,
    error_page: adw::StatusPage,
    manager: Option<Arc<CgroupManager>>,
    last: RefCell<Option<StatusView>>,
    /// The list's rows in order, each with the view its trash button acts
    /// on. Rows are keyed by cgroup: when the same cgroups are listed again
    /// the rows are updated in place, so focus on a trash button survives
    /// PIDs and process counts changing.
    rows: RefCell<Vec<(adw::ActionRow, Rc<RefCell<RowView>>)>>,
}

/// Whether rows for `old` cgroups can be updated in place to show `new`.
fn same_cgroups(old: &[String], new: &[RowView]) -> bool {
    old.len() == new.len() && old.iter().zip(new).all(|(a, b)| *a == b.cgroup)
}

impl StatusPage {
    pub fn new(manager: Option<Arc<CgroupManager>>) -> Rc<Self> {
        let stack = gtk::Stack::new();

        // The list of limited processes.
        let page = adw::PreferencesPage::new();
        let group = adw::PreferencesGroup::new();
        group.set_description(Some(
            "Processes rlm has limited and their limits. The trash button removes a limit.",
        ));
        let refresh_btn = icon_button("view-refresh-symbolic", "Refresh process list");
        group.set_header_suffix(Some(&refresh_btn));
        let list_box = gtk::ListBox::new();
        list_box.set_selection_mode(gtk::SelectionMode::None);
        list_box.add_css_class("boxed-list");
        group.add(&list_box);
        page.add(&group);
        stack.add_named(&page, Some("list"));

        // Nothing limited yet.
        let empty = adw::StatusPage::new();
        empty.set_icon_name(Some("view-list-symbolic"));
        empty.set_title("No limited processes");
        empty.set_description(Some(
            "Limit an app that is already running, or start one with limits.",
        ));
        let buttons = gtk::Box::new(gtk::Orientation::Vertical, 12);
        buttons.set_halign(gtk::Align::Center);
        let limit_btn = gtk::Button::with_label("Limit a Running App");
        limit_btn.add_css_class("pill");
        limit_btn.add_css_class("suggested-action");
        limit_btn.set_action_name(Some("win.goto-limit"));
        let run_btn = gtk::Button::with_label("Launch an App");
        run_btn.add_css_class("pill");
        run_btn.set_action_name(Some("win.goto-run"));
        buttons.append(&limit_btn);
        buttons.append(&run_btn);
        empty.set_child(Some(&buttons));
        stack.add_named(&empty, Some("empty"));

        // No cgroup manager; the window's banner has the details.
        let unavailable = adw::StatusPage::new();
        unavailable.set_icon_name(Some("dialog-warning-symbolic"));
        unavailable.set_title("Resource limiting is unavailable");
        unavailable.set_description(Some("Run rlm doctor in a terminal to see why."));
        stack.add_named(&unavailable, Some("unavailable"));

        let error_page = adw::StatusPage::new();
        error_page.set_icon_name(Some("dialog-warning-symbolic"));
        error_page.set_title("Could not load processes");
        stack.add_named(&error_page, Some("error"));

        let this = Rc::new(Self {
            stack,
            list_box,
            error_page,
            manager,
            last: RefCell::new(None),
            rows: RefCell::new(Vec::new()),
        });

        let weak = Rc::downgrade(&this);
        refresh_btn.connect_clicked(move |_| {
            if let Some(page) = weak.upgrade() {
                page.refresh();
            }
        });

        this.refresh();
        // Redraw with the installed apps' names once they are loaded.
        let weak = Rc::downgrade(&this);
        super::when_app_names_load(move || {
            if let Some(page) = weak.upgrade() {
                page.refresh();
            }
        });
        this
    }

    pub fn widget(&self) -> gtk::Widget {
        self.stack.clone().upcast()
    }

    /// Re-read rlm's cgroups and redraw the page if anything changed.
    pub fn refresh(self: &Rc<Self>) {
        let view = build_view(
            self.manager
                .as_ref()
                .map(|m| rlm_core::status::get_managed_processes(m)),
            app_name,
        );
        if self.last.borrow().as_ref() == Some(&view) {
            return;
        }
        self.render(&view);
        self.last.replace(Some(view));
    }

    fn render(self: &Rc<Self>, view: &StatusView) {
        match view {
            StatusView::Unavailable => self.stack.set_visible_child_name("unavailable"),
            StatusView::Error(e) => {
                self.error_page.set_description(Some(e));
                self.stack.set_visible_child_name("error");
            }
            StatusView::Empty => self.stack.set_visible_child_name("empty"),
            StatusView::Rows(rows) => {
                let old: Vec<String> = self
                    .rows
                    .borrow()
                    .iter()
                    .map(|(_, v)| v.borrow().cgroup.clone())
                    .collect();
                if same_cgroups(&old, rows) {
                    for ((row, shown), view) in self.rows.borrow().iter().zip(rows) {
                        if row.title() != view.title {
                            row.set_title(&view.title);
                        }
                        if row.subtitle().as_deref() != Some(view.subtitle.as_str()) {
                            row.set_subtitle(&view.subtitle);
                        }
                        shown.replace(view.clone());
                    }
                } else {
                    while let Some(child) = self.list_box.first_child() {
                        self.list_box.remove(&child);
                    }
                    let built: Vec<_> = rows.iter().map(|r| self.process_row(r)).collect();
                    for (row, _) in &built {
                        self.list_box.append(row);
                    }
                    self.rows.replace(built);
                }
                self.stack.set_visible_child_name("list");
            }
        }
    }

    fn process_row(self: &Rc<Self>, view: &RowView) -> (adw::ActionRow, Rc<RefCell<RowView>>) {
        let row = adw::ActionRow::new();
        row.set_title(&view.title);
        row.set_subtitle(&view.subtitle);

        let label = format!("Remove limit from {}", view.name);
        let remove_btn = gtk::Button::from_icon_name("user-trash-symbolic");
        remove_btn.set_valign(gtk::Align::Center);
        remove_btn.add_css_class("flat");
        remove_btn.set_tooltip_text(Some(&label));
        remove_btn.update_property(&[gtk::accessible::Property::Label(&label)]);

        let weak = Rc::downgrade(self);
        let shown = Rc::new(RefCell::new(view.clone()));
        let current = shown.clone();
        remove_btn.connect_clicked(move |_| {
            if let Some(page) = weak.upgrade() {
                let view = current.borrow().clone();
                page.remove(&view);
            }
        });

        row.add_suffix(&remove_btn);
        row.set_activatable(false);
        (row, shown)
    }

    fn toast(&self, toast: adw::Toast) {
        show_toast(&self.stack, toast);
    }

    /// Remove the limit on `row`'s cgroup, then offer a way back: Forget
    /// rule when a saved rule will put it back anyway, Undo otherwise.
    fn remove(self: &Rc<Self>, row: &RowView) {
        let Some(manager) = self.manager.clone() else {
            return;
        };
        // Each PID with its start time, so Undo can tell a process that is
        // still running from a new one that reused the PID.
        let pids: Vec<(u32, Option<u64>)> = manager
            .pids_in_cgroup(&row.cgroup)
            .into_iter()
            .map(|pid| (pid, start_time(pid)))
            .collect();
        if let Err(e) = manager.cleanup_cgroup(&row.cgroup) {
            self.toast(plain_toast(&format!(
                "Could not remove the limit from {}: {}",
                row.name,
                gui_error(&e)
            )));
            self.refresh();
            return;
        }
        self.refresh();

        let rules = Config::load()
            .map(|c| rules_for_cgroup(&c.rules, &row.cgroup))
            .unwrap_or_default();
        let weak = Rc::downgrade(self);
        let toast = if !rules.is_empty() {
            let toast = plain_toast(&rule_kept_text(&row.name, &rules, guard_running()));
            toast.set_button_label(Some(if rules.len() == 1 {
                "Forget rule"
            } else {
                "Forget rules"
            }));
            let cgroup = row.cgroup.clone();
            toast.connect_button_clicked(move |_| {
                let Some(page) = weak.upgrade() else { return };
                let text = match forget_rules(&rules) {
                    Ok(()) => {
                        // The guard may have put the limit back since it was
                        // removed; take it off again now the rule is gone,
                        // unless the cgroup now holds other processes: then
                        // it was limited again on purpose.
                        if let Some(manager) = page.manager.as_ref() {
                            let current: Vec<(u32, Option<u64>)> = manager
                                .pids_in_cgroup(&cgroup)
                                .into_iter()
                                .map(|pid| (pid, start_time(pid)))
                                .collect();
                            if only_removed_processes(&pids, &current) {
                                let _ = manager.cleanup_cgroup(&cgroup);
                            }
                        }
                        page.refresh();
                        forgot_text(&rules, guard_running())
                    }
                    Err(e) => format!(
                        "Could not forget {}: {}",
                        rules_phrase(&rules),
                        gui_error(&e)
                    ),
                };
                page.toast(plain_toast(&text));
            });
            toast
        } else if pids.is_empty() {
            plain_toast(&format!("Removed the limit from {}", row.name))
        } else {
            let toast = plain_toast(&format!("Removed the limit from {}", row.name));
            toast.set_button_label(Some("Undo"));
            let row = row.clone();
            toast.connect_button_clicked(move |_| {
                if let Some(page) = weak.upgrade() {
                    page.undo_remove(&row, &pids);
                }
            });
            toast
        };
        toast.set_timeout(ACTION_TOAST_SECS);
        self.toast(toast);
    }

    /// Put the limits `row` showed back on those of `pids` still running,
    /// in a cgroup of the same name.
    fn undo_remove(self: &Rc<Self>, row: &RowView, pids: &[(u32, Option<u64>)]) {
        let Some(manager) = self.manager.clone() else {
            return;
        };
        let alive = still_running(pids, start_time);
        if alive.is_empty() {
            self.toast(plain_toast(&format!(
                "{} is no longer running; nothing to restore",
                row.name
            )));
            return;
        }
        let result = restore_limit(row)
            .and_then(|limit| manager.apply_limit_to_multiple(&alive, &limit, &row.cgroup));
        // The launch's own cleanup poll stopped when the cgroup was removed,
        // so start another one for the restored cgroup.
        if result.is_ok() && super::run::is_launch_cgroup(&row.cgroup) {
            super::run::schedule_cleanup(manager.clone(), row.cgroup.clone());
        }
        self.refresh();
        match result {
            Ok(warnings) if warnings.is_empty() => {}
            Ok(warnings) => self.toast(plain_toast(&format!(
                "Restored the limit on {}, with warnings: {}",
                row.name,
                warnings.join("; ")
            ))),
            Err(e) => self.toast(plain_toast(&format!(
                "Could not restore the limit on {}: {}",
                row.name,
                gui_error(&e)
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(name: &str, cgroup: &str, shared: bool) -> ProcessStatus {
        ProcessStatus {
            pid: 42,
            name: name.into(),
            cgroup_name: cgroup.into(),
            memory_max: Some(512 * 1024 * 1024),
            cpu_quota: Some(50),
            io_read_bps: None,
            io_write_bps: Some(10 * 1024 * 1024),
            is_shared: shared,
            process_count: shared.then_some(3),
            populated: true,
        }
    }

    #[test]
    fn process_counts_read_as_english() {
        assert_eq!(processes_text(1), "1 process");
        assert_eq!(processes_text(0), "0 processes");
        assert_eq!(processes_text(9), "9 processes");
        let mut one = proc("gnome-calculato", "app-gnome-calculator", true);
        one.pid = 1217697;
        one.process_count = Some(1);
        one.cpu_quota = None;
        one.io_write_bps = None;
        one.memory_max = Some(1024 * 1024 * 1024);
        let r = row_view(&one, "Calculator");
        assert_eq!(r.title, "Calculator");
        assert_eq!(
            r.subtitle,
            "PID 1217697, 1 process | Memory: 1.0G (shared among all processes)"
        );
    }

    #[test]
    fn view_states() {
        assert_eq!(build_view(None, app_name), StatusView::Unavailable);
        assert_eq!(build_view(Some(Ok(vec![])), app_name), StatusView::Empty);
        assert!(matches!(
            build_view(Some(Err(common::Error::Config("x".into()))), app_name),
            StatusView::Error(_)
        ));
        let v = build_view(Some(Ok(vec![proc("firefox", "app-firefox", true)])), |_| {
            "Firefox".to_string()
        });
        let StatusView::Rows(rows) = v else {
            panic!("expected rows")
        };
        assert_eq!(rows[0].title, "Firefox");
        assert_eq!(rows[0].name, "Firefox");
        assert_eq!(
            rows[0].subtitle,
            "PID 42, 3 processes | Memory: 512.0M | CPU: 50% | I/O Write: 10.0M/s \
             (shared among all processes)"
        );
    }

    #[test]
    fn same_processes_give_an_equal_view() {
        let name = |p: &ProcessStatus| p.name.clone();
        let a = build_view(Some(Ok(vec![proc("a", "pid-42", false)])), name);
        let b = build_view(Some(Ok(vec![proc("a", "pid-42", false)])), name);
        assert_eq!(a, b);
        let c = build_view(Some(Ok(vec![proc("b", "pid-42", false)])), name);
        assert_ne!(a, c);
    }

    #[test]
    fn rows_are_kept_while_the_same_cgroups_are_listed() {
        let a = row_view(&proc("a", "pid-1", false), "A");
        let mut b = row_view(&proc("b", "app-b", true), "B");
        let old = vec!["pid-1".to_string(), "app-b".to_string()];
        b.title = "Other".into();
        b.subtitle = "PID 7, 9 processes | Memory: 1.0G".into();
        assert!(same_cgroups(&old, &[a.clone(), b.clone()]));
        assert!(!same_cgroups(&old, &[b.clone(), a.clone()]));
        assert!(!same_cgroups(&old, &[a]));
    }

    #[test]
    fn undo_skips_exited_and_reused_pids() {
        let recorded = [
            (10, Some(100)),
            (11, Some(200)),
            (12, Some(300)),
            (13, None),
        ];
        let now = |pid: u32| match pid {
            10 => Some(100), // still the same process
            11 => Some(999), // PID reused by a newer process
            13 => Some(5),
            _ => None, // exited
        };
        assert_eq!(still_running(&recorded, now), [10]);
    }

    #[test]
    fn forget_rule_cleans_up_only_the_removed_processes() {
        let removed = [(10, Some(100)), (11, Some(110)), (12, None)];
        // The guard put back the same processes, or some of them.
        assert!(only_removed_processes(
            &removed,
            &[(10, Some(100)), (11, Some(110))]
        ));
        assert!(only_removed_processes(&removed, &[(11, Some(110))]));
        assert!(only_removed_processes(&removed, &[]));
        // A new process, or a reused PID: limited again since.
        assert!(!only_removed_processes(
            &removed,
            &[(10, Some(100)), (13, Some(130))]
        ));
        assert!(!only_removed_processes(&removed, &[(10, Some(999))]));
        // Unknown start times never match.
        assert!(!only_removed_processes(&removed, &[(12, None)]));
    }

    #[test]
    fn names_are_escaped_in_the_title_only() {
        let r = row_view(&proc("x", "pid-42", false), "a<b&c");
        assert_eq!(r.title, "a&lt;b&amp;c");
        assert_eq!(r.name, "a<b&c");
        assert!(r.subtitle.starts_with("PID 42 | Memory: 512.0M"));
    }

    #[test]
    fn restore_limit_matches_the_row() {
        let r = row_view(&proc("a", "pid-42", false), "A");
        let l = restore_limit(&r).unwrap();
        assert_eq!(l.memory.unwrap().bytes(), 512 * 1024 * 1024);
        assert_eq!(l.cpu.unwrap().percent(), 50);
        let io = l.io.unwrap();
        assert_eq!(io.read_bps, None);
        assert_eq!(io.write_bps, Some(10 * 1024 * 1024));

        let mut zero_cpu = r.clone();
        zero_cpu.cpu_percent = Some(0);
        assert!(restore_limit(&zero_cpu).unwrap().cpu.is_none());
    }

    #[test]
    fn rules_are_found_by_their_cgroup_name() {
        let mut rules = HashMap::new();
        rules.insert("firefox".to_string(), AppRule::default());
        rules.insert("my app".to_string(), AppRule::default());
        assert_eq!(rules_for_cgroup(&rules, "app-firefox"), ["firefox"]);
        assert_eq!(rules_for_cgroup(&rules, "app-my_app"), ["my app"]);
        assert!(rules_for_cgroup(&rules, "pid-42").is_empty());
        assert!(rules_for_cgroup(&rules, "app-chrome").is_empty());
        // Two names that map to one cgroup are both found.
        rules.insert("my_app".to_string(), AppRule::default());
        assert_eq!(rules_for_cgroup(&rules, "app-my_app"), ["my app", "my_app"]);
    }

    #[test]
    fn rule_toasts_mention_the_guard_only_while_it_runs() {
        let one = vec!["firefox".to_string()];
        let two = vec!["my app".to_string(), "my_app".to_string()];
        assert_eq!(
            rule_kept_text("firefox", &one, true),
            "Rule 'firefox' is still saved; rlm-guard will apply it again"
        );
        assert_eq!(
            rule_kept_text("firefox", &one, false),
            "Removed the limit from firefox; rule 'firefox' still saved"
        );
        assert_eq!(
            rule_kept_text("app", &two, true),
            "Rules 'my app' and 'my_app' are still saved; rlm-guard will apply them again"
        );
        assert_eq!(
            forgot_text(&one, true),
            "Forgot rule 'firefox'. Restart rlm-guard to stop it applying the rule."
        );
        assert_eq!(forgot_text(&one, false), "Forgot rule 'firefox'.");
        assert_eq!(
            forgot_text(&two, false),
            "Forgot rules 'my app' and 'my_app'."
        );
        let three = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        assert_eq!(quoted_names(&three), "'a', 'b' and 'c'");
    }
}

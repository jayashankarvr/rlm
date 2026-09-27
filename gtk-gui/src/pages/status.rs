//! Managed Processes page: the cgroups rlm has limited, with a button to
//! remove each limit.
//!
//! The page is rebuilt only when what it would show changes ([`StatusView`]),
//! so the 2 s auto-refresh never steals keyboard focus or scroll position.

use crate::pages::{plain_toast, show_toast};
use adw::prelude::*;
use common::{build_limit, format_bytes, AppRule, Config, Limit};
use gtk::glib;
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
    /// The first process's name, as plain text.
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

pub fn row_view(p: &ProcessStatus) -> RowView {
    let name = glib::markup_escape_text(&p.name);
    let title = match (p.is_shared, p.process_count) {
        (true, Some(count)) => format!("{name} (PID {}, {count} processes)", p.pid),
        (true, None) => format!("{name} (PID {}, shared)", p.pid),
        (false, _) => format!("{name} (PID {})", p.pid),
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
        "No limits set".to_string()
    } else {
        limits.join(" | ")
    };
    if p.is_shared {
        subtitle.push_str(" (shared among all processes)");
    }

    RowView {
        cgroup: p.cgroup_name.clone(),
        name: p.name.clone(),
        title,
        subtitle: glib::markup_escape_text(&subtitle).to_string(),
        memory_max: p.memory_max,
        cpu_percent: p.cpu_quota,
        io_read_bps: p.io_read_bps,
        io_write_bps: p.io_write_bps,
    }
}

/// The page's view from the result of reading rlm's cgroups, or `None` when
/// there is no cgroup manager.
pub fn build_view(result: Option<common::Result<Vec<ProcessStatus>>>) -> StatusView {
    match result {
        None => StatusView::Unavailable,
        Some(Err(e)) => StatusView::Error(e.to_string()),
        Some(Ok(procs)) if procs.is_empty() => StatusView::Empty,
        Some(Ok(procs)) => StatusView::Rows(procs.iter().map(row_view).collect()),
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

/// The saved rule that owns `cgroup`, if any: rlm-guard keeps each rule's
/// processes in `app-<rule name>`, so removing that cgroup's limit only
/// lasts until the guard's next pass.
pub fn rule_for_cgroup(rules: &HashMap<String, AppRule>, cgroup: &str) -> Option<String> {
    let mut names: Vec<&String> = rules
        .keys()
        .filter(|n| cgroup_name_for(n) == cgroup)
        .collect();
    names.sort();
    names.first().map(|n| (*n).clone())
}

/// Remove the saved rule `name`, as `rlm unlimit --application <name>
/// --forget` does.
fn forget_rule(name: &str) -> common::Result<()> {
    let mut config = Config::load()?;
    if config.remove_rule(name) {
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
        let refresh_btn = gtk::Button::from_icon_name("view-refresh-symbolic");
        refresh_btn.add_css_class("flat");
        refresh_btn.set_tooltip_text(Some("Refresh process list"));
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
        });

        let weak = Rc::downgrade(&this);
        refresh_btn.connect_clicked(move |_| {
            if let Some(page) = weak.upgrade() {
                page.refresh();
            }
        });

        this.refresh();
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
                while let Some(child) = self.list_box.first_child() {
                    self.list_box.remove(&child);
                }
                for row in rows {
                    self.list_box.append(&self.process_row(row));
                }
                self.stack.set_visible_child_name("list");
            }
        }
    }

    fn process_row(self: &Rc<Self>, view: &RowView) -> adw::ActionRow {
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
        let view = view.clone();
        remove_btn.connect_clicked(move |_| {
            if let Some(page) = weak.upgrade() {
                page.remove(&view);
            }
        });

        row.add_suffix(&remove_btn);
        row.set_activatable(false);
        row
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
        let pids = manager.pids_in_cgroup(&row.cgroup);
        if let Err(e) = manager.cleanup_cgroup(&row.cgroup) {
            self.toast(plain_toast(&format!(
                "Could not remove the limit from {}: {e}",
                row.name
            )));
            self.refresh();
            return;
        }
        self.refresh();

        let rule = Config::load()
            .ok()
            .and_then(|c| rule_for_cgroup(&c.rules, &row.cgroup));
        let weak = Rc::downgrade(self);
        let toast = if let Some(rule) = rule {
            let toast = plain_toast(&format!(
                "Rule '{rule}' is still saved; rlm-guard will apply it again"
            ));
            toast.set_button_label(Some("Forget rule"));
            toast.connect_button_clicked(move |_| {
                let Some(page) = weak.upgrade() else { return };
                let text = match forget_rule(&rule) {
                    Ok(()) => format!("Forgot rule '{rule}'"),
                    Err(e) => format!("Could not forget rule '{rule}': {e}"),
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
    fn undo_remove(self: &Rc<Self>, row: &RowView, pids: &[u32]) {
        let Some(manager) = self.manager.clone() else {
            return;
        };
        let alive: Vec<u32> = pids
            .iter()
            .copied()
            .filter(|p| std::path::Path::new(&format!("/proc/{p}")).exists())
            .collect();
        if alive.is_empty() {
            self.toast(plain_toast(&format!(
                "{} is no longer running; nothing to restore",
                row.name
            )));
            return;
        }
        let result = restore_limit(row)
            .and_then(|limit| manager.apply_limit_to_multiple(&alive, &limit, &row.cgroup));
        self.refresh();
        match result {
            Ok(warnings) if warnings.is_empty() => {}
            Ok(warnings) => self.toast(plain_toast(&warnings.join("; "))),
            Err(e) => self.toast(plain_toast(&format!(
                "Could not restore the limit on {}: {e}",
                row.name
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
    fn view_states() {
        assert_eq!(build_view(None), StatusView::Unavailable);
        assert_eq!(build_view(Some(Ok(vec![]))), StatusView::Empty);
        assert!(matches!(
            build_view(Some(Err(common::Error::Config("x".into())))),
            StatusView::Error(_)
        ));
        let v = build_view(Some(Ok(vec![proc("firefox", "app-firefox", true)])));
        let StatusView::Rows(rows) = v else {
            panic!("expected rows")
        };
        assert_eq!(rows[0].title, "firefox (PID 42, 3 processes)");
        assert_eq!(
            rows[0].subtitle,
            "Memory: 512.0M | CPU: 50% | I/O Write: 10.0M/s (shared among all processes)"
        );
    }

    #[test]
    fn same_processes_give_an_equal_view() {
        let a = build_view(Some(Ok(vec![proc("a", "pid-42", false)])));
        let b = build_view(Some(Ok(vec![proc("a", "pid-42", false)])));
        assert_eq!(a, b);
        let c = build_view(Some(Ok(vec![proc("b", "pid-42", false)])));
        assert_ne!(a, c);
    }

    #[test]
    fn names_are_escaped_in_the_title_only() {
        let r = row_view(&proc("a<b&c", "pid-42", false));
        assert_eq!(r.title, "a&lt;b&amp;c (PID 42)");
        assert_eq!(r.name, "a<b&c");
    }

    #[test]
    fn restore_limit_matches_the_row() {
        let r = row_view(&proc("a", "pid-42", false));
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
    fn rule_is_found_by_its_cgroup_name() {
        let mut rules = HashMap::new();
        rules.insert("firefox".to_string(), AppRule::default());
        rules.insert("my app".to_string(), AppRule::default());
        assert_eq!(
            rule_for_cgroup(&rules, "app-firefox"),
            Some("firefox".into())
        );
        assert_eq!(rule_for_cgroup(&rules, "app-my_app"), Some("my app".into()));
        assert_eq!(rule_for_cgroup(&rules, "pid-42"), None);
        assert_eq!(rule_for_cgroup(&rules, "app-chrome"), None);
    }
}

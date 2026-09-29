use crate::widgets::{
    cpu_suffix_label, cpu_value, create_io_unit_dropdown, create_unit_dropdown, fill_limits,
    fit_list_height, form_limit, icon_button, limits_description, list_scroller, on_enter,
    require_manager, setup_number_validation, setup_size_validation, size_value, status_toast,
    unshown_note, with_action_bar, NO_MANAGER_HINT,
};
use adw::prelude::*;
use gtk::glib;
use rlm_core::CgroupManager;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

// Field length limits
const MAX_COMMAND_LEN: usize = 1000;
const MAX_SEARCH_LEN: usize = 100;

struct RunState {
    command_entry: adw::EntryRow,
    memory_entry: adw::EntryRow,
    memory_unit: gtk::DropDown,
    cpu_entry: adw::EntryRow,
    io_read_entry: adw::EntryRow,
    io_read_unit: gtk::DropDown,
    io_write_entry: adw::EntryRow,
    io_write_unit: gtk::DropDown,
    status_label: gtk::Label,
    toast_overlay: adw::ToastOverlay,
    app_list: gtk::ListBox,
    manager: Option<Arc<CgroupManager>>,
    all_apps: RefCell<Vec<rlm_core::desktop::DesktopApp>>,
    running_pid: RefCell<Option<u32>>,
    cgroup_name: RefCell<Option<String>>,
    /// When the last launch started. Holding Enter in a field repeats the
    /// activation, so launches closer together than [`RELAUNCH_GAP`] are
    /// ignored rather than starting several instances.
    last_launch: Cell<Option<Instant>>,
}

/// Shortest time between two launches; see `RunState::last_launch`.
const RELAUNCH_GAP: Duration = Duration::from_secs(1);

/// Whether a launch (or, on the Limit Running page, an apply) at `now` comes
/// too soon after the one at `last`.
pub(super) fn too_soon(last: Option<Instant>, now: Instant) -> bool {
    last.is_some_and(|t| now.saturating_duration_since(t) < RELAUNCH_GAP)
}

static RUN_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

thread_local! {
    /// Set while [`refresh_profiles`] replaces the profile list, so the
    /// selection changes that causes do not refill the limit fields.
    static REFRESHING_PROFILES: Cell<bool> = const { Cell::new(false) };
}

pub fn create(manager: Option<Arc<CgroupManager>>) -> gtk::Widget {
    let toast_overlay = adw::ToastOverlay::new();

    let page = adw::PreferencesPage::new();
    page.set_title("Run");
    page.set_icon_name(Some("media-playback-start-symbolic"));

    // Main heading group
    let header_group = adw::PreferencesGroup::new();
    header_group.set_title("Launch New Process");
    header_group.set_description(Some(
        "Start a program with limits applied from its first instruction",
    ));
    page.add(&header_group);

    // Status label
    let status_label = gtk::Label::new(None);
    status_label.set_wrap(true);
    // Only take up room when there is a message; an empty label would push
    // the button further down the page.
    status_label.set_visible(false);
    status_label.connect_label_notify(|l| l.set_visible(!l.label().is_empty()));

    // Command group
    let command_group = adw::PreferencesGroup::new();
    command_group.set_title("Command");
    command_group.set_description(Some(
        "The program and its arguments, or pick an application below",
    ));

    let command_entry = adw::EntryRow::new();
    command_entry.set_title("Command");
    setup_command_validation(&command_entry);
    command_group.add(&command_entry);

    page.add(&command_group);

    // App search group
    let apps_group = adw::PreferencesGroup::new();
    apps_group.set_title("Applications");
    apps_group.set_description(Some("Installed apps. Selecting one fills in its command."));

    // Refresh button in header
    let refresh_btn = icon_button("view-refresh-symbolic", "Refresh application list");
    apps_group.set_header_suffix(Some(&refresh_btn));

    // Search entry
    let search_entry = gtk::SearchEntry::new();
    search_entry.set_placeholder_text(Some("Type to search applications..."));
    search_entry.set_margin_bottom(12);
    apps_group.add(&search_entry);

    // App list
    let app_list = gtk::ListBox::new();
    // The picked app stays highlighted while the command is its command.
    app_list.set_selection_mode(gtk::SelectionMode::Single);
    app_list.add_css_class("boxed-list");

    let scroll = list_scroller(&app_list);

    apps_group.add(&scroll);
    page.add(&apps_group);

    // Profile selection group
    let profile_group = adw::PreferencesGroup::new();
    profile_group.set_title("Quick Apply");
    profile_group.set_description(Some("Choosing a profile fills in the limits below"));

    let profiles = load_profile_names();
    let profile_list =
        gtk::StringList::new(&profiles.iter().map(|s| s.as_str()).collect::<Vec<_>>());
    let profile_dropdown = gtk::DropDown::new(Some(profile_list), gtk::Expression::NONE);
    profile_dropdown.set_selected(0);
    profile_dropdown.set_valign(gtk::Align::Center);
    profile_dropdown.set_widget_name("run-profile-dropdown");

    let profile_row = adw::ActionRow::new();
    profile_row.set_title("Profile");
    profile_row.add_suffix(&profile_dropdown);
    profile_group.add(&profile_row);

    page.add(&profile_group);

    // Limits group
    let limits_group = adw::PreferencesGroup::new();
    limits_group.set_title("Limits");
    limits_group.set_description(Some(&limits_description()));

    // Memory with unit dropdown
    let memory_entry = adw::EntryRow::new();
    memory_entry.set_title("Memory");
    memory_entry.set_input_purpose(gtk::InputPurpose::Number);
    setup_size_validation(&memory_entry);
    let memory_unit = create_unit_dropdown();
    memory_entry.add_suffix(&memory_unit);
    limits_group.add(&memory_entry);

    // CPU with fixed % suffix
    let cpu_entry = adw::EntryRow::new();
    cpu_entry.set_title("CPU");
    cpu_entry.set_input_purpose(gtk::InputPurpose::Digits);
    setup_number_validation(&cpu_entry);
    cpu_entry.add_suffix(&cpu_suffix_label());
    limits_group.add(&cpu_entry);

    // I/O Read with unit dropdown
    let io_read_entry = adw::EntryRow::new();
    io_read_entry.set_title("I/O Read");
    io_read_entry.set_input_purpose(gtk::InputPurpose::Number);
    setup_size_validation(&io_read_entry);
    let io_read_unit = create_io_unit_dropdown();
    io_read_entry.add_suffix(&io_read_unit);
    limits_group.add(&io_read_entry);

    // I/O Write with unit dropdown
    let io_write_entry = adw::EntryRow::new();
    io_write_entry.set_title("I/O Write");
    io_write_entry.set_input_purpose(gtk::InputPurpose::Number);
    setup_size_validation(&io_write_entry);
    let io_write_unit = create_io_unit_dropdown();
    io_write_entry.add_suffix(&io_write_unit);
    limits_group.add(&io_write_entry);

    page.add(&limits_group);

    // Run button
    let run_btn = gtk::Button::with_label("Run Command");
    run_btn.add_css_class("suggested-action");
    run_btn.add_css_class("pill");
    run_btn.set_halign(gtk::Align::Center);
    require_manager(&run_btn, manager.is_some());

    // Store state
    let state = Rc::new(RefCell::new(RunState {
        command_entry: command_entry.clone(),
        memory_entry: memory_entry.clone(),
        memory_unit: memory_unit.clone(),
        cpu_entry: cpu_entry.clone(),
        io_read_entry: io_read_entry.clone(),
        io_read_unit: io_read_unit.clone(),
        io_write_entry: io_write_entry.clone(),
        io_write_unit: io_write_unit.clone(),
        status_label: status_label.clone(),
        toast_overlay: toast_overlay.clone(),
        app_list: app_list.clone(),
        manager: manager.clone(),
        all_apps: RefCell::new(Vec::new()),
        running_pid: RefCell::new(None),
        cgroup_name: RefCell::new(None),
        last_launch: Cell::new(None),
    }));

    // Load apps
    load_all_apps(&state);
    filter_apps(&state, "");

    // Refresh button handler
    let state_clone = state.clone();
    let search_entry_clone = search_entry.clone();
    refresh_btn.connect_clicked(move |_| {
        load_all_apps(&state_clone);
        filter_apps(&state_clone, search_entry_clone.text().as_str());
    });

    // Search handler with length limit
    let state_clone = state.clone();
    search_entry.connect_search_changed(move |entry| {
        let text = entry.text();
        if text.chars().count() > MAX_SEARCH_LEN {
            // Cut on a character boundary; a byte slice panics inside a
            // multibyte character.
            let cut: String = text.chars().take(MAX_SEARCH_LEN).collect();
            entry.set_text(&cut);
            return;
        }
        filter_apps(&state_clone, text.as_str());
    });

    // Profile selection handler
    let state_clone = state.clone();
    profile_dropdown.connect_selected_notify(move |dropdown| {
        if REFRESHING_PROFILES.with(Cell::get) {
            return;
        }
        apply_profile(&state_clone, selected_profile(dropdown).as_deref());
    });

    // Run button handler
    let state_clone = state.clone();
    run_btn.connect_clicked(move |_| {
        run_command(&state_clone);
    });

    // Editing the command away from the picked app's drops the highlight.
    let app_list_clone = app_list.clone();
    command_entry.connect_changed(move |entry| {
        let picked = app_list_clone
            .selected_row()
            .and_downcast::<adw::ActionRow>()
            .and_then(|row| row.subtitle());
        let text = glib::markup_escape_text(&entry.text());
        if picked.is_some_and(|sub| sub != text) {
            app_list_clone.unselect_all();
        }
    });

    // Enter in a field does what the button does.
    let state_clone = state.clone();
    on_enter(
        &[
            &command_entry,
            &memory_entry,
            &cpu_entry,
            &io_read_entry,
            &io_write_entry,
        ],
        move || run_command(&state_clone),
    );

    // Toasts show over the page, above the action bar, never covering it.
    toast_overlay.set_child(Some(&page));
    with_action_bar(&toast_overlay, &status_label, &run_btn).upcast()
}

fn load_profile_names() -> Vec<String> {
    let mut names = vec!["(None)".to_string()];
    if let Ok(config) = common::Config::load() {
        names.extend(config.profile_names());
    }
    names
}

fn load_all_apps(state: &Rc<RefCell<RunState>>) {
    if let Ok(apps) = rlm_core::desktop::list_applications() {
        state.borrow().all_apps.replace(apps);
    }
}

fn filter_apps(state: &Rc<RefCell<RunState>>, query: &str) {
    let state_ref = state.borrow();
    let list = &state_ref.app_list;

    // Clear existing rows
    while let Some(child) = list.first_child() {
        list.remove(&child);
    }

    let apps = state_ref.all_apps.borrow();
    let query_lower = query.to_lowercase();

    // Get desktop apps
    let mut filtered: Vec<_> = if query.is_empty() {
        apps.iter().take(50).cloned().collect()
    } else {
        apps.iter()
            .filter(|app| app.name.to_lowercase().contains(&query_lower))
            .take(50)
            .cloned()
            .collect()
    };

    // Add CLI apps from PATH when searching
    if !query.is_empty() {
        let cli_apps = rlm_core::desktop::search_cli_apps(query);
        for cli_app in cli_apps {
            if !filtered.iter().any(|a| a.exec == cli_app.exec) {
                filtered.push(cli_app);
            }
        }
    }

    if filtered.is_empty() {
        let row = adw::ActionRow::new();
        row.set_title(if query.is_empty() {
            "No applications found"
        } else {
            "No matching applications"
        });
        row.set_selectable(false);
        list.append(&row);
    } else {
        for app in filtered {
            let row = adw::ActionRow::new();
            row.set_title(&glib::markup_escape_text(&app.name));
            row.set_subtitle(&glib::markup_escape_text(&app.exec));
            row.set_activatable(true);

            let exec = app.exec.clone();
            let command_entry = state_ref.command_entry.clone();
            row.connect_activated(move |_| {
                command_entry.set_text(&exec);
            });

            list.append(&row);
            if app.exec == state_ref.command_entry.text().as_str() {
                list.select_row(Some(&row));
            }
        }
    }
    fit_list_height(list);
}

/// The profile name a dropdown shows, or `None` for "(None)".
fn selected_profile(dropdown: &gtk::DropDown) -> Option<String> {
    if dropdown.selected() == 0 {
        return None;
    }
    dropdown
        .selected_item()
        .and_downcast::<gtk::StringObject>()
        .map(|s| s.string().to_string())
}

/// Fill the limit fields from a profile. Every field is cleared first, so
/// a limit the profile leaves unset does not keep an earlier profile's value.
fn apply_profile(state: &Rc<RefCell<RunState>>, name: Option<&str>) {
    let Some(name) = name else {
        return;
    };
    let Some(profile) = common::Config::load()
        .ok()
        .and_then(|config| config.get_profile(name))
    else {
        return;
    };
    let state = state.borrow();
    let unshown = fill_limits(
        (&state.memory_entry, &state.memory_unit),
        &state.cpu_entry,
        (&state.io_read_entry, &state.io_read_unit),
        (&state.io_write_entry, &state.io_write_unit),
        &profile,
    );
    match unshown_note(name, &unshown) {
        Some(note) => show_status(&state.status_label, &note, true),
        None => state.status_label.set_text(""),
    }
}

fn run_command(state: &Rc<RefCell<RunState>>) {
    let state = state.borrow();
    if too_soon(state.last_launch.get(), Instant::now()) {
        return;
    }

    let command_text = state.command_entry.text();
    if command_text.is_empty() {
        show_status(&state.status_label, "Enter a command", true);
        return;
    }

    let memory = size_value(&state.memory_entry, &state.memory_unit);
    let cpu = cpu_value(&state.cpu_entry);
    let io_read = size_value(&state.io_read_entry, &state.io_read_unit);
    let io_write = size_value(&state.io_write_entry, &state.io_write_unit);

    if memory.is_none() && cpu.is_none() && io_read.is_none() && io_write.is_none() {
        show_status(&state.status_label, "Set at least one limit", true);
        return;
    }

    let Some(ref manager) = state.manager else {
        show_status(&state.status_label, NO_MANAGER_HINT, true);
        return;
    };

    let limit = match form_limit(
        memory.as_deref(),
        cpu.as_deref(),
        io_read.as_deref(),
        io_write.as_deref(),
    ) {
        Ok(l) => l,
        Err(message) => {
            show_status(&state.status_label, &message, true);
            return;
        }
    };

    let parts = match split_command(&command_text) {
        Ok(parts) => parts,
        Err(message) => {
            show_status(&state.status_label, &message, true);
            return;
        }
    };
    let program = parts[0].as_str();
    let args = &parts[1..];

    let count = RUN_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let cgroup_name = format!("gtk-{}-{}", std::process::id(), count);

    let (cgroup_path, mut warnings) = match manager.prepare_cgroup(&cgroup_name, &limit) {
        Ok(p) => (p.path, p.warnings),
        Err(e) => {
            show_status(
                &state.status_label,
                &format!("Could not create the cgroup: {e}"),
                true,
            );
            return;
        }
    };

    // Place the child into the cgroup before it execs, so limits apply from its
    // first instruction (see CgroupManager::placement_command). add_to_cgroup
    // below remains as a fallback.
    let mut cmd = manager.placement_command(&cgroup_path, program);
    cmd.args(args);
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = manager.remove_if_empty(&cgroup_name);
            show_status(
                &state.status_label,
                &format!("Could not start the program: {e}"),
                true,
            );
            return;
        }
    };

    let pid = child.id();
    state.last_launch.set(Some(Instant::now()));

    // Pre-exec placement already ran; add_to_cgroup here is only a fallback.
    // A failure does not mean the child is unlimited or unreaped, so it
    // becomes a warning rather than a cleanup-and-return.
    if let Err(e) = manager.add_to_cgroup(&cgroup_path, pid) {
        warnings.push(format!("failed to apply limits: {e}"));
    }

    *state.running_pid.borrow_mut() = Some(pid);
    *state.cgroup_name.borrow_mut() = Some(cgroup_name.clone());

    // Show success toast; non-fatal warnings (e.g. I/O limits) go in the label.
    if warnings.is_empty() {
        state.status_label.set_text("");
    } else {
        show_status(
            &state.status_label,
            &format!("Warning: {}", warnings.join("; ")),
            true,
        );
    }
    let toast = status_toast(&format!("Started {} (PID {})", program, pid), 5);
    state.toast_overlay.add_toast(toast);

    // Monitor process exit. glib reaps the child here; std must not wait on it.
    drop(child);
    let manager_clone = manager.clone();
    let toast_overlay = state.toast_overlay.clone();
    let name = cgroup_name.clone();
    glib::child_watch_add_local(glib::Pid(pid as i32), move |_, raw| {
        use std::os::unix::process::ExitStatusExt;
        let status = std::process::ExitStatus::from_raw(raw);
        let oom = manager_clone.oom_kills(&name).unwrap_or(0);
        let (_, mut lines) = rlm_core::exit::exit_report(
            status.code(),
            status.signal(),
            oom,
            manager_clone.memory_max(&name),
        );
        if manager_clone.is_populated(&name) == Some(true) {
            lines.push(format!(
                "The launcher exited; {} process(es) keep running with limits in {name}",
                manager_clone.pids_in_cgroup(&name).len()
            ));
        }
        if !cleanup_once(&manager_clone, &name) {
            // Remove the cgroup once the processes the launcher left behind
            // have exited too, so it does not linger empty.
            schedule_cleanup(manager_clone.clone(), name.clone());
        }
        let text = if lines.is_empty() {
            format!("Process {pid} exited")
        } else {
            lines.join("\n")
        };
        let toast = super::plain_toast(&text);
        toast.set_timeout(5);
        toast_overlay.add_toast(toast);
    });
}

/// Split a command line like a shell does (quotes group words), without
/// running a shell. Always at least one word on success.
fn split_command(text: &str) -> Result<Vec<String>, String> {
    if text.trim().is_empty() {
        return Err("Enter a command".into());
    }
    let argv = glib::shell_parse_argv(text)
        .map_err(|e| format!("Could not read the command: {}", e.message()))?;
    let parts: Vec<String> = argv
        .into_iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    if parts.is_empty() {
        return Err("Enter a command".into());
    }
    Ok(parts)
}

/// What the post-exit cleanup does with a launched app's cgroup on one poll.
#[derive(Debug, PartialEq, Eq)]
enum CleanupStep {
    /// The cgroup directory is gone: stop polling.
    Done,
    /// Processes are still in it: poll again later.
    Wait,
    /// It looks empty, or `cgroup.events` could not be read: try to remove
    /// it, and poll again if that fails.
    TryRemove,
}

fn cleanup_step(exists: bool, populated: Option<bool>) -> CleanupStep {
    match (exists, populated) {
        (false, _) => CleanupStep::Done,
        (true, Some(true)) => CleanupStep::Wait,
        (true, _) => CleanupStep::TryRemove,
    }
}

/// One cleanup poll for cgroup `name`; true when there is nothing left to do.
/// An unreadable `populated` state no longer ends the polling while the
/// directory still exists.
fn cleanup_once(manager: &CgroupManager, name: &str) -> bool {
    match cleanup_step(manager.cgroup_exists(name), manager.is_populated(name)) {
        CleanupStep::Done => true,
        CleanupStep::Wait => false,
        CleanupStep::TryRemove => matches!(manager.remove_if_empty(name), Ok(true)),
    }
}

/// Poll every 5 s and remove cgroup `name` once it is empty. Keeps polling
/// while the directory exists, even if cgroup.events is unreadable, and gives
/// up after a minute of failed removals (e.g. a child cgroup or a permission
/// error) instead of retrying forever.
pub(super) fn schedule_cleanup(manager: Arc<CgroupManager>, name: String) {
    let mut failed_removals = 0u32;
    glib::timeout_add_seconds_local(5, move || {
        match cleanup_step(manager.cgroup_exists(&name), manager.is_populated(&name)) {
            CleanupStep::Done => glib::ControlFlow::Break,
            CleanupStep::Wait => glib::ControlFlow::Continue,
            CleanupStep::TryRemove => {
                if matches!(manager.remove_if_empty(&name), Ok(true)) {
                    return glib::ControlFlow::Break;
                }
                failed_removals += 1;
                if failed_removals >= 12 {
                    glib::ControlFlow::Break
                } else {
                    glib::ControlFlow::Continue
                }
            }
        }
    });
}

/// Whether `cgroup` holds a launched command (`gtk-*` from Launch New,
/// `run-*` from `rlm run`), which nothing but a cleanup poll removes once
/// it empties.
pub(super) fn is_launch_cgroup(cgroup: &str) -> bool {
    cgroup.starts_with("gtk-") || cgroup.starts_with("run-")
}

fn show_status(label: &gtk::Label, message: &str, is_error: bool) {
    label.set_text(message);
    label.remove_css_class("success");
    label.remove_css_class("error");
    if is_error {
        label.add_css_class("error");
    } else {
        label.add_css_class("success");
    }
}

fn setup_command_validation(entry: &adw::EntryRow) {
    entry.connect_changed(move |e| {
        let text = e.text();
        if text.chars().count() > MAX_COMMAND_LEN {
            // Cut on a character boundary; a byte slice panics inside a
            // multibyte character.
            let cut: String = text.chars().take(MAX_COMMAND_LEN).collect();
            e.set_text(&cut);
        }
        // Visual feedback for empty command
        if text.trim().is_empty() && !text.is_empty() {
            e.add_css_class("error");
        } else {
            e.remove_css_class("error");
        }
    });
}

/// Refresh the profile dropdown
pub fn refresh_profiles(widget: &gtk::Widget) {
    if let Some(dropdown) = find_widget_by_name(widget, "run-profile-dropdown") {
        if let Some(dropdown) = dropdown.downcast_ref::<gtk::DropDown>() {
            let profiles = load_profile_names();
            let current = selected_profile(dropdown);
            let unchanged = dropdown.model().is_some_and(|m| {
                m.n_items() as usize == profiles.len()
                    && profiles.iter().enumerate().all(|(i, name)| {
                        m.item(i as u32)
                            .and_downcast::<gtk::StringObject>()
                            .is_some_and(|s| s.string() == name.as_str())
                    })
            });
            if unchanged {
                return;
            }
            let profile_list =
                gtk::StringList::new(&profiles.iter().map(|s| s.as_str()).collect::<Vec<_>>());
            // Keep the chosen profile selected while it still exists,
            // without filling the limits in again: the user may have edited
            // them since choosing it.
            let keep = current
                .and_then(|c| profiles.iter().position(|p| *p == c))
                .unwrap_or(0);
            REFRESHING_PROFILES.with(|f| f.set(true));
            dropdown.set_model(Some(&profile_list));
            dropdown.set_selected(keep as u32);
            REFRESHING_PROFILES.with(|f| f.set(false));
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_split_like_a_shell() {
        assert_eq!(
            split_command("'/opt/My App/app' --flag").unwrap(),
            ["/opt/My App/app", "--flag"]
        );
        assert_eq!(
            split_command(r#"sh -c "echo hi; sleep 1""#).unwrap(),
            ["sh", "-c", "echo hi; sleep 1"]
        );
        assert_eq!(split_command("  ").unwrap_err(), "Enter a command");
        assert!(split_command("app 'open").is_err());
    }

    #[test]
    fn a_held_enter_launches_once() {
        let t = Instant::now();
        assert!(!too_soon(None, t));
        assert!(too_soon(Some(t), t + Duration::from_millis(30)));
        assert!(too_soon(Some(t), t + Duration::from_millis(999)));
        assert!(!too_soon(Some(t), t + RELAUNCH_GAP));
    }

    #[test]
    fn cleanup_keeps_polling_while_the_cgroup_exists() {
        assert_eq!(cleanup_step(false, None), CleanupStep::Done);
        assert_eq!(cleanup_step(false, Some(true)), CleanupStep::Done);
        assert_eq!(cleanup_step(true, Some(true)), CleanupStep::Wait);
        assert_eq!(cleanup_step(true, Some(false)), CleanupStep::TryRemove);
        assert_eq!(cleanup_step(true, None), CleanupStep::TryRemove);
    }

    #[test]
    fn only_launch_cgroups_need_the_cleanup_poll() {
        assert!(is_launch_cgroup("gtk-123-0"));
        assert!(is_launch_cgroup("run-45-2"));
        assert!(!is_launch_cgroup("app-firefox"));
        assert!(!is_launch_cgroup("pid-42"));
        assert!(!is_launch_cgroup("multi-7"));
    }
}

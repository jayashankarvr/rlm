use crate::widgets::{
    create_unit_dropdown, get_unit_suffix, parse_cpu_value, set_value_with_unit,
    setup_number_validation,
};
use adw::prelude::*;
use gtk::glib;
use rlm_core::CgroupManager;
use std::cell::RefCell;
use std::process::Command;
use std::rc::Rc;
use std::sync::Arc;

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
    profiles: RefCell<Vec<String>>,
    all_apps: RefCell<Vec<rlm_core::desktop::DesktopApp>>,
    running_pid: RefCell<Option<u32>>,
    cgroup_name: RefCell<Option<String>>,
}

static RUN_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn create(manager: Option<Arc<CgroupManager>>) -> gtk::Widget {
    let toast_overlay = adw::ToastOverlay::new();

    let page = adw::PreferencesPage::new();
    page.set_title("Run");
    page.set_icon_name(Some("media-playback-start-symbolic"));

    // Main heading group
    let header_group = adw::PreferencesGroup::new();
    header_group.set_title("Launch New Process");
    header_group.set_description(Some("Start an application with resource limits"));
    page.add(&header_group);

    // Status label
    let status_label = gtk::Label::new(None);
    status_label.set_margin_top(12);
    status_label.set_margin_bottom(12);
    status_label.set_wrap(true);

    // Command group
    let command_group = adw::PreferencesGroup::new();
    command_group.set_title("Command");

    let command_entry = adw::EntryRow::new();
    command_entry.set_title("Command");
    setup_command_validation(&command_entry);
    command_group.add(&command_entry);

    page.add(&command_group);

    // App search group
    let apps_group = adw::PreferencesGroup::new();
    apps_group.set_title("Applications");

    // Refresh button in header
    let refresh_btn = gtk::Button::from_icon_name("view-refresh-symbolic");
    refresh_btn.add_css_class("flat");
    refresh_btn.set_tooltip_text(Some("Refresh application list"));
    apps_group.set_header_suffix(Some(&refresh_btn));

    // Search entry
    let search_entry = gtk::SearchEntry::new();
    search_entry.set_placeholder_text(Some("Type to search applications..."));
    search_entry.set_margin_bottom(12);
    apps_group.add(&search_entry);

    // App list
    let app_list = gtk::ListBox::new();
    app_list.set_selection_mode(gtk::SelectionMode::None);
    app_list.add_css_class("boxed-list");

    let scroll = gtk::ScrolledWindow::new();
    scroll.set_child(Some(&app_list));
    scroll.set_min_content_height(150);
    scroll.set_max_content_height(200);

    apps_group.add(&scroll);
    page.add(&apps_group);

    // Profile selection group
    let profile_group = adw::PreferencesGroup::new();
    profile_group.set_title("Quick Apply");
    profile_group.set_description(Some("Use a saved profile"));

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
    limits_group.set_title("Manual Limits");
    limits_group.set_description(Some("Override or set limits manually"));

    // Memory with unit dropdown
    let memory_entry = adw::EntryRow::new();
    memory_entry.set_title("Memory Limit");
    memory_entry.set_input_purpose(gtk::InputPurpose::Digits);
    setup_number_validation(&memory_entry);
    let memory_unit = create_unit_dropdown();
    memory_unit.set_selected(1); // Default to MB
    memory_entry.add_suffix(&memory_unit);
    limits_group.add(&memory_entry);

    // CPU with fixed % suffix
    let cpu_entry = adw::EntryRow::new();
    cpu_entry.set_title("CPU Limit");
    cpu_entry.set_input_purpose(gtk::InputPurpose::Digits);
    setup_number_validation(&cpu_entry);
    let cpu_suffix = gtk::Label::new(Some("%"));
    cpu_suffix.add_css_class("dim-label");
    cpu_suffix.set_margin_start(4);
    cpu_entry.add_suffix(&cpu_suffix);
    limits_group.add(&cpu_entry);

    // I/O Read with unit dropdown
    let io_read_entry = adw::EntryRow::new();
    io_read_entry.set_title("I/O Read Limit");
    io_read_entry.set_input_purpose(gtk::InputPurpose::Digits);
    setup_number_validation(&io_read_entry);
    let io_read_unit = create_unit_dropdown();
    io_read_unit.set_selected(1); // Default to MB
    io_read_entry.add_suffix(&io_read_unit);
    limits_group.add(&io_read_entry);

    // I/O Write with unit dropdown
    let io_write_entry = adw::EntryRow::new();
    io_write_entry.set_title("I/O Write Limit");
    io_write_entry.set_input_purpose(gtk::InputPurpose::Digits);
    setup_number_validation(&io_write_entry);
    let io_write_unit = create_unit_dropdown();
    io_write_unit.set_selected(1); // Default to MB
    io_write_entry.add_suffix(&io_write_unit);
    limits_group.add(&io_write_entry);

    page.add(&limits_group);

    // Run button
    let run_btn = gtk::Button::with_label("Run Command");
    run_btn.add_css_class("suggested-action");
    run_btn.add_css_class("pill");
    run_btn.set_halign(gtk::Align::Center);
    run_btn.set_margin_top(24);
    run_btn.set_margin_bottom(24);

    let button_box = gtk::Box::new(gtk::Orientation::Vertical, 12);
    button_box.append(&status_label);
    button_box.append(&run_btn);

    let button_group = adw::PreferencesGroup::new();
    button_group.add(&button_box);
    page.add(&button_group);

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
        profiles: RefCell::new(profiles),
        all_apps: RefCell::new(Vec::new()),
        running_pid: RefCell::new(None),
        cgroup_name: RefCell::new(None),
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
        if text.len() > MAX_SEARCH_LEN {
            entry.set_text(&text[..MAX_SEARCH_LEN]);
            return;
        }
        filter_apps(&state_clone, text.as_str());
    });

    // Profile selection handler
    let state_clone = state.clone();
    profile_dropdown.connect_selected_notify(move |dropdown| {
        apply_profile(&state_clone, dropdown.selected() as usize);
    });

    // Run button handler
    let state_clone = state.clone();
    run_btn.connect_clicked(move |_| {
        run_command(&state_clone);
    });

    toast_overlay.set_child(Some(&page));
    toast_overlay.upcast()
}

fn load_profile_names() -> Vec<String> {
    let mut names = vec!["(None)".to_string()];
    if let Ok(config) = common::Config::load() {
        names.extend(config.all_profiles().keys().cloned());
    }
    names.sort();
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
        apps.iter().cloned().take(50).collect()
    } else {
        apps.iter()
            .filter(|app| app.name.to_lowercase().contains(&query_lower))
            .cloned()
            .take(50)
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
        }
    }
}

fn apply_profile(state: &Rc<RefCell<RunState>>, index: usize) {
    let state = state.borrow();
    let profiles = state.profiles.borrow();

    if index == 0 || index >= profiles.len() {
        return;
    }

    let profile_name = &profiles[index];
    if let Ok(config) = common::Config::load() {
        if let Some(profile) = config.get_profile(profile_name) {
            if let Some(ref mem) = profile.memory {
                set_value_with_unit(&state.memory_entry, &state.memory_unit, mem);
            }
            if let Some(ref cpu) = profile.cpu {
                state.cpu_entry.set_text(&parse_cpu_value(cpu));
            }
            if let Some(ref ior) = profile.io_read {
                set_value_with_unit(&state.io_read_entry, &state.io_read_unit, ior);
            }
            if let Some(ref iow) = profile.io_write {
                set_value_with_unit(&state.io_write_entry, &state.io_write_unit, iow);
            }
        }
    }
}

fn run_command(state: &Rc<RefCell<RunState>>) {
    let state = state.borrow();

    let command_text = state.command_entry.text();
    if command_text.is_empty() {
        show_status(&state.status_label, "Error: Enter a command", true);
        return;
    }

    let memory_val = state.memory_entry.text();
    let cpu_val = state.cpu_entry.text();
    let io_read_val = state.io_read_entry.text();
    let io_write_val = state.io_write_entry.text();

    if memory_val.is_empty()
        && cpu_val.is_empty()
        && io_read_val.is_empty()
        && io_write_val.is_empty()
    {
        show_status(
            &state.status_label,
            "Error: Specify at least one limit",
            true,
        );
        return;
    }

    let Some(ref manager) = state.manager else {
        show_status(
            &state.status_label,
            "Error: Cgroup manager not available",
            true,
        );
        return;
    };

    // Build limit values with units
    let memory = if memory_val.is_empty() {
        None
    } else {
        Some(format!(
            "{}{}",
            memory_val,
            get_unit_suffix(&state.memory_unit)
        ))
    };
    let cpu = if cpu_val.is_empty() {
        None
    } else {
        Some(format!("{}%", cpu_val))
    };
    let io_read = if io_read_val.is_empty() {
        None
    } else {
        Some(format!(
            "{}{}",
            io_read_val,
            get_unit_suffix(&state.io_read_unit)
        ))
    };
    let io_write = if io_write_val.is_empty() {
        None
    } else {
        Some(format!(
            "{}{}",
            io_write_val,
            get_unit_suffix(&state.io_write_unit)
        ))
    };

    let limit = match common::build_limit(
        memory.as_deref(),
        cpu.as_deref(),
        io_read.as_deref(),
        io_write.as_deref(),
    ) {
        Ok(l) => l,
        Err(e) => {
            show_status(&state.status_label, &format!("Error: {e}"), true);
            return;
        }
    };

    let parts: Vec<&str> = command_text.split_whitespace().collect();
    if parts.is_empty() {
        show_status(&state.status_label, "Error: Invalid command", true);
        return;
    }

    let program = parts[0];
    let args = &parts[1..];

    let count = RUN_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let cgroup_name = format!("gtk-{}-{}", std::process::id(), count);

    let cgroup_path = match manager.prepare_cgroup(&cgroup_name, &limit) {
        Ok(p) => p,
        Err(e) => {
            show_status(
                &state.status_label,
                &format!("Error creating cgroup: {e}"),
                true,
            );
            return;
        }
    };

    let child = match Command::new(program).args(args).spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = manager.cleanup_cgroup(&cgroup_name);
            show_status(&state.status_label, &format!("Error spawning: {e}"), true);
            return;
        }
    };

    let pid = child.id();

    if let Err(e) = manager.add_to_cgroup(&cgroup_path, pid) {
        let _ = manager.cleanup_cgroup(&cgroup_name);
        show_status(
            &state.status_label,
            &format!("Error adding to cgroup: {e}"),
            true,
        );
        return;
    }

    *state.running_pid.borrow_mut() = Some(pid);
    *state.cgroup_name.borrow_mut() = Some(cgroup_name.clone());

    // Show success toast
    state.status_label.set_text("");
    let toast = adw::Toast::new(&format!("Started {} (PID {})", program, pid));
    toast.set_timeout(3);
    state.toast_overlay.add_toast(toast);

    // Monitor process exit
    let manager_clone = manager.clone();
    let toast_overlay = state.toast_overlay.clone();
    glib::timeout_add_local(std::time::Duration::from_millis(500), move || {
        let proc_path = format!("/proc/{pid}");
        if !std::path::Path::new(&proc_path).exists() {
            let _ = manager_clone.cleanup_cgroup(&cgroup_name);
            let toast = adw::Toast::new(&format!("Process {} exited", pid));
            toast.set_timeout(2);
            toast_overlay.add_toast(toast);
            return glib::ControlFlow::Break;
        }
        glib::ControlFlow::Continue
    });
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
        if text.len() > MAX_COMMAND_LEN {
            e.set_text(&text[..MAX_COMMAND_LEN]);
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
            let profile_list =
                gtk::StringList::new(&profiles.iter().map(|s| s.as_str()).collect::<Vec<_>>());
            dropdown.set_model(Some(&profile_list));
            dropdown.set_selected(0);
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

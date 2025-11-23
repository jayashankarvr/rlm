use crate::widgets::{create_unit_dropdown, get_unit_suffix, setup_number_validation};
use adw::prelude::*;
use rlm_core::CgroupManager;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

// Field length limits
const MAX_PID_LEN: usize = 10;

struct LimitState {
    pid_entry: adw::EntryRow,
    memory_entry: adw::EntryRow,
    memory_unit: gtk::DropDown,
    cpu_entry: adw::EntryRow,
    io_read_entry: adw::EntryRow,
    io_read_unit: gtk::DropDown,
    io_write_entry: adw::EntryRow,
    io_write_unit: gtk::DropDown,
    status_label: gtk::Label,
    toast_overlay: adw::ToastOverlay,
    process_list: gtk::ListBox,
    manager: Option<Arc<CgroupManager>>,
    all_processes: RefCell<Vec<rlm_core::process::ProcessInfo>>,
    profiles: RefCell<Vec<String>>,
}

pub fn create(manager: Option<Arc<CgroupManager>>) -> gtk::Widget {
    let toast_overlay = adw::ToastOverlay::new();

    let page = adw::PreferencesPage::new();
    page.set_title("Limit");
    page.set_icon_name(Some("speedometer-symbolic"));

    // Status label for feedback
    let status_label = gtk::Label::new(None);
    status_label.set_margin_top(12);
    status_label.set_margin_bottom(12);
    status_label.set_wrap(true);

    // Target process group
    let target_group = adw::PreferencesGroup::new();
    target_group.set_title("Target Process");
    target_group.set_description(Some("Enter PID or search below"));

    let pid_entry = adw::EntryRow::new();
    pid_entry.set_title("Process ID");
    pid_entry.set_input_purpose(gtk::InputPurpose::Digits);
    setup_pid_validation(&pid_entry);
    target_group.add(&pid_entry);

    page.add(&target_group);

    // Process search group
    let search_group = adw::PreferencesGroup::new();
    search_group.set_title("Find Process");

    // Refresh button in header
    let refresh_btn = gtk::Button::from_icon_name("view-refresh-symbolic");
    refresh_btn.add_css_class("flat");
    refresh_btn.set_tooltip_text(Some("Refresh process list"));
    search_group.set_header_suffix(Some(&refresh_btn));

    let search_entry = gtk::SearchEntry::new();
    search_entry.set_placeholder_text(Some("Type to search by name or PID..."));
    search_entry.set_margin_bottom(12);
    search_group.add(&search_entry);

    let process_list = gtk::ListBox::new();
    process_list.set_selection_mode(gtk::SelectionMode::None);
    process_list.add_css_class("boxed-list");

    let scroll = gtk::ScrolledWindow::new();
    scroll.set_child(Some(&process_list));
    scroll.set_min_content_height(180);
    scroll.set_max_content_height(200);

    search_group.add(&scroll);
    page.add(&search_group);

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

    let profile_row = adw::ActionRow::new();
    profile_row.set_title("Profile");
    profile_row.add_suffix(&profile_dropdown);
    profile_group.add(&profile_row);

    page.add(&profile_group);

    // Limits group
    let limits_group = adw::PreferencesGroup::new();
    limits_group.set_title("Custom Limits");
    limits_group.set_description(Some("Or set manually"));

    // Memory with unit dropdown
    let memory_entry = adw::EntryRow::new();
    memory_entry.set_title("Memory");
    memory_entry.set_input_purpose(gtk::InputPurpose::Digits);
    setup_number_validation(&memory_entry);
    let memory_unit = create_unit_dropdown();
    memory_unit.set_selected(1); // Default to MB
    memory_entry.add_suffix(&memory_unit);
    limits_group.add(&memory_entry);

    // CPU with fixed % suffix
    let cpu_entry = adw::EntryRow::new();
    cpu_entry.set_title("CPU");
    cpu_entry.set_input_purpose(gtk::InputPurpose::Digits);
    setup_number_validation(&cpu_entry);
    let cpu_suffix = gtk::Label::new(Some("%"));
    cpu_suffix.add_css_class("dim-label");
    cpu_suffix.set_margin_start(4);
    cpu_entry.add_suffix(&cpu_suffix);
    limits_group.add(&cpu_entry);

    // I/O Read with unit dropdown
    let io_read_entry = adw::EntryRow::new();
    io_read_entry.set_title("I/O Read");
    io_read_entry.set_input_purpose(gtk::InputPurpose::Digits);
    setup_number_validation(&io_read_entry);
    let io_read_unit = create_unit_dropdown();
    io_read_unit.set_selected(1); // Default to MB
    io_read_entry.add_suffix(&io_read_unit);
    limits_group.add(&io_read_entry);

    // I/O Write with unit dropdown
    let io_write_entry = adw::EntryRow::new();
    io_write_entry.set_title("I/O Write");
    io_write_entry.set_input_purpose(gtk::InputPurpose::Digits);
    setup_number_validation(&io_write_entry);
    let io_write_unit = create_unit_dropdown();
    io_write_unit.set_selected(1); // Default to MB
    io_write_entry.add_suffix(&io_write_unit);
    limits_group.add(&io_write_entry);

    page.add(&limits_group);

    // Apply button
    let apply_btn = gtk::Button::with_label("Apply Limits");
    apply_btn.add_css_class("suggested-action");
    apply_btn.add_css_class("pill");
    apply_btn.set_halign(gtk::Align::Center);
    apply_btn.set_margin_top(24);
    apply_btn.set_margin_bottom(24);

    let button_box = gtk::Box::new(gtk::Orientation::Vertical, 12);
    button_box.append(&status_label);
    button_box.append(&apply_btn);

    let button_group = adw::PreferencesGroup::new();
    button_group.add(&button_box);
    page.add(&button_group);

    // Store state
    let state = Rc::new(RefCell::new(LimitState {
        pid_entry: pid_entry.clone(),
        memory_entry: memory_entry.clone(),
        memory_unit: memory_unit.clone(),
        cpu_entry: cpu_entry.clone(),
        io_read_entry: io_read_entry.clone(),
        io_read_unit: io_read_unit.clone(),
        io_write_entry: io_write_entry.clone(),
        io_write_unit: io_write_unit.clone(),
        status_label: status_label.clone(),
        toast_overlay: toast_overlay.clone(),
        process_list: process_list.clone(),
        manager: manager.clone(),
        all_processes: RefCell::new(Vec::new()),
        profiles: RefCell::new(profiles),
    }));

    // Load initial processes
    load_all_processes(&state);
    filter_processes(&state, "");

    // Refresh button handler
    let state_clone = state.clone();
    let search_entry_clone = search_entry.clone();
    refresh_btn.connect_clicked(move |_| {
        load_all_processes(&state_clone);
        filter_processes(&state_clone, search_entry_clone.text().as_str());
    });

    // Search handler with length limit
    let state_clone = state.clone();
    search_entry.connect_search_changed(move |entry| {
        let text = entry.text();
        // Limit search query length
        if text.len() > 100 {
            entry.set_text(&text[..100]);
            return;
        }
        filter_processes(&state_clone, text.as_str());
    });

    // Profile selection handler
    let state_clone = state.clone();
    profile_dropdown.connect_selected_notify(move |dropdown| {
        apply_profile(&state_clone, dropdown.selected() as usize);
    });

    // Apply button handler
    let state_clone = state.clone();
    apply_btn.connect_clicked(move |_| {
        apply_limits(&state_clone);
    });

    toast_overlay.set_child(Some(&page));
    toast_overlay.upcast()
}

fn setup_pid_validation(entry: &adw::EntryRow) {
    entry.connect_changed(move |e| {
        let text = e.text();
        if text.len() > MAX_PID_LEN {
            e.set_text(&text[..MAX_PID_LEN]);
            return;
        }
        // Only allow digits
        let filtered: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
        if filtered != text.as_str() {
            e.set_text(&filtered);
        }
        // Visual feedback
        if !text.is_empty() && text.parse::<u32>().is_err() {
            e.add_css_class("error");
        } else {
            e.remove_css_class("error");
        }
    });
}

fn load_profile_names() -> Vec<String> {
    let mut names = vec!["(None)".to_string()];
    if let Ok(config) = common::Config::load() {
        names.extend(config.all_profiles().keys().cloned());
    }
    names.sort();
    names
}

fn apply_profile(state: &Rc<RefCell<LimitState>>, index: usize) {
    let state = state.borrow();
    let profiles = state.profiles.borrow();

    if index == 0 || index >= profiles.len() {
        return;
    }

    let profile_name = &profiles[index];
    if let Ok(config) = common::Config::load() {
        if let Some(profile) = config.get_profile(profile_name) {
            if let Some(ref mem) = profile.memory {
                state.memory_entry.set_text(mem);
            }
            if let Some(ref cpu) = profile.cpu {
                state.cpu_entry.set_text(cpu);
            }
            if let Some(ref ior) = profile.io_read {
                state.io_read_entry.set_text(ior);
            }
            if let Some(ref iow) = profile.io_write {
                state.io_write_entry.set_text(iow);
            }
        }
    }
}

fn load_all_processes(state: &Rc<RefCell<LimitState>>) {
    if let Ok(processes) = rlm_core::process::list_all() {
        state.borrow().all_processes.replace(processes);
    }
}

fn filter_processes(state: &Rc<RefCell<LimitState>>, query: &str) {
    let state_ref = state.borrow();
    let list = &state_ref.process_list;

    while let Some(child) = list.first_child() {
        list.remove(&child);
    }

    let processes = state_ref.all_processes.borrow();
    let query_lower = query.to_lowercase();

    let filtered: Vec<_> = if query.is_empty() {
        processes.iter().take(50).collect()
    } else {
        // Allow searching by PID or name
        let query_pid: Option<u32> = query.parse().ok();
        processes
            .iter()
            .filter(|p| p.name.to_lowercase().contains(&query_lower) || query_pid == Some(p.pid))
            .take(50)
            .collect()
    };

    if filtered.is_empty() {
        let row = adw::ActionRow::new();
        row.set_title(if query.is_empty() {
            "No processes found"
        } else {
            "No matching processes"
        });
        list.append(&row);
    } else {
        for proc in filtered {
            let row = adw::ActionRow::new();
            row.set_title(&proc.name);
            row.set_subtitle(&format!("PID: {}", proc.pid));
            row.set_activatable(true);

            let pid = proc.pid;
            let pid_entry = state_ref.pid_entry.clone();
            row.connect_activated(move |_| {
                pid_entry.set_text(&pid.to_string());
            });

            list.append(&row);
        }
    }
}

fn apply_limits(state: &Rc<RefCell<LimitState>>) {
    let state = state.borrow();

    let pid_text = state.pid_entry.text();
    let memory_val = state.memory_entry.text();
    let cpu_val = state.cpu_entry.text();
    let io_read_val = state.io_read_entry.text();
    let io_write_val = state.io_write_entry.text();

    // Validate PID
    if pid_text.is_empty() {
        show_status(&state.status_label, "Enter a PID first", true);
        return;
    }

    let pid: u32 = match pid_text.parse() {
        Ok(p) if p > 0 => p,
        _ => {
            show_status(
                &state.status_label,
                "Invalid PID (must be positive number)",
                true,
            );
            return;
        }
    };

    // Check at least one limit is set
    if memory_val.is_empty()
        && cpu_val.is_empty()
        && io_read_val.is_empty()
        && io_write_val.is_empty()
    {
        show_status(&state.status_label, "Set at least one limit", true);
        return;
    }

    let Some(ref manager) = state.manager else {
        show_status(&state.status_label, "Cgroup manager unavailable", true);
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
            show_status(&state.status_label, &format!("{e}"), true);
            return;
        }
    };

    match manager.apply_limit(pid, &limit) {
        Ok(()) => {
            state.status_label.set_text("");
            let toast = adw::Toast::new(&format!("Limits applied to PID {pid}"));
            toast.set_timeout(3);
            state.toast_overlay.add_toast(toast);
        }
        Err(e) => show_status(&state.status_label, &format!("{e}"), true),
    }
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

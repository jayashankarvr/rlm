use crate::widgets::{
    create_unit_dropdown, get_unit_suffix, parse_cpu_value, set_value_with_unit,
    setup_number_validation,
};
use adw::prelude::*;
use gtk::glib;
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
    limit_mode: RefCell<LimitMode>, // Individual or Application
    selected_pids: RefCell<Vec<u32>>, // For multi-select in application mode
}

#[derive(Clone, Copy, PartialEq)]
enum LimitMode {
    Individual,
    Application,
}

pub fn create(manager: Option<Arc<CgroupManager>>) -> gtk::Widget {
    let toast_overlay = adw::ToastOverlay::new();

    let page = adw::PreferencesPage::new();
    page.set_title("Limit");
    page.set_icon_name(Some("speedometer-symbolic"));

    // Main heading group
    let header_group = adw::PreferencesGroup::new();
    header_group.set_title("Limit Running Process");
    header_group.set_description(Some("Apply resource limits to a running process"));
    page.add(&header_group);

    // Status label for feedback
    let status_label = gtk::Label::new(None);
    status_label.set_margin_top(12);
    status_label.set_margin_bottom(12);
    status_label.set_wrap(true);

    // Limit mode selection
    let mode_group = adw::PreferencesGroup::new();
    mode_group.set_title("Limit Mode");

    let mode_row = adw::ComboRow::new();
    mode_row.set_title("Mode");
    mode_row.set_subtitle("Individual: each process gets its own limit. Application: all processes share limits");
    
    let mode_list = gtk::StringList::new(&["Individual", "Application (Shared)"]);
    mode_row.set_model(Some(&mode_list));
    mode_row.set_selected(0);
    mode_group.add(&mode_row);

    page.add(&mode_group);

    // Target process group
    let target_group = adw::PreferencesGroup::new();
    target_group.set_title("Target Process");

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

    // Mode info label
    let mode_info_label = gtk::Label::new(None);
    mode_info_label.add_css_class("dim-label");
    mode_info_label.set_margin_bottom(6);
    mode_info_label.set_wrap(true);
    search_group.add(&mode_info_label);

    let search_entry = gtk::SearchEntry::new();
    search_entry.set_placeholder_text(Some("Type to search by name or PID..."));
    search_entry.set_margin_bottom(12);
    search_group.add(&search_entry);

    let process_list = gtk::ListBox::new();
    process_list.set_selection_mode(gtk::SelectionMode::Multiple); // Allow multi-select
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
    profile_dropdown.set_widget_name("limit-profile-dropdown");

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
        limit_mode: RefCell::new(LimitMode::Individual),
        selected_pids: RefCell::new(Vec::new()),
    }));

    // Load initial processes
    load_all_processes(&state);
    filter_processes(&state, "");

    // Mode change handler
    let state_clone = state.clone();
    let mode_info_label_clone = mode_info_label.clone();
    let search_entry_clone = search_entry.clone();
    mode_row.connect_selected_notify(move |row| {
        let mode = if row.selected() == 0 {
            LimitMode::Individual
        } else {
            LimitMode::Application
        };
        state_clone.borrow().limit_mode.replace(mode);
        update_mode_info(&mode_info_label_clone, mode);
        filter_processes(&state_clone, search_entry_clone.text().as_str());
    });
    update_mode_info(&mode_info_label, LimitMode::Individual);

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

    // Process list selection handler (for application mode)
    let state_clone = state.clone();
    let pid_entry_clone = pid_entry.clone();
    process_list.connect_selected_rows_changed(move |list| {
        let state = state_clone.borrow();
        if *state.limit_mode.borrow() == LimitMode::Application {
            // Collect PIDs from selected rows (including nested rows in expanders)
            let mut selected_pids = Vec::new();
            for row in list.selected_rows() {
                // Check if it's a direct process row
                if let Some(pid_str) = row.widget_name().strip_prefix("proc-") {
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        selected_pids.push(pid);
                    }
                }
                // Check nested rows in expander rows
                if let Some(expander) = row.downcast_ref::<adw::ExpanderRow>() {
                    let mut child = expander.first_child();
                    while let Some(c) = child {
                        if let Some(proc_row) = c.downcast_ref::<adw::ActionRow>() {
                            if let Some(pid_str) = proc_row.widget_name().strip_prefix("proc-") {
                                if let Ok(pid) = pid_str.parse::<u32>() {
                                    selected_pids.push(pid);
                                }
                            }
                        }
                        child = c.next_sibling();
                    }
                }
            }
            
            state.selected_pids.replace(selected_pids.clone());
            
            // Update PID entry with comma-separated list
            if !selected_pids.is_empty() {
                let pids_str = selected_pids.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
                pid_entry_clone.set_text(&pids_str);
            } else {
                pid_entry_clone.set_text("");
            }
        }
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

fn load_all_processes(state: &Rc<RefCell<LimitState>>) {
    if let Ok(processes) = rlm_core::process::list_all() {
        state.borrow().all_processes.replace(processes);
    }
}

fn update_mode_info(label: &gtk::Label, mode: LimitMode) {
    match mode {
        LimitMode::Individual => {
            label.set_text("Select a single process. Each process gets its own limits.");
        }
        LimitMode::Application => {
            label.set_text("Select multiple processes. All selected processes will share the same limits (combined pool).");
        }
    }
}

fn filter_processes(state: &Rc<RefCell<LimitState>>, query: &str) {
    let state_ref = state.borrow();
    let list = &state_ref.process_list;
    let mode = *state_ref.limit_mode.borrow();

    while let Some(child) = list.first_child() {
        list.remove(&child);
    }

    let processes = state_ref.all_processes.borrow();
    let query_lower = query.to_lowercase();

    if mode == LimitMode::Application {
        // Group processes by executable
        let groups = rlm_core::process::group_by_executable(&processes);
        
        let filtered_groups: Vec<_> = if query.is_empty() {
            groups.iter().take(20).collect()
        } else {
            groups
                .iter()
                .filter(|g| g.name.to_lowercase().contains(&query_lower))
                .take(20)
                .collect()
        };

        if filtered_groups.is_empty() {
            let row = adw::ActionRow::new();
            row.set_title(if query.is_empty() {
                "No application groups found"
            } else {
                "No matching applications"
            });
            list.append(&row);
        } else {
            for group in filtered_groups {
                let row = adw::ExpanderRow::new();
                row.set_title(&glib::markup_escape_text(&group.name));
                row.set_subtitle(&format!("{} process(es)", group.processes.len()));
                row.set_widget_name(&format!("group-{}", group.name.replace('/', "_")));

                // Add "Select All" button
                let select_all_btn = gtk::Button::with_label("Select All");
                select_all_btn.add_css_class("flat");
                select_all_btn.add_css_class("suggested-action");
                
                let group_pids: Vec<u32> = group.processes.iter().map(|p| p.pid).collect();
                let state_clone = state.clone();
                let list_clone = list.clone();
                let pid_entry_clone = state_ref.pid_entry.clone();
                select_all_btn.connect_clicked(move |_| {
                    // Select all processes in this group
                    state_clone.borrow().selected_pids.replace(group_pids.clone());
                    let pids_str = group_pids.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
                    pid_entry_clone.set_text(&pids_str);
                    
                    // Update list selection (visual feedback)
                    let mut child = list_clone.first_child();
                    while let Some(c) = child {
                        if let Some(row) = c.downcast_ref::<adw::ActionRow>() {
                            if let Some(pid_str) = row.widget_name().strip_prefix("proc-") {
                                if let Ok(pid) = pid_str.parse::<u32>() {
                                    if group_pids.contains(&pid) {
                                        list_clone.select_row(Some(row));
                                    }
                                }
                            }
                        }
                        child = c.next_sibling();
                    }
                });
                row.add_suffix(&select_all_btn);

                // List individual processes in the group
                for proc in &group.processes {
                    let proc_row = adw::ActionRow::new();
                    proc_row.set_title(&glib::markup_escape_text(&proc.name));
                    proc_row.set_subtitle(&format!("PID: {}", proc.pid));
                    proc_row.set_widget_name(&format!("proc-{}", proc.pid));
                    row.add_row(&proc_row);
                }

                list.append(&row);
            }
        }
    } else {
        // Individual mode - show processes as before
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
                row.set_title(&glib::markup_escape_text(&proc.name));
                row.set_subtitle(&format!("PID: {}", proc.pid));
                row.set_activatable(true);
                row.set_widget_name(&format!("proc-{}", proc.pid));

                let pid = proc.pid;
                let pid_entry = state_ref.pid_entry.clone();
                row.connect_activated(move |_| {
                    pid_entry.set_text(&pid.to_string());
                });

                list.append(&row);
            }
        }
    }
}

fn apply_limits(state: &Rc<RefCell<LimitState>>) {
    let state = state.borrow();
    let mode = *state.limit_mode.borrow();

    let pid_text = state.pid_entry.text();
    let memory_val = state.memory_entry.text();
    let cpu_val = state.cpu_entry.text();
    let io_read_val = state.io_read_entry.text();
    let io_write_val = state.io_write_entry.text();

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

    match mode {
        LimitMode::Application => {
            // Application mode - shared limits
            if pid_text.is_empty() {
                show_status(&state.status_label, "Select processes first", true);
                return;
            }

            // Parse comma-separated PIDs or use selected PIDs
            let pids: Vec<u32> = if !pid_text.contains(',') {
                // Single PID or use selected
                if let Ok(pid) = pid_text.parse::<u32>() {
                    vec![pid]
                } else {
                    state.selected_pids.borrow().clone()
                }
            } else {
                // Comma-separated PIDs
                pid_text
                    .split(',')
                    .filter_map(|s| s.trim().parse::<u32>().ok())
                    .collect()
            };

            if pids.is_empty() {
                show_status(&state.status_label, "No valid PIDs selected", true);
                return;
            }

            // Generate cgroup name from first process or application name
            let cgroup_name = if pids.len() == 1 {
                format!("pid-{}", pids[0])
            } else {
                // Try to get application name from first process
                let app_name = state
                    .all_processes
                    .borrow()
                    .iter()
                    .find(|p| p.pid == pids[0])
                    .and_then(|p| {
                        p.executable
                            .as_ref()
                            .and_then(|e| e.file_name())
                            .and_then(|n| n.to_str())
                            .map(String::from)
                    })
                    .unwrap_or_else(|| format!("multi-{}", pids[0]));
                format!("app-{}", app_name.replace(['/', ' '], "_"))
            };

            match manager.apply_limit_to_multiple(&pids, &limit, &cgroup_name) {
                Ok(()) => {
                    state.status_label.set_text("");
                    let msg = if pids.len() == 1 {
                        format!("Limits applied to PID {}", pids[0])
                    } else {
                        format!("Shared limits applied to {} process(es)", pids.len())
                    };
                    let toast = adw::Toast::new(&msg);
                    toast.set_timeout(3);
                    state.toast_overlay.add_toast(toast);
                }
                Err(e) => show_status(&state.status_label, &format!("{e}"), true),
            }
        }
        LimitMode::Individual => {
            // Individual mode - separate limits per process
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

/// Refresh the profile dropdown
pub fn refresh_profiles(widget: &gtk::Widget) {
    if let Some(dropdown) = find_widget_by_name(widget, "limit-profile-dropdown") {
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

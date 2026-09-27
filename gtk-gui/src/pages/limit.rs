use crate::widgets::{
    cpu_suffix_label, create_io_unit_dropdown, create_unit_dropdown, get_unit_suffix,
    limits_description, parse_cpu_value, set_value_with_unit, setup_number_validation,
    setup_size_validation,
};
use adw::prelude::*;
use gtk::glib;
use rlm_core::CgroupManager;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

// Field length limits
/// Longest text the PID field keeps: room for a few hundred PIDs when an
/// application is selected, which fills the field with a comma-separated list.
const MAX_PID_LEN: usize = 65536;

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
    limit_mode: RefCell<LimitMode>, // Individual or Application
    /// PIDs of each application row in Application mode, keyed by the row's
    /// widget name, so selecting a row can fill in all of its processes.
    group_pids: RefCell<std::collections::HashMap<String, Vec<u32>>>,
    /// Set while filter_processes rebuilds the list, so the selection
    /// changes that causes do not rewrite the PID field.
    rebuilding: std::cell::Cell<bool>,
    /// Each application row's Select button, keyed like `group_pids`. An
    /// expander row draws no selection highlight, so the button shows it.
    group_buttons: RefCell<std::collections::HashMap<String, gtk::Button>>,
    save_rule_check: gtk::CheckButton, // Persist as a rule (application mode only)
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
    page.set_icon_name(Some("power-profile-balanced-symbolic"));

    // Main heading group
    let header_group = adw::PreferencesGroup::new();
    header_group.set_title("Limit Running Process");
    header_group.set_description(Some("Limit processes that are already running. Limits last until you remove them or the processes exit."));
    page.add(&header_group);

    // Status label for feedback
    let status_label = gtk::Label::new(None);
    status_label.set_wrap(true);
    // Only take up room when there is a message; an empty label would push
    // the button further down the page.
    status_label.set_visible(false);
    status_label.connect_label_notify(|l| l.set_visible(!l.label().is_empty()));

    // Limit mode selection
    let mode_group = adw::PreferencesGroup::new();
    mode_group.set_title("Limit Mode");
    mode_group.set_description(Some(
        "Individual limits one process. Application puts several processes under one shared limit.",
    ));

    let mode_row = adw::ComboRow::new();
    mode_row.set_title("Mode");
    // No subtitle: a long one squeezes the selected value down to "A...".
    // The group description and the hint under Find Process explain the modes.

    let mode_list = gtk::StringList::new(&["Individual", "Application (Shared)"]);
    mode_row.set_model(Some(&mode_list));
    mode_row.set_selected(0);
    mode_group.add(&mode_row);

    page.add(&mode_group);

    // Target process group
    let target_group = adw::PreferencesGroup::new();
    target_group.set_title("Target Process");
    target_group.set_description(Some("Type a PID, or pick from the list below"));

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
    // Individual mode selects one row; filter_processes switches this per mode.
    process_list.set_selection_mode(gtk::SelectionMode::Single);
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
    profile_group.set_description(Some("Choosing a profile fills in the limits below"));

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

    // Persist-as-rule toggle (only meaningful in application mode; hidden otherwise)
    let save_rule_check = gtk::CheckButton::with_label("Also save as a rule for rlm-guard");
    save_rule_check.set_halign(gtk::Align::Center);
    save_rule_check.set_visible(false);

    // Apply button
    let apply_btn = gtk::Button::with_label("Apply Limits");
    apply_btn.add_css_class("suggested-action");
    apply_btn.add_css_class("pill");
    apply_btn.set_halign(gtk::Align::Center);
    apply_btn.set_margin_bottom(24);

    let button_box = gtk::Box::new(gtk::Orientation::Vertical, 12);
    button_box.append(&status_label);
    button_box.append(&save_rule_check);
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
        limit_mode: RefCell::new(LimitMode::Individual),
        group_pids: RefCell::new(std::collections::HashMap::new()),
        rebuilding: std::cell::Cell::new(false),
        group_buttons: RefCell::new(std::collections::HashMap::new()),
        save_rule_check: save_rule_check.clone(),
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
        // A PID list from Application mode means nothing in Individual mode
        // (and the reverse), so start each mode with an empty selection.
        state_clone.borrow().pid_entry.set_text("");
        update_mode_info(&mode_info_label_clone, mode);
        // The "save as rule" toggle only applies to application (shared) mode.
        state_clone
            .borrow()
            .save_rule_check
            .set_visible(mode == LimitMode::Application);
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
        if text.chars().count() > 100 {
            // Cut on a character boundary; a byte slice panics inside a
            // multibyte character.
            let cut: String = text.chars().take(100).collect();
            entry.set_text(&cut);
            return;
        }
        filter_processes(&state_clone, text.as_str());
    });

    // The PID field mirrors the list selection. Individual mode: the one
    // selected process. Application mode: every process of every selected
    // application.
    let state_clone = state.clone();
    let pid_entry_clone = pid_entry.clone();
    process_list.connect_selected_rows_changed(move |list| {
        let state = state_clone.borrow();
        if state.rebuilding.get() {
            return;
        }
        let mode = *state.limit_mode.borrow();
        let groups = state.group_pids.borrow();
        let mut pids = Vec::new();
        for row in list.selected_rows() {
            let name = row.widget_name();
            match mode {
                LimitMode::Individual => {
                    if let Some(pid) = name
                        .strip_prefix("proc-")
                        .and_then(|p| p.parse::<u32>().ok())
                    {
                        pids.push(pid);
                    }
                }
                LimitMode::Application => {
                    if let Some(group) = groups.get(name.as_str()) {
                        pids.extend(group);
                    }
                }
            }
        }
        let text = pids
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        pid_entry_clone.set_text(&text);
        drop(groups);
        sync_group_buttons(&state, list);
    });

    // Profile selection handler
    let state_clone = state.clone();
    profile_dropdown.connect_selected_notify(move |dropdown| {
        apply_profile(&state_clone, selected_profile(dropdown).as_deref());
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
        let cleaned = clean_pid_input(&text);
        if cleaned != text.as_str() {
            e.set_text(&cleaned);
            return;
        }
        // Visual feedback
        if !text.is_empty() && parse_pid_list(&text).is_none() {
            e.add_css_class("error");
        } else {
            e.remove_css_class("error");
        }
    });
}

/// Keep only what a PID or a comma-separated PID list can contain (digits,
/// commas and spaces), capped at [`MAX_PID_LEN`]. Commas must survive:
/// selecting an application writes its PIDs as "2894,52896", and dropping
/// the comma would turn that into the single PID 289452896. A cap cuts at
/// the last comma, never inside a number, for the same reason.
fn clean_pid_input(text: &str) -> String {
    let kept: String = text
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == ',' || *c == ' ')
        .collect();
    if kept.len() <= MAX_PID_LEN {
        return kept;
    }
    let cut = &kept[..MAX_PID_LEN];
    match cut.rfind(',') {
        Some(i) => cut[..i].to_string(),
        None => cut.to_string(),
    }
}

/// Parse "123" or "123, 456" into PIDs. `None` if any entry is not a
/// positive number; empty entries (a trailing comma) are ignored.
fn parse_pid_list(text: &str) -> Option<Vec<u32>> {
    let mut pids = Vec::new();
    for part in text.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        match part.parse::<u32>() {
            Ok(pid) if pid > 0 => pids.push(pid),
            _ => return None,
        }
    }
    Some(pids)
}

fn load_profile_names() -> Vec<String> {
    let mut names = vec!["(None)".to_string()];
    if let Ok(config) = common::Config::load() {
        names.extend(config.profile_names());
    }
    names
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
fn apply_profile(state: &Rc<RefCell<LimitState>>, name: Option<&str>) {
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
    let fill = |entry: &adw::EntryRow, unit: &gtk::DropDown, value: &Option<String>| {
        entry.set_text("");
        if let Some(value) = value {
            set_value_with_unit(entry, unit, value);
        }
    };
    fill(&state.memory_entry, &state.memory_unit, &profile.memory);
    state.cpu_entry.set_text(
        &profile
            .cpu
            .as_deref()
            .map(parse_cpu_value)
            .unwrap_or_default(),
    );
    fill(&state.io_read_entry, &state.io_read_unit, &profile.io_read);
    fill(
        &state.io_write_entry,
        &state.io_write_unit,
        &profile.io_write,
    );
}

fn load_all_processes(state: &Rc<RefCell<LimitState>>) {
    let uid = rlm_core::process::current_uid();
    let processes = if uid == 0 {
        rlm_core::process::list_all()
    } else {
        rlm_core::process::list_for_uid(uid)
    };
    if let Ok(processes) = processes {
        let protect = common::protect_set(
            &common::Config::load()
                .map(|c| c.guard.selection.protect)
                .unwrap_or_default(),
        );
        let processes: Vec<_> = processes
            .into_iter()
            .filter(|p| !common::is_protected(&protect, &p.name, p.exe_name()))
            .collect();
        state.borrow().all_processes.replace(processes);
    }
}

fn update_mode_info(label: &gtk::Label, mode: LimitMode) {
    match mode {
        LimitMode::Individual => {
            label.set_text("Select one process. It gets its own limits.");
        }
        LimitMode::Application => {
            label.set_text("Select an application or several processes. They share one set of limits: 4G for 10 processes is 4G in total.");
        }
    }
}

fn filter_processes(state: &Rc<RefCell<LimitState>>, query: &str) {
    let state_ref = state.borrow();
    let list = &state_ref.process_list;
    let mode = *state_ref.limit_mode.borrow();

    state_ref.rebuilding.set(true);
    while let Some(child) = list.first_child() {
        list.remove(&child);
    }
    list.set_selection_mode(match mode {
        LimitMode::Individual => gtk::SelectionMode::Single,
        LimitMode::Application => gtk::SelectionMode::Multiple,
    });
    // Rebuilt below; cleared after the rows are gone so the selection
    // handler never reads it while it is borrowed mutably.
    state_ref.group_pids.borrow_mut().clear();
    state_ref.group_buttons.borrow_mut().clear();

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
                let row_name = format!("group-{}", group.name.replace('/', "_"));
                row.set_widget_name(&row_name);
                state_ref
                    .group_pids
                    .borrow_mut()
                    .insert(row_name, group.processes.iter().map(|p| p.pid).collect());

                // Selects or deselects the whole application; the selection
                // handler then fills the PID field with all of its processes.
                let select_all_btn = gtk::Button::with_label("Select");
                select_all_btn.set_valign(gtk::Align::Center);
                let list_clone = list.clone();
                let row_clone = row.clone();
                select_all_btn.connect_clicked(move |_| {
                    if row_clone.is_selected() {
                        list_clone.unselect_row(&row_clone);
                    } else {
                        list_clone.select_row(Some(&row_clone));
                    }
                });
                state_ref
                    .group_buttons
                    .borrow_mut()
                    .insert(row.widget_name().to_string(), select_all_btn.clone());
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
                .filter(|p| {
                    p.name.to_lowercase().contains(&query_lower) || query_pid == Some(p.pid)
                })
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

                list.append(&row);
            }
        }
    }

    // Keep the PID field as it was and highlight the rows that match it.
    let wanted: Vec<u32> = parse_pid_list(&state_ref.pid_entry.text()).unwrap_or_default();
    if !wanted.is_empty() {
        let groups = state_ref.group_pids.borrow();
        let mut child = list.first_child();
        while let Some(c) = child {
            if let Some(row) = c.downcast_ref::<gtk::ListBoxRow>() {
                let name = row.widget_name();
                let matches = match mode {
                    LimitMode::Individual => name
                        .strip_prefix("proc-")
                        .and_then(|p| p.parse::<u32>().ok())
                        .is_some_and(|pid| wanted.contains(&pid)),
                    LimitMode::Application => groups
                        .get(name.as_str())
                        .is_some_and(|g| g.iter().all(|pid| wanted.contains(pid))),
                };
                if matches {
                    list.select_row(Some(row));
                }
            }
            child = c.next_sibling();
        }
    }
    sync_group_buttons(&state_ref, list);
    state_ref.rebuilding.set(false);
}

/// Show each application row's selection on its button: "Selected" in the
/// accent colour, or a plain "Select".
fn sync_group_buttons(state: &LimitState, list: &gtk::ListBox) {
    for (name, btn) in state.group_buttons.borrow().iter() {
        let selected = list
            .selected_rows()
            .iter()
            .any(|r| r.widget_name().as_str() == name);
        btn.set_label(if selected { "Selected" } else { "Select" });
        if selected {
            btn.add_css_class("suggested-action");
        } else {
            btn.remove_css_class("suggested-action");
        }
    }
}

/// The shared executable basename of all `pids`, or `None` if they don't all
/// resolve to the same executable. Used to gate saving a persistent rule so its
/// `match_exe` is meaningful.
fn common_exe_basename(procs: &[rlm_core::process::ProcessInfo], pids: &[u32]) -> Option<String> {
    let mut found: Option<String> = None;
    for pid in pids {
        let p = procs.iter().find(|p| p.pid == *pid)?;
        let base = p
            .executable
            .as_ref()
            .and_then(|e| e.file_name())
            .and_then(|n| n.to_str())
            .map(String::from)
            .unwrap_or_else(|| p.name.clone());
        match &found {
            None => found = Some(base),
            Some(prev) if *prev != base => return None,
            _ => {}
        }
    }
    found
}

/// Persist an application limit as a rule in the user config, keyed by exe name.
/// Stores the unit-qualified limit strings (a snapshot), matching the CLI
/// `--save` behavior.
fn save_app_rule(
    app_name: &str,
    memory: Option<String>,
    cpu: Option<String>,
    io_read: Option<String>,
    io_write: Option<String>,
) -> common::Result<()> {
    let mut config = common::Config::load()?;
    config.add_rule(
        app_name,
        common::AppRule {
            match_exe: vec![app_name.to_string()],
            memory,
            cpu,
            io_read,
            io_write,
        },
    );
    config.save()
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
        show_status(
            &state.status_label,
            "Cannot set up cgroups for your user. Run rlm doctor in a terminal to see why.",
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

            // The field holds one PID or the selected application's list.
            let pids: Vec<u32> = match parse_pid_list(&pid_text) {
                Some(pids) => pids,
                None => {
                    show_status(
                        &state.status_label,
                        "Invalid PID list (use numbers separated by commas)",
                        true,
                    );
                    return;
                }
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
                Ok(warnings) => {
                    show_warnings(&state.status_label, &warnings);
                    let mut msg = if pids.len() == 1 {
                        format!("Limits applied to PID {}", pids[0])
                    } else {
                        format!("Shared limits applied to {} process(es)", pids.len())
                    };

                    // Persist as a rule if requested. A rule matches by executable
                    // basename, so only save when every selected PID is the same
                    // app, otherwise the saved match_exe would be misleading.
                    if state.save_rule_check.is_active() {
                        match common_exe_basename(&state.all_processes.borrow(), &pids) {
                            Some(exe) => match save_app_rule(
                                &exe,
                                memory.clone(),
                                cpu.clone(),
                                io_read.clone(),
                                io_write.clone(),
                            ) {
                                Ok(()) => {
                                    // rlm-guard reads rules at startup, so say how to
                                    // load the new one, as `rlm limit --save` does.
                                    let active =
                                        rlm_core::guard::service::query().active == "active";
                                    msg.push_str(&format!(
                                        "; saved rule '{exe}' ({})",
                                        if active {
                                            "restart the guard to load it"
                                        } else {
                                            "turn the guard on to enforce it"
                                        }
                                    ))
                                }
                                Err(e) => msg.push_str(&format!("; could not save rule: {e}")),
                            },
                            None => msg.push_str(
                                "; (rule not saved: select instances of a single application)",
                            ),
                        }
                    }

                    let toast = adw::Toast::new(&msg);
                    toast.set_timeout(6);
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

            let pid: u32 = match pid_text.trim().parse() {
                Ok(p) if p > 0 => p,
                _ => {
                    let several = pid_text.trim().contains([',', ' ']);
                    show_status(
                        &state.status_label,
                        if several {
                            "Individual mode takes one PID; to limit several processes together, switch to Application mode"
                        } else {
                            "Enter a positive PID"
                        },
                        true,
                    );
                    return;
                }
            };

            match manager.apply_limit(pid, &limit) {
                Ok(warnings) => {
                    show_warnings(&state.status_label, &warnings);
                    let toast = adw::Toast::new(&format!("Limits applied to PID {pid}"));
                    toast.set_timeout(3);
                    state.toast_overlay.add_toast(toast);
                }
                Err(e) => show_status(&state.status_label, &format!("{e}"), true),
            }
        }
    }
}

/// Clear the status label, or show non-fatal warnings from a limit call.
fn show_warnings(label: &gtk::Label, warnings: &[String]) {
    if warnings.is_empty() {
        label.set_text("");
    } else {
        show_status(label, &format!("Warning: {}", warnings.join("; ")), true);
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
            dropdown.set_model(Some(&profile_list));
            // Keep the chosen profile selected while it still exists.
            let keep = current
                .and_then(|c| profiles.iter().position(|p| *p == c))
                .unwrap_or(0);
            dropdown.set_selected(keep as u32);
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
    fn application_pid_list_keeps_its_commas() {
        assert_eq!(clean_pid_input("2894,52896"), "2894,52896");
        assert_eq!(clean_pid_input("12a, 3-4"), "12, 34");
        assert_eq!(parse_pid_list("2894,52896"), Some(vec![2894, 52896]));
        assert_eq!(parse_pid_list(" 7 , 8,"), Some(vec![7, 8]));
        assert_eq!(parse_pid_list(""), Some(vec![]));
        assert_eq!(parse_pid_list("0"), None);
        assert_eq!(parse_pid_list("99999999999"), None);
    }

    #[test]
    fn long_application_lists_are_not_cut_to_one_pid() {
        let list = (1000..1300)
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(clean_pid_input(&list), list);
        assert_eq!(parse_pid_list(&list).map(|p| p.len()), Some(300));
    }

    #[test]
    fn capping_a_huge_list_never_splits_a_pid() {
        let list = (100_000..120_000)
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let kept = clean_pid_input(&list);
        assert!(kept.len() <= MAX_PID_LEN);
        let pids = parse_pid_list(&kept).unwrap();
        assert!(pids.iter().all(|p| (100_000..120_000).contains(p)));
    }
}

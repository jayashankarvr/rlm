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
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Instant;

// Field length limits
/// Longest text the PID field keeps: room for a few hundred PIDs when an
/// application is selected, which fills the field with a comma-separated list.
const MAX_PID_LEN: usize = 65536;

/// Rows the list shows at most, per mode; a search finds the rest.
const MAX_APP_ROWS: usize = 30;
const MAX_PROCESS_ROWS: usize = 50;

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
    /// "Showing N of M" under the list when it is capped.
    cap_label: gtk::Label,
    manager: Option<Arc<CgroupManager>>,
    all_processes: RefCell<Vec<rlm_core::process::ProcessInfo>>,
    /// Each listed PID's start time when it was listed, so applying can
    /// skip a process that has exited (or whose PID was reused) since.
    start_times: RefCell<HashMap<u32, u64>>,
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
    /// Persist as a rule (whole-app mode only)
    save_rule_switch: adw::SwitchRow,
    summary_label: gtk::Label,
    /// When limits were last applied. Holding Enter in a field repeats the
    /// activation, so applies closer together than a second are ignored, as
    /// Launch New does for launches.
    last_apply: Cell<Option<Instant>>,
}

#[derive(Clone, Copy, PartialEq)]
enum LimitMode {
    Individual,
    Application,
}

thread_local! {
    /// Set while [`refresh_profiles`] replaces the profile list, so the
    /// selection changes that causes do not refill the limit fields.
    static REFRESHING_PROFILES: Cell<bool> = const { Cell::new(false) };
}

pub fn create(manager: Option<Arc<CgroupManager>>) -> gtk::Widget {
    let toast_overlay = adw::ToastOverlay::new();

    let page = adw::PreferencesPage::new();
    page.set_title("Limit");
    page.set_icon_name(Some("power-profile-balanced-symbolic"));

    // Main heading group
    let header_group = adw::PreferencesGroup::new();
    header_group.set_title("Limit Running Process");
    header_group.set_description(Some(
        "Limit processes that are already running. Limits last until you remove them or the processes exit. \
         Memory a process already uses is not counted, only what it allocates from now on; \
         to cap an app's whole memory, start it from Launch New.",
    ));
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
        "Whole app puts every process of the selected apps under one shared limit. \
         Single process limits one process on its own.",
    ));

    let mode_row = adw::ComboRow::new();
    mode_row.set_title("Mode");
    // No subtitle: a long one squeezes the selected value down to "W...".
    // The group description and the hint under Target explain the modes.

    // Order matches mode_for_index.
    let mode_list = gtk::StringList::new(&["Whole app", "Single process"]);
    mode_row.set_model(Some(&mode_list));
    mode_row.set_selected(0);
    mode_group.add(&mode_row);

    page.add(&mode_group);

    // Target: search, what is selected, then the list
    let search_group = adw::PreferencesGroup::new();
    search_group.set_title("Target");

    // Refresh button in header
    let refresh_btn = icon_button("view-refresh-symbolic", "Refresh process list");
    search_group.set_header_suffix(Some(&refresh_btn));

    // Mode info label
    let mode_info_label = gtk::Label::new(None);
    mode_info_label.add_css_class("dim-label");
    mode_info_label.set_margin_bottom(6);
    mode_info_label.set_wrap(true);
    mode_info_label.set_xalign(0.0);
    search_group.add(&mode_info_label);

    let search_entry = gtk::SearchEntry::new();
    search_entry.set_placeholder_text(Some("Type to search by name or PID..."));
    search_entry.set_margin_bottom(12);
    search_group.add(&search_entry);

    // What the limits will apply to, e.g. "2 apps selected, 8 processes"
    let summary_label = gtk::Label::new(None);
    summary_label.add_css_class("heading");
    summary_label.set_xalign(0.0);
    summary_label.set_wrap(true);
    summary_label.set_margin_bottom(6);
    search_group.add(&summary_label);

    let process_list = gtk::ListBox::new();
    // filter_processes sets single or multiple selection per mode.
    process_list.set_selection_mode(gtk::SelectionMode::Multiple);
    process_list.add_css_class("boxed-list");

    let scroll = list_scroller(&process_list);

    search_group.add(&scroll);

    let cap_label = gtk::Label::new(None);
    cap_label.add_css_class("dim-label");
    cap_label.set_margin_top(6);
    cap_label.set_visible(false);
    search_group.add(&cap_label);
    page.add(&search_group);

    // Manual PID entry, tucked below the list. It mirrors the list
    // selection, and typing in it is the way to reach a process the list
    // does not show.
    let manual_group = adw::PreferencesGroup::new();
    let manual_row = adw::ExpanderRow::new();
    manual_row.set_title("Enter PIDs manually");
    manual_row.set_subtitle("Process IDs, separated by commas");

    let pid_entry = adw::EntryRow::new();
    pid_entry.set_title("Process ID");
    pid_entry.set_input_purpose(gtk::InputPurpose::Digits);
    setup_pid_validation(&pid_entry);
    manual_row.add_row(&pid_entry);
    manual_group.add(&manual_row);
    page.add(&manual_group);

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

    // Persist as a rule; only whole-app limits can be saved, so it is
    // hidden in single-process mode.
    let save_rule_switch = adw::SwitchRow::new();
    save_rule_switch.set_title("Save as a rule for rlm-guard");
    save_rule_switch
        .set_subtitle("rlm-guard then applies these limits to future instances of the app");
    limits_group.add(&save_rule_switch);

    page.add(&limits_group);

    // Apply button
    let apply_btn = gtk::Button::with_label("Apply Limits");
    apply_btn.add_css_class("suggested-action");
    apply_btn.add_css_class("pill");
    apply_btn.set_halign(gtk::Align::Center);
    require_manager(&apply_btn, manager.is_some());

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
        cap_label: cap_label.clone(),
        manager: manager.clone(),
        all_processes: RefCell::new(Vec::new()),
        start_times: RefCell::new(HashMap::new()),
        limit_mode: RefCell::new(LimitMode::Application),
        group_pids: RefCell::new(std::collections::HashMap::new()),
        rebuilding: std::cell::Cell::new(false),
        group_buttons: RefCell::new(std::collections::HashMap::new()),
        save_rule_switch: save_rule_switch.clone(),
        summary_label: summary_label.clone(),
        last_apply: Cell::new(None),
    }));

    // Load initial processes
    load_all_processes(&state);
    filter_processes(&state, "");

    // Mode change handler
    let state_clone = state.clone();
    let mode_info_label_clone = mode_info_label.clone();
    let search_entry_clone = search_entry.clone();
    mode_row.connect_selected_notify(move |row| {
        let mode = mode_for_index(row.selected());
        state_clone.borrow().limit_mode.replace(mode);
        // A PID list from Application mode means nothing in Individual mode
        // (and the reverse), so start each mode with an empty selection.
        state_clone.borrow().pid_entry.set_text("");
        update_mode_info(&mode_info_label_clone, mode);
        // The "save as rule" switch only applies to whole-app mode.
        state_clone
            .borrow()
            .save_rule_switch
            .set_visible(mode == LimitMode::Application);
        filter_processes(&state_clone, search_entry_clone.text().as_str());
    });
    update_mode_info(&mode_info_label, LimitMode::Application);

    // The summary follows the PID field, which mirrors the list selection.
    let state_clone = state.clone();
    pid_entry.connect_changed(move |_| {
        update_summary(&state_clone.borrow());
    });
    update_summary(&state.borrow());

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
        if REFRESHING_PROFILES.with(Cell::get) {
            return;
        }
        apply_profile(&state_clone, selected_profile(dropdown).as_deref());
    });

    // Apply button handler
    let state_clone = state.clone();
    apply_btn.connect_clicked(move |_| {
        apply_limits(&state_clone);
    });

    // Enter in a field does what the button does.
    let state_clone = state.clone();
    on_enter(
        &[
            &pid_entry,
            &memory_entry,
            &cpu_entry,
            &io_read_entry,
            &io_write_entry,
        ],
        move || apply_limits(&state_clone),
    );

    // Toasts show over the page, above the action bar, never covering it.
    toast_overlay.set_child(Some(&page));
    let widget: gtk::Widget = with_action_bar(&toast_overlay, &status_label, &apply_btn).upcast();

    // Reload the list each time the page is shown (the window's stack maps
    // only the visible page), so it never offers processes from hours ago.
    // filter_processes keeps the PID field and highlights its rows again.
    let state_clone = state.clone();
    let search_entry_clone = search_entry.clone();
    widget.connect_map(move |_| {
        load_all_processes(&state_clone);
        filter_processes(&state_clone, search_entry_clone.text().as_str());
    });
    widget
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
        let mut processes: Vec<_> = processes
            .into_iter()
            .filter(|p| !common::is_protected(&protect, &p.name, p.exe_name()))
            .collect();
        // Biggest memory users first: those are the ones worth limiting.
        processes.sort_by(|a, b| b.rss_kb.cmp(&a.rss_kb).then_with(|| a.name.cmp(&b.name)));
        let fresh: HashMap<u32, u64> = processes
            .iter()
            .filter_map(|p| rlm_core::process::start_time(p.pid).map(|t| (p.pid, t)))
            .collect();
        let state = state.borrow();
        // The PID field survives a reload, so its PIDs keep the start time
        // they were chosen with; applying then skips any that changed.
        let keep = parse_pid_list(&state.pid_entry.text()).unwrap_or_default();
        let merged = merge_start_times(&state.start_times.borrow(), fresh, &keep);
        state.start_times.replace(merged);
        state.all_processes.replace(processes);
    }
}

/// Start times after a reload: `fresh` for every listed process, except
/// that a PID in `keep` (the PID field) holds on to the time it had in
/// `old`, so a process that exited while selected is not mistaken for a
/// new one that reused its PID.
fn merge_start_times(
    old: &HashMap<u32, u64>,
    mut fresh: HashMap<u32, u64>,
    keep: &[u32],
) -> HashMap<u32, u64> {
    for pid in keep {
        if let Some(t) = old.get(pid) {
            fresh.insert(*pid, *t);
        }
    }
    fresh
}

/// Split `pids` into those still worth limiting and a count of those that
/// have exited: a PID with a start time in `listed` counts only while
/// `now` gives the same time. PIDs never listed (typed by hand) are kept.
fn live_pids(
    pids: &[u32],
    listed: &HashMap<u32, u64>,
    now: impl Fn(u32) -> Option<u64>,
) -> (Vec<u32>, usize) {
    let mut kept = Vec::new();
    let mut gone = 0;
    for pid in pids {
        match listed.get(pid) {
            Some(t) if now(*pid) != Some(*t) => gone += 1,
            _ => kept.push(*pid),
        }
    }
    (kept, gone)
}

/// The error when every selected process has exited since the list loaded.
fn exited_error(gone: usize) -> &'static str {
    if gone == 1 {
        "The selected process has exited; nothing was limited"
    } else {
        "The selected processes have all exited; nothing was limited"
    }
}

/// "; 2 processes had exited and were skipped", or nothing when none were.
fn skipped_note(gone: usize) -> String {
    match gone {
        0 => String::new(),
        1 => "; 1 process had exited and was skipped".to_string(),
        n => format!("; {n} processes had exited and were skipped"),
    }
}

/// The mode a Mode row index stands for: whole app first, the default.
fn mode_for_index(index: u32) -> LimitMode {
    if index == 0 {
        LimitMode::Application
    } else {
        LimitMode::Individual
    }
}

/// Plural-aware "1 app" / "2 apps".
fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// What the limits will apply to, from the selected app rows and the PIDs
/// in the PID field.
fn selection_summary(mode: LimitMode, apps: usize, pids: &[u32]) -> String {
    match (mode, pids) {
        (LimitMode::Individual, []) => "No process selected".into(),
        (LimitMode::Individual, [pid]) => format!("PID {pid}"),
        (LimitMode::Individual, _) => format!(
            "{} entered; Single process mode takes one",
            count(pids.len(), "PID", "PIDs")
        ),
        (LimitMode::Application, []) => "No application selected".into(),
        (LimitMode::Application, _) if apps > 0 => format!(
            "{} selected, {}",
            count(apps, "app", "apps"),
            count(pids.len(), "process", "processes")
        ),
        (LimitMode::Application, _) => {
            format!("{} entered", count(pids.len(), "process", "processes"))
        }
    }
}

/// How many selected apps the PID field stands for: all of them while it
/// holds exactly their processes, none once it has been edited by hand, so
/// the summary then counts the field's processes instead of stale apps.
fn apps_in_field(selected: &[&[u32]], pids: &[u32]) -> usize {
    use std::collections::BTreeSet;
    let from_rows: BTreeSet<u32> = selected.iter().flat_map(|g| g.iter().copied()).collect();
    let in_field: BTreeSet<u32> = pids.iter().copied().collect();
    if !selected.is_empty() && from_rows == in_field {
        selected.len()
    } else {
        0
    }
}

fn update_summary(state: &LimitState) {
    let mode = *state.limit_mode.borrow();
    let pids = parse_pid_list(&state.pid_entry.text()).unwrap_or_default();
    let apps = match mode {
        LimitMode::Application => {
            let groups = state.group_pids.borrow();
            let selected: Vec<&[u32]> = state
                .process_list
                .selected_rows()
                .iter()
                .filter_map(|r| groups.get(r.widget_name().as_str()).map(Vec::as_slice))
                .collect();
            apps_in_field(&selected, &pids)
        }
        LimitMode::Individual => 0,
    };
    state
        .summary_label
        .set_text(&selection_summary(mode, apps, &pids));
}

fn update_mode_info(label: &gtk::Label, mode: LimitMode) {
    match mode {
        LimitMode::Individual => {
            label.set_text("Select one process. It gets its own limits.");
        }
        LimitMode::Application => {
            label.set_text("Select one or more applications. They share one set of limits: 4G for 10 processes is 4G in total.");
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
    let (total, shown);

    if mode == LimitMode::Application {
        // Group processes by executable
        let groups = rlm_core::process::group_by_executable(&processes);

        // Each group with its friendly name ("Google Chrome" for chrome).
        let matching: Vec<_> = groups
            .iter()
            .map(|g| {
                let comm = g.processes.first().map(|p| p.name.as_str());
                (g, rlm_core::appname::friendly_name(&g.name, comm))
            })
            .filter(|(g, app)| matches_query(&query_lower, &[app, &g.name]))
            .collect();
        total = matching.len();
        let filtered_groups: Vec<_> = matching.into_iter().take(MAX_APP_ROWS).collect();
        shown = filtered_groups.len();

        if filtered_groups.is_empty() {
            let row = adw::ActionRow::new();
            row.set_title(if query.is_empty() {
                "No applications found"
            } else {
                "No matching applications"
            });
            list.append(&row);
        } else {
            for (group, app) in filtered_groups {
                let row = adw::ExpanderRow::new();
                let count = group.processes.len();
                let detail = format!(
                    "{count} {}, {}",
                    if count == 1 { "process" } else { "processes" },
                    format_memory(group.rss_kb())
                );
                let (title, subtitle) = row_texts(&app, &group.name, &detail);
                row.set_title(&glib::markup_escape_text(&title));
                row.set_subtitle(&glib::markup_escape_text(&subtitle));
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
                    proc_row.set_subtitle(&format!(
                        "PID {}, {}",
                        proc.pid,
                        format_memory(proc.rss_kb)
                    ));
                    proc_row.set_widget_name(&format!("proc-{}", proc.pid));
                    row.add_row(&proc_row);
                }

                list.append(&row);
            }
        }
    } else {
        // Individual mode - show processes as before
        // Search by PID or name
        let query_pid: Option<u32> = query.parse().ok();
        let matching: Vec<_> = processes
            .iter()
            .map(|p| {
                let app = rlm_core::appname::friendly_name(p.display_name(), Some(&p.name));
                (p, app)
            })
            .filter(|(p, app)| {
                query_pid == Some(p.pid)
                    || matches_query(&query_lower, &[app, p.display_name(), &p.name])
            })
            .collect();
        total = matching.len();
        let filtered: Vec<_> = matching.into_iter().take(MAX_PROCESS_ROWS).collect();
        shown = filtered.len();

        if filtered.is_empty() {
            let row = adw::ActionRow::new();
            row.set_title(if query.is_empty() {
                "No processes found"
            } else {
                "No matching processes"
            });
            list.append(&row);
        } else {
            for (proc, app) in filtered {
                let row = adw::ActionRow::new();
                let detail = format!("PID {}, {}", proc.pid, format_memory(proc.rss_kb));
                let (title, subtitle) = row_texts(&app, proc.display_name(), &detail);
                row.set_title(&glib::markup_escape_text(&title));
                row.set_subtitle(&glib::markup_escape_text(&subtitle));
                row.set_activatable(true);
                row.set_widget_name(&format!("proc-{}", proc.pid));

                list.append(&row);
            }
        }
    }

    match cap_note(shown, total, !query.is_empty()) {
        Some(note) => {
            state_ref.cap_label.set_text(&note);
            state_ref.cap_label.set_visible(true);
        }
        None => state_ref.cap_label.set_visible(false),
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
    update_summary(&state_ref);
    fit_list_height(list);
}

/// Whether any of `names` contains `query_lower` (already lower-cased),
/// ignoring case. An empty query matches everything.
fn matches_query(query_lower: &str, names: &[&str]) -> bool {
    names.iter().any(|n| n.to_lowercase().contains(query_lower))
}

/// Title and subtitle of a row for the app called `app` whose program is
/// `program`: the friendly name as title, and the program name in front of
/// `detail` when it is not just the same name, so the program people know
/// from a terminal stays visible.
fn row_texts(app: &str, program: &str, detail: &str) -> (String, String) {
    let subtitle = if app.to_lowercase() == program.to_lowercase() {
        detail.to_string()
    } else {
        format!("{program}, {detail}")
    };
    (app.to_string(), subtitle)
}

/// Memory in KB as "900 KB", "512 MB" or "1.2 GB".
fn format_memory(kb: u64) -> String {
    const MB: u64 = 1024;
    const GB: u64 = 1024 * 1024;
    if kb >= GB {
        format!("{:.1} GB", kb as f64 / GB as f64)
    } else if kb >= MB {
        format!("{} MB", (kb + MB / 2) / MB)
    } else {
        format!("{kb} KB")
    }
}

/// The note under a capped list, or `None` when every match is shown.
fn cap_note(shown: usize, total: usize, searching: bool) -> Option<String> {
    (shown < total).then(|| {
        if searching {
            format!("Showing {shown} of {total} matches; type more to narrow the search")
        } else {
            format!("Showing {shown} of {total}; type to search")
        }
    })
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
    if super::run::too_soon(state.last_apply.get(), Instant::now()) {
        return;
    }
    let mode = *state.limit_mode.borrow();

    let pid_text = state.pid_entry.text();
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

    match mode {
        LimitMode::Application => {
            // Application mode - shared limits
            if pid_text.is_empty() {
                show_status(&state.status_label, "Select an application first", true);
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

            let (pids, gone) = live_pids(
                &pids,
                &state.start_times.borrow(),
                rlm_core::process::start_time,
            );
            if pids.is_empty() {
                show_status(&state.status_label, exited_error(gone), true);
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
                    state.last_apply.set(Some(Instant::now()));
                    show_warnings(&state.status_label, &warnings);
                    let mut msg = if pids.len() == 1 {
                        format!("Limits applied to PID {}", pids[0])
                    } else {
                        format!("Shared limits applied to {} process(es)", pids.len())
                    };
                    msg.push_str(&skipped_note(gone));

                    // Persist as a rule if requested. A rule matches by executable
                    // basename, so only save when every selected PID is the same
                    // app, otherwise the saved match_exe would be misleading.
                    if state.save_rule_switch.is_active() {
                        let exe = common_exe_basename(&state.all_processes.borrow(), &pids);
                        // A version-number name changes with every update, so a
                        // rule keyed by it would stop matching.
                        match (exe.as_deref().and_then(common::versioned_rule_name), exe) {
                            (Some(problem), _) => msg.push_str(&format!(
                                ". {problem} Limits were applied without saving a rule."
                            )),
                            (None, Some(exe)) => match save_app_rule(
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
                            (None, None) => msg.push_str(
                                "; (rule not saved: select instances of a single application)",
                            ),
                        }
                    }

                    let toast = status_toast(&msg, 6);
                    state.toast_overlay.add_toast(toast);
                }
                Err(e) => show_status(&state.status_label, &format!("{e}"), true),
            }
        }
        LimitMode::Individual => {
            // Individual mode - separate limits per process
            if pid_text.is_empty() {
                show_status(&state.status_label, "Select a process first", true);
                return;
            }

            let pid: u32 = match pid_text.trim().parse() {
                Ok(p) if p > 0 => p,
                _ => {
                    let several = pid_text.trim().contains([',', ' ']);
                    show_status(
                        &state.status_label,
                        if several {
                            "Single process mode takes one PID; to limit several processes together, switch to Whole app mode"
                        } else {
                            "Enter a positive PID"
                        },
                        true,
                    );
                    return;
                }
            };

            let (_, gone) = live_pids(
                &[pid],
                &state.start_times.borrow(),
                rlm_core::process::start_time,
            );
            if gone > 0 {
                show_status(&state.status_label, exited_error(gone), true);
                return;
            }

            match manager.apply_limit(pid, &limit) {
                Ok(warnings) => {
                    state.last_apply.set(Some(Instant::now()));
                    show_warnings(&state.status_label, &warnings);
                    let toast = status_toast(&format!("Limits applied to PID {pid}"), 5);
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
    fn exited_processes_are_skipped_when_applying() {
        let listed: HashMap<u32, u64> = [(10, 100), (11, 110), (12, 120)].into();
        // 11 exited, 12's PID now names a newer process, 99 was typed by hand.
        let now = |pid: u32| match pid {
            10 => Some(100),
            12 => Some(500),
            99 => Some(7),
            _ => None,
        };
        let (kept, gone) = live_pids(&[10, 11, 12, 99], &listed, now);
        assert_eq!(kept, vec![10, 99]);
        assert_eq!(gone, 2);
        assert_eq!(
            skipped_note(gone),
            "; 2 processes had exited and were skipped"
        );
        assert_eq!(skipped_note(1), "; 1 process had exited and was skipped");
        assert_eq!(skipped_note(0), "");
        // A hand-typed PID is kept even if it is not running; applying says so.
        assert_eq!(live_pids(&[99], &HashMap::new(), |_| None), (vec![99], 0));
        let (kept, gone) = live_pids(&[11], &listed, now);
        assert!(kept.is_empty());
        assert_eq!(
            exited_error(gone),
            "The selected process has exited; nothing was limited"
        );
    }

    #[test]
    fn a_reload_keeps_the_start_times_of_selected_pids() {
        let old: HashMap<u32, u64> = [(10, 100), (11, 110)].into();
        // PID 10 was reused by a new process; 11 exited; 20 is new.
        let fresh: HashMap<u32, u64> = [(10, 900), (20, 200)].into();
        let merged = merge_start_times(&old, fresh.clone(), &[10, 11]);
        assert_eq!(merged.get(&10), Some(&100));
        assert_eq!(merged.get(&11), Some(&110));
        assert_eq!(merged.get(&20), Some(&200));
        // Unselected PIDs take the fresh times.
        let merged = merge_start_times(&old, fresh, &[]);
        assert_eq!(merged.get(&10), Some(&900));
        assert_eq!(merged.get(&11), None);
    }

    #[test]
    fn rows_show_the_app_name_and_keep_the_program_name() {
        assert_eq!(
            row_texts("Google Chrome", "chrome", "24 processes, 3.8 GB"),
            (
                "Google Chrome".to_string(),
                "chrome, 24 processes, 3.8 GB".to_string()
            )
        );
        assert_eq!(
            row_texts("Firefox", "firefox", "3 processes, 1.2 GB"),
            ("Firefox".to_string(), "3 processes, 1.2 GB".to_string())
        );
        assert_eq!(
            row_texts("Claude", "2.1.284", "PID 7, 512 MB").1,
            "2.1.284, PID 7, 512 MB"
        );
    }

    #[test]
    fn search_matches_the_app_or_the_program_name() {
        assert!(matches_query("chrome", &["Google Chrome", "chrome"]));
        assert!(matches_query("google", &["Google Chrome", "chrome"]));
        assert!(matches_query("2.1", &["Claude", "2.1.284"]));
        assert!(matches_query("", &["Claude", "2.1.284"]));
        assert!(!matches_query("firefox", &["Google Chrome", "chrome"]));
    }

    #[test]
    fn memory_is_shown_in_a_readable_unit() {
        assert_eq!(format_memory(900), "900 KB");
        assert_eq!(format_memory(512 * 1024), "512 MB");
        assert_eq!(format_memory(1536), "2 MB");
        assert_eq!(format_memory(1024 * 1024 * 3 / 2), "1.5 GB");
    }

    #[test]
    fn capped_lists_say_how_many_are_hidden() {
        assert_eq!(cap_note(50, 50, false), None);
        assert_eq!(
            cap_note(50, 312, false).as_deref(),
            Some("Showing 50 of 312; type to search")
        );
        assert!(cap_note(30, 40, true).unwrap().contains("type more"));
    }

    #[test]
    fn whole_app_is_the_first_and_default_mode() {
        assert!(mode_for_index(0) == LimitMode::Application);
        assert!(mode_for_index(1) == LimitMode::Individual);
    }

    #[test]
    fn summary_says_what_the_limits_apply_to() {
        use LimitMode::*;
        assert_eq!(
            selection_summary(Application, 2, &[1, 2, 3, 4, 5, 6, 7, 8]),
            "2 apps selected, 8 processes"
        );
        assert_eq!(
            selection_summary(Application, 1, &[9]),
            "1 app selected, 1 process"
        );
        assert_eq!(
            selection_summary(Application, 0, &[9, 10]),
            "2 processes entered"
        );
        assert_eq!(
            selection_summary(Application, 0, &[]),
            "No application selected"
        );
        assert_eq!(selection_summary(Individual, 0, &[3019]), "PID 3019");
        assert_eq!(selection_summary(Individual, 0, &[]), "No process selected");
        assert!(selection_summary(Individual, 0, &[1, 2]).starts_with("2 PIDs entered"));
    }

    #[test]
    fn a_hand_edited_pid_field_is_counted_as_processes() {
        let firefox: &[u32] = &[1, 2, 3];
        let code: &[u32] = &[7];
        assert_eq!(apps_in_field(&[firefox, code], &[1, 2, 3, 7]), 2);
        assert_eq!(apps_in_field(&[firefox], &[3, 2, 1]), 1);
        // A PID added or removed by hand: the field no longer is the apps.
        assert_eq!(apps_in_field(&[firefox], &[1, 2, 3, 99]), 0);
        assert_eq!(apps_in_field(&[firefox], &[1, 2]), 0);
        assert_eq!(apps_in_field(&[], &[5]), 0);
        assert_eq!(
            selection_summary(LimitMode::Application, 0, &[1, 2, 3, 99]),
            "4 processes entered"
        );
    }

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

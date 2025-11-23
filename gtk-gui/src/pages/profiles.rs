use crate::widgets::{create_unit_dropdown, get_unit_suffix, setup_number_validation};
use adw::prelude::*;
use common::{Config, Profile};
use std::cell::RefCell;
use std::rc::Rc;

// Field length limits
const MAX_NAME_LEN: usize = 50;

struct ProfilesState {
    profiles_group: adw::PreferencesGroup,
}

pub fn create() -> gtk::Widget {
    let page = adw::PreferencesPage::new();
    page.set_title("Profiles");
    page.set_icon_name(Some("document-properties-symbolic"));

    // Add button header
    let add_btn = gtk::Button::from_icon_name("list-add-symbolic");
    add_btn.add_css_class("flat");
    add_btn.set_tooltip_text(Some("Create new profile"));

    // Profiles group
    let profiles_group = adw::PreferencesGroup::new();
    profiles_group.set_title("Saved Profiles");
    profiles_group.set_description(Some("Reusable limit configurations"));
    profiles_group.set_header_suffix(Some(&add_btn));

    page.add(&profiles_group);

    // Store state
    let state = Rc::new(RefCell::new(ProfilesState {
        profiles_group: profiles_group.clone(),
    }));

    // Load profiles
    refresh_profiles(&state);

    // Add button handler
    let state_clone = state.clone();
    let page_clone = page.clone();
    add_btn.connect_clicked(move |_| {
        show_profile_dialog(&page_clone, &state_clone);
    });

    page.upcast()
}

fn refresh_profiles(state: &Rc<RefCell<ProfilesState>>) {
    let state = state.borrow();
    let group = &state.profiles_group;

    // Clear existing rows
    while let Some(child) = group.first_child() {
        if child.downcast_ref::<adw::ActionRow>().is_some()
            || child.downcast_ref::<adw::ExpanderRow>().is_some()
        {
            group.remove(&child);
        } else {
            break;
        }
    }

    // Load profiles from config
    match Config::load() {
        Ok(config) => {
            if config.profiles.is_empty() {
                let empty_row = adw::ActionRow::new();
                empty_row.set_title("No profiles yet");
                empty_row.set_subtitle("Click + to create your first profile");
                group.add(&empty_row);
            } else {
                for (name, profile) in &config.profiles {
                    let row = create_profile_row(name, profile);
                    group.add(&row);
                }
            }
        }
        Err(e) => {
            let error_row = adw::ActionRow::new();
            error_row.set_title("Error loading profiles");
            error_row.set_subtitle(&e.to_string());
            group.add(&error_row);
        }
    }
}

fn create_profile_row(name: &str, profile: &Profile) -> adw::ExpanderRow {
    let row = adw::ExpanderRow::new();
    row.set_title(name);

    // Build subtitle with limits summary
    let mut limits = Vec::new();
    if let Some(ref mem) = profile.memory {
        limits.push(format!("Mem: {mem}"));
    }
    if let Some(ref cpu) = profile.cpu {
        limits.push(format!("CPU: {cpu}"));
    }
    if let Some(ref ior) = profile.io_read {
        limits.push(format!("IO↓: {ior}"));
    }
    if let Some(ref iow) = profile.io_write {
        limits.push(format!("IO↑: {iow}"));
    }
    if limits.is_empty() {
        row.set_subtitle("No limits set");
    } else {
        row.set_subtitle(&limits.join(" · "));
    }

    // Detail rows
    if let Some(ref mem) = profile.memory {
        let detail = adw::ActionRow::new();
        detail.set_title("Memory Limit");
        detail.set_subtitle(mem);
        row.add_row(&detail);
    }

    if let Some(ref cpu) = profile.cpu {
        let detail = adw::ActionRow::new();
        detail.set_title("CPU Limit");
        detail.set_subtitle(cpu);
        row.add_row(&detail);
    }

    if let Some(ref ior) = profile.io_read {
        let detail = adw::ActionRow::new();
        detail.set_title("I/O Read Limit");
        detail.set_subtitle(ior);
        row.add_row(&detail);
    }

    if let Some(ref iow) = profile.io_write {
        let detail = adw::ActionRow::new();
        detail.set_title("I/O Write Limit");
        detail.set_subtitle(iow);
        row.add_row(&detail);
    }

    // Button box for edit and delete
    let btn_box = gtk::Box::new(gtk::Orientation::Horizontal, 4);
    btn_box.set_valign(gtk::Align::Center);

    // Edit button
    let edit_btn = gtk::Button::from_icon_name("document-edit-symbolic");
    edit_btn.add_css_class("flat");
    edit_btn.set_tooltip_text(Some("Edit profile"));

    let name_for_edit = name.to_string();
    let profile_for_edit = profile.clone();
    edit_btn.connect_clicked(move |btn| {
        if let Some(page) = btn
            .ancestor(adw::PreferencesPage::static_type())
            .and_then(|w| w.downcast::<adw::PreferencesPage>().ok())
        {
            show_edit_profile_dialog(&page, &name_for_edit, &profile_for_edit);
        }
    });
    btn_box.append(&edit_btn);

    // Delete button
    let delete_btn = gtk::Button::from_icon_name("user-trash-symbolic");
    delete_btn.add_css_class("flat");
    delete_btn.add_css_class("error");
    delete_btn.set_tooltip_text(Some("Delete profile"));

    let name_clone = name.to_string();
    delete_btn.connect_clicked(move |btn| {
        delete_profile(&name_clone, btn);
    });
    btn_box.append(&delete_btn);

    row.add_suffix(&btn_box);

    row
}

fn show_profile_dialog(parent: &adw::PreferencesPage, state: &Rc<RefCell<ProfilesState>>) {
    // Find parent window
    let parent_window = parent.root().and_then(|r| r.downcast::<gtk::Window>().ok());

    let dialog = adw::Window::builder()
        .title("New Profile")
        .modal(true)
        .default_width(450)
        .default_height(400)
        .build();

    if let Some(ref win) = parent_window {
        dialog.set_transient_for(Some(win));
    }

    let content = gtk::Box::new(gtk::Orientation::Vertical, 0);

    // Header bar with cancel/save
    let header = adw::HeaderBar::new();

    let cancel_btn = gtk::Button::with_label("Cancel");
    let save_btn = gtk::Button::with_label("Save");
    save_btn.add_css_class("suggested-action");

    header.pack_start(&cancel_btn);
    header.pack_end(&save_btn);
    content.append(&header);

    // Form
    let form_scroll = gtk::ScrolledWindow::new();
    form_scroll.set_vexpand(true);

    let form_clamp = adw::Clamp::new();
    form_clamp.set_maximum_size(500);

    let form_box = gtk::Box::new(gtk::Orientation::Vertical, 24);
    form_box.set_margin_top(24);
    form_box.set_margin_bottom(24);
    form_box.set_margin_start(12);
    form_box.set_margin_end(12);

    // Name group
    let name_group = adw::PreferencesGroup::new();
    name_group.set_title("Profile Name");

    let name_entry = adw::EntryRow::new();
    name_entry.set_title("Name");
    setup_name_validation(&name_entry);
    let name_hint = gtk::Label::new(Some("e.g., Browser, Heavy App"));
    name_hint.add_css_class("dim-label");
    name_entry.add_suffix(&name_hint);
    name_group.add(&name_entry);
    form_box.append(&name_group);

    // Limits group
    let limits_group = adw::PreferencesGroup::new();
    limits_group.set_title("Resource Limits");
    limits_group.set_description(Some("Leave empty to skip"));

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

    form_box.append(&limits_group);

    form_clamp.set_child(Some(&form_box));
    form_scroll.set_child(Some(&form_clamp));
    content.append(&form_scroll);

    dialog.set_content(Some(&content));

    // Cancel handler
    let dialog_clone = dialog.clone();
    cancel_btn.connect_clicked(move |_| {
        dialog_clone.close();
    });

    // Save handler
    let dialog_clone = dialog.clone();
    let state_clone = state.clone();
    let memory_unit_clone = memory_unit.clone();
    let io_read_unit_clone = io_read_unit.clone();
    let io_write_unit_clone = io_write_unit.clone();
    let name_entry_clone = name_entry.clone();
    let memory_entry_clone = memory_entry.clone();
    let cpu_entry_clone = cpu_entry.clone();
    let io_read_entry_clone = io_read_entry.clone();
    let io_write_entry_clone = io_write_entry.clone();
    save_btn.connect_clicked(move |_| {
        let name = name_entry_clone.text().to_string().trim().to_string();
        if name.is_empty() {
            return;
        }

        // Build limit values with units
        let memory_val = memory_entry_clone.text();
        let cpu_val = cpu_entry_clone.text();
        let io_read_val = io_read_entry_clone.text();
        let io_write_val = io_write_entry_clone.text();

        let memory = if memory_val.is_empty() {
            None
        } else {
            Some(format!(
                "{}{}",
                memory_val,
                get_unit_suffix(&memory_unit_clone)
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
                get_unit_suffix(&io_read_unit_clone)
            ))
        };
        let io_write = if io_write_val.is_empty() {
            None
        } else {
            Some(format!(
                "{}{}",
                io_write_val,
                get_unit_suffix(&io_write_unit_clone)
            ))
        };

        let profile = Profile {
            match_exe: Vec::new(),
            memory,
            cpu,
            io_read,
            io_write,
        };

        // Check if profile exists and warn about overwrite
        let config = match Config::load() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to load config: {e}");
                return;
            }
        };

        let dialog_ref = dialog_clone.clone();
        let state_ref = state_clone.clone();
        let name_clone = name.clone();

        if config.profiles.contains_key(&name) {
            // Show overwrite confirmation
            let confirm = adw::MessageDialog::new(
                Some(&dialog_clone),
                Some(&format!("Replace \"{}\"?", name)),
                Some("A profile with this name already exists. Do you want to replace it?"),
            );
            confirm.add_response("cancel", "Cancel");
            confirm.add_response("replace", "Replace");
            confirm.set_response_appearance("replace", adw::ResponseAppearance::Destructive);
            confirm.set_default_response(Some("cancel"));
            confirm.set_close_response("cancel");

            confirm.connect_response(None, move |_, response| {
                if response != "replace" {
                    return;
                }
                save_profile_to_config(&name_clone, profile.clone(), &state_ref);
                dialog_ref.close();
            });

            confirm.present();
        } else {
            save_profile_to_config(&name, profile, &state_clone);
            dialog_clone.close();
        }
    });

    dialog.present();
}

fn delete_profile(name: &str, btn: &gtk::Button) {
    let name = name.to_string();
    let btn = btn.clone();

    // Find parent window for dialog
    let parent_window = btn.root().and_then(|r| r.downcast::<gtk::Window>().ok());

    // Create confirmation dialog
    let dialog = adw::MessageDialog::new(
        parent_window.as_ref(),
        Some(&format!("Delete \"{}\"?", name)),
        Some("This profile will be permanently deleted. This action cannot be undone."),
    );
    dialog.add_response("cancel", "Cancel");
    dialog.add_response("delete", "Delete");
    dialog.set_response_appearance("delete", adw::ResponseAppearance::Destructive);
    dialog.set_default_response(Some("cancel"));
    dialog.set_close_response("cancel");

    let name_clone = name.clone();
    let btn_clone = btn.clone();
    dialog.connect_response(None, move |_, response| {
        if response != "delete" {
            return;
        }

        if let Ok(mut config) = Config::load() {
            config.profiles.remove(&name_clone);
            if let Err(e) = config.save() {
                tracing::error!("Failed to save config: {e}");
                return;
            }

            // Remove row from UI
            if let Some(group) = btn_clone
                .ancestor(adw::PreferencesGroup::static_type())
                .and_then(|w| w.downcast::<adw::PreferencesGroup>().ok())
            {
                if let Some(row) = btn_clone
                    .ancestor(adw::ExpanderRow::static_type())
                    .and_then(|w| w.downcast::<adw::ExpanderRow>().ok())
                {
                    group.remove(&row);
                }
            }
        }
    });

    dialog.present();
}

fn show_edit_profile_dialog(parent: &adw::PreferencesPage, name: &str, profile: &Profile) {
    let parent_window = parent.root().and_then(|r| r.downcast::<gtk::Window>().ok());

    let dialog = adw::Window::builder()
        .title("Edit Profile")
        .modal(true)
        .default_width(450)
        .default_height(400)
        .build();

    if let Some(ref win) = parent_window {
        dialog.set_transient_for(Some(win));
    }

    let content = gtk::Box::new(gtk::Orientation::Vertical, 0);

    // Header bar with cancel/save
    let header = adw::HeaderBar::new();

    let cancel_btn = gtk::Button::with_label("Cancel");
    let save_btn = gtk::Button::with_label("Save");
    save_btn.add_css_class("suggested-action");

    header.pack_start(&cancel_btn);
    header.pack_end(&save_btn);
    content.append(&header);

    // Form
    let form_scroll = gtk::ScrolledWindow::new();
    form_scroll.set_vexpand(true);

    let form_clamp = adw::Clamp::new();
    form_clamp.set_maximum_size(500);

    let form_box = gtk::Box::new(gtk::Orientation::Vertical, 24);
    form_box.set_margin_top(24);
    form_box.set_margin_bottom(24);
    form_box.set_margin_start(12);
    form_box.set_margin_end(12);

    // Name display (read-only for edit)
    let name_group = adw::PreferencesGroup::new();
    name_group.set_title("Profile Name");

    let name_label = adw::ActionRow::new();
    name_label.set_title(name);
    name_label.set_subtitle("Name cannot be changed");
    name_group.add(&name_label);
    form_box.append(&name_group);

    // Limits group
    let limits_group = adw::PreferencesGroup::new();
    limits_group.set_title("Resource Limits");
    limits_group.set_description(Some("Leave empty to skip"));

    // Helper to extract numeric value and unit index from limit string
    fn parse_limit(limit: Option<&String>) -> (String, u32) {
        match limit {
            Some(s) => {
                let s = s.trim();
                if let Some(v) = s.strip_suffix('K') {
                    (v.to_string(), 0)
                } else if let Some(v) = s.strip_suffix('M') {
                    (v.to_string(), 1)
                } else if let Some(v) = s.strip_suffix('G') {
                    (v.to_string(), 2)
                } else if let Some(v) = s.strip_suffix('T') {
                    (v.to_string(), 3)
                } else if let Some(v) = s.strip_suffix('%') {
                    (v.to_string(), 0)
                } else {
                    (s.to_string(), 1) // Default MB
                }
            }
            None => (String::new(), 1),
        }
    }

    // Memory with unit dropdown
    let memory_entry = adw::EntryRow::new();
    memory_entry.set_title("Memory");
    memory_entry.set_input_purpose(gtk::InputPurpose::Digits);
    setup_number_validation(&memory_entry);
    let memory_unit = create_unit_dropdown();
    let (mem_val, mem_unit_idx) = parse_limit(profile.memory.as_ref());
    memory_entry.set_text(&mem_val);
    memory_unit.set_selected(mem_unit_idx);
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
    let (cpu_val, _) = parse_limit(profile.cpu.as_ref());
    cpu_entry.set_text(&cpu_val);
    limits_group.add(&cpu_entry);

    // I/O Read with unit dropdown
    let io_read_entry = adw::EntryRow::new();
    io_read_entry.set_title("I/O Read");
    io_read_entry.set_input_purpose(gtk::InputPurpose::Digits);
    setup_number_validation(&io_read_entry);
    let io_read_unit = create_unit_dropdown();
    let (ior_val, ior_unit_idx) = parse_limit(profile.io_read.as_ref());
    io_read_entry.set_text(&ior_val);
    io_read_unit.set_selected(ior_unit_idx);
    io_read_entry.add_suffix(&io_read_unit);
    limits_group.add(&io_read_entry);

    // I/O Write with unit dropdown
    let io_write_entry = adw::EntryRow::new();
    io_write_entry.set_title("I/O Write");
    io_write_entry.set_input_purpose(gtk::InputPurpose::Digits);
    setup_number_validation(&io_write_entry);
    let io_write_unit = create_unit_dropdown();
    let (iow_val, iow_unit_idx) = parse_limit(profile.io_write.as_ref());
    io_write_entry.set_text(&iow_val);
    io_write_unit.set_selected(iow_unit_idx);
    io_write_entry.add_suffix(&io_write_unit);
    limits_group.add(&io_write_entry);

    form_box.append(&limits_group);

    form_clamp.set_child(Some(&form_box));
    form_scroll.set_child(Some(&form_clamp));
    content.append(&form_scroll);

    dialog.set_content(Some(&content));

    // Cancel handler
    let dialog_clone = dialog.clone();
    cancel_btn.connect_clicked(move |_| {
        dialog_clone.close();
    });

    // Save handler
    let dialog_clone = dialog.clone();
    let name_clone = name.to_string();
    let parent_clone = parent.clone();
    save_btn.connect_clicked(move |_| {
        // Build limit values with units
        let memory_val = memory_entry.text();
        let cpu_val = cpu_entry.text();
        let io_read_val = io_read_entry.text();
        let io_write_val = io_write_entry.text();

        let memory = if memory_val.is_empty() {
            None
        } else {
            Some(format!("{}{}", memory_val, get_unit_suffix(&memory_unit)))
        };
        let cpu = if cpu_val.is_empty() {
            None
        } else {
            Some(format!("{}%", cpu_val))
        };
        let io_read = if io_read_val.is_empty() {
            None
        } else {
            Some(format!("{}{}", io_read_val, get_unit_suffix(&io_read_unit)))
        };
        let io_write = if io_write_val.is_empty() {
            None
        } else {
            Some(format!(
                "{}{}",
                io_write_val,
                get_unit_suffix(&io_write_unit)
            ))
        };

        let profile = Profile {
            match_exe: Vec::new(),
            memory,
            cpu,
            io_read,
            io_write,
        };

        // Save directly (no overwrite warning - we're editing existing)
        if let Ok(mut config) = Config::load() {
            config.profiles.insert(name_clone.clone(), profile);
            if let Err(e) = config.save() {
                tracing::error!("Failed to save config: {e}");
            } else {
                // Refresh the profiles list
                if let Some(group) = parent_clone
                    .first_child()
                    .and_then(|c| c.downcast::<adw::PreferencesGroup>().ok())
                {
                    // Clear and reload
                    while let Some(child) = group.first_child() {
                        if child.downcast_ref::<adw::ActionRow>().is_some()
                            || child.downcast_ref::<adw::ExpanderRow>().is_some()
                        {
                            group.remove(&child);
                        } else {
                            break;
                        }
                    }
                    if let Ok(config) = Config::load() {
                        for (name, profile) in &config.profiles {
                            let row = create_profile_row(name, profile);
                            group.add(&row);
                        }
                    }
                }
            }
        }

        dialog_clone.close();
    });

    dialog.present();
}

fn save_profile_to_config(name: &str, profile: Profile, state: &Rc<RefCell<ProfilesState>>) {
    match Config::load() {
        Ok(mut config) => {
            config.profiles.insert(name.to_string(), profile);
            if let Err(e) = config.save() {
                tracing::error!("Failed to save config: {e}");
            } else {
                refresh_profiles(state);
            }
        }
        Err(e) => {
            tracing::error!("Failed to load config: {e}");
        }
    }
}

fn setup_name_validation(entry: &adw::EntryRow) {
    entry.connect_changed(move |e| {
        let text = e.text();
        if text.len() > MAX_NAME_LEN {
            e.set_text(&text[..MAX_NAME_LEN]);
            return;
        }
        // Visual feedback for empty or whitespace-only name
        if !text.is_empty() && text.trim().is_empty() {
            e.add_css_class("error");
        } else {
            e.remove_css_class("error");
        }
    });
}

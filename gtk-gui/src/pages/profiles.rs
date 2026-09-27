//! Profiles page: the built-in presets and the user's own profiles. A row
//! opens the edit dialog; editing a preset saves a copy under the same name
//! that takes its place.

use crate::pages::{plain_toast, show_toast};
use crate::widgets::{
    cpu_suffix_label, create_io_unit_dropdown, create_unit_dropdown, fill_limits, form_limit,
    get_unit_suffix, icon_button, setup_number_validation, setup_size_validation, unshown_fields,
};
use adw::prelude::*;
use common::{builtin_presets, Config, Profile};
use gtk::glib;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

// Field length limits
const MAX_NAME_LEN: usize = 50;

/// Why a profile form cannot be saved yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormProblem {
    NoName,
    NoLimits,
    /// A limit does not parse; the text says which and why.
    Invalid(String),
}

/// Where a listed profile comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// A built-in preset, as shipped.
    Builtin,
    /// A built-in preset the user has edited; their copy is used.
    ChangedBuiltin,
    /// A profile the user created.
    User,
}

/// A limit value from an entry's text and its unit suffix, or `None` when
/// the entry is empty.
fn field(text: &str, suffix: &str) -> Option<String> {
    let text = text.trim();
    if text.is_empty() {
        None
    } else {
        Some(format!("{text}{suffix}"))
    }
}

/// A profile from the form's (text, unit suffix) pairs and CPU text.
pub fn profile_from_fields(
    memory: (&str, &str),
    cpu: &str,
    io_read: (&str, &str),
    io_write: (&str, &str),
) -> Profile {
    Profile {
        match_exe: Vec::new(),
        memory: field(memory.0, memory.1),
        cpu: field(cpu, "%"),
        io_read: field(io_read.0, io_read.1),
        io_write: field(io_write.0, io_write.1),
    }
}

/// Whether a profile named `name` with these limits can be saved.
pub fn check_form(name: &str, profile: &Profile) -> Result<(), FormProblem> {
    let limit = form_limit(
        profile.memory.as_deref(),
        profile.cpu.as_deref(),
        profile.io_read.as_deref(),
        profile.io_write.as_deref(),
    )
    .map_err(FormProblem::Invalid)?;
    if name.trim().is_empty() {
        return Err(FormProblem::NoName);
    }
    if limit.is_empty() {
        return Err(FormProblem::NoLimits);
    }
    Ok(())
}

/// The existing profile name that `name` would clash with, ignoring case:
/// an exact match first, otherwise the first that differs only in case.
fn existing_name(names: &[String], name: &str) -> Option<String> {
    names
        .iter()
        .find(|n| n.as_str() == name)
        .or_else(|| {
            names
                .iter()
                .find(|n| n.to_lowercase() == name.to_lowercase())
        })
        .cloned()
}

/// Whether two profiles set the same limits and match the same executables.
fn same_limits(a: &Profile, b: &Profile) -> bool {
    a.match_exe == b.match_exe
        && a.memory == b.memory
        && a.cpu == b.cpu
        && a.io_read == b.io_read
        && a.io_write == b.io_write
}

/// Every profile to list, sorted by name, with where it comes from.
pub fn listed_profiles(config: &Config) -> Vec<(String, Profile, Origin)> {
    let presets = builtin_presets();
    let all = config.all_profiles();
    config
        .profile_names()
        .into_iter()
        .filter_map(|name| {
            // A saved copy of a preset that matches it exactly still counts
            // as the preset.
            let origin = match (presets.get(&name), config.profiles.get(&name)) {
                (Some(preset), Some(mine)) if !same_limits(preset, mine) => Origin::ChangedBuiltin,
                (Some(_), _) => Origin::Builtin,
                (None, _) => Origin::User,
            };
            let profile = all.get(&name)?.clone();
            Some((name, profile, origin))
        })
        .collect()
}

/// One line listing a profile's limits.
pub fn limits_summary(p: &Profile) -> String {
    let mut limits = Vec::new();
    if let Some(ref mem) = p.memory {
        limits.push(format!("Memory {mem}"));
    }
    if let Some(ref cpu) = p.cpu {
        limits.push(format!("CPU {cpu}"));
    }
    if let Some(ref ior) = p.io_read {
        limits.push(format!("Read {ior}/s"));
    }
    if let Some(ref iow) = p.io_write {
        limits.push(format!("Write {iow}/s"));
    }
    if limits.is_empty() {
        "No limits set".to_string()
    } else {
        limits.join(" · ")
    }
}

/// Save `profile` under `name` in the user config.
fn save_profile(name: &str, profile: Profile) -> common::Result<()> {
    let mut config = Config::load()?;
    config.profiles.insert(name.to_string(), profile);
    config.save()
}

/// Remove the user's profile `name`. For an edited preset this brings the
/// built-in version back.
fn remove_profile(name: &str) -> common::Result<()> {
    let mut config = Config::load()?;
    config.profiles.remove(name);
    config.save()
}

/// A size limit entry with its unit dropdown (MB/GB for memory, KB/s to
/// GB/s for I/O).
fn unit_entry(title: &str, io: bool) -> (adw::EntryRow, gtk::DropDown) {
    let entry = adw::EntryRow::new();
    entry.set_title(title);
    entry.set_input_purpose(gtk::InputPurpose::Number);
    setup_size_validation(&entry);
    let unit = if io {
        create_io_unit_dropdown()
    } else {
        create_unit_dropdown()
    };
    entry.add_suffix(&unit);
    (entry, unit)
}

/// The profile to save from the dialog: each limit the user did not edit
/// (`edited`: memory, CPU, I/O read, I/O write) keeps its stored text
/// exactly, even one the form could not show or would write differently
/// ("1536K" shows as 1.5 MB), so saving never deletes or changes it. The
/// match_exe list, which the dialog does not show, is kept too.
pub fn keep_unedited(form: Profile, stored: &Profile, edited: [bool; 4]) -> Profile {
    let pick = |from_form: Option<String>, from_store: &Option<String>, edited: bool| {
        if edited {
            from_form
        } else {
            from_store.clone()
        }
    };
    Profile {
        match_exe: stored.match_exe.clone(),
        memory: pick(form.memory, &stored.memory, edited[0]),
        cpu: pick(form.cpu, &stored.cpu, edited[1]),
        io_read: pick(form.io_read, &stored.io_read, edited[2]),
        io_write: pick(form.io_write, &stored.io_write, edited[3]),
    }
}

pub struct ProfilesPage {
    page: adw::PreferencesPage,
    group: adw::PreferencesGroup,
    /// The rows currently in `group`, so a refresh can remove them.
    rows: RefCell<Vec<adw::ActionRow>>,
}

impl ProfilesPage {
    pub fn new() -> Rc<Self> {
        let page = adw::PreferencesPage::new();

        let add_btn = icon_button("list-add-symbolic", "Create new profile");

        let group = adw::PreferencesGroup::new();
        group.set_title("Saved Profiles");
        group.set_description(Some("Named sets of limits. Pick one under Profile on Limit Running or Launch New, or use rlm run --profile."));
        group.set_header_suffix(Some(&add_btn));
        page.add(&group);

        let this = Rc::new(Self {
            page,
            group,
            rows: RefCell::new(Vec::new()),
        });
        this.refresh();

        let weak = Rc::downgrade(&this);
        add_btn.connect_clicked(move |_| {
            if let Some(page) = weak.upgrade() {
                page.open_dialog(None);
            }
        });

        this
    }

    pub fn widget(&self) -> gtk::Widget {
        self.page.clone().upcast()
    }

    /// Reload the profiles from the config and rebuild the list.
    pub fn refresh(self: &Rc<Self>) {
        for row in self.rows.borrow_mut().drain(..) {
            self.group.remove(&row);
        }
        let mut rows = Vec::new();
        match Config::load() {
            Ok(config) => {
                for (name, profile, origin) in listed_profiles(&config) {
                    rows.push(self.profile_row(&name, &profile, origin));
                }
            }
            Err(e) => {
                let row = adw::ActionRow::new();
                row.set_use_markup(false);
                row.set_title("Could not load profiles");
                row.set_subtitle(&e.to_string());
                rows.push(row);
            }
        }
        for row in &rows {
            self.group.add(row);
        }
        self.rows.replace(rows);
    }

    fn toast(&self, text: &str) {
        show_toast(&self.page, plain_toast(text));
    }

    fn profile_row(
        self: &Rc<Self>,
        name: &str,
        profile: &Profile,
        origin: Origin,
    ) -> adw::ActionRow {
        let row = adw::ActionRow::new();
        row.set_title(&glib::markup_escape_text(name));
        row.set_subtitle(&glib::markup_escape_text(&limits_summary(profile)));
        row.set_activatable(true);

        let tag = match origin {
            Origin::Builtin => Some("Built-in"),
            Origin::ChangedBuiltin => Some("Built-in, changed"),
            Origin::User => None,
        };
        if let Some(tag) = tag {
            let label = gtk::Label::new(Some(tag));
            label.add_css_class("dim-label");
            label.add_css_class("caption");
            label.set_valign(gtk::Align::Center);
            row.add_suffix(&label);
        }

        // Presets cannot be deleted; an edited preset can be restored.
        let remove = match origin {
            Origin::Builtin => None,
            Origin::ChangedBuiltin => {
                Some(("edit-undo-symbolic", format!("Restore built-in {name}")))
            }
            Origin::User => Some(("user-trash-symbolic", format!("Delete profile {name}"))),
        };
        if let Some((icon, label)) = remove {
            let btn = gtk::Button::from_icon_name(icon);
            btn.add_css_class("flat");
            btn.set_valign(gtk::Align::Center);
            btn.set_tooltip_text(Some(&label));
            btn.update_property(&[gtk::accessible::Property::Label(&label)]);
            let weak = Rc::downgrade(self);
            let name = name.to_string();
            btn.connect_clicked(move |_| {
                if let Some(page) = weak.upgrade() {
                    page.confirm_remove(&name, origin);
                }
            });
            row.add_suffix(&btn);
        }

        let weak = Rc::downgrade(self);
        let name = name.to_string();
        let profile = profile.clone();
        row.connect_activated(move |_| {
            if let Some(page) = weak.upgrade() {
                page.open_dialog(Some((name.clone(), profile.clone(), origin)));
            }
        });
        row
    }

    fn confirm_remove(self: &Rc<Self>, name: &str, origin: Origin) {
        let parent = self
            .page
            .root()
            .and_then(|r| r.downcast::<gtk::Window>().ok());
        let (heading, body, verb, label) = if origin == Origin::ChangedBuiltin {
            (
                format!("Restore \u{201c}{name}\u{201d}?"),
                "Your changes to this built-in profile are removed and its original limits apply again.",
                "restore",
                "Restore",
            )
        } else {
            (
                format!("Delete \u{201c}{name}\u{201d}?"),
                "This profile will be permanently deleted. This action cannot be undone.",
                "delete",
                "Delete",
            )
        };
        let dialog = adw::MessageDialog::new(parent.as_ref(), Some(&heading), Some(body));
        dialog.add_response("cancel", "Cancel");
        dialog.add_response(verb, label);
        dialog.set_response_appearance(verb, adw::ResponseAppearance::Destructive);
        dialog.set_default_response(Some("cancel"));
        dialog.set_close_response("cancel");

        let weak = Rc::downgrade(self);
        let name = name.to_string();
        dialog.connect_response(None, move |_, response| {
            if response != verb {
                return;
            }
            let Some(page) = weak.upgrade() else { return };
            match remove_profile(&name) {
                Ok(()) => page.refresh(),
                Err(e) => page.toast(&format!("Could not {verb} profile {name}: {e}")),
            }
        });
        dialog.present();
    }

    /// The New Profile dialog, or the edit dialog for `existing`. Save stays
    /// insensitive until the name is set and the limits are valid; the
    /// dialog closes only once the profile is saved.
    fn open_dialog(self: &Rc<Self>, existing: Option<(String, Profile, Origin)>) {
        let parent_window = self
            .page
            .root()
            .and_then(|r| r.downcast::<gtk::Window>().ok());

        let title = match &existing {
            None => "New Profile",
            Some(_) => "Edit Profile",
        };
        let dialog = adw::Window::builder()
            .title(title)
            .modal(true)
            .default_width(450)
            .default_height(580)
            .build();
        if let Some(ref win) = parent_window {
            dialog.set_transient_for(Some(win));
        }

        let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
        let header = adw::HeaderBar::new();
        let cancel_btn = gtk::Button::with_label("Cancel");
        let save_btn = gtk::Button::with_label("Save");
        save_btn.add_css_class("suggested-action");
        save_btn.set_sensitive(false);
        header.pack_start(&cancel_btn);
        header.pack_end(&save_btn);
        content.append(&header);

        let form_scroll = gtk::ScrolledWindow::new();
        form_scroll.set_vexpand(true);
        let form_clamp = adw::Clamp::new();
        form_clamp.set_maximum_size(500);
        let form_box = gtk::Box::new(gtk::Orientation::Vertical, 24);
        form_box.set_margin_top(24);
        form_box.set_margin_bottom(24);
        form_box.set_margin_start(12);
        form_box.set_margin_end(12);

        let name_group = adw::PreferencesGroup::new();
        name_group.set_title("Profile Name");
        // A new profile gets a name entry; an existing one keeps its name.
        let name_entry = adw::EntryRow::new();
        match &existing {
            None => {
                name_entry.set_title("Name");
                setup_name_validation(&name_entry);
                let name_hint = gtk::Label::new(Some("e.g., Browser, Heavy App"));
                name_hint.add_css_class("dim-label");
                name_entry.add_suffix(&name_hint);
                name_group.add(&name_entry);
            }
            Some((name, _, origin)) => {
                name_entry.set_text(name);
                let name_row = adw::ActionRow::new();
                name_row.set_title(&glib::markup_escape_text(name));
                name_row.set_subtitle(if *origin == Origin::Builtin {
                    "Built-in profile. Saving keeps your changes in your own copy."
                } else {
                    "To rename, create a new profile and delete this one"
                });
                name_group.add(&name_row);
            }
        }
        form_box.append(&name_group);

        let limits_group = adw::PreferencesGroup::new();
        limits_group.set_title("Resource Limits");
        limits_group.set_description(Some("Leave a field empty to leave that resource unlimited"));

        let current = existing
            .as_ref()
            .map(|(_, p, _)| p.clone())
            .unwrap_or_default();
        let (memory_entry, memory_unit) = unit_entry("Memory", false);
        limits_group.add(&memory_entry);

        let cpu_entry = adw::EntryRow::new();
        cpu_entry.set_title("CPU");
        cpu_entry.set_input_purpose(gtk::InputPurpose::Digits);
        setup_number_validation(&cpu_entry);
        cpu_entry.add_suffix(&cpu_suffix_label());
        limits_group.add(&cpu_entry);

        let (io_read_entry, io_read_unit) = unit_entry("I/O Read", true);
        limits_group.add(&io_read_entry);
        let (io_write_entry, io_write_unit) = unit_entry("I/O Write", true);
        limits_group.add(&io_write_entry);
        form_box.append(&limits_group);

        let unshown = fill_limits(
            (&memory_entry, &memory_unit),
            &cpu_entry,
            (&io_read_entry, &io_read_unit),
            (&io_write_entry, &io_write_unit),
            &current,
        );
        if !unshown.is_empty() {
            let kept = if unshown.len() == 1 {
                "It is kept as saved unless you type a new value."
            } else {
                "They are kept as saved unless you type new values."
            };
            let note = gtk::Label::new(Some(&format!(
                "{} cannot be shown here. {kept}",
                unshown_fields(&unshown)
            )));
            note.add_css_class("dim-label");
            note.set_wrap(true);
            note.set_xalign(0.0);
            form_box.append(&note);
        }

        // Which limits the user has changed. Connected after the fields are
        // filled, and before the validation below, so it is set first.
        let edited: Rc<[Cell<bool>; 4]> = Rc::new(Default::default());
        let fields = [
            (&memory_entry, Some(&memory_unit)),
            (&cpu_entry, None),
            (&io_read_entry, Some(&io_read_unit)),
            (&io_write_entry, Some(&io_write_unit)),
        ];
        for (i, (entry, unit)) in fields.into_iter().enumerate() {
            let flags = edited.clone();
            entry.connect_changed(move |_| flags[i].set(true));
            if let Some(unit) = unit {
                let flags = edited.clone();
                unit.connect_selected_notify(move |_| flags[i].set(true));
            }
        }

        let error_label = gtk::Label::new(None);
        error_label.add_css_class("error");
        error_label.set_wrap(true);
        error_label.set_xalign(0.0);
        error_label.set_visible(false);
        form_box.append(&error_label);

        form_clamp.set_child(Some(&form_box));
        form_scroll.set_child(Some(&form_clamp));
        content.append(&form_scroll);
        dialog.set_content(Some(&content));

        // The form's current contents as a profile; see keep_unedited.
        let read_form = {
            let name_entry = name_entry.clone();
            let memory_entry = memory_entry.clone();
            let memory_unit = memory_unit.clone();
            let cpu_entry = cpu_entry.clone();
            let io_read_entry = io_read_entry.clone();
            let io_read_unit = io_read_unit.clone();
            let io_write_entry = io_write_entry.clone();
            let io_write_unit = io_write_unit.clone();
            let edited = edited.clone();
            let current = current.clone();
            Rc::new(move || {
                let form = profile_from_fields(
                    (&memory_entry.text(), &get_unit_suffix(&memory_unit)),
                    &cpu_entry.text(),
                    (&io_read_entry.text(), &get_unit_suffix(&io_read_unit)),
                    (&io_write_entry.text(), &get_unit_suffix(&io_write_unit)),
                );
                let flags = [0, 1, 2, 3].map(|i| edited[i].get());
                let profile = keep_unedited(form, &current, flags);
                (name_entry.text().trim().to_string(), profile)
            })
        };

        let validate = {
            let read_form = read_form.clone();
            let save_btn = save_btn.clone();
            let error_label = error_label.clone();
            Rc::new(move || {
                let (name, profile) = read_form();
                let result = check_form(&name, &profile);
                save_btn.set_sensitive(result.is_ok());
                match result {
                    Err(FormProblem::Invalid(msg)) => {
                        error_label.set_text(&msg);
                        error_label.set_visible(true);
                    }
                    _ => error_label.set_visible(false),
                }
            })
        };
        for entry in [
            &name_entry,
            &memory_entry,
            &cpu_entry,
            &io_read_entry,
            &io_write_entry,
        ] {
            let validate = validate.clone();
            entry.connect_changed(move |_| validate());
        }
        for unit in [&memory_unit, &io_read_unit, &io_write_unit] {
            let validate = validate.clone();
            unit.connect_selected_notify(move |_| validate());
        }
        validate();

        let dialog_clone = dialog.clone();
        cancel_btn.connect_clicked(move |_| {
            dialog_clone.close();
        });

        let is_new = existing.is_none();
        let weak = Rc::downgrade(self);
        let dialog_clone = dialog.clone();
        save_btn.connect_clicked(move |_| {
            let (name, profile) = read_form();
            if check_form(&name, &profile).is_err() {
                return;
            }
            let Some(page) = weak.upgrade() else { return };
            let finish = {
                let dialog = dialog_clone.clone();
                let error_label = error_label.clone();
                let page = page.clone();
                move |name: &str, profile: Profile| match save_profile(name, profile) {
                    Ok(()) => {
                        page.refresh();
                        dialog.close();
                    }
                    Err(e) => {
                        error_label.set_text(&format!("Could not save the profile: {e}"));
                        error_label.set_visible(true);
                    }
                }
            };

            // Profile names are looked up case-insensitively (see
            // Config::resolve_profile_name), so "browser" would clash with
            // "Browser". Replacing keeps the existing name.
            let taken = if is_new {
                Config::load()
                    .ok()
                    .and_then(|c| existing_name(&c.profile_names(), &name))
            } else {
                None
            };
            let Some(name) = taken else {
                finish(&name, profile);
                return;
            };
            let confirm = adw::MessageDialog::new(
                Some(&dialog_clone),
                Some(&format!("Replace \u{201c}{name}\u{201d}?")),
                Some("A profile with this name already exists. Do you want to replace it?"),
            );
            confirm.add_response("cancel", "Cancel");
            confirm.add_response("replace", "Replace");
            confirm.set_response_appearance("replace", adw::ResponseAppearance::Destructive);
            confirm.set_default_response(Some("cancel"));
            confirm.set_close_response("cancel");
            confirm.connect_response(None, move |_, response| {
                if response == "replace" {
                    finish(&name, profile.clone());
                }
            });
            confirm.present();
        });

        dialog.present();
    }
}

fn setup_name_validation(entry: &adw::EntryRow) {
    entry.connect_changed(move |e| {
        let text = e.text();
        if text.chars().count() > MAX_NAME_LEN {
            // Cut on a character boundary; a byte slice panics inside a
            // multibyte character.
            let cut: String = text.chars().take(MAX_NAME_LEN).collect();
            e.set_text(&cut);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_become_limit_strings() {
        let p = profile_from_fields(("512", "M"), "25", ("", "M"), (" 10 ", "K"));
        assert_eq!(p.memory.as_deref(), Some("512M"));
        assert_eq!(p.cpu.as_deref(), Some("25%"));
        assert_eq!(p.io_read, None);
        assert_eq!(p.io_write.as_deref(), Some("10K"));
    }

    #[test]
    fn form_needs_a_name_and_valid_limits() {
        let ok = profile_from_fields(("512", "M"), "", ("", "M"), ("", "M"));
        assert_eq!(check_form("Web", &ok), Ok(()));
        assert_eq!(check_form("  ", &ok), Err(FormProblem::NoName));

        let empty = profile_from_fields(("", "M"), "", ("", "M"), ("", "M"));
        assert_eq!(check_form("Web", &empty), Err(FormProblem::NoLimits));

        // Below the 8 MiB floor and a zero CPU both fail to parse.
        let tiny = profile_from_fields(("1", "M"), "", ("", "M"), ("", "M"));
        match check_form("Web", &tiny) {
            Err(FormProblem::Invalid(msg)) => {
                assert!(msg.contains("8M minimum"), "{msg}");
                assert!(!msg.contains('\n'), "CLI hint leaked: {msg}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
        let zero_cpu = profile_from_fields(("", "M"), "0", ("", "M"), ("", "M"));
        assert!(matches!(
            check_form("", &zero_cpu),
            Err(FormProblem::Invalid(_))
        ));
    }

    #[test]
    fn presets_are_listed_and_marked() {
        let mut config = Config::default();
        config.profiles.insert(
            "Light".into(),
            Profile {
                memory: Some("1G".into()),
                ..Profile::default()
            },
        );
        config.profiles.insert(
            "mine".into(),
            Profile {
                cpu: Some("10%".into()),
                ..Profile::default()
            },
        );
        config
            .profiles
            .insert("Heavy".into(), builtin_presets()["Heavy"].clone());
        let listed = listed_profiles(&config);
        let origin = |n: &str| listed.iter().find(|(name, _, _)| name == n).map(|e| e.2);
        assert_eq!(origin("Heavy"), Some(Origin::Builtin));
        assert_eq!(origin("Light"), Some(Origin::ChangedBuiltin));
        assert_eq!(origin("mine"), Some(Origin::User));
        let light = listed.iter().find(|(n, _, _)| n == "Light").unwrap();
        assert_eq!(light.1.memory.as_deref(), Some("1G"));
        let names: Vec<&str> = listed.iter().map(|(n, _, _)| n.as_str()).collect();
        assert_eq!(names, ["Browser", "Heavy", "Light", "Medium", "mine"]);
    }

    #[test]
    fn a_new_name_clashes_whatever_its_case() {
        let names = vec!["Browser".to_string(), "mine".to_string()];
        assert_eq!(existing_name(&names, "Browser"), Some("Browser".into()));
        assert_eq!(existing_name(&names, "browser"), Some("Browser".into()));
        assert_eq!(existing_name(&names, "MINE"), Some("mine".into()));
        assert_eq!(existing_name(&names, "Web"), None);
    }

    #[test]
    fn saving_keeps_the_limits_the_user_did_not_edit() {
        let stored = Profile {
            match_exe: vec!["firefox".into()],
            memory: Some("1536K".into()),
            cpu: Some("50.5%".into()),
            io_read: Some("10M".into()),
            io_write: None,
        };
        // The form shows memory as 1.5 MB and cannot show the CPU value.
        let form = profile_from_fields(("1.5", "M"), "", ("20", "M"), ("", "M"));
        let saved = keep_unedited(form, &stored, [false, false, true, false]);
        assert_eq!(saved.memory.as_deref(), Some("1536K"));
        assert_eq!(saved.cpu.as_deref(), Some("50.5%"));
        assert_eq!(saved.io_read.as_deref(), Some("20M"));
        assert_eq!(saved.io_write, None);
        assert_eq!(saved.match_exe, ["firefox"]);
        // Clearing an edited field removes that limit.
        let cleared = profile_from_fields(("", "M"), "", ("", "M"), ("", "M"));
        let saved = keep_unedited(cleared, &stored, [true, true, false, false]);
        assert_eq!(saved.memory, None);
        assert_eq!(saved.cpu, None);
    }

    #[test]
    fn summary_lists_each_limit() {
        let p = Profile {
            memory: Some("2G".into()),
            cpu: Some("50%".into()),
            io_read: Some("50M".into()),
            io_write: None,
            ..Profile::default()
        };
        assert_eq!(limits_summary(&p), "Memory 2G · CPU 50% · Read 50M/s");
        assert_eq!(limits_summary(&Profile::default()), "No limits set");
    }
}

// Shared form widgets and utilities

use adw::prelude::*;

// Unit options for memory/IO
pub const UNITS: &[&str] = &["KB", "MB", "GB", "TB"];
pub const UNIT_SUFFIXES: &[&str] = &["K", "M", "G", "T"];

// Field length limits
pub const MAX_LIMIT_LEN: usize = 20;

/// Setup validation for numeric entry fields (digits only)
pub fn setup_number_validation(entry: &adw::EntryRow) {
    entry.connect_changed(move |e| {
        let text = e.text();
        if text.len() > MAX_LIMIT_LEN {
            e.set_text(&text[..MAX_LIMIT_LEN]);
            return;
        }
        // Only allow digits
        let filtered: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
        if filtered != text.as_str() {
            e.set_text(&filtered);
        }
    });
}

/// Create a unit dropdown (KB/MB/GB/TB)
pub fn create_unit_dropdown() -> gtk::DropDown {
    let units = gtk::StringList::new(UNITS);
    let dropdown = gtk::DropDown::new(Some(units), gtk::Expression::NONE);
    dropdown.set_valign(gtk::Align::Center);
    dropdown
}

/// Get the unit suffix for cgroup (K, M, G, T)
pub fn get_unit_suffix(dropdown: &gtk::DropDown) -> &'static str {
    let idx = dropdown.selected() as usize;
    UNIT_SUFFIXES.get(idx).copied().unwrap_or("M")
}

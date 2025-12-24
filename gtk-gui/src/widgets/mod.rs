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

/// Parse a value like "4G" or "100M" and set entry + dropdown
pub fn set_value_with_unit(entry: &adw::EntryRow, dropdown: &gtk::DropDown, value: &str) {
    let value = value.trim();
    if value.is_empty() {
        entry.set_text("");
        return;
    }

    // Find where digits end
    let digit_end = value
        .chars()
        .position(|c| !c.is_ascii_digit())
        .unwrap_or(value.len());

    let (num_part, unit_part) = value.split_at(digit_end);

    // Set numeric part
    entry.set_text(num_part);

    // Set unit dropdown based on suffix
    let unit_idx = match unit_part.trim().to_uppercase().as_str() {
        "K" | "KB" => 0,
        "M" | "MB" => 1,
        "G" | "GB" => 2,
        "T" | "TB" => 3,
        _ => 1, // Default to MB
    };
    dropdown.set_selected(unit_idx);
}

/// Parse a CPU value like "75%" and return just the number
pub fn parse_cpu_value(value: &str) -> String {
    value.trim().trim_end_matches('%').to_string()
}

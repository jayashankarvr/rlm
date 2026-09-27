// Shared form widgets and utilities

use adw::prelude::*;

// Unit options for memory/IO. The first letter of each label is the suffix
// the value is sent with (K, M, G, T).
pub const UNITS: &[&str] = &["KB", "MB", "GB", "TB"];

// Field length limits
pub const MAX_LIMIT_LEN: usize = 20;

/// Setup validation for whole-number entry fields (digits only)
pub fn setup_number_validation(entry: &adw::EntryRow) {
    connect_filter(entry, false);
}

/// Setup validation for size fields: digits and one decimal point, so
/// "1.5" GB can be typed.
pub fn setup_size_validation(entry: &adw::EntryRow) {
    connect_filter(entry, true);
}

fn connect_filter(entry: &adw::EntryRow, decimal: bool) {
    entry.connect_changed(move |e| {
        let text = e.text();
        let filtered = filter_number(&text, decimal);
        if filtered != text.as_str() {
            e.set_text(&filtered);
        }
    });
}

/// Keep digits (and the first '.' when `decimal`), capped at
/// [`MAX_LIMIT_LEN`] characters.
fn filter_number(text: &str, decimal: bool) -> String {
    let mut seen_dot = false;
    text.chars()
        .filter(|c| {
            if c.is_ascii_digit() {
                true
            } else if decimal && *c == '.' && !seen_dot {
                seen_dot = true;
                true
            } else {
                false
            }
        })
        .take(MAX_LIMIT_LEN)
        .collect()
}

/// Create a unit dropdown (KB/MB/GB/TB), MB selected
pub fn create_unit_dropdown() -> gtk::DropDown {
    let units = gtk::StringList::new(UNITS);
    let dropdown = gtk::DropDown::new(Some(units), gtk::Expression::NONE);
    dropdown.set_valign(gtk::Align::Center);
    dropdown.set_selected(1);
    dropdown
}

/// The unit letters a dropdown offers, in order.
fn dropdown_suffixes(dropdown: &gtk::DropDown) -> Vec<char> {
    let Some(model) = dropdown.model() else {
        return Vec::new();
    };
    (0..model.n_items())
        .filter_map(|i| model.item(i).and_downcast::<gtk::StringObject>())
        .filter_map(|s| s.string().chars().next())
        .collect()
}

/// Get the unit suffix for cgroup (K, M, G, T)
pub fn get_unit_suffix(dropdown: &gtk::DropDown) -> String {
    dropdown_suffixes(dropdown)
        .get(dropdown.selected() as usize)
        .map(|c| c.to_string())
        .unwrap_or_else(|| "M".into())
}

/// Parse a value like "4G", "1.5GiB" or "512MB" and set entry + dropdown.
/// An empty or unreadable value clears the entry.
pub fn set_value_with_unit(entry: &adw::EntryRow, dropdown: &gtk::DropDown, value: &str) {
    match split_size(value, &dropdown_suffixes(dropdown)) {
        Some((number, idx)) => {
            entry.set_text(&number);
            dropdown.set_selected(idx as u32);
        }
        None => entry.set_text(""),
    }
}

fn unit_bytes(suffix: char) -> u64 {
    match suffix.to_ascii_uppercase() {
        'K' => 1 << 10,
        'M' => 1 << 20,
        'G' => 1 << 30,
        'T' => 1 << 40,
        _ => 1,
    }
}

/// `bytes / unit` with `decimals` decimal places, rounded up, trailing
/// zeros dropped. Rounding up matters: [`common::parse_size`] rounds the
/// fraction down, so a rounded-up number reads back as the same byte count.
fn scaled_decimal(bytes: u64, unit: u64, decimals: u32) -> String {
    let scale = 10u128.pow(decimals);
    let scaled = (u128::from(bytes) * scale).div_ceil(u128::from(unit));
    let whole = scaled / scale;
    let frac = scaled % scale;
    if frac == 0 {
        return whole.to_string();
    }
    let frac = format!("{frac:0width$}", width = decimals as usize);
    format!("{whole}.{}", frac.trim_end_matches('0'))
}

/// Split a size like "1.5G" into the number to show and the index of the
/// unit in `suffixes` (unit letters such as `['M', 'G']`), so that sending
/// the number with that unit gives the same byte count. A number written
/// in one of the offered units is kept as written; otherwise the largest
/// unit that shows it with at most three decimals is used. `None` when the
/// value is empty or not a size.
pub fn split_size(value: &str, suffixes: &[char]) -> Option<(String, usize)> {
    let value = value.trim();
    let bytes = common::parse_size(value).ok()?;
    if suffixes.is_empty() {
        return None;
    }
    let split = value
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(value.len());
    let (number, unit) = value.split_at(split);
    let unit_mult = unit.trim().chars().next().map_or(1, unit_bytes);
    if let Some(idx) = suffixes.iter().position(|s| unit_bytes(*s) == unit_mult) {
        return Some((number.to_string(), idx));
    }
    let reads_back = |text: &str, suffix: char| {
        common::parse_size(&format!("{text}{suffix}")).ok() == Some(bytes)
    };
    // The largest unit with a short number, then the smallest unit with as
    // many decimals as parse_size reads.
    let short = (0..suffixes.len())
        .rev()
        .flat_map(|idx| (0..=3).map(move |d| (idx, d)));
    let long = (4..=9).map(|d| (0, d));
    for (idx, d) in short.chain(long) {
        let text = scaled_decimal(bytes, unit_bytes(suffixes[idx]), d);
        if reads_back(&text, suffixes[idx]) {
            return Some((text, idx));
        }
    }
    Some((scaled_decimal(bytes, unit_bytes(suffixes[0]), 9), 0))
}

/// Parse a CPU value like "75%" and return just the number
pub fn parse_cpu_value(value: &str) -> String {
    value.trim().trim_end_matches('%').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: &[char] = &['K', 'M', 'G', 'T'];

    fn round_trips(value: &str, suffixes: &[char]) {
        let (number, idx) = split_size(value, suffixes).unwrap();
        let back = format!("{number}{}", suffixes[idx]);
        assert_eq!(
            common::parse_size(&back).unwrap(),
            common::parse_size(value).unwrap(),
            "{value} shown as {back}"
        );
    }

    #[test]
    fn sizes_in_an_offered_unit_keep_their_number() {
        assert_eq!(split_size("4G", ALL), Some(("4".into(), 2)));
        assert_eq!(split_size("1.5G", ALL), Some(("1.5".into(), 2)));
        assert_eq!(split_size("4GiB", ALL), Some(("4".into(), 2)));
        assert_eq!(split_size("512MB", ALL), Some(("512".into(), 1)));
        assert_eq!(split_size(" 512 mb ", ALL), Some(("512".into(), 1)));
        assert_eq!(split_size("100K", ALL), Some(("100".into(), 0)));
    }

    #[test]
    fn sizes_in_other_units_convert_exactly() {
        let mem = &['M', 'G'];
        assert_eq!(split_size("1T", mem), Some(("1024".into(), 1)));
        assert_eq!(split_size("512K", mem), Some(("0.5".into(), 0)));
        assert_eq!(split_size("8388608", mem), Some(("8".into(), 0)));
        assert_eq!(split_size("1536K", mem), Some(("1.5".into(), 0)));
        for v in ["1T", "512K", "8388608", "1536K", "100K", "1.3T", "7"] {
            round_trips(v, mem);
        }
    }

    #[test]
    fn unreadable_sizes_give_none() {
        assert_eq!(split_size("", ALL), None);
        assert_eq!(split_size("abc", ALL), None);
        assert_eq!(split_size("4X", ALL), None);
    }

    #[test]
    fn number_filter_keeps_one_decimal_point() {
        assert_eq!(filter_number("1.5", true), "1.5");
        assert_eq!(filter_number("1.5.2", true), "1.52");
        assert_eq!(filter_number("1.5", false), "15");
        assert_eq!(filter_number("4 GB", true), "4");
        assert_eq!(filter_number(&"9".repeat(30), true).len(), MAX_LIMIT_LEN);
    }
}

// Shared form widgets and utilities

use adw::prelude::*;

// Unit options. The first letter of each label is the suffix the value is
// sent with (K, M, G). Memory starts at MB because the minimum is 8 MB; I/O
// keeps KB/s because its minimum is 64 KB/s.
pub const MEMORY_UNITS: &[&str] = &["MB", "GB"];
pub const IO_UNITS: &[&str] = &["KB/s", "MB/s", "GB/s"];

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

fn unit_dropdown(units: &[&str]) -> gtk::DropDown {
    let list = gtk::StringList::new(units);
    let dropdown = gtk::DropDown::new(Some(list), gtk::Expression::NONE);
    dropdown.set_valign(gtk::Align::Center);
    // MB or MB/s to start with.
    dropdown.set_selected(units.iter().position(|u| u.starts_with('M')).unwrap_or(0) as u32);
    dropdown
}

/// Create a memory unit dropdown (MB/GB), MB selected
pub fn create_unit_dropdown() -> gtk::DropDown {
    unit_dropdown(MEMORY_UNITS)
}

/// Create an I/O unit dropdown (KB/s, MB/s, GB/s), MB/s selected
pub fn create_io_unit_dropdown() -> gtk::DropDown {
    unit_dropdown(IO_UNITS)
}

/// A flat button showing only `icon`, with `label` as both its tooltip and
/// the name screen readers announce.
pub fn icon_button(icon: &str, label: &str) -> gtk::Button {
    let button = gtk::Button::from_icon_name(icon);
    button.add_css_class("flat");
    button.set_tooltip_text(Some(label));
    button.update_property(&[gtk::accessible::Property::Label(label)]);
    button
}

/// Shown when rlm has no cgroup manager, so nothing can be limited.
pub const NO_MANAGER_HINT: &str =
    "Cannot set up cgroups for your user. Run rlm doctor in a terminal to see why.";

/// Make an action button insensitive, with [`NO_MANAGER_HINT`] as its
/// tooltip, when there is no cgroup manager.
pub fn require_manager(button: &gtk::Button, has_manager: bool) {
    if !has_manager {
        button.set_sensitive(false);
        button.set_tooltip_text(Some(NO_MANAGER_HINT));
    }
}

/// Put `page` above a bottom bar holding `status` and the page's main
/// `button`, so the button stays in view however far the page scrolls.
pub fn with_action_bar(
    page: &impl IsA<gtk::Widget>,
    status: &gtk::Label,
    button: &gtk::Button,
) -> adw::ToolbarView {
    let bar = gtk::Box::new(gtk::Orientation::Vertical, 6);
    bar.set_margin_top(6);
    bar.set_margin_bottom(6);
    bar.set_margin_start(12);
    bar.set_margin_end(12);
    bar.append(status);
    bar.append(button);
    let view = adw::ToolbarView::new();
    view.set_content(Some(page));
    view.add_bottom_bar(&bar);
    view.set_bottom_bar_style(adw::ToolbarStyle::Raised);
    view
}

/// Height of one list row with a subtitle, in pixels.
const LIST_ROW_HEIGHT: i32 = 56;
/// Rows a list shows before it scrolls.
const LIST_VISIBLE_ROWS: i32 = 6;

/// A scrolled window for a list; call [`fit_list_height`] after filling
/// the list.
pub fn list_scroller(list: &gtk::ListBox) -> gtk::ScrolledWindow {
    let scroll = gtk::ScrolledWindow::new();
    scroll.set_child(Some(list));
    scroll.set_hscrollbar_policy(gtk::PolicyType::Never);
    scroll.set_propagate_natural_height(true);
    scroll.set_max_content_height(LIST_ROW_HEIGHT * LIST_VISIBLE_ROWS);
    fit_list_height(list);
    scroll
}

/// Make the list's scrolled window as tall as its rows, up to about six,
/// so a short list takes no extra room and a long one scrolls.
pub fn fit_list_height(list: &gtk::ListBox) {
    let Some(scroll) = list
        .ancestor(gtk::ScrolledWindow::static_type())
        .and_downcast::<gtk::ScrolledWindow>()
    else {
        return;
    };
    let mut rows = 0;
    let mut child = list.first_child();
    while let Some(c) = child {
        rows += 1;
        child = c.next_sibling();
    }
    scroll.set_min_content_height(LIST_ROW_HEIGHT * rows.clamp(1, LIST_VISIBLE_ROWS));
}

/// A success toast whose "Open" button shows the Managed Processes page,
/// where the new limits can be seen and removed.
pub fn status_toast(text: &str, timeout: u32) -> adw::Toast {
    let toast = adw::Toast::new(text);
    toast.set_timeout(timeout);
    toast.set_button_label(Some("Open"));
    toast.set_action_name(Some("win.goto-status"));
    toast
}

/// Run `action` when Enter is pressed in any of `entries`.
pub fn on_enter(entries: &[&adw::EntryRow], action: impl Fn() + Clone + 'static) {
    for entry in entries {
        let action = action.clone();
        entry.connect_entry_activated(move |_| action());
    }
}

/// The dim "% of one core" text after a CPU field.
pub fn cpu_suffix_label() -> gtk::Label {
    let label = gtk::Label::new(Some("% of one core"));
    label.add_css_class("dim-label");
    label.set_margin_start(4);
    label
}

/// The description of a Limits group, with this computer's core count.
pub fn limits_description() -> String {
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    limits_description_for(cores)
}

fn limits_description_for(cores: usize) -> String {
    let cores = if cores == 1 {
        "1 core".to_string()
    } else {
        format!("{cores} cores")
    };
    format!(
        "Set at least one. Empty fields stay unlimited. For CPU, 100% is one core; \
         this computer has {cores}. Memory must be at least 8 MB and I/O at least 64 KB/s."
    )
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

/// A size field's text with its unit suffix ("1.5G"), or `None` when the
/// field is empty.
pub fn size_value(entry: &adw::EntryRow, unit: &gtk::DropDown) -> Option<String> {
    let text = entry.text();
    let text = text.trim();
    (!text.is_empty()).then(|| format!("{text}{}", get_unit_suffix(unit)))
}

/// A CPU field's text as a percentage ("50%"), or `None` when it is empty.
pub fn cpu_value(entry: &adw::EntryRow) -> Option<String> {
    let text = entry.text();
    let text = text.trim();
    (!text.is_empty()).then(|| format!("{text}%"))
}

/// Whether the number in a size such as "1.5G" is written out in full:
/// "5." and ".5" are not, though the field lets them be typed.
fn complete_number(value: &str) -> bool {
    let value = value.trim();
    let end = value
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(value.len());
    let number = &value[..end];
    !number.is_empty() && !number.starts_with('.') && !number.ends_with('.')
}

/// A limit parse error for the field `label`, in words for the GUI: no
/// "invalid memory value" prefix (it would be wrong for an I/O field) and
/// no command-line hint.
fn field_error(label: &str, value: &str, e: &common::Error) -> String {
    let text = e.to_string();
    let line = text.lines().next().unwrap_or("");
    let detail = line
        .strip_prefix("invalid memory value: ")
        .or_else(|| line.strip_prefix("invalid cpu value: "))
        .unwrap_or(line);
    // A parse error that only repeats the input says nothing new.
    if value.trim().trim_end_matches('%') == detail.trim() {
        format!("{label}: {} is not a valid value", value.trim())
    } else {
        format!("{label}: {detail}")
    }
}

/// The limits a form's fields ask for, or a message naming the field that
/// is wrong. `memory`, `io_read` and `io_write` are sizes with their unit
/// ("1.5G"), `cpu` a percentage ("50%"); `None` is an empty field.
pub fn form_limit(
    memory: Option<&str>,
    cpu: Option<&str>,
    io_read: Option<&str>,
    io_write: Option<&str>,
) -> Result<common::Limit, String> {
    let sizes = [
        ("Memory", memory),
        ("I/O Read", io_read),
        ("I/O Write", io_write),
    ];
    for (label, value) in sizes {
        if value.is_some_and(|v| !complete_number(v)) {
            return Err(format!("{label}: enter a number like 1.5"));
        }
    }
    if let Some(v) = memory {
        common::MemoryLimit::parse(v).map_err(|e| field_error("Memory", v, &e))?;
    }
    if let Some(v) = cpu {
        common::CpuLimit::parse(v).map_err(|e| field_error("CPU", v, &e))?;
    }
    for (label, value) in &sizes[1..] {
        if let Some(v) = value {
            common::IoLimit::parse_bps(v).map_err(|e| field_error(label, v, &e))?;
        }
    }
    common::build_limit(memory, cpu, io_read, io_write)
        .map_err(|e| e.to_string().lines().next().unwrap_or("").to_string())
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
    fn unit_labels_start_with_the_suffix_they_send() {
        let mem: Vec<char> = MEMORY_UNITS
            .iter()
            .filter_map(|u| u.chars().next())
            .collect();
        let io: Vec<char> = IO_UNITS.iter().filter_map(|u| u.chars().next()).collect();
        assert_eq!(mem, ['M', 'G']);
        assert_eq!(io, ['K', 'M', 'G']);
        // Saved values in units no longer offered still show exactly.
        assert_eq!(split_size("2T", &mem), Some(("2048".into(), 1)));
        assert_eq!(split_size("100K", &io), Some(("100".into(), 0)));
    }

    #[test]
    fn limits_description_names_the_core_count() {
        assert!(limits_description_for(1).contains("has 1 core."));
        assert!(limits_description_for(8).contains("100% is one core; this computer has 8 cores."));
    }

    #[test]
    fn half_typed_decimals_ask_for_a_number() {
        for v in ["5.M", ".5G"] {
            assert_eq!(
                form_limit(Some(v), None, None, None).unwrap_err(),
                "Memory: enter a number like 1.5"
            );
        }
        assert_eq!(
            form_limit(None, None, Some("5.M"), None).unwrap_err(),
            "I/O Read: enter a number like 1.5"
        );
        assert!(form_limit(Some("1.5G"), None, None, None).is_ok());
    }

    #[test]
    fn form_errors_name_the_field_in_gui_words() {
        let io = form_limit(None, None, None, Some("1K")).unwrap_err();
        assert_eq!(io, "I/O Write: 1K per second is below the 64K minimum");
        assert!(!io.to_lowercase().contains("memory"), "{io}");
        let mem = form_limit(Some("1M"), None, None, None).unwrap_err();
        assert!(
            mem.starts_with("Memory: 1M is below the 8M minimum"),
            "{mem}"
        );
        assert!(!mem.contains('\n'), "{mem}");
        assert_eq!(
            form_limit(None, Some("0%"), None, None).unwrap_err(),
            "CPU: value cannot be zero"
        );
        assert_eq!(
            form_limit(None, Some("50.5%"), None, None).unwrap_err(),
            "CPU: 50.5% is not a valid value"
        );
        let l = form_limit(Some("512M"), Some("50%"), Some("1M"), None).unwrap();
        assert_eq!(l.cpu.unwrap().percent(), 50);
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

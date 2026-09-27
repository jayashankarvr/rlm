pub mod guard;
pub mod limit;
pub mod profiles;
pub mod run;
pub mod status;

use adw::prelude::*;

/// Show `toast` in the toast overlay that contains `widget`. Does nothing if
/// `widget` is not inside one, for example before it is added to the window.
pub fn show_toast(widget: &impl IsA<gtk::Widget>, toast: adw::Toast) {
    if let Some(overlay) = widget
        .ancestor(adw::ToastOverlay::static_type())
        .and_then(|w| w.downcast::<adw::ToastOverlay>().ok())
    {
        overlay.add_toast(toast);
    }
}

/// An error as the GUI shows it: the first line only, since later lines are
/// hints for the command line (flags, shell commands).
pub fn gui_error(e: &common::Error) -> String {
    e.to_string().lines().next().unwrap_or("").to_string()
}

/// A toast whose title is shown as plain text, so names with `&` or `<` in
/// them are not read as markup.
pub fn plain_toast(title: &str) -> adw::Toast {
    adw::Toast::new(&gtk::glib::markup_escape_text(title))
}

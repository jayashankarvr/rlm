mod pages;
mod widgets;
mod window;

use adw::prelude::*;
use rlm_core::CgroupManager;
use std::sync::Arc;

const APP_ID: &str = "io.github.rlm.gtk";

fn main() -> gtk::glib::ExitCode {
    tracing_subscriber::fmt::init();

    let app = adw::Application::builder().application_id(APP_ID).build();

    app.connect_activate(build_ui);

    app.run()
}

fn build_ui(app: &adw::Application) {
    // Initialize cgroup manager
    let (manager, error) = match CgroupManager::new() {
        Ok(m) => (Some(Arc::new(m)), None),
        Err(e) => {
            tracing::error!("Failed to initialize cgroup manager: {e}");
            (None, Some(e.to_string()))
        }
    };

    let window = window::Window::new(app, manager);
    window.present();

    // Show error dialog if cgroup manager failed
    if let Some(err_msg) = error {
        let dialog = adw::MessageDialog::new(
            Some(&window),
            Some("Resource Limiting Unavailable"),
            Some(&format!(
                "Cannot manage resource limits: {}\n\n\
                 Run 'rlm doctor' in a terminal for setup instructions.",
                err_msg
            )),
        );
        dialog.add_response("ok", "OK");
        dialog.set_default_response(Some("ok"));
        dialog.present();
    }
}

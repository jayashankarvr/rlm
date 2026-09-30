mod icons;
mod pages;
mod widgets;
mod window;

use adw::prelude::*;
use rlm_core::CgroupManager;
use std::sync::Arc;

const APP_ID: &str = "io.github.rlm.gtk";

fn main() -> gtk::glib::ExitCode {
    rlm_core::logging::init(tracing::Level::WARN);
    // Read the installed apps' names off the UI thread; the pages that show
    // them wait for this read only if they need a name before it is done.
    std::thread::spawn(|| {
        rlm_core::appname::desktop_names();
    });

    let app = adw::Application::builder().application_id(APP_ID).build();

    app.connect_activate(build_ui);

    app.run()
}

fn build_ui(app: &adw::Application) {
    // Launching the app again while it runs brings the open window forward.
    if let Some(window) = app.active_window() {
        window.present();
        return;
    }

    // Without a cgroup manager the window shows a banner that says so.
    let manager = match CgroupManager::new() {
        Ok(m) => Some(Arc::new(m)),
        Err(e) => {
            tracing::error!("Failed to initialize cgroup manager: {e}");
            None
        }
    };

    let window = window::Window::new(app, manager);
    window.present();
}

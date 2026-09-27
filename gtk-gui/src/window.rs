use crate::pages;
use adw::prelude::*;
use adw::subclass::prelude::*;
use gtk::{gio, glib};
use rlm_core::CgroupManager;
use std::cell::RefCell;
use std::sync::Arc;

/// The sidebar pages, in display order: (id, title, icon). Ctrl+1 opens the
/// first, Ctrl+2 the second, and so on.
pub const NAV_PAGES: [(&str, &str, &str); 5] = [
    ("status", "Managed Processes", "view-list-symbolic"),
    ("limit", "Limit Running", "power-profile-balanced-symbolic"),
    ("run", "Launch New", "media-playback-start-symbolic"),
    ("profiles", "Profiles", "document-properties-symbolic"),
    ("guard", "Guard", "security-high-symbolic"),
];

/// The sidebar row index for a page id, or `None` if it isn't a nav page.
pub fn nav_index(page: &str) -> Option<usize> {
    NAV_PAGES.iter().position(|(id, _, _)| *id == page)
}

/// The keyboard shortcuts window, as GtkBuilder XML: one Ctrl+N entry per
/// sidebar page, then the general shortcuts.
fn shortcuts_ui() -> String {
    let shortcut = |accel: &str, title: &str| {
        format!(
            "<child><object class=\"GtkShortcutsShortcut\">\
             <property name=\"accelerator\">{}</property>\
             <property name=\"title\">{}</property>\
             </object></child>",
            glib::markup_escape_text(accel),
            glib::markup_escape_text(title)
        )
    };
    let pages: String = NAV_PAGES
        .iter()
        .enumerate()
        .map(|(i, (_, title, _))| shortcut(&format!("<Control>{}", i + 1), title))
        .collect();
    let general = [
        shortcut("<Control>question", "Keyboard Shortcuts"),
        shortcut("<Control>q", "Quit"),
    ]
    .concat();
    format!(
        "<interface><object class=\"GtkShortcutsWindow\" id=\"shortcuts\">\
         <property name=\"modal\">true</property>\
         <child><object class=\"GtkShortcutsSection\">\
         <property name=\"section-name\">shortcuts</property>\
         <child><object class=\"GtkShortcutsGroup\">\
         <property name=\"title\">Pages</property>{pages}</object></child>\
         <child><object class=\"GtkShortcutsGroup\">\
         <property name=\"title\">General</property>{general}</object></child>\
         </object></child></object></interface>"
    )
}

mod imp {
    use super::*;

    #[derive(Default)]
    pub struct Window {
        pub manager: RefCell<Option<Arc<CgroupManager>>>,
        pub sidebar: RefCell<Option<gtk::ListBox>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for Window {
        const NAME: &'static str = "RlmWindow";
        type Type = super::Window;
        type ParentType = adw::ApplicationWindow;
    }

    impl ObjectImpl for Window {}
    impl WidgetImpl for Window {}
    impl WindowImpl for Window {}
    impl ApplicationWindowImpl for Window {}
    impl AdwApplicationWindowImpl for Window {}
}

glib::wrapper! {
    pub struct Window(ObjectSubclass<imp::Window>)
        @extends adw::ApplicationWindow, gtk::ApplicationWindow, gtk::Window, gtk::Widget,
        @implements gio::ActionGroup, gio::ActionMap;
}

impl Window {
    pub fn new(app: &adw::Application, manager: Option<Arc<CgroupManager>>) -> Self {
        let window: Self = glib::Object::builder()
            .property("application", app)
            .property("title", "Resource Limit Manager")
            .property("default-width", 900)
            .property("default-height", 600)
            .build();

        window.imp().manager.replace(manager);
        window.setup_shortcuts(app);
        window.setup_ui();
        window
    }

    fn setup_shortcuts(&self, app: &adw::Application) {
        // Quit shortcut (Ctrl+Q)
        let quit_action = gio::SimpleAction::new("quit", None);
        let window = self.clone();
        quit_action.connect_activate(move |_, _| {
            window.close();
        });
        self.add_action(&quit_action);
        app.set_accels_for_action("win.quit", &["<Control>q"]);

        // Page navigation shortcuts (Ctrl+1 onwards). Selecting the sidebar
        // row (rather than switching the stack directly) keeps the highlight
        // in sync with the visible page.
        for (i, (id, _, _)) in NAV_PAGES.iter().enumerate() {
            let action = gio::SimpleAction::new(&format!("goto-{id}"), None);
            let window_clone = self.clone();
            action.connect_activate(move |_, _| {
                if let Some(list) = window_clone.imp().sidebar.borrow().as_ref() {
                    if let Some(row) = list.row_at_index(i as i32) {
                        list.select_row(Some(&row));
                    }
                }
            });
            self.add_action(&action);
            app.set_accels_for_action(&format!("win.goto-{id}"), &[&format!("<Control>{}", i + 1)]);
        }

        // Keyboard Shortcuts window: GtkApplicationWindow adds the
        // win.show-help-overlay action once a help overlay is set.
        let builder = gtk::Builder::from_string(&shortcuts_ui());
        if let Some(shortcuts) = builder.object::<gtk::ShortcutsWindow>("shortcuts") {
            self.set_help_overlay(Some(&shortcuts));
            app.set_accels_for_action("win.show-help-overlay", &["<Control>question"]);
        }

        let about_action = gio::SimpleAction::new("about", None);
        let window = self.clone();
        about_action.connect_activate(move |_, _| {
            window.show_about();
        });
        self.add_action(&about_action);
    }

    fn show_about(&self) {
        let about = adw::AboutWindow::builder()
            .transient_for(self)
            .modal(true)
            .application_name("Resource Limit Manager")
            .application_icon("io.github.rlm.gtk")
            .developer_name("Jayashankar")
            .version(env!("CARGO_PKG_VERSION"))
            .comments(
                "Set memory, CPU and I/O limits on your own processes with cgroups, and \
                 optionally let a guard freeze or cap a runaway app under memory pressure.",
            )
            .website("https://github.com/jayashankarvr/rlm")
            .issue_url("https://github.com/jayashankarvr/rlm/issues")
            .license_type(gtk::License::Apache20)
            .copyright("© 2025-2026 Jayashankar")
            .build();
        about.present();
    }

    fn manager(&self) -> Option<Arc<CgroupManager>> {
        self.imp().manager.borrow().clone()
    }

    fn primary_menu() -> gtk::MenuButton {
        let menu = gio::Menu::new();
        menu.append(Some("Keyboard Shortcuts"), Some("win.show-help-overlay"));
        menu.append(Some("About rlm"), Some("win.about"));
        let button = gtk::MenuButton::new();
        button.set_icon_name("open-menu-symbolic");
        button.set_menu_model(Some(&menu));
        button.set_tooltip_text(Some("Main Menu"));
        button
    }

    fn setup_ui(&self) {
        // Create content stack
        let content_stack = gtk::Stack::new();
        content_stack.set_transition_type(gtk::StackTransitionType::Crossfade);

        // Add pages
        let status_page = pages::status::create(self.manager());
        let limit_page = pages::limit::create(self.manager());
        let run_page = pages::run::create(self.manager());
        let profiles_page = pages::profiles::create();
        let guard_page = pages::guard::create();

        content_stack.add_named(&status_page, Some("status"));
        content_stack.add_named(&limit_page, Some("limit"));
        content_stack.add_named(&run_page, Some("run"));
        content_stack.add_named(&profiles_page, Some("profiles"));
        content_stack.add_named(&guard_page, Some("guard"));

        // Create sidebar
        let sidebar_list = gtk::ListBox::new();
        sidebar_list.set_selection_mode(gtk::SelectionMode::Single);
        sidebar_list.add_css_class("navigation-sidebar");

        for (id, title, icon) in NAV_PAGES {
            let row = Self::create_sidebar_row(id, title, icon);
            sidebar_list.append(&row);
        }

        self.imp().sidebar.replace(Some(sidebar_list.clone()));

        // Content area: header bar, then the pages under a toast overlay.
        // The header shows the content page's title, which follows the
        // selected sidebar row.
        let content_header = adw::HeaderBar::new();
        let content_toolbar = adw::ToolbarView::new();
        content_toolbar.add_top_bar(&content_header);
        let toast_overlay = adw::ToastOverlay::new();
        toast_overlay.set_child(Some(&content_stack));
        content_toolbar.set_content(Some(&toast_overlay));
        let content_page = adw::NavigationPage::new(&content_toolbar, NAV_PAGES[0].1);

        // Connect sidebar selection to stack
        let content_stack_clone = content_stack.clone();
        let content_page_clone = content_page.clone();
        let status_page_clone = status_page.clone();
        let limit_page_clone = limit_page.clone();
        let run_page_clone = run_page.clone();
        let guard_page_clone = guard_page.clone();
        let manager_clone = self.manager();
        sidebar_list.connect_row_selected(move |_, row| {
            let Some(row) = row else { return };
            let Some(id) = row
                .widget_name()
                .as_str()
                .strip_prefix("nav-")
                .map(str::to_string)
            else {
                return;
            };
            content_stack_clone.set_visible_child_name(&id);
            if let Some(i) = nav_index(&id) {
                content_page_clone.set_title(NAV_PAGES[i].1);
            }
            match id.as_str() {
                "status" => {
                    if let Some(ref mgr) = manager_clone {
                        pages::status::refresh(&status_page_clone, mgr.clone());
                    }
                }
                "limit" => {
                    pages::limit::refresh_profiles(&limit_page_clone);
                }
                "run" => {
                    pages::run::refresh_profiles(&run_page_clone);
                }
                "guard" => {
                    pages::guard::refresh(&guard_page_clone);
                }
                _ => {}
            }
        });

        // Select the status page by default.
        if let Some(idx) = nav_index("status") {
            if let Some(first_row) = sidebar_list.row_at_index(idx as i32) {
                sidebar_list.select_row(Some(&first_row));
            }
        }

        // Sidebar with header and the primary menu
        let sidebar_header = adw::HeaderBar::new();
        sidebar_header.pack_end(&Self::primary_menu());

        let sidebar_content = gtk::Box::new(gtk::Orientation::Vertical, 0);
        let sidebar_scroll = gtk::ScrolledWindow::new();
        sidebar_scroll.set_child(Some(&sidebar_list));
        sidebar_scroll.set_vexpand(true);
        sidebar_content.append(&sidebar_scroll);

        let sidebar_toolbar = adw::ToolbarView::new();
        sidebar_toolbar.add_top_bar(&sidebar_header);
        sidebar_toolbar.set_content(Some(&sidebar_content));

        // Create split view
        let split_view = adw::NavigationSplitView::new();

        let sidebar_page = adw::NavigationPage::new(&sidebar_toolbar, "RLM");

        split_view.set_sidebar(Some(&sidebar_page));
        split_view.set_content(Some(&content_page));
        split_view.set_min_sidebar_width(200.0);
        split_view.set_max_sidebar_width(280.0);

        self.set_content(Some(&split_view));

        // Start auto-refresh for the status and guard pages
        self.setup_auto_refresh(&content_stack, &status_page, &guard_page);
    }

    fn create_sidebar_row(id: &str, title: &str, icon_name: &str) -> gtk::ListBoxRow {
        debug_assert!(
            crate::icons::STOCK_ICONS.contains(&icon_name),
            "{icon_name} is not a stock Adwaita icon"
        );
        let row = gtk::ListBoxRow::new();
        row.set_widget_name(&format!("nav-{id}"));

        let hbox = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        hbox.set_margin_top(8);
        hbox.set_margin_bottom(8);
        hbox.set_margin_start(12);
        hbox.set_margin_end(12);

        let icon = gtk::Image::from_icon_name(icon_name);
        let label = gtk::Label::new(Some(title));
        label.set_halign(gtk::Align::Start);
        label.set_hexpand(true);

        hbox.append(&icon);
        hbox.append(&label);
        row.set_child(Some(&hbox));

        row
    }

    fn setup_auto_refresh(
        &self,
        stack: &gtk::Stack,
        status_page: &gtk::Widget,
        guard_page: &gtk::Widget,
    ) {
        let stack_clone = stack.clone();
        let status_page_clone = status_page.clone();
        let guard_page_clone = guard_page.clone();
        let manager = self.manager();

        glib::timeout_add_local(std::time::Duration::from_secs(2), move || {
            let visible = stack_clone.visible_child();
            if visible.as_ref() == Some(&status_page_clone) {
                if let Some(ref mgr) = manager {
                    pages::status::refresh(&status_page_clone, mgr.clone());
                }
            } else if visible.as_ref() == Some(&guard_page_clone) {
                pages::guard::refresh(&guard_page_clone);
            }
            glib::ControlFlow::Continue
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_page_has_a_sidebar_row_and_shortcut() {
        assert_eq!(nav_index("status"), Some(0));
        assert_eq!(nav_index("guard"), Some(NAV_PAGES.len() - 1));
        assert_eq!(nav_index("about"), None);
        assert_eq!(nav_index("nope"), None);
    }

    #[test]
    fn shortcuts_window_lists_every_page_and_quit() {
        let ui = shortcuts_ui();
        for (i, (_, title, _)) in NAV_PAGES.iter().enumerate() {
            assert!(ui.contains(&format!("&lt;Control&gt;{}", i + 1)), "{ui}");
            assert!(ui.contains(title), "{title} missing");
        }
        assert!(ui.contains("&lt;Control&gt;q"));
        assert!(!ui.contains(&format!("&lt;Control&gt;{}", NAV_PAGES.len() + 1)));
    }
}

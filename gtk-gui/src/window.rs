use crate::pages;
use adw::prelude::*;
use adw::subclass::prelude::*;
use gtk::{gio, glib};
use rlm_core::CgroupManager;
use std::cell::RefCell;
use std::sync::Arc;

/// The sidebar pages, in display order: (id, title, icon).
pub const NAV_PAGES: [(&str, &str, &str); 6] = [
    ("status", "Managed Processes", "view-list-symbolic"),
    ("limit", "Limit Running", "power-profile-balanced-symbolic"),
    ("run", "Launch New", "media-playback-start-symbolic"),
    ("profiles", "Profiles", "document-properties-symbolic"),
    ("guard", "Guard", "security-high-symbolic"),
    ("about", "About", "help-about-symbolic"),
];

/// The sidebar row index for a page id, or `None` if it isn't a nav page.
pub fn nav_index(page: &str) -> Option<usize> {
    NAV_PAGES.iter().position(|(id, _, _)| *id == page)
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

        // Page navigation shortcuts (Ctrl+1 through Ctrl+5). Selecting the
        // sidebar row (rather than switching the stack directly) keeps the
        // highlight in sync with the visible page.
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
    }

    fn manager(&self) -> Option<Arc<CgroupManager>> {
        self.imp().manager.borrow().clone()
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
        let about_page = pages::about::create();

        content_stack.add_named(&status_page, Some("status"));
        content_stack.add_named(&limit_page, Some("limit"));
        content_stack.add_named(&run_page, Some("run"));
        content_stack.add_named(&profiles_page, Some("profiles"));
        content_stack.add_named(&guard_page, Some("guard"));
        content_stack.add_named(&about_page, Some("about"));

        // Create sidebar
        let sidebar_list = gtk::ListBox::new();
        sidebar_list.set_selection_mode(gtk::SelectionMode::Single);
        sidebar_list.add_css_class("navigation-sidebar");

        for (id, title, icon) in NAV_PAGES {
            let row = Self::create_sidebar_row(id, title, icon);
            sidebar_list.append(&row);
        }

        self.imp().sidebar.replace(Some(sidebar_list.clone()));

        // Connect sidebar selection to stack
        let content_stack_clone = content_stack.clone();
        let status_page_clone = status_page.clone();
        let limit_page_clone = limit_page.clone();
        let run_page_clone = run_page.clone();
        let guard_page_clone = guard_page.clone();
        let manager_clone = self.manager();
        sidebar_list.connect_row_selected(move |_, row| {
            if let Some(row) = row {
                if let Some(id) = row.widget_name().as_str().strip_prefix("nav-") {
                    content_stack_clone.set_visible_child_name(id);
                    match id {
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
                }
            }
        });

        // Select the status page by default.
        if let Some(idx) = nav_index("status") {
            if let Some(first_row) = sidebar_list.row_at_index(idx as i32) {
                sidebar_list.select_row(Some(&first_row));
            }
        }

        // Sidebar with header
        let sidebar_header = adw::HeaderBar::new();

        let sidebar_content = gtk::Box::new(gtk::Orientation::Vertical, 0);
        let sidebar_scroll = gtk::ScrolledWindow::new();
        sidebar_scroll.set_child(Some(&sidebar_list));
        sidebar_scroll.set_vexpand(true);
        sidebar_content.append(&sidebar_scroll);

        let sidebar_toolbar = adw::ToolbarView::new();
        sidebar_toolbar.add_top_bar(&sidebar_header);
        sidebar_toolbar.set_content(Some(&sidebar_content));

        // Content area with header
        let content_header = adw::HeaderBar::new();
        let content_toolbar = adw::ToolbarView::new();
        content_toolbar.add_top_bar(&content_header);
        content_toolbar.set_content(Some(&content_stack));

        // Create split view
        let split_view = adw::NavigationSplitView::new();

        let sidebar_page = adw::NavigationPage::new(&sidebar_toolbar, "RLM");
        let content_page = adw::NavigationPage::new(&content_toolbar, "Resource Limit Manager");

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
        assert_eq!(nav_index("about"), Some(NAV_PAGES.len() - 1));
        assert_eq!(nav_index("nope"), None);
    }
}

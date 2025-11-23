use crate::pages;
use adw::prelude::*;
use adw::subclass::prelude::*;
use gtk::{gio, glib};
use rlm_core::CgroupManager;
use std::cell::RefCell;
use std::sync::Arc;

mod imp {
    use super::*;

    #[derive(Default)]
    pub struct Window {
        pub manager: RefCell<Option<Arc<CgroupManager>>>,
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

        // Page navigation shortcuts (Ctrl+1 through Ctrl+5)
        for (i, page) in ["status", "limit", "run", "profiles", "about"]
            .iter()
            .enumerate()
        {
            let action = gio::SimpleAction::new(&format!("goto-{page}"), None);
            let page_name = page.to_string();
            let window_clone = self.clone();
            action.connect_activate(move |_, _| {
                if let Some(stack) = window_clone.find_content_stack() {
                    stack.set_visible_child_name(&page_name);
                }
            });
            self.add_action(&action);
            app.set_accels_for_action(
                &format!("win.goto-{page}"),
                &[&format!("<Control>{}", i + 1)],
            );
        }
    }

    fn find_content_stack(&self) -> Option<gtk::Stack> {
        // Navigate through the widget hierarchy to find the stack
        let content = self.content()?;
        let split_view = content.downcast::<adw::NavigationSplitView>().ok()?;
        let content_page = split_view.content()?;
        let toolbar = content_page.child().and_downcast::<adw::ToolbarView>()?;
        toolbar.content().and_downcast::<gtk::Stack>()
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
        let about_page = pages::about::create();

        content_stack.add_named(&status_page, Some("status"));
        content_stack.add_named(&limit_page, Some("limit"));
        content_stack.add_named(&run_page, Some("run"));
        content_stack.add_named(&profiles_page, Some("profiles"));
        content_stack.add_named(&about_page, Some("about"));

        // Create sidebar
        let sidebar_list = gtk::ListBox::new();
        sidebar_list.set_selection_mode(gtk::SelectionMode::Single);
        sidebar_list.add_css_class("navigation-sidebar");

        let nav_items = [
            (
                "status",
                "Managed Processes",
                "utilities-system-monitor-symbolic",
            ),
            ("limit", "Limit Running", "speedometer-symbolic"),
            ("run", "Launch New", "media-playback-start-symbolic"),
            ("profiles", "Profiles", "document-properties-symbolic"),
            ("about", "About", "help-about-symbolic"),
        ];

        for (id, title, icon) in nav_items {
            let row = Self::create_sidebar_row(id, title, icon);
            sidebar_list.append(&row);
        }

        // Connect sidebar selection to stack
        let content_stack_clone = content_stack.clone();
        sidebar_list.connect_row_selected(move |_, row| {
            if let Some(row) = row {
                if let Some(id) = row.widget_name().as_str().strip_prefix("nav-") {
                    content_stack_clone.set_visible_child_name(id);
                }
            }
        });

        // Select first item by default
        if let Some(first_row) = sidebar_list.row_at_index(0) {
            sidebar_list.select_row(Some(&first_row));
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

        // Start auto-refresh for status page
        self.setup_auto_refresh(&content_stack, &status_page);
    }

    fn create_sidebar_row(id: &str, title: &str, icon_name: &str) -> gtk::ListBoxRow {
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

    fn setup_auto_refresh(&self, stack: &gtk::Stack, status_page: &gtk::Widget) {
        let stack_clone = stack.clone();
        let status_page_clone = status_page.clone();
        let manager = self.manager();

        glib::timeout_add_local(std::time::Duration::from_secs(2), move || {
            if stack_clone.visible_child().as_ref() == Some(&status_page_clone) {
                if let Some(ref mgr) = manager {
                    pages::status::refresh(&status_page_clone, mgr.clone());
                }
            }
            glib::ControlFlow::Continue
        });
    }
}

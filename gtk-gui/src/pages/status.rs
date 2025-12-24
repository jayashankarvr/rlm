use adw::prelude::*;
use common::format_bytes;
use gtk::glib;
use rlm_core::CgroupManager;
use std::sync::Arc;

pub fn create(manager: Option<Arc<CgroupManager>>) -> gtk::Widget {
    let page = adw::PreferencesPage::new();
    page.set_title("Status");
    page.set_icon_name(Some("view-list-symbolic"));

    // Process list group
    let group = adw::PreferencesGroup::new();
    group.set_title("Managed Processes");
    group.set_description(Some("Processes with active resource limits"));

    // Refresh button in header
    let refresh_btn = gtk::Button::from_icon_name("view-refresh-symbolic");
    refresh_btn.add_css_class("flat");
    refresh_btn.set_tooltip_text(Some("Refresh process list"));
    group.set_header_suffix(Some(&refresh_btn));

    let list_box = gtk::ListBox::new();
    list_box.set_selection_mode(gtk::SelectionMode::None);
    list_box.add_css_class("boxed-list");
    list_box.set_widget_name("status-list-box");

    // Empty state
    let empty_row = adw::ActionRow::new();
    empty_row.set_title("No managed processes");
    empty_row.set_subtitle("Use the Limit or Run tabs to manage processes");
    list_box.append(&empty_row);

    group.add(&list_box);
    page.add(&group);

    // Initial refresh
    if let Some(ref mgr) = manager {
        do_refresh(&list_box, mgr.clone());

        // Refresh button handler
        let list_box_clone = list_box.clone();
        let mgr_clone = mgr.clone();
        refresh_btn.connect_clicked(move |_| {
            do_refresh(&list_box_clone, mgr_clone.clone());
        });
    }

    page.upcast()
}

pub fn refresh(widget: &gtk::Widget, manager: Arc<CgroupManager>) {
    // Find the list box by name (recursive search)
    if let Some(list_box) = find_widget_by_name(widget, "status-list-box") {
        if let Some(list_box) = list_box.downcast_ref::<gtk::ListBox>() {
            do_refresh(list_box, manager);
        }
    }
}

fn find_widget_by_name(widget: &gtk::Widget, name: &str) -> Option<gtk::Widget> {
    if widget.widget_name() == name {
        return Some(widget.clone());
    }
    let mut child = widget.first_child();
    while let Some(c) = child {
        if let Some(found) = find_widget_by_name(&c, name) {
            return Some(found);
        }
        child = c.next_sibling();
    }
    None
}

fn do_refresh(list_box: &gtk::ListBox, manager: Arc<CgroupManager>) {
    // Clear existing rows
    while let Some(child) = list_box.first_child() {
        list_box.remove(&child);
    }

    // Get managed processes
    match rlm_core::status::get_managed_processes(&manager) {
        Ok(processes) => {
            if processes.is_empty() {
                let empty_row = adw::ActionRow::new();
                empty_row.set_title("No managed processes");
                empty_row.set_subtitle("Use the Limit or Run tabs to manage processes");
                list_box.append(&empty_row);
            } else {
                for proc in processes {
                    let row = create_process_row(&proc, manager.clone(), list_box);
                    list_box.append(&row);
                }
            }
        }
        Err(e) => {
            let error_row = adw::ActionRow::new();
            error_row.set_title("Error loading processes");
            error_row.set_subtitle(&e.to_string());
            error_row.add_css_class("error");
            list_box.append(&error_row);
        }
    }
}

fn create_process_row(
    proc: &rlm_core::status::ProcessStatus,
    manager: Arc<CgroupManager>,
    list_box: &gtk::ListBox,
) -> adw::ActionRow {
    let row = adw::ActionRow::new();
    row.set_title(&format!(
        "{} (PID {})",
        glib::markup_escape_text(&proc.name),
        proc.pid
    ));

    // Build subtitle with limits
    let mut limits = Vec::new();
    if let Some(mem) = proc.memory_max {
        limits.push(format!("Memory: {}", format_bytes(mem)));
    }
    if let Some(cpu) = proc.cpu_quota {
        limits.push(format!("CPU: {}%", cpu));
    }
    if let Some(r) = proc.io_read_bps {
        limits.push(format!("I/O Read: {}/s", format_bytes(r)));
    }
    if let Some(w) = proc.io_write_bps {
        limits.push(format!("I/O Write: {}/s", format_bytes(w)));
    }

    if limits.is_empty() {
        row.set_subtitle("No limits set");
    } else {
        row.set_subtitle(&limits.join(" | "));
    }

    // Remove button
    let remove_btn = gtk::Button::from_icon_name("user-trash-symbolic");
    remove_btn.set_valign(gtk::Align::Center);
    remove_btn.add_css_class("flat");
    remove_btn.set_tooltip_text(Some("Remove limits"));

    let cgroup_name = proc.cgroup_name.clone();
    let list_box_clone = list_box.clone();
    let manager_clone = manager.clone();
    remove_btn.connect_clicked(move |_| {
        if let Err(e) = manager_clone.cleanup_cgroup(&cgroup_name) {
            tracing::error!("Failed to remove limit: {e}");
        } else {
            do_refresh(&list_box_clone, manager_clone.clone());
        }
    });

    row.add_suffix(&remove_btn);
    row.set_activatable(false);
    row
}

use adw::prelude::*;

pub fn create() -> gtk::Widget {
    let page = adw::PreferencesPage::new();
    page.set_title("About");
    page.set_icon_name(Some("help-about-symbolic"));

    // App info group
    let info_group = adw::PreferencesGroup::new();

    let title_label = gtk::Label::new(Some("Resource Limit Manager"));
    title_label.add_css_class("title-1");
    title_label.set_margin_top(24);
    title_label.set_margin_bottom(12);

    let version_label = gtk::Label::new(Some(&format!("Version {}", env!("CARGO_PKG_VERSION"))));
    version_label.add_css_class("dim-label");
    version_label.set_margin_bottom(24);

    let desc_label = gtk::Label::new(Some(
        "A Linux resource management tool that prevents system freezes through proactive cgroup-based resource limiting.",
    ));
    desc_label.set_wrap(true);
    desc_label.set_justify(gtk::Justification::Center);
    desc_label.set_margin_bottom(24);

    let header_box = gtk::Box::new(gtk::Orientation::Vertical, 0);
    header_box.set_halign(gtk::Align::Center);
    header_box.append(&title_label);
    header_box.append(&version_label);
    header_box.append(&desc_label);

    info_group.add(&header_box);
    page.add(&info_group);

    // Links group
    let links_group = adw::PreferencesGroup::new();
    links_group.set_title("Links");

    let repo_row = adw::ActionRow::new();
    repo_row.set_title("Repository");
    repo_row.set_subtitle("https://github.com/jayashankarvr/rlm");
    repo_row.set_activatable(true);
    repo_row.add_suffix(&gtk::Image::from_icon_name("external-link-symbolic"));
    repo_row.connect_activated(|_| {
        let _ = open::that("https://github.com/jayashankarvr/rlm");
    });
    links_group.add(&repo_row);

    let issues_row = adw::ActionRow::new();
    issues_row.set_title("Report Issues");
    issues_row.set_subtitle("https://github.com/jayashankarvr/rlm/issues");
    issues_row.set_activatable(true);
    issues_row.add_suffix(&gtk::Image::from_icon_name("external-link-symbolic"));
    issues_row.connect_activated(|_| {
        let _ = open::that("https://github.com/jayashankarvr/rlm/issues");
    });
    links_group.add(&issues_row);

    page.add(&links_group);

    // License group
    let license_group = adw::PreferencesGroup::new();
    license_group.set_title("License");

    let license_row = adw::ActionRow::new();
    license_row.set_title("Apache License 2.0");
    license_row.set_subtitle("Open source license allowing commercial use");
    license_group.add(&license_row);

    let license_text = gtk::TextView::new();
    license_text.set_editable(false);
    license_text.set_cursor_visible(false);
    license_text.set_wrap_mode(gtk::WrapMode::Word);
    license_text.set_margin_top(12);
    license_text.set_margin_bottom(12);
    license_text.set_margin_start(12);
    license_text.set_margin_end(12);
    license_text.buffer().set_text(LICENSE_TEXT);

    let license_scroll = gtk::ScrolledWindow::new();
    license_scroll.set_child(Some(&license_text));
    license_scroll.set_min_content_height(200);
    license_scroll.set_max_content_height(200);
    license_scroll.add_css_class("card");

    license_group.add(&license_scroll);
    page.add(&license_group);

    // Credits group
    let credits_group = adw::PreferencesGroup::new();
    credits_group.set_title("Credits");

    let credits_row = adw::ActionRow::new();
    credits_row.set_title("RLM Contributors");
    credits_row.set_subtitle("Thank you to all contributors!");
    credits_group.add(&credits_row);

    page.add(&credits_group);

    page.upcast()
}

const LICENSE_TEXT: &str = r#"Copyright 2025 Jayashankar

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License."#;

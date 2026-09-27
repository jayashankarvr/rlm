//! Icon names the GUI may use. Each ships with the stock Adwaita icon theme,
//! except `adw-external-link-symbolic`, which libadwaita bundles itself.
pub const STOCK_ICONS: &[&str] = &[
    "view-list-symbolic",
    "power-profile-balanced-symbolic",
    "media-playback-start-symbolic",
    "document-properties-symbolic",
    "security-high-symbolic",
    "help-about-symbolic",
    "view-refresh-symbolic",
    "list-add-symbolic",
    "document-edit-symbolic",
    "user-trash-symbolic",
    "dialog-warning-symbolic",
    "adw-external-link-symbolic",
];

#[cfg(test)]
mod tests {
    use super::STOCK_ICONS;

    const SOURCES: &[(&str, &str)] = &[
        ("window.rs", include_str!("window.rs")),
        ("pages/about.rs", include_str!("pages/about.rs")),
        ("pages/guard.rs", include_str!("pages/guard.rs")),
        ("pages/limit.rs", include_str!("pages/limit.rs")),
        ("pages/profiles.rs", include_str!("pages/profiles.rs")),
        ("pages/run.rs", include_str!("pages/run.rs")),
        ("pages/status.rs", include_str!("pages/status.rs")),
    ];

    #[test]
    fn every_icon_name_used_is_stock() {
        for (file, src) in SOURCES {
            for lit in src
                .split('"')
                .filter(|s| s.ends_with("-symbolic") && !s.contains(' '))
            {
                assert!(
                    STOCK_ICONS.contains(&lit),
                    "{file} uses {lit}, which stock Adwaita does not ship"
                );
            }
        }
    }
}

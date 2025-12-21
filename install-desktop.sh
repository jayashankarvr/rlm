#!/bin/bash
# Install rlm-gui desktop entry and icons

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_ID="io.github.rlm.gtk"

# Determine install prefix
if [ "$1" = "--system" ] || [ "$(id -u)" = "0" ]; then
    DESKTOP_DIR="/usr/share/applications"
    ICON_DIR="/usr/share/icons/hicolor"
else
    DESKTOP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
    ICON_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor"
fi

echo "Installing desktop entry to: $DESKTOP_DIR"
echo "Installing icons to: $ICON_DIR"

# Create directories
mkdir -p "$DESKTOP_DIR"
mkdir -p "$ICON_DIR/scalable/apps"
mkdir -p "$ICON_DIR/symbolic/apps"

# Install desktop file
cp "$SCRIPT_DIR/gtk-gui/assets/$APP_ID.desktop" "$DESKTOP_DIR/"

# Install icons
cp "$SCRIPT_DIR/gtk-gui/assets/rlm-icon.svg" "$ICON_DIR/scalable/apps/$APP_ID.svg"
cp "$SCRIPT_DIR/gtk-gui/assets/rlm-symbolic.svg" "$ICON_DIR/symbolic/apps/$APP_ID-symbolic.svg"

# Update icon cache (if gtk-update-icon-cache is available)
if command -v gtk-update-icon-cache &> /dev/null; then
    gtk-update-icon-cache -f -t "$ICON_DIR" 2>/dev/null || true
fi

# Update desktop database (if update-desktop-database is available)
if command -v update-desktop-database &> /dev/null; then
    update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
fi

echo "Done! You may need to log out and back in for the icon to appear."

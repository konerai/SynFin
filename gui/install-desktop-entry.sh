#!/bin/sh
# Adds SynFin to the desktop's application menu for the current user (no root needed).
# Usage: gui/install-desktop-entry.sh [--uninstall]
set -e

GUI_DIR=$(cd "$(dirname "$0")" && pwd)
DATA_HOME=${XDG_DATA_HOME:-$HOME/.local/share}
DESKTOP_FILE=$DATA_HOME/applications/synfin.desktop
SIZES="16 24 32 48 64 128 256 512"

refresh() {
    command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q "$DATA_HOME/applications" || true
    command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q -t "$DATA_HOME/icons/hicolor" || true
}

if [ "$1" = "--uninstall" ]; then
    rm -f "$DESKTOP_FILE"
    for size in $SIZES; do
        rm -f "$DATA_HOME/icons/hicolor/${size}x${size}/apps/synfin.png"
    done
    refresh
    echo "SynFin removed from the application menu."
    exit 0
fi

for size in $SIZES; do
    mkdir -p "$DATA_HOME/icons/hicolor/${size}x${size}/apps"
    cp "$GUI_DIR/icons/synfin-$size.png" "$DATA_HOME/icons/hicolor/${size}x${size}/apps/synfin.png"
done

mkdir -p "$DATA_HOME/applications"
cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Name=SynFin
GenericName=TCP Session Analyzer
Comment=Reconstruct TCP sessions from .pcap captures
Exec=python3 "$GUI_DIR/synfin_gui.py"
Path=$GUI_DIR
Icon=synfin
Terminal=false
Categories=Network;Monitor;
Keywords=pcap;tcp;network;capture;session;
StartupWMClass=Synfin
EOF

refresh
echo "SynFin added to the application menu ($DESKTOP_FILE)."

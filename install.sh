#!/usr/bin/env bash
# install.sh -- build and install Ubuntu Deep Uninstaller onto this machine.
#
# Usage: ./install.sh
# Run from the project root (the directory this script lives in), as your
# normal user -- it will ask for sudo itself, only for the two steps that
# actually need it (installing build dependencies, copying binaries into
# /usr/bin). It never runs as root as a whole, and it never writes to your
# home directory as root.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
BIN_DIR="/usr/bin"
DESKTOP_DIR="/usr/share/applications"
MANIFEST_DIR="$HOME/.local/state/ubuntu-deep-uninstaller"
MANIFEST="$MANIFEST_DIR/install-manifest.txt"

if [ "$(id -u)" -eq 0 ]; then
    echo "Please run this as your normal user, not as root/with sudo." >&2
    echo "The script will ask for sudo itself for the specific steps that need it." >&2
    exit 1
fi

echo "== Ubuntu Deep Uninstaller installer =="
echo "Project root: $PROJECT_ROOT"
echo

# --- 1. Check build dependencies -------------------------------------------
MISSING=()
command -v cmake  >/dev/null 2>&1 || MISSING+=(cmake)
command -v g++    >/dev/null 2>&1 || MISSING+=(build-essential)
command -v pkg-config >/dev/null 2>&1 || MISSING+=(pkg-config)
if ! pkg-config --exists gtk4 2>/dev/null; then MISSING+=(libgtk-4-dev); fi
if ! pkg-config --exists libadwaita-1 2>/dev/null; then MISSING+=(libadwaita-1-dev); fi

if [ "${#MISSING[@]}" -gt 0 ]; then
    echo "Missing build dependencies: ${MISSING[*]}"
    read -r -p "Install them now with 'sudo apt install'? [y/N] " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        sudo apt update
        sudo apt install -y "${MISSING[@]}"
    else
        echo "Cannot continue without these packages. Re-run install.sh after installing them yourself:"
        echo "  sudo apt install ${MISSING[*]}"
        exit 1
    fi
fi
echo

# --- 2. Configure + build ---------------------------------------------------
echo "Configuring and building (this can take a minute)..."
cmake -B "$BUILD_DIR" -S "$PROJECT_ROOT" -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build "$BUILD_DIR" -j"$(nproc)"
echo

if [ ! -x "$BUILD_DIR/ubuntu-deep-uninstaller-gui" ]; then
    echo "NOTE: the GUI target did not build (GTK4/libadwaita dev packages were not found"
    echo "at configure time). The CLI and context-menu integration below still work fully"
    echo "without it -- re-run install.sh after installing libgtk-4-dev/libadwaita-1-dev if"
    echo "you also want the GUI."
    echo
fi

# --- 3. Run the test suite (abort install on a regression) -----------------
if [ -x "$BUILD_DIR/udu_tests" ]; then
    echo "Running the test suite..."
    if ! "$BUILD_DIR/udu_tests"; then
        echo "Tests FAILED -- aborting install. This should not happen on an unmodified" >&2
        echo "checkout; if you've edited the source, fix the failing test(s) first." >&2
        exit 1
    fi
    echo
fi

# --- 4. Install binaries + desktop entry (requires sudo) --------------------
echo "Installing to $BIN_DIR (requires sudo)..."
sudo install -m 755 "$BUILD_DIR/ubuntu-deep-uninstaller" "$BIN_DIR/ubuntu-deep-uninstaller"
INSTALLED_GUI=0
if [ -x "$BUILD_DIR/ubuntu-deep-uninstaller-gui" ]; then
    sudo install -m 755 "$BUILD_DIR/ubuntu-deep-uninstaller-gui" "$BIN_DIR/ubuntu-deep-uninstaller-gui"
    INSTALLED_GUI=1
fi
sudo install -m 644 "$PROJECT_ROOT/packaging/org.uduninstaller.UbuntuDeepUninstaller.desktop" \
    "$DESKTOP_DIR/org.uduninstaller.UbuntuDeepUninstaller.desktop"
echo

# --- 5. Record what we installed, for uninstall.sh --------------------------
mkdir -p "$MANIFEST_DIR"
{
    echo "$BIN_DIR/ubuntu-deep-uninstaller"
    [ "$INSTALLED_GUI" -eq 1 ] && echo "$BIN_DIR/ubuntu-deep-uninstaller-gui"
    echo "$DESKTOP_DIR/org.uduninstaller.UbuntuDeepUninstaller.desktop"
} > "$MANIFEST"

# --- 6. Register the context-menu action for the CURRENT user ---------------
# Deliberately NOT run as root: the override files this writes go under
# THIS user's own ~/.local/share/applications/, which is exactly where they
# need to be for this user's GNOME Shell session to find them.
echo "Registering the 'Uninstall Completely' context-menu action for your account..."
"$BIN_DIR/ubuntu-deep-uninstaller" --sync-integration
echo

echo "================================================================"
echo " Install complete."
echo "================================================================"
echo
echo "Installed:"
echo "  $BIN_DIR/ubuntu-deep-uninstaller"
[ "$INSTALLED_GUI" -eq 1 ] && echo "  $BIN_DIR/ubuntu-deep-uninstaller-gui"
echo "  $DESKTOP_DIR/org.uduninstaller.UbuntuDeepUninstaller.desktop"
echo
echo "IMPORTANT: log out and back in (GNOME Shell on Wayland has no live-reload"
echo "for application actions), or on X11 run: killall -3 gnome-shell"
echo
echo "After that, right-click any application in the GNOME app grid and look for"
echo "'Uninstall Completely'."
[ "$INSTALLED_GUI" -eq 1 ] && echo "You can also just run: ubuntu-deep-uninstaller-gui"
echo
echo "To remove this tool later, run: $PROJECT_ROOT/uninstall.sh"

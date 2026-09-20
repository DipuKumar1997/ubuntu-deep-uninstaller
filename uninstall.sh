#!/usr/bin/env bash
# uninstall.sh -- remove Ubuntu Deep Uninstaller from this machine.
#
# Usage: ./uninstall.sh
# Run as your normal user (not root) -- it asks for sudo only for the
# system-file removal step.
set -euo pipefail

MANIFEST_DIR="$HOME/.local/state/ubuntu-deep-uninstaller"
MANIFEST="$MANIFEST_DIR/install-manifest.txt"

if [ "$(id -u)" -eq 0 ]; then
    echo "Please run this as your normal user, not as root/with sudo." >&2
    exit 1
fi

echo "== Ubuntu Deep Uninstaller -- removing this tool =="
echo

# --- 1. Remove installed binaries + desktop entry ---------------------------
if [ -f "$MANIFEST" ]; then
    echo "Using install manifest: $MANIFEST"
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        if [ -e "$f" ]; then
            echo "Removing $f"
            sudo rm -f "$f"
        fi
    done < "$MANIFEST"
    rm -f "$MANIFEST"
else
    echo "No install manifest found at $MANIFEST (maybe installed a different way)."
    echo "Falling back to the well-known default paths:"
    for f in /usr/bin/ubuntu-deep-uninstaller /usr/bin/ubuntu-deep-uninstaller-gui \
             /usr/share/applications/org.uduninstaller.UbuntuDeepUninstaller.desktop; do
        if [ -e "$f" ]; then
            echo "Removing $f"
            sudo rm -f "$f"
        fi
    done
fi
echo

# --- 2. Offer to remove the context-menu overrides it wrote everywhere else -
# These live under the CURRENT user's own ~/.local/share/applications/ (each
# override carries a distinctive "[Desktop Action UduUninstall]" group), and
# are inert once the binary above is gone, but leaving them around is untidy.
MATCHES=()
if [ -d "$HOME/.local/share/applications" ]; then
    while IFS= read -r -d '' f; do
        MATCHES+=("$f")
    done < <(grep -rlZ "UduUninstall" "$HOME/.local/share/applications" 2>/dev/null || true)
fi

if [ "${#MATCHES[@]}" -gt 0 ]; then
    echo "This tool also wrote 'Uninstall Completely' context-menu overrides for"
    echo "${#MATCHES[@]} application(s) to your own ~/.local/share/applications/."
    read -r -p "Remove those overrides too? [y/N] " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        for f in "${MATCHES[@]}"; do
            echo "Removing override: $f"
            rm -f "$f"
        done
    else
        echo "Leaving the overrides in place (they are harmless now that the binary is gone)."
    fi
else
    echo "No context-menu overrides found under ~/.local/share/applications/."
fi
echo

echo "================================================================"
echo " Uninstall complete."
echo "================================================================"
echo "Log out and back in (or restart GNOME Shell on X11 with"
echo "'killall -3 gnome-shell') for any removed menu items to disappear."

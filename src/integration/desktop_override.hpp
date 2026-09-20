// integration/desktop_override.hpp
//
// Implements the GNOME context-menu integration described in Phase 1:
// rather than editing package-owned files under /usr/share/applications
// (which dpkg would silently revert and flag as modified), we write a
// user-local override into ~/.local/share/applications/<same-id>.desktop.
// Per the XDG Desktop Entry spec, a user-local file with the same
// desktop-file-ID takes precedence over the system one, and GNOME Shell's
// app grid renders Desktop Actions from whichever file wins that
// precedence -- so our "Uninstall Completely" action appears, and every
// other key (Name, Icon, Exec, existing Actions=...) is carried over
// byte-for-byte from the original so nothing else about the app's
// behavior changes.
//
// The original system file is NEVER modified. A pristine copy of it is
// additionally archived under this tool's state directory so "uninstall
// the uninstaller" can cleanly remove every override it created.
#pragma once

#include <string>
#include <vector>
#include "../desktop_entry.hpp"

namespace udu::integration {

struct OverrideResult {
    bool success = false;
    std::string override_path;
    std::string message;
};

// Writes (or refreshes) the override for `entry`, adding an
// "Uninstall Completely" Desktop Action that invokes
// `uninstaller_binary --uninstall-by-desktop-id <original-path> %k` while
// preserving every existing key and every existing Desktop Action found in
// `entry`. Idempotent: re-running it just regenerates the override from
// the current system file, so package upgrades of the underlying app are
// picked up automatically the next time sync runs.
OverrideResult install_override(const DesktopEntry& entry, const std::string& uninstaller_binary);

// Removes a previously-installed override (used by both "undo this app's
// integration" and by the uninstaller's own self-uninstall path).
bool remove_override(const std::string& desktop_id);

// Regenerates overrides for every application desktop file found under the
// system application directories that isn't already NoDisplay and doesn't
// already have our action installed. Returns how many were (re)written.
// This is the operation the GUI's "Refresh integration" action triggers.
struct SyncSummary {
    int created = 0;
    int refreshed = 0;
    int skipped = 0;
    std::vector<std::string> errors;
};
SyncSummary sync_all(const std::string& uninstaller_binary);

}  // namespace udu::integration

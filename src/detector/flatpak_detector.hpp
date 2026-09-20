// detector/flatpak_detector.hpp
//
// Detects Flatpak applications from the Exec= pattern GNOME/flatpak itself
// generates ("/usr/bin/flatpak run --branch=... <app-id>" or similar), then
// enriches with `flatpak info`. Removal is always delegated to
// `flatpak uninstall` -- this detector never inspects
// ~/.local/share/flatpak or /var/lib/flatpak file-by-file.
#pragma once

#include <optional>
#include <string>
#include "types.hpp"
#include "../desktop_entry.hpp"

namespace udu::detector {

// Operates on the raw Exec= line (before field-code stripping is fine too;
// the app-id token itself contains no field codes) plus the desktop file's
// own path, since flatpak-exported desktop files live under a
// recognizable path (~/.local/share/flatpak/exports/... or
// /var/lib/flatpak/exports/...).
std::optional<DetectionResult> detect_flatpak(const DesktopEntry& entry);

}  // namespace udu::detector

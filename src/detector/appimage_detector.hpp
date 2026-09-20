// detector/appimage_detector.hpp
//
// Detects AppImage applications by resolving Exec= to a file ending in
// .AppImage (following at most one level of wrapper-script indirection).
// Never searches the filesystem for files "containing" the app name.
#pragma once

#include <optional>
#include <string>
#include "types.hpp"
#include "../desktop_entry.hpp"

namespace udu::detector {

std::optional<DetectionResult> detect_appimage(const DesktopEntry& entry);

}  // namespace udu::detector

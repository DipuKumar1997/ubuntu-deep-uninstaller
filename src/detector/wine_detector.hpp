// detector/wine_detector.hpp
//
// Detects Windows applications launched through Wine. The critical safety
// property here is prefix-sharing detection: if other .desktop files also
// point into the same WINEPREFIX, we must never offer to delete the whole
// prefix, only the application's own subtree under drive_c.
#pragma once

#include <optional>
#include <string>
#include "types.hpp"
#include "../desktop_entry.hpp"

namespace udu::detector {

std::optional<DetectionResult> detect_wine(const DesktopEntry& entry);

}  // namespace udu::detector

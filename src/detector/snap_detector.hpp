// detector/snap_detector.hpp
//
// Detects Snap applications from the Exec= pattern
// (/snap/bin/<name> or /snap/bin/<name>.<app>), enriched with `snap info`.
// Removal is always delegated to `snap remove`.
#pragma once

#include <optional>
#include <string>
#include "types.hpp"
#include "../desktop_entry.hpp"

namespace udu::detector {

std::optional<DetectionResult> detect_snap(const DesktopEntry& entry);

}  // namespace udu::detector

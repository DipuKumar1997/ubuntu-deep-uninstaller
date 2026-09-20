// detector/manual_detector.hpp
//
// Last-resort detector for executables that aren't owned by dpkg, aren't
// Flatpak/Snap launchers, aren't Wine, and aren't an AppImage. Covers
// hand-installed binaries under /opt, /usr/local, ~/.local/bin, ~/bin,
// ~/Applications, or a manually compiled program anywhere else the
// resolved Exec= path points.
//
// This detector is intentionally the most conservative: it only ever
// proposes the resolved executable itself (High confidence, it's literally
// what Exec= pointed at) and, separately, the executable's *immediate*
// parent directory as a Medium-confidence candidate -- and only when that
// parent directory looks like an application-private directory rather than
// a shared system location.
#pragma once

#include <optional>
#include <string>
#include "types.hpp"
#include "../desktop_entry.hpp"

namespace udu::detector {

std::optional<DetectionResult> detect_manual(const DesktopEntry& entry);

}  // namespace udu::detector

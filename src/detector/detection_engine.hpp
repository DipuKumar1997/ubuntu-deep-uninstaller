// detector/detection_engine.hpp
//
// Runs the individual detectors in the order that makes evidentiary sense
// (pattern-specific detectors before the generic fallback), also checks
// whether the application is currently running, and returns exactly one
// DetectionResult -- the first confident match, or an Unknown result
// carrying whatever partial evidence was gathered.
#pragma once

#include "types.hpp"
#include "../desktop_entry.hpp"

namespace udu::detector {

DetectionResult run_detection(const DesktopEntry& entry);

}  // namespace udu::detector

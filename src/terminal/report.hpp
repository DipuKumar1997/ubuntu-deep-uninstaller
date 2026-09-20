// terminal/report.hpp
//
// Formats a DetectionResult / RemovalPlan into the human-readable,
// forensic-log style terminal output described in the project spec:
// [CHECK] / [FOUND] / [SKIP] / [REMOVE] / [WARNING] / [ERROR] / [VERIFY] /
// [SUCCESS] status-tagged lines. Pure formatting -- no side effects.
#pragma once

#include <string>
#include "../detector/types.hpp"
#include "../desktop_entry.hpp"
#include "../planner/removal_plan.hpp"
#include "../verification/verify.hpp"

namespace udu::terminal {

std::string banner(const std::string& title);

std::string format_detection(const DesktopEntry& entry, const detector::DetectionResult& result);

std::string format_plan(const planner::RemovalPlan& plan);

std::string format_verification(const verification::VerificationReport& report);

}  // namespace udu::terminal

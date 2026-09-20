// detector/apt_detector.hpp
//
// Detects whether a resolved executable belongs to an APT/dpkg package,
// using `dpkg -S` (reverse file-to-package lookup) as the ONLY identity
// source -- never string comparison between package name and app name.
#pragma once

#include <optional>
#include <string>
#include "types.hpp"

namespace udu::detector {

// `resolved_executable` must already be an absolute, canonicalized path
// (see common::resolve_exec_target). Returns std::nullopt if the path is
// not owned by any dpkg package (not an APT-installed app, or dpkg itself
// is unavailable).
std::optional<DetectionResult> detect_apt(const std::string& resolved_executable);

}  // namespace udu::detector

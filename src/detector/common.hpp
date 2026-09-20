// detector/common.hpp
//
// Small helpers shared across detectors: resolving the first whitespace-
// separated token of an Exec= line to a real executable path, and building
// *candidate* (never auto-applied) user-space resource guesses under the
// standard XDG base directories. These candidates are always attached at
// Medium or Low confidence and are subject to further validation
// (existence + evidence of actually belonging to the app) before the
// planner will ever mark them Remove.
#pragma once

#include <string>
#include <vector>
#include <optional>
#include "types.hpp"

namespace udu::detector::common {

// Splits an Exec= value (already stripped of field codes) into argv-like
// tokens, respecting simple quoting per the Desktop Entry spec's exec
// grammar. Good enough for "get me the first token" use; this project
// never re-executes this string through a shell.
std::vector<std::string> tokenize_exec(const std::string& exec_no_field_codes);

// Resolves the first token of Exec= to an absolute path:
//  - if it already contains '/', canonicalize it directly
//  - otherwise, search $PATH the same way execvp would
// Returns std::nullopt if it cannot be resolved to an existing file.
std::optional<std::string> resolve_exec_target(const std::string& first_token);

std::string home_dir();

// For a given lowercase candidate name (e.g. a package name, or the
// lowercased leaf of a resolved binary path), returns the set of
// ~/.config/<name>, ~/.cache/<name>, ~/.local/share/<name>,
// ~/.local/state/<name> paths that currently EXIST on disk. Existence is
// checked here so callers only ever see real candidates, never invented
// paths -- but existence alone is still only Medium/Low confidence
// evidence of ownership (the directory could coincidentally share a name).
struct XdgGuess {
    std::string path;
    ResourceType type;
};
std::vector<XdgGuess> existing_xdg_candidates(const std::string& candidate_name);

// Autostart entries (~/.config/autostart/*.desktop and
// /etc/xdg/autostart/*.desktop) whose Exec= resolves to the same
// executable target as `resolved_executable`. This is evidence-based (we
// parse and compare, not name-match).
std::vector<std::string> matching_autostart_entries(const std::string& resolved_executable);

}  // namespace udu::detector::common

// uninstall/history.hpp
//
// Records a durable log of applications this tool has successfully
// uninstalled, and reads it back. Shared by both the CLI and the GUI (the
// CLI's --uninstall and the GUI's "Uninstall Completely" both ultimately
// call uninstall::execute_plan(), which is where a success gets recorded --
// so history works identically no matter which front-end was used).
#pragma once

#include <string>
#include <vector>
#include "../planner/removal_plan.hpp"

namespace udu::uninstall {

struct HistoryEntry {
    std::string timestamp;   // ISO-8601-ish, human-readable
    std::string app_name;
    std::string source;      // "APT", "Flatpak", "Snap", "Wine", "AppImage", "Manual installation"
};

// Appends one entry. Called automatically by execute_plan() on success;
// exposed here too in case a caller wants to record something outside
// that path. Best-effort: a failure to write history never fails the
// uninstall itself, it just means that one entry doesn't show up later.
void record_history(const std::string& app_name, const std::string& source);

// Reads all recorded entries, oldest first.
std::vector<HistoryEntry> read_history();

// Path to the history file, exposed so the GUI/CLI can tell the user
// where it lives (e.g. "copy this file", or a "clear history" hint).
std::string history_file_path();

}  // namespace udu::uninstall

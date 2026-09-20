// uninstall/executor.hpp
//
// Executes an already-built, already-confirmed RemovalPlan. This is the
// ONLY module in the project allowed to mutate the system, and it only
// ever acts on PlannedResource entries that survived planner validation
// (PlannedResource::validated == true) and were not skipped.
//
// Per-source removal logic (apt/flatpak/snap/wine/appimage/manual) is
// implemented as separate functions below -- logically the same module
// boundaries as the architecture's uninstall/apt_uninstaller,
// uninstall/flatpak_uninstaller, etc. They are kept in one translation
// unit for now because they are individually small (a handful of lines of
// package-manager invocation or filesystem removal each); splitting into
// separate .cpp files is a mechanical follow-up with no behavior change.
#pragma once

#include <string>
#include <vector>
#include "../planner/removal_plan.hpp"

namespace udu::uninstall {

struct ExecutionLogLine {
    std::string tag;   // "[REMOVE]", "[SUCCESS]", "[ERROR]", "[SKIP]", "[WARNING]"
    std::string text;
};

struct ExecutionOptions {
    bool purge_apt_configs = false;         // apt purge vs apt remove
    bool include_warn_items = false;        // also act on RemoveWithWarning items
    bool run_autoremove_if_offered = false; // only ever set true after the user
                                             // explicitly approved the shown autoremove set
};

struct ExecutionResult {
    std::vector<ExecutionLogLine> log;
    bool overall_success = false;
};

// Executes the plan. Assumes the caller has ALREADY obtained the "type
// UNINSTALL to continue" confirmation described in the project spec --
// this function performs no interactive prompting itself, so it can be
// driven identically by the terminal frontend and by tests.
ExecutionResult execute_plan(const planner::RemovalPlan& plan, const ExecutionOptions& options);

}  // namespace udu::uninstall

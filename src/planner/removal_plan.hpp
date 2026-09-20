// planner/removal_plan.hpp
//
// Turns a DetectionResult into an immutable RemovalPlan. This is the
// single point where "evidence" becomes "things we are proposing to do",
// and it is the ONLY object the execution layer is allowed to act on --
// the executor never re-derives targets itself.
//
// Every PlannedResource has already been through
// security::validate_removal_target() by the time build_plan() returns, so
// a plan that survives construction is, by definition, made only of
// resources that resolved to real paths under evidence-derived roots and
// were not caught by the catastrophic-path backstop.
#pragma once

#include <string>
#include <vector>
#include <optional>
#include "../detector/types.hpp"
#include "../desktop_entry.hpp"

namespace udu::planner {

enum class PlanAction { Remove, RemoveWithWarning, Skip };

struct PlannedResource {
    std::string path;
    detector::ResourceType type;
    detector::Confidence confidence;
    std::string reason;              // why we're doing what we're doing
    PlanAction action;
    bool requires_sudo;
    bool validated;                  // passed validate_removal_target
};

struct RemovalPlan {
    std::string application_name;
    std::string desktop_entry_path;
    detector::InstallationSource source;
    detector::Confidence source_confidence;
    std::optional<detector::PackageInfo> package;
    std::optional<std::string> wine_prefix;
    bool wine_prefix_is_shared = false;

    std::vector<PlannedResource> resources;
    std::vector<std::string> dependencies_would_remove;   // from apt simulate, informational
    std::vector<std::string> dependencies_kept_shared;    // explicitly NOT touched
    std::vector<std::string> warnings;
    std::vector<std::string> evidence_trail;

    bool app_currently_running = false;
    std::vector<std::string> running_process_lines;

    [[nodiscard]] size_t remove_count() const;
    [[nodiscard]] size_t skip_count() const;
    [[nodiscard]] bool has_high_risk_items() const;  // e.g. RemoveWithWarning items present
};

// Builds a plan from a detection result. `entry` supplies the application
// name and desktop-entry path (always included as the first resource to
// remove, since it belongs to this tool's own integration layer or to the
// user's local override regardless of installation source).
RemovalPlan build_plan(const DesktopEntry& entry, const detector::DetectionResult& detection);

}  // namespace udu::planner

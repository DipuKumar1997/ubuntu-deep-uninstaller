#include "removal_plan.hpp"
#include "../security/paths.hpp"

namespace udu::planner {

size_t RemovalPlan::remove_count() const {
    size_t n = 0;
    for (const auto& r : resources) if (r.action != PlanAction::Skip) ++n;
    return n;
}

size_t RemovalPlan::skip_count() const {
    size_t n = 0;
    for (const auto& r : resources) if (r.action == PlanAction::Skip) ++n;
    return n;
}

bool RemovalPlan::has_high_risk_items() const {
    for (const auto& r : resources) if (r.action == PlanAction::RemoveWithWarning) return true;
    return false;
}

namespace {

bool is_package_like(detector::ResourceType t) {
    return t == detector::ResourceType::Package;
}

}  // namespace

RemovalPlan build_plan(const DesktopEntry& entry, const detector::DetectionResult& detection) {
    RemovalPlan plan;
    plan.application_name = entry.name.empty() ? entry.desktop_id : entry.name;
    plan.desktop_entry_path = entry.source_path;
    plan.source = detection.source;
    plan.source_confidence = detection.overall_confidence;
    plan.package = detection.package;
    plan.wine_prefix = detection.wine_prefix;
    plan.wine_prefix_is_shared = detection.wine_prefix_is_shared;
    plan.warnings = detection.warnings;
    plan.evidence_trail = detection.evidence_trail;
    plan.app_currently_running = detection.running.is_running;
    plan.running_process_lines = detection.running.pids_and_cmdlines;

    if (detection.package) {
        plan.dependencies_would_remove = detection.package->would_also_remove;
        plan.dependencies_kept_shared = detection.package->kept_shared_dependencies;
    }

    // The desktop entry itself (or, per the integration layer, the user's
    // local override copy of it) is always the first planned resource.
    {
        PlannedResource pr;
        pr.path = entry.source_path;
        pr.type = detector::ResourceType::DesktopEntry;
        pr.confidence = detector::Confidence::High;
        pr.reason = "the launcher entry that identified this application";
        pr.requires_sudo = entry.source_path.rfind("/usr/", 0) == 0;
        auto validation = udu::security::validate_removal_target(entry.source_path, {entry.source_path});
        pr.validated = validation.safe_to_remove;
        pr.action = pr.validated ? PlanAction::Remove : PlanAction::Skip;
        if (!pr.validated) pr.reason += " (VALIDATION FAILED: " + validation.reason + ")";
        plan.resources.push_back(pr);
    }

    for (const auto& res : detection.resources) {
        PlannedResource pr;
        pr.path = res.path;
        pr.type = res.type;
        pr.confidence = res.confidence;
        pr.reason = res.evidence;
        pr.requires_sudo = !res.user_owned;

        if (is_package_like(res.type)) {
            // Packages/Flatpak-IDs/Snap-names are not filesystem paths, so
            // they never go through validate_removal_target -- they are
            // handed to the package manager's own resolver, which is the
            // authoritative "does this exist and what does removing it
            // affect" check (already run during detection).
            pr.validated = true;
        } else {
            auto validation = udu::security::validate_removal_target(res.path, res.allowed_roots);
            pr.validated = validation.safe_to_remove;
            if (!pr.validated) pr.reason += " (VALIDATION FAILED: " + validation.reason + ")";
        }

        switch (res.recommended_action) {
            case detector::PlannedAction::Remove:
                pr.action = pr.validated ? PlanAction::Remove : PlanAction::Skip;
                break;
            case detector::PlannedAction::WarnBeforeRemove:
                pr.action = pr.validated ? PlanAction::RemoveWithWarning : PlanAction::Skip;
                break;
            case detector::PlannedAction::SkipShared:
            case detector::PlannedAction::SkipLowConfidence:
                pr.action = PlanAction::Skip;
                break;
        }

        // Low-confidence items are never auto-Removed regardless of what
        // the detector recommended, as a second independent backstop.
        if (res.confidence == detector::Confidence::Low && pr.action == PlanAction::Remove) {
            pr.action = PlanAction::RemoveWithWarning;
        }

        plan.resources.push_back(pr);
    }

    return plan;
}

}  // namespace udu::planner

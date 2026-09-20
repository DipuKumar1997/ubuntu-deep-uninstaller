#include "report.hpp"
#include "color.hpp"
#include <sstream>

namespace udu::terminal {

using detector::Confidence;
using detector::to_string;

std::string banner(const std::string& title) {
    std::ostringstream os;
    std::string line(40, '=');
    // Blue is used specifically for section banners -- the visual anchor
    // that tells the user "a new phase of the active operation is
    // starting" (Detection / Removal Plan / Verification), independent of
    // the individual [TAG] colors used for line-by-line status below.
    os << color::blue_bold(line) << "\n " << color::blue_bold(title) << "\n"
       << color::blue_bold(line) << "\n";
    return os.str();
}

std::string format_detection(const DesktopEntry& entry, const detector::DetectionResult& result) {
    std::ostringstream os;
    os << "Application: " << (entry.name.empty() ? entry.desktop_id : entry.name) << "\n";
    os << "Desktop Entry:\n  " << entry.source_path << "\n\n";
    os << color::tag("[CHECK]") << " Parsing desktop entry...\n";
    os << color::tag("[FOUND]") << " Exec= " << entry.exec << "\n\n";

    os << color::tag("[CHECK]") << " Resolving installation source...\n";
    for (const auto& line : result.evidence_trail) {
        os << color::tag("[FOUND]") << " " << line << "\n";
    }
    if (result.source == detector::InstallationSource::Unknown) {
        os << color::tag("[WARNING]") << " Installation source could not be determined with confidence.\n";
    } else {
        os << color::tag("[FOUND]") << " Installation source: " << to_string(result.source)
           << "  (confidence: " << to_string(result.overall_confidence) << ")\n";
    }
    os << "\n";

    if (result.running.is_running) {
        os << color::tag("[WARNING]") << " This application appears to be currently running:\n";
        for (const auto& p : result.running.pids_and_cmdlines) os << "    " << p << "\n";
        os << "\n";
    }

    for (const auto& w : result.warnings) {
        os << color::tag("[WARNING]") << " " << w << "\n";
    }
    if (!result.warnings.empty()) os << "\n";

    return os.str();
}

namespace {
std::string action_tag(planner::PlanAction a) {
    switch (a) {
        case planner::PlanAction::Remove: return color::tag("[REMOVE]");
        case planner::PlanAction::RemoveWithWarning: return color::tag("[REMOVE*]");
        case planner::PlanAction::Skip: return color::tag("[SKIP]") + "  ";
    }
    return "[?]";
}
}  // namespace

std::string format_plan(const planner::RemovalPlan& plan) {
    std::ostringstream os;
    os << "REMOVAL PLAN\n------------\n\n";
    os << "Application:\n  " << plan.application_name << "\n\n";
    os << "Source:\n  " << to_string(plan.source)
       << " (confidence: " << to_string(plan.source_confidence) << ")\n\n";

    if (plan.package) {
        os << "Package:\n  " << plan.package->name;
        if (!plan.package->version.empty()) os << " " << plan.package->version;
        os << (plan.package->manually_installed ? "  [manually installed]" : "  [auto-installed dependency]")
           << "\n\n";
    }

    if (plan.wine_prefix) {
        os << "Wine prefix:\n  " << *plan.wine_prefix
           << (plan.wine_prefix_is_shared ? "  [SHARED with other applications -- will NOT be removed]" : "")
           << "\n\n";
    }

    os << "Planned resources (" << plan.remove_count() << " to act on, "
       << plan.skip_count() << " skipped):\n\n";
    for (const auto& r : plan.resources) {
        os << "  " << action_tag(r.action) << " [" << to_string(r.type) << "] " << r.path << "\n";
        os << "           reason: " << r.reason << "\n";
        if (r.requires_sudo) os << "           requires elevated privileges\n";
    }
    os << "\n";

    if (!plan.dependencies_would_remove.empty()) {
        os << "The following packages would ALSO be removed (transitive dependencies with\n"
              "no other reverse-dependency):\n";
        for (const auto& d : plan.dependencies_would_remove) os << "  - " << d << "\n";
        os << "\n";
    }
    if (!plan.dependencies_kept_shared.empty()) {
        os << "The following dependencies will NOT be removed because other installed\n"
              "packages still depend on them:\n";
        for (const auto& d : plan.dependencies_kept_shared) os << "  - " << d << "\n";
        os << "\n";
    }

    if (plan.app_currently_running) {
        os << color::tag("[WARNING]") << " Application is currently running:\n";
        for (const auto& p : plan.running_process_lines) os << "    " << p << "\n";
        os << "\n";
    }

    for (const auto& w : plan.warnings) os << color::tag("[WARNING]") << " " << w << "\n";
    if (!plan.warnings.empty()) os << "\n";

    if (plan.has_high_risk_items()) {
        os << color::tag("[WARNING]")
           << " This plan contains items marked [REMOVE*] -- these are lower-\n"
              "confidence or explicitly optional removals (e.g. an entire Wine prefix, or a\n"
              "name-matched XDG directory). They require SEPARATE confirmation at execution\n"
              "time and are not included in the default removal set.\n\n";
    }

    return os.str();
}

std::string format_verification(const verification::VerificationReport& report) {
    std::ostringstream os;
    os << "Verification:\n\n";
    for (const auto& item : report.items) {
        std::string tag = "[VERIFY]";
        std::string status_word;
        switch (item.status) {
            case verification::ItemStatus::Removed: status_word = "REMOVED"; break;
            case verification::ItemStatus::StillPresent: status_word = "STILL PRESENT"; tag = "[WARNING]"; break;
            case verification::ItemStatus::NotApplicableSkipped: status_word = "SKIPPED (not selected)"; break;
            case verification::ItemStatus::CouldNotVerify: status_word = "COULD NOT VERIFY"; break;
        }
        os << color::tag(tag) << " " << item.label << "\n";
        os << "         " << status_word << " -- " << item.detail << "\n";
    }
    os << "\n";
    os << (report.all_clear() ? color::tag("[SUCCESS]") + " Deep cleanup completed.\n"
                               : color::tag("[WARNING]") + " Some items remain; see above for reasons.\n");
    return os.str();
}

}  // namespace udu::terminal

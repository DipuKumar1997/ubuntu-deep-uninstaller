#include "snap_detector.hpp"
#include "common.hpp"
#include "../security/proc_exec.hpp"
#include "../security/debug_log.hpp"

#include <regex>

namespace udu::detector {

namespace {
using udu::security::run;

std::optional<std::string> extract_snap_name(const std::string& exec) {
    // /snap/bin/foo, /snap/bin/foo.bar-app, /var/lib/snapd/snap/bin/foo
    static const std::regex re(R"((?:/snap/bin/|/var/lib/snapd/snap/bin/)([A-Za-z0-9+._-]+))");
    std::smatch m;
    if (!std::regex_search(exec, m, re)) return std::nullopt;
    std::string token = m[1].str();
    // Strip a ".<app>" suffix if present -- the snap NAME is before the dot.
    auto dot = token.find('.');
    return dot == std::string::npos ? token : token.substr(0, dot);
}
}  // namespace

std::optional<DetectionResult> detect_snap(const DesktopEntry& entry) {
    UDU_LOG("detect_snap(): checking Exec='" + entry.exec + "' against the snap launcher pattern");
    auto name = extract_snap_name(entry.exec);
    if (!name) return std::nullopt;

    DetectionResult result;
    result.source = InstallationSource::Snap;
    result.evidence_trail.push_back(
        "Exec= line matched the snap launcher path pattern -> candidate snap name '" + *name + "'");
    result.overall_confidence = Confidence::High;

    PackageInfo pinfo;
    pinfo.name = *name;
    pinfo.manually_installed = true;

    if (udu::security::executable_exists("snap")) {
        auto info = run({"snap", "info", *name});
        if (info.ok()) {
            for (auto& line : std::vector<std::string>{}) (void)line;  // no-op, keep simple
            // Look for "installed:" line for revision/version.
            std::istringstream is(info.stdout_text);
            std::string line;
            while (std::getline(is, line)) {
                if (line.rfind("installed:", 0) == 0) {
                    pinfo.version = line.substr(10);
                    result.evidence_trail.push_back("snap info: " + line);
                }
            }
        } else {
            result.warnings.push_back(
                "'snap info " + *name + "' did not confirm this snap is currently installed; "
                "the name was recovered from the Exec= path and may be stale.");
            result.overall_confidence = Confidence::Medium;
        }
    } else {
        result.warnings.push_back("The 'snap' command is not available on this system; "
                                   "cannot verify installation state.");
        result.overall_confidence = Confidence::Medium;
    }
    result.package = pinfo;

    Resource r;
    r.path = *name;
    r.type = ResourceType::Package;
    r.confidence = result.overall_confidence;
    r.evidence = "Snap package name derived from the launcher path; removed via 'snap remove', "
                "never by manual deletion under /snap";
    r.user_owned = false;
    r.recommended_action = PlannedAction::Remove;
    result.resources.push_back(r);

    result.warnings.push_back(
        "'snap remove' retains a data snapshot by default; pass a purge option if you want it "
        "gone immediately -- this will be offered explicitly at confirmation time, not assumed.");

    return result;
}

}  // namespace udu::detector

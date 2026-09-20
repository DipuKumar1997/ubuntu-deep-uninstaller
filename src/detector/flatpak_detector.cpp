#include "flatpak_detector.hpp"
#include "common.hpp"
#include "../security/proc_exec.hpp"
#include "../security/debug_log.hpp"

#include <regex>
#include <sstream>

namespace udu::detector {

namespace {
using udu::security::run;

// Matches the app-id out of an Exec= like:
//   /usr/bin/flatpak run --branch=stable --arch=x86_64 --command=foo org.example.Foo
//   flatpak run org.example.Foo @@u %u @@
std::optional<std::string> extract_app_id_from_exec(const std::string& exec) {
    static const std::regex re(R"(flatpak\s+run\s+(?:--[A-Za-z0-9_=./-]+\s+)*([A-Za-z0-9_.-]+\.[A-Za-z0-9_.-]+))");
    std::smatch m;
    if (std::regex_search(exec, m, re)) return m[1].str();
    return std::nullopt;
}

// flatpak-exported desktop files live under a recognizable exports path;
// their filename IS the app-id.
std::optional<std::string> extract_app_id_from_export_path(const std::string& path) {
    static const std::regex re(R"(flatpak/exports/share/applications/([A-Za-z0-9_.-]+)\.desktop$)");
    std::smatch m;
    if (std::regex_search(path, m, re)) return m[1].str();
    return std::nullopt;
}

}  // namespace

std::optional<DetectionResult> detect_flatpak(const DesktopEntry& entry) {
    UDU_LOG("detect_flatpak(): checking Exec='" + entry.exec + "' against the flatpak pattern");
    auto app_id = extract_app_id_from_exec(entry.exec);
    std::string id_evidence = "Exec= line matched the 'flatpak run ... <app-id>' pattern";
    if (!app_id) {
        app_id = extract_app_id_from_export_path(entry.source_path);
        id_evidence = "desktop file path is under a flatpak exports/ directory, "
                      "filename is the application ID";
    }
    if (!app_id) return std::nullopt;

    DetectionResult result;
    result.source = InstallationSource::Flatpak;
    result.evidence_trail.push_back(id_evidence + ": " + *app_id);
    result.overall_confidence = Confidence::High;

    bool have_flatpak = udu::security::executable_exists("flatpak");
    std::string scope = "unknown";
    if (have_flatpak) {
        auto user_info = run({"flatpak", "info", "--user", *app_id});
        auto system_info = run({"flatpak", "info", "--system", *app_id});
        if (user_info.ok()) {
            scope = "user";
            result.evidence_trail.push_back("flatpak info --user: installed (per-user scope)");
        } else if (system_info.ok()) {
            scope = "system";
            result.evidence_trail.push_back("flatpak info --system: installed (system-wide scope)");
        } else {
            result.warnings.push_back(
                "'flatpak info' could not confirm " + *app_id + " in either scope; the "
                "application ID was recovered from the desktop entry but may be stale.");
            result.overall_confidence = Confidence::Medium;
        }
    } else {
        result.warnings.push_back("The 'flatpak' command is not available on this system; "
                                   "cannot verify installation scope or enrich package details.");
        result.overall_confidence = Confidence::Medium;
    }

    PackageInfo pinfo;
    pinfo.name = *app_id;
    pinfo.manually_installed = true;  // flatpak has no separate auto/manual concept exposed here
    result.package = pinfo;

    Resource app_resource;
    app_resource.path = *app_id;
    app_resource.type = ResourceType::Package;
    app_resource.confidence = result.overall_confidence;
    app_resource.evidence = "Flatpak application ID (" + scope + " scope); removed via "
                            "'flatpak uninstall', never by manual file deletion";
    app_resource.user_owned = (scope == "user");
    app_resource.recommended_action = PlannedAction::Remove;
    result.resources.push_back(app_resource);

    result.warnings.push_back(
        "Unused runtimes are NEVER removed automatically by this tool. If you want to also "
        "prune unused Flatpak runtimes afterward, run 'flatpak uninstall --unused' yourself "
        "and review its own list first.");

    return result;
}

}  // namespace udu::detector

// detector/types.hpp
//
// The evidence model. Every detector produces a DetectionResult built from
// these types; the planner consumes DetectionResults and never talks to
// the filesystem or a package manager directly -- it only reasons about
// evidence that has already been gathered and recorded here. This keeps
// "why are we about to delete this" auditable end-to-end.
#pragma once

#include <string>
#include <vector>
#include <optional>

namespace udu::detector {

enum class Confidence { High, Medium, Low };

[[nodiscard]] constexpr const char* to_string(Confidence c) {
    switch (c) {
        case Confidence::High: return "HIGH";
        case Confidence::Medium: return "MEDIUM";
        case Confidence::Low: return "LOW";
    }
    return "UNKNOWN";
}

enum class InstallationSource { Apt, Flatpak, Snap, Wine, AppImage, Manual, Unknown };

[[nodiscard]] constexpr const char* to_string(InstallationSource s) {
    switch (s) {
        case InstallationSource::Apt: return "APT";
        case InstallationSource::Flatpak: return "Flatpak";
        case InstallationSource::Snap: return "Snap";
        case InstallationSource::Wine: return "Wine";
        case InstallationSource::AppImage: return "AppImage";
        case InstallationSource::Manual: return "Manual installation";
        case InstallationSource::Unknown: return "Unknown";
    }
    return "Unknown";
}

enum class ResourceType {
    Package, Binary, DesktopEntry, Config, Cache, Data, State,
    Autostart, SystemdService, WinePrefixSubtree, Icon, Other
};

[[nodiscard]] constexpr const char* to_string(ResourceType t) {
    switch (t) {
        case ResourceType::Package: return "package";
        case ResourceType::Binary: return "binary";
        case ResourceType::DesktopEntry: return "desktop entry";
        case ResourceType::Config: return "configuration";
        case ResourceType::Cache: return "cache";
        case ResourceType::Data: return "application data";
        case ResourceType::State: return "state";
        case ResourceType::Autostart: return "autostart entry";
        case ResourceType::SystemdService: return "systemd service";
        case ResourceType::WinePrefixSubtree: return "Wine prefix subtree";
        case ResourceType::Icon: return "icon";
        case ResourceType::Other: return "other";
    }
    return "other";
}

enum class PlannedAction { Remove, SkipLowConfidence, SkipShared, WarnBeforeRemove };

// A single filesystem (or package-manager-managed) resource discovered
// during detection, along with the reasoning that ties it to the
// application and a recommended action. The planner may downgrade
// `recommended_action` further (e.g. shared-file protection) but never
// upgrades a Skip into a Remove.
struct Resource {
    std::string path;                 // filesystem path, or a symbolic identifier
                                       // for non-path resources (e.g. "systemd:user:foo.service")
    ResourceType type = ResourceType::Other;
    Confidence confidence = Confidence::Low;
    std::string evidence;             // human-readable "how we found this"
    bool user_owned = true;           // false => lives under /etc, /usr, /var, etc.
    PlannedAction recommended_action = PlannedAction::SkipLowConfidence;
    std::vector<std::string> allowed_roots;  // evidence-derived roots this path must
                                              // resolve under (fed to validate_removal_target)
};

struct PackageInfo {
    std::string name;
    std::string version;
    std::string architecture;
    bool manually_installed = true;   // apt-mark showmanual vs showauto
    std::vector<std::string> would_also_remove;      // from apt simulate
    std::vector<std::string> kept_shared_dependencies; // things we will NOT touch
};

struct RunningProcessInfo {
    bool is_running = false;
    std::vector<std::string> pids_and_cmdlines;
};

struct DetectionResult {
    InstallationSource source = InstallationSource::Unknown;
    Confidence overall_confidence = Confidence::Low;
    std::vector<std::string> evidence_trail;   // ordered log lines for the report
    std::optional<PackageInfo> package;        // populated for Apt (and partially Flatpak/Snap)
    std::optional<std::string> resolved_executable;  // canonical path to the real binary, if any
    std::optional<std::string> wine_prefix;           // populated for Wine
    bool wine_prefix_is_shared = false;
    std::vector<Resource> resources;
    std::vector<std::string> warnings;
    RunningProcessInfo running;
};

}  // namespace udu::detector

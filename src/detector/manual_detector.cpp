#include "manual_detector.hpp"
#include "common.hpp"
#include "portable_app_finding.hpp"
#include "../security/paths.hpp"
#include "../security/debug_log.hpp"

#include <filesystem>
#include <unordered_set>

namespace fs = std::filesystem;

namespace udu::detector {

namespace {

// Directories whose immediate children are "shared system bins", never
// treated as a single app's private directory even if an app happens to
// live directly inside them (e.g. /usr/local/bin/mytool -- the parent
// /usr/local/bin is NOT private to mytool).
bool is_shared_system_bindir(const std::string& dir) {
    static const std::unordered_set<std::string> shared = {
        "/usr/local/bin", "/usr/local/lib", "/usr/local/sbin",
        "/usr/bin", "/usr/lib", "/usr/sbin", "/bin", "/sbin",
        "/opt", "/usr/local", "/home",
    };
    std::string home_bin = udu::detector::common::home_dir() + "/bin";
    std::string home_local_bin = udu::detector::common::home_dir() + "/.local/bin";
    return shared.count(dir) || dir == home_bin || dir == home_local_bin;
}

}  // namespace

std::optional<DetectionResult> detect_manual(const DesktopEntry& entry) {
    UDU_LOG("detect_manual(): resolving Exec='" + entry.exec + "' as a last-resort fallback");
    auto exec_stripped = entry.exec_without_field_codes();
    auto toks = udu::detector::common::tokenize_exec(exec_stripped);
    if (toks.empty()) return std::nullopt;

    auto resolved = udu::detector::common::resolve_exec_target(toks[0]);
    if (!resolved) {
        DetectionResult result;
        result.source = InstallationSource::Unknown;
        result.overall_confidence = Confidence::Low;
        result.warnings.push_back(
            "Could not resolve the Exec= target ('" + toks[0] + "') to an existing file on "
            "disk or on PATH. No resources will be proposed for removal beyond the desktop "
            "entry itself; investigate manually.");
        return result;
    }

    DetectionResult result;
    result.source = InstallationSource::Manual;
    result.resolved_executable = *resolved;
    result.overall_confidence = Confidence::High;
    result.evidence_trail.push_back(
        "Exec= resolved to an existing file not owned by dpkg/Flatpak/Snap/Wine/AppImage: " + *resolved);

    Resource exe_resource;
    exe_resource.path = *resolved;
    exe_resource.type = ResourceType::Binary;
    exe_resource.confidence = Confidence::High;
    exe_resource.evidence = "direct resolution of the desktop entry's Exec= target";
    exe_resource.user_owned = resolved->rfind(udu::detector::common::home_dir(), 0) == 0;
    exe_resource.recommended_action = PlannedAction::Remove;
    exe_resource.allowed_roots = {*resolved};
    result.resources.push_back(exe_resource);

    fs::path exe_path(*resolved);
    std::string parent = exe_path.parent_path().string();
    if (!is_shared_system_bindir(parent)) {
        Resource dir_resource;
        dir_resource.path = parent;
        dir_resource.type = ResourceType::Data;
        dir_resource.confidence = Confidence::Medium;
        dir_resource.evidence = "immediate parent directory of the resolved executable; does not "
                                "look like a shared system bin directory, so likely private to "
                                "this application -- OFFERED, not auto-selected";
        dir_resource.user_owned = parent.rfind(udu::detector::common::home_dir(), 0) == 0;
        dir_resource.recommended_action = PlannedAction::WarnBeforeRemove;
        dir_resource.allowed_roots = {parent};
        result.resources.push_back(dir_resource);
    } else {
        result.warnings.push_back(
            "The executable lives directly inside a shared system directory (" + parent + "). "
            "Only the single binary file is proposed for removal; the containing directory will "
            "NOT be touched because other unrelated files live there too.");
    }

    // Portable-app enhancement: many manually extracted apps (JetBrains
    // IDEs, Arduino IDE, etc.) launch via a wrapper inside a `bin/`
    // subdirectory of a much larger extracted archive. The
    // immediate-parent candidate above only offers that `bin/` folder;
    // this also offers the actual extracted root, plus a possible
    // matching installer archive in ~/Downloads -- both cached (see
    // portable_app_finding.cpp) so this only ever computes once per app,
    // keeping every later detection run for the same app fast.
    auto cached_finding = load_cached_portable_finding(*resolved);
    PortableAppFinding finding = cached_finding ? *cached_finding
                                                 : compute_and_cache_portable_finding(*resolved);

    if (finding.extracted_root) {
        Resource root_resource;
        root_resource.path = *finding.extracted_root;
        root_resource.type = ResourceType::Data;
        root_resource.confidence = Confidence::Medium;
        root_resource.evidence = "the executable's immediate parent directory is named 'bin' -- a "
                                 "near-universal convention for a manually extracted application "
                                 "archive -- so this directory (one level up) looks like the actual "
                                 "extracted application root, not just its bin/ folder";
        root_resource.user_owned = finding.extracted_root->rfind(udu::detector::common::home_dir(), 0) == 0;
        root_resource.recommended_action = PlannedAction::WarnBeforeRemove;
        root_resource.allowed_roots = {*finding.extracted_root};
        result.resources.push_back(root_resource);
    }

    if (finding.matching_download_archive) {
        Resource archive_resource;
        archive_resource.path = *finding.matching_download_archive;
        archive_resource.type = ResourceType::Other;
        archive_resource.confidence = Confidence::Low;
        archive_resource.evidence = "a file in ~/Downloads whose name loosely matches this "
                                    "application -- likely the installer archive it was originally "
                                    "extracted from; this is a weak, name-based match and is never "
                                    "auto-selected";
        archive_resource.user_owned = true;
        archive_resource.recommended_action = PlannedAction::WarnBeforeRemove;
        archive_resource.allowed_roots = {*finding.matching_download_archive};
        result.resources.push_back(archive_resource);
    }

    // Existence-checked XDG guesses keyed off the executable's own leaf name.
    std::string leaf = exe_path.filename().string();
    for (const auto& g : udu::detector::common::existing_xdg_candidates(leaf)) {
        Resource r;
        r.path = g.path;
        r.type = g.type;
        r.confidence = Confidence::Low;
        r.evidence = "directory name matches the executable's filename under a standard XDG "
                     "base directory; this is a weak, name-based signal for a manually "
                     "installed application and is never auto-selected";
        r.user_owned = true;
        r.recommended_action = PlannedAction::SkipLowConfidence;
        r.allowed_roots = {g.path};
        result.resources.push_back(r);
    }

    return result;
}

}  // namespace udu::detector

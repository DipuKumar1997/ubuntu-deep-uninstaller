#include "wine_detector.hpp"
#include "common.hpp"
#include "../security/paths.hpp"
#include "../security/debug_log.hpp"

#include <regex>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

namespace udu::detector {

namespace {

std::optional<std::string> extract_wineprefix_env(const std::string& exec) {
    static const std::regex re(R"re(WINEPREFIX=(?:"([^"]+)"|(\S+)))re");
    std::smatch m;
    if (std::regex_search(exec, m, re)) {
        return m[1].matched ? m[1].str() : m[2].str();
    }
    return std::nullopt;
}

// Finds a Windows-style exe reference: either "C:\...\App.exe" (backslash
// form, as Wine .desktop files usually write it) or a unix path that
// already contains "/drive_c/" and ends in .exe.
std::optional<std::string> extract_windows_exe_token(const std::string& exec) {
    static const std::regex win_form(R"(([A-Za-z]:\\[^"]+\.[Ee][Xx][Ee]))");
    static const std::regex unix_form(R"((\S*drive_c\S*\.[Ee][Xx][Ee]))");
    std::smatch m;
    if (std::regex_search(exec, m, win_form)) return m[1].str();
    if (std::regex_search(exec, m, unix_form)) return m[1].str();
    return std::nullopt;
}

std::string windows_path_to_unix(const std::string& prefix, const std::string& win_path) {
    // "C:\Program Files\Foo\foo.exe" -> "<prefix>/drive_c/Program Files/Foo/foo.exe"
    std::string rest = win_path.substr(win_path.find('\\') + 1);
    for (auto& c : rest) if (c == '\\') c = '/';
    return prefix + "/drive_c/" + rest;
}

bool looks_like_wine_prefix(const std::string& dir) {
    std::error_code ec;
    return fs::exists(dir + "/system.reg", ec) && fs::exists(dir + "/drive_c", ec);
}

}  // namespace

std::optional<DetectionResult> detect_wine(const DesktopEntry& entry) {
    UDU_LOG("detect_wine(): checking Exec='" + entry.exec + "' for a Wine pattern");
    bool mentions_wine = entry.exec.find("wine") != std::string::npos ||
                          entry.exec.find("Wine") != std::string::npos;
    auto exe_token = extract_windows_exe_token(entry.exec);
    if (!mentions_wine && !exe_token) return std::nullopt;

    std::string prefix = extract_wineprefix_env(entry.exec).value_or(
        udu::detector::common::home_dir() + "/.wine");

    if (!looks_like_wine_prefix(prefix)) {
        // Could still be a Wine launcher pointing at a prefix we can't
        // confirm (e.g. relative/unset); do not claim high confidence.
        if (!exe_token) return std::nullopt;
    }

    DetectionResult result;
    result.source = InstallationSource::Wine;
    result.wine_prefix = prefix;
    result.evidence_trail.push_back("Exec= references Wine; resolved WINEPREFIX = " + prefix);

    std::string app_unix_path;
    if (exe_token) {
        if (exe_token->find(':') == 1) {  // "C:\..." form
            app_unix_path = windows_path_to_unix(prefix, *exe_token);
        } else {
            app_unix_path = *exe_token;  // already a unix drive_c path
        }
        result.evidence_trail.push_back("Windows executable resolved to: " + app_unix_path);
    }

    auto canon_prefix = udu::security::canonicalize(prefix);
    result.overall_confidence = canon_prefix ? Confidence::High : Confidence::Medium;
    if (!canon_prefix) {
        result.warnings.push_back(
            "Could not canonicalize the Wine prefix path '" + prefix + "'; it may not exist. "
            "Proceeding with desktop-entry cleanup only.");
    }

    // Shared-prefix detection: scan other .desktop files for the same
    // WINEPREFIX. This is the single most important safety check for Wine.
    UDU_LOG("detect_wine(): scanning sibling .desktop files for shared-prefix usage of " + prefix);
    std::vector<std::string> sibling_dirs = {
        udu::detector::common::home_dir() + "/.local/share/applications",
        udu::detector::common::home_dir() + "/.local/share/applications/wine",
        "/usr/share/applications",
    };
    int other_apps_in_prefix = 0;
    std::error_code ec;
    for (const auto& dir : sibling_dirs) {
        if (!fs::exists(dir, ec) || !fs::is_directory(dir, ec)) continue;
        for (const auto& f : fs::directory_iterator(dir, ec)) {
            if (f.path().extension() != ".desktop") continue;
            if (f.path().string() == entry.source_path) continue;
            std::ifstream in(f.path());
            std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            auto other_prefix = extract_wineprefix_env(content).value_or(
                udu::detector::common::home_dir() + "/.wine");
            if (other_prefix == prefix && (content.find("wine") != std::string::npos)) {
                ++other_apps_in_prefix;
            }
        }
    }
    result.wine_prefix_is_shared = other_apps_in_prefix > 0;
    if (result.wine_prefix_is_shared) {
        result.warnings.push_back(
            "This Wine prefix (" + prefix + ") is referenced by " +
            std::to_string(other_apps_in_prefix) + " other .desktop launcher(s). "
            "The prefix root, its registry (system.reg/user.reg), and its drive_c root will "
            "NOT be removed. Only this application's own subtree under drive_c will be offered "
            "for removal.");
    }

    // Resource: the application's own directory under drive_c (its parent
    // directory), never the prefix root itself.
    if (!app_unix_path.empty()) {
        fs::path p(app_unix_path);
        std::string app_dir = p.parent_path().string();
        Resource r;
        r.path = app_dir;
        r.type = ResourceType::WinePrefixSubtree;
        r.confidence = Confidence::High;
        r.evidence = "directory containing the application's .exe, resolved from Exec=";
        r.user_owned = true;
        r.recommended_action = PlannedAction::Remove;
        r.allowed_roots = {app_dir};
        result.resources.push_back(r);
    }

    if (!result.wine_prefix_is_shared && canon_prefix) {
        Resource whole_prefix;
        whole_prefix.path = *canon_prefix;
        whole_prefix.type = ResourceType::WinePrefixSubtree;
        whole_prefix.confidence = Confidence::Medium;
        whole_prefix.evidence = "sole application referencing this Wine prefix -- offered as an "
                                "OPTIONAL, separately-confirmed full-prefix removal";
        whole_prefix.user_owned = true;
        whole_prefix.recommended_action = PlannedAction::WarnBeforeRemove;
        whole_prefix.allowed_roots = {*canon_prefix};
        result.resources.push_back(whole_prefix);
    } else if (result.wine_prefix_is_shared && canon_prefix) {
        Resource protected_prefix;
        protected_prefix.path = *canon_prefix;
        protected_prefix.type = ResourceType::WinePrefixSubtree;
        protected_prefix.confidence = Confidence::High;
        protected_prefix.evidence = "prefix is shared with other installed applications";
        protected_prefix.user_owned = true;
        protected_prefix.recommended_action = PlannedAction::SkipShared;
        result.resources.push_back(protected_prefix);
    }

    // result.package intentionally left disengaged (its default state) --
    // Wine apps have no package-manager entry.
    return result;
}

}  // namespace udu::detector

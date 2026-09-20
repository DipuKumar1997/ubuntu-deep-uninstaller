#include "appimage_detector.hpp"
#include "common.hpp"
#include "../security/paths.hpp"
#include "../security/debug_log.hpp"

#include <regex>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <array>

namespace fs = std::filesystem;

namespace udu::detector {

namespace {

std::optional<std::string> find_appimage_path_in_string(const std::string& s) {
    static const std::regex re(R"((\S*\.[Aa]pp[Ii]mage))");
    std::smatch m;
    if (std::regex_search(s, m, re)) return m[1].str();
    return std::nullopt;
}

// A real AppImage-launching wrapper script is always a small text file
// (a shell script a few hundred bytes to a few KB long). This check
// exists specifically to make sure we NEVER hand a large or binary file
// to find_appimage_path_in_string()'s regex: libstdc++'s std::regex uses
// a backtracking engine that can be extremely slow, and can overflow the
// stack and crash, when run against megabytes of dense, non-matching,
// arbitrary binary content -- which is exactly what a compiled ELF
// executable (e.g. /usr/bin/flameshot) looks like. This is not a
// hypothetical: it reproduced a real segfault (see DEVLOG.md) the moment
// Exec= resolved directly to a compiled binary instead of a script.
constexpr uintmax_t kMaxWrapperScriptBytes = 65536;  // 64 KB

bool looks_like_small_text_script(const std::string& path) {
    std::error_code ec;
    auto size = fs::file_size(path, ec);
    if (ec || size > kMaxWrapperScriptBytes) return false;

    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::array<char, 4> magic{};
    f.read(magic.data(), magic.size());
    auto read = f.gcount();
    // ELF magic number: 0x7F 'E' 'L' 'F'. Any file starting with this is a
    // compiled binary, never a shell script, regardless of its size.
    if (read >= 4 && magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F') {
        return false;
    }
    return true;
}

}  // namespace

std::optional<DetectionResult> detect_appimage(const DesktopEntry& entry) {
    auto exec_stripped = entry.exec_without_field_codes();
    auto direct = find_appimage_path_in_string(exec_stripped);

    std::string discovery_note;
    std::string appimage_ref;
    if (direct) {
        appimage_ref = *direct;
        discovery_note = "Exec= directly references an .AppImage file";
    } else {
        // One level of wrapper-script indirection: if the first token is a
        // SMALL TEXT script we can safely read, look for an .AppImage path
        // inside it. See looks_like_small_text_script()'s comment for why
        // this guard is not optional.
        auto toks = udu::detector::common::tokenize_exec(exec_stripped);
        if (toks.empty()) return std::nullopt;
        auto resolved = udu::detector::common::resolve_exec_target(toks[0]);
        if (!resolved) return std::nullopt;

        UDU_LOG("detect_appimage(): checking whether " + *resolved + " looks like a small text "
                 "wrapper script before reading it...");
        if (!looks_like_small_text_script(*resolved)) {
            UDU_LOG("detect_appimage(): " + *resolved + " is not a small text file "
                     "(too large or a compiled binary) -- skipping the wrapper-script scan entirely");
            return std::nullopt;
        }

        std::ifstream f(*resolved, std::ios::binary);
        if (!f) return std::nullopt;
        std::ostringstream buf;
        buf << f.rdbuf();
        UDU_LOG("detect_appimage(): scanning " + std::to_string(buf.str().size()) +
                 " byte(s) of " + *resolved + " for an .AppImage reference...");
        auto inside = find_appimage_path_in_string(buf.str());
        if (!inside) return std::nullopt;
        appimage_ref = *inside;
        discovery_note = "Exec= runs a wrapper script (" + *resolved +
                          ") that itself references an .AppImage file";
    }

    auto canon = udu::security::canonicalize(appimage_ref);
    if (!canon) {
        // Can't verify the file currently exists; still report it, but at
        // reduced confidence, and skip resource-removal for the missing file.
        DetectionResult result;
        result.source = InstallationSource::AppImage;
        result.overall_confidence = Confidence::Low;
        result.evidence_trail.push_back(discovery_note + ": " + appimage_ref + " (NOT FOUND on disk)");
        result.warnings.push_back(
            "The .AppImage referenced by this launcher no longer exists at the recorded path; "
            "only the desktop entry itself will be offered for removal.");
        return result;
    }

    DetectionResult result;
    result.source = InstallationSource::AppImage;
    result.overall_confidence = Confidence::High;
    result.evidence_trail.push_back(discovery_note + ": " + *canon);
    result.resolved_executable = *canon;

    // AppImageLauncher integration marker, if present -- prefer deferring
    // to it rather than guessing at its internal bookkeeping.
    std::string ail_dir = udu::detector::common::home_dir() + "/.local/share/AppImageLauncher";
    std::error_code ec;
    if (std::filesystem::exists(ail_dir, ec)) {
        result.warnings.push_back(
            "AppImageLauncher appears to be installed on this system (" + ail_dir + "). "
            "If this AppImage was integrated through AppImageLauncher, prefer removing it via "
            "AppImageLauncher's own 'Remove integration' action for the AppImage's registry to "
            "stay consistent; this tool will still remove the file and desktop entry directly.");
    }

    Resource r;
    r.path = *canon;
    r.type = ResourceType::Binary;
    r.confidence = Confidence::High;
    r.evidence = discovery_note;
    r.user_owned = canon->rfind(udu::detector::common::home_dir(), 0) == 0 || canon->rfind("/opt", 0) == 0;
    r.recommended_action = PlannedAction::Remove;
    r.allowed_roots = {*canon};
    result.resources.push_back(r);

    return result;
}

}  // namespace udu::detector

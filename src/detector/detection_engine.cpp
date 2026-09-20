#include "detection_engine.hpp"
#include "common.hpp"
#include "apt_detector.hpp"
#include "flatpak_detector.hpp"
#include "snap_detector.hpp"
#include "wine_detector.hpp"
#include "appimage_detector.hpp"
#include "manual_detector.hpp"
#include "../security/paths.hpp"
#include "../security/debug_log.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace fs = std::filesystem;

namespace udu::detector {

namespace {

// Scans /proc for processes whose /proc/<pid>/exe resolves to
// `resolved_executable`, or (for package/id-based sources where there is
// no single exe path, e.g. Flatpak/Snap) whose /proc/<pid>/cmdline
// contains `id_token`. Read-only; never signals anything here.
RunningProcessInfo check_running(const std::optional<std::string>& resolved_executable,
                                  const std::optional<std::string>& id_token) {
    UDU_LOG("check_running(): scanning /proc, resolved_executable=" +
             resolved_executable.value_or("(none)"));
    RunningProcessInfo info;
    std::error_code ec;
    if (!fs::exists("/proc", ec)) return info;
    for (const auto& entry : fs::directory_iterator("/proc", ec)) {
        const std::string name = entry.path().filename().string();
        if (name.empty() || !std::all_of(name.begin(), name.end(), ::isdigit)) continue;

        bool matched = false;
        if (resolved_executable) {
            std::error_code lec;
            auto exe_link = fs::read_symlink(entry.path() / "exe", lec);
            if (!lec && exe_link.string() == *resolved_executable) matched = true;
        }
        if (!matched && id_token) {
            std::ifstream cmdline_file(entry.path() / "cmdline", std::ios::binary);
            std::ostringstream buf;
            buf << cmdline_file.rdbuf();
            std::string cmdline = buf.str();
            for (auto& c : cmdline) if (c == '\0') c = ' ';
            if (!cmdline.empty() && cmdline.find(*id_token) != std::string::npos) matched = true;
        }
        if (matched) {
            std::ifstream cmdline_file(entry.path() / "cmdline", std::ios::binary);
            std::ostringstream buf;
            buf << cmdline_file.rdbuf();
            std::string cmdline = buf.str();
            for (auto& c : cmdline) if (c == '\0') c = ' ';
            info.is_running = true;
            info.pids_and_cmdlines.push_back("pid " + name + ": " + cmdline);
        }
    }
    UDU_LOG("check_running(): done, is_running=" + std::to_string(info.is_running));
    return info;
}

}  // namespace

DetectionResult run_detection(const DesktopEntry& entry) {
    UDU_LOG("run_detection(): starting for '" + entry.source_path + "' Exec=" + entry.exec);

    // Pattern-specific detectors first, in order of how unambiguous their
    // Exec= signature is. Each returns std::nullopt fast if its pattern
    // doesn't match, so this is cheap.
    UDU_LOG("run_detection(): trying detect_flatpak...");
    if (auto r = detect_flatpak(entry)) { r->running = check_running(r->resolved_executable, r->package ? std::optional(r->package->name) : std::nullopt); UDU_LOG("run_detection(): matched flatpak"); return *r; }
    UDU_LOG("run_detection(): trying detect_snap...");
    if (auto r = detect_snap(entry))    { r->running = check_running(r->resolved_executable, r->package ? std::optional(r->package->name) : std::nullopt); UDU_LOG("run_detection(): matched snap"); return *r; }
    UDU_LOG("run_detection(): trying detect_wine...");
    if (auto r = detect_wine(entry))    { r->running = check_running(r->resolved_executable, std::nullopt); UDU_LOG("run_detection(): matched wine"); return *r; }
    UDU_LOG("run_detection(): trying detect_appimage...");
    if (auto r = detect_appimage(entry)){ r->running = check_running(r->resolved_executable, std::nullopt); UDU_LOG("run_detection(): matched appimage"); return *r; }

    // For APT and the manual fallback we need the resolved executable
    // first, since dpkg -S needs a concrete path.
    UDU_LOG("run_detection(): resolving exec target for apt/manual detectors...");
    auto exec_stripped = entry.exec_without_field_codes();
    auto toks = udu::detector::common::tokenize_exec(exec_stripped);
    std::optional<std::string> resolved;
    if (!toks.empty()) resolved = udu::detector::common::resolve_exec_target(toks[0]);
    UDU_LOG("run_detection(): resolved exec target = " + resolved.value_or("(none)"));

    if (resolved) {
        UDU_LOG("run_detection(): trying detect_apt...");
        if (auto r = detect_apt(*resolved)) {
            UDU_LOG("run_detection(): detect_apt returned, checking running processes...");
            r->running = check_running(r->resolved_executable, std::nullopt);
            UDU_LOG("run_detection(): matched apt, done");
            return *r;
        }
    }

    UDU_LOG("run_detection(): falling back to detect_manual...");
    auto r = detect_manual(entry);
    if (r) {
        r->running = check_running(r->resolved_executable, std::nullopt);
        UDU_LOG("run_detection(): matched manual, done");
        return *r;
    }

    UDU_LOG("run_detection(): no source determined, returning Unknown");
    DetectionResult unknown;
    unknown.source = InstallationSource::Unknown;
    unknown.overall_confidence = Confidence::Low;
    unknown.warnings.push_back(
        "No installation source could be established from this desktop entry's Exec= line. "
        "Only the desktop entry itself will be offered for removal.");
    return unknown;
}

}  // namespace udu::detector

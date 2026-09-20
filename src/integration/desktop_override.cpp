#include "desktop_override.hpp"
#include "../detector/common.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

namespace udu::integration {

namespace {

std::string local_apps_dir() {
    return udu::detector::common::home_dir() + "/.local/share/applications";
}

std::string backup_dir() {
    return udu::detector::common::home_dir() + "/.local/state/ubuntu-deep-uninstaller/desktop-backups";
}

// Rewrites raw desktop-file content, merging in our action while leaving
// every other line untouched. This is a targeted text transform rather
// than a full re-serialization, specifically so we never accidentally
// drop or reorder keys/groups the original author (a packager, or an
// upstream project) put there for a reason.
std::string merge_action_into_content(const std::string& original,
                                       const std::vector<std::string>& existing_actions,
                                       const std::string& uninstaller_binary,
                                       const std::string& original_path) {
    std::istringstream in(original);
    std::ostringstream out;
    std::string line;
    bool wrote_actions_line = false;
    bool in_main_group = false;

    std::vector<std::string> merged_actions = existing_actions;
    merged_actions.push_back("UduUninstall");

    while (std::getline(in, line)) {
        std::string trimmed = line;
        while (!trimmed.empty() && (trimmed.back() == '\r')) trimmed.pop_back();

        if (trimmed == "[Desktop Entry]") {
            in_main_group = true;
            out << trimmed << "\n";
            continue;
        }
        if (!trimmed.empty() && trimmed.front() == '[' && trimmed != "[Desktop Entry]") {
            in_main_group = false;
        }

        if (in_main_group && trimmed.rfind("Actions=", 0) == 0) {
            out << "Actions=";
            for (size_t i = 0; i < merged_actions.size(); ++i) {
                out << merged_actions[i] << ";";
            }
            out << "\n";
            wrote_actions_line = true;
            continue;
        }

        out << line << "\n";
    }

    if (!wrote_actions_line) {
        // No pre-existing Actions= key: we need to insert one right after
        // [Desktop Entry]. Re-scan is avoided by handling it in a second
        // pass over what we already built, inserting immediately after the
        // group header.
        std::string built = out.str();
        std::string marker = "[Desktop Entry]\n";
        auto pos = built.find(marker);
        if (pos != std::string::npos) {
            std::string actions_line = "Actions=";
            for (const auto& a : merged_actions) actions_line += a + ";";
            actions_line += "\n";
            built.insert(pos + marker.size(), actions_line);
        }
        out.str("");
        out << built;
    }

    out << "\n[Desktop Action UduUninstall]\n";
    out << "Name=Uninstall Completely\n";
    // --uninstall-by-desktop-id-in-terminal (not the plain
    // --uninstall-by-desktop-id) is deliberate: GNOME Shell runs this
    // Exec= command directly with no terminal attached, so the CLI's own
    // interactive confirmation prompt would otherwise be invisible and
    // never receive input. The "-in-terminal" variant finds a real
    // terminal emulator, launches the interactive command inside it
    // (detached, so GNOME Shell's action activation returns immediately),
    // and keeps the window open after completion so the user can read the
    // full removal log.
    out << "Exec=" << uninstaller_binary << " --uninstall-by-desktop-id-in-terminal '" << original_path << "'\n";

    return out.str();
}

}  // namespace

OverrideResult install_override(const DesktopEntry& entry, const std::string& uninstaller_binary) {
    OverrideResult result;
    std::error_code ec;

    fs::create_directories(local_apps_dir(), ec);
    fs::create_directories(backup_dir(), ec);

    // Already have our own action? (Re-run == refresh, not duplicate.)
    bool already_has_action = false;
    for (const auto& a : entry.actions) {
        if (a.id == "UduUninstall") { already_has_action = true; break; }
    }
    if (already_has_action) {
        result.success = true;
        result.override_path = entry.source_path;
        result.message = "already integrated (source file itself carries the action, or this is "
                          "already our own override) -- nothing to do";
        return result;
    }

    // Archive a pristine copy of the ORIGINAL system file before we ever
    // write an override derived from it, so self-uninstall / restore is
    // always possible even if the system file changes later.
    std::string backup_path = backup_dir() + "/" + entry.desktop_id + ".orig";
    if (!fs::exists(backup_path, ec)) {
        fs::copy_file(entry.source_path, backup_path, fs::copy_options::overwrite_existing, ec);
    }

    std::string merged = merge_action_into_content(entry.raw_content, entry.existing_action_ids,
                                                     uninstaller_binary, entry.source_path);

    std::string override_path = local_apps_dir() + "/" + entry.desktop_id;
    std::ofstream out(override_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        result.success = false;
        result.message = "failed to open " + override_path + " for writing";
        return result;
    }
    out << merged;
    out.close();

    result.success = true;
    result.override_path = override_path;
    result.message = "wrote user-local override with 'Uninstall Completely' action";
    return result;
}

bool remove_override(const std::string& desktop_id) {
    std::string p = local_apps_dir() + "/" + desktop_id;
    std::error_code ec;
    return fs::remove(p, ec);
}

SyncSummary sync_all(const std::string& uninstaller_binary) {
    SyncSummary summary;
    std::vector<std::string> roots = {"/usr/share/applications", "/usr/local/share/applications"};
    std::error_code ec;
    for (const auto& root : roots) {
        if (!fs::exists(root, ec) || !fs::is_directory(root, ec)) continue;
        for (const auto& f : fs::recursive_directory_iterator(root, ec)) {
            if (f.path().extension() != ".desktop") continue;
            auto entry = udu::parse_desktop_file(f.path().string());
            if (!entry) { summary.errors.push_back("failed to parse " + f.path().string()); continue; }
            if (entry->no_display || entry->type != "Application") { summary.skipped++; continue; }
            bool existed_before = fs::exists(local_apps_dir() + "/" + entry->desktop_id, ec);
            auto r = install_override(*entry, uninstaller_binary);
            if (!r.success) { summary.errors.push_back(r.message + " (" + f.path().string() + ")"); continue; }
            if (existed_before) summary.refreshed++; else summary.created++;
        }
    }
    return summary;
}

}  // namespace udu::integration

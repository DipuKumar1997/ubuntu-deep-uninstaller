// main.cpp -- CLI entry point.
//
// This is Phase 1/2/3/4 wired together behind a command line interface.
// The GTK4/libadwaita GUI (src/gui/) is a separate front-end that calls
// into exactly the same detector/planner/uninstall/verification library;
// it is not required for the core tool to be useful and testable.
#include <iostream>
#include <string>
#include <vector>
#include <optional>
#include <filesystem>
#include <unordered_set>

#include "desktop_entry.hpp"
#include "detector/detection_engine.hpp"
#include "detector/common.hpp"
#include "planner/removal_plan.hpp"
#include "planner/plan_cache.hpp"
#include "terminal/report.hpp"
#include "terminal/color.hpp"
#include "terminal/launcher.hpp"
#include "uninstall/executor.hpp"
#include "verification/verify.hpp"
#include "integration/desktop_override.hpp"
#include "security/proc_exec.hpp"
#include "security/crash_handler.hpp"
#include "security/debug_log.hpp"
#include "uninstall/history.hpp"

namespace {

void print_usage() {
    std::cout <<
        "Ubuntu Deep Uninstaller\n\n"
        "Usage:\n"
        "  ubuntu-deep-uninstaller --inspect-desktop <path-to-.desktop>\n"
        "  ubuntu-deep-uninstaller --dry-run <path-to-.desktop>\n"
        "  ubuntu-deep-uninstaller --uninstall <path-to-.desktop>\n"
        "  ubuntu-deep-uninstaller --uninstall-by-desktop-id <path-to-.desktop>\n"
        "  ubuntu-deep-uninstaller --uninstall-by-desktop-id-in-terminal <path-to-.desktop>\n"
        "  ubuntu-deep-uninstaller --list-applications\n"
        "  ubuntu-deep-uninstaller --install-integration <path-to-.desktop>\n"
        "  ubuntu-deep-uninstaller --sync-integration\n"
        "  ubuntu-deep-uninstaller --history\n"
        "  ubuntu-deep-uninstaller --version\n";
}

int cmd_inspect_or_dry_run(const std::string& desktop_path, bool dry_run_wording) {
    auto entry = udu::parse_desktop_file(desktop_path);
    if (!entry) {
        std::cerr << "[ERROR] Could not parse desktop file: " << desktop_path << "\n";
        return 2;
    }
    std::cout << udu::terminal::banner("Ubuntu Deep Uninstaller"
                                        + std::string(dry_run_wording ? " (dry run)" : "")) << "\n";

    udu::planner::RemovalPlan plan;
    auto cached = udu::planner::load_plan_cache_if_fresh(desktop_path);
    if (cached) {
        UDU_LOG("cmd_inspect_or_dry_run(): reusing cached plan, skipping run_detection()");
        std::cout << udu::terminal::color::tag("[FOUND]")
                  << " Reusing the removal plan already computed for this application "
                     "(skipping re-detection).\n\n";
        for (const auto& e : cached->evidence_trail) {
            std::cout << udu::terminal::color::tag("[FOUND]") << " " << e << "\n";
        }
        std::cout << "\n";
        plan = *cached;
    } else {
        UDU_LOG("cmd_inspect_or_dry_run(): no usable cache, calling run_detection()...");
        auto detection = udu::detector::run_detection(*entry);
        UDU_LOG("cmd_inspect_or_dry_run(): run_detection() returned, source=" +
                 std::string(udu::detector::to_string(detection.source)));
        std::cout << udu::terminal::format_detection(*entry, detection);
        plan = udu::planner::build_plan(*entry, detection);
    }
    std::cout << udu::terminal::format_plan(plan);

    if (dry_run_wording) {
        std::cout << "This was a dry run. Nothing has been removed.\n";
    }
    UDU_LOG("cmd_inspect_or_dry_run(): done");
    return 0;
}

int cmd_uninstall(const std::string& desktop_path) {
    auto entry = udu::parse_desktop_file(desktop_path);
    if (!entry) {
        std::cerr << "[ERROR] Could not parse desktop file: " << desktop_path << "\n";
        return 2;
    }
    std::cout << udu::terminal::banner("Ubuntu Deep Uninstaller") << "\n";

    udu::planner::RemovalPlan plan;
    auto cached = udu::planner::load_plan_cache_if_fresh(desktop_path);
    if (cached) {
        // This is the fix for "why does it scan again when I click
        // Uninstall Completely -- it already knew where this belongs":
        // the GUI wrote this exact plan to disk the moment it finished
        // computing it for the currently-selected app, tagged with this
        // exact desktop path. If it's still here and still fresh (see
        // plan_cache.cpp for the freshness window), reuse it instead of
        // running dpkg/apt-get/etc. all over again.
        UDU_LOG("cmd_uninstall(): reusing cached plan, skipping run_detection()");
        std::cout << udu::terminal::color::tag("[FOUND]")
                  << " Reusing the removal plan already computed for this application "
                     "(skipping re-detection).\n\n";
        for (const auto& e : cached->evidence_trail) {
            std::cout << udu::terminal::color::tag("[FOUND]") << " " << e << "\n";
        }
        std::cout << "\n";
        plan = *cached;
    } else {
        UDU_LOG("cmd_uninstall(): no usable cache, calling run_detection()...");
        auto detection = udu::detector::run_detection(*entry);
        UDU_LOG("cmd_uninstall(): run_detection() returned, source=" +
                 std::string(udu::detector::to_string(detection.source)));
        std::cout << udu::terminal::format_detection(*entry, detection);
        plan = udu::planner::build_plan(*entry, detection);
    }
    std::cout << udu::terminal::format_plan(plan);

    // Defaults to "yes" on a bare Enter (only an explicit 'n'/'N' declines)
    // for every secondary choice below. The main "press Enter to continue"
    // gate just below still requires an explicit action (Enter or
    // Ctrl+C) before anything is removed, but no longer requires typing
    // the word UNINSTALL -- changed at the project owner's explicit,
    // repeated request to reduce friction. Ctrl+C remains available at
    // every prompt in this flow as the actual "stop right now" option.
    auto ask_yes_default = [](const std::string& prompt) {
        std::cout << prompt << " [Y/n] ";
        std::string ans;
        std::getline(std::cin, ans);
        return !(ans == "n" || ans == "N");
    };

    if (plan.app_currently_running) {
        std::cout << "The application appears to be running.\n";
        if (!ask_yes_default("Continue anyway?")) {
            std::cout << "Aborted.\n";
            return 1;
        }
    }

    std::cout << "\nWARNING\n\n"
                 "This operation will remove the application and its associated\n"
                 "configuration/data discovered by the scanner. Some data may be\n"
                 "permanently deleted.\n\n"
                 "Press ENTER to continue, or Ctrl+C to cancel.\n> ";
    std::string confirm;
    std::getline(std::cin, confirm);

    bool include_warn = false;
    if (plan.has_high_risk_items()) {
        include_warn = ask_yes_default(
            "\nInclude the additional lower-confidence/optional items marked [REMOVE*] above too?");
    }

    bool purge = false;
    if (plan.source == udu::detector::InstallationSource::Apt) {
        purge = ask_yes_default(
            "\nAlso remove configuration files (apt purge) rather than keeping them (apt remove)?");
    }

    bool autoremove = false;
    if (!plan.dependencies_would_remove.empty()) {
        std::cout << "\n(" << plan.dependencies_would_remove.size()
                  << " now-unused dependency package(s) were listed above.)\n";
        autoremove = ask_yes_default("Also remove those now-unused dependencies?");
    }

    udu::uninstall::ExecutionOptions options;
    options.include_warn_items = include_warn;
    options.purge_apt_configs = purge;
    options.run_autoremove_if_offered = autoremove;

    std::cout << "\n";
    auto result = udu::uninstall::execute_plan(plan, options);
    int succeeded = 0, failed = 0;
    for (const auto& line : result.log) {
        std::cout << udu::terminal::color::tag(line.tag) << " " << line.text << "\n";
        if (line.tag == "[SUCCESS]") ++succeeded;
        if (line.tag == "[ERROR]") ++failed;
    }

    std::cout << "\n" << udu::terminal::banner("Verification");
    auto verification = udu::verification::verify(plan);
    std::cout << udu::terminal::format_verification(verification);

    // A plain "exit code 1" tells you nothing about WHAT went wrong or
    // where -- this summary line is the last thing printed, right where
    // you're looking, and points back at the specific [ERROR] lines above
    // rather than making you infer anything from a process exit status.
    std::cout << "\n";
    if (failed == 0) {
        std::cout << udu::terminal::color::green("SUCCEEDED") << ": all " << succeeded
                  << " planned action(s) completed without error.\n";
    } else {
        std::cout << udu::terminal::color::red("COMPLETED WITH ERRORS") << ": " << succeeded
                  << " action(s) succeeded, " << failed << " failed. Scroll up to the "
                  << udu::terminal::color::tag("[ERROR]") << " line(s) above for exactly what "
                     "went wrong and why.\n";
    }

    return result.overall_success ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
    udu::security::install_crash_handler();
    UDU_LOG("main(): ubuntu-deep-uninstaller starting, argc=" + std::to_string(argc));

    std::vector<std::string> args(argv + 1, argv + argc);
    if (args.empty()) { print_usage(); return 1; }

    const std::string& cmd = args[0];
    UDU_LOG("main(): dispatching command '" + cmd + "'" +
             (args.size() > 1 ? " arg='" + args[1] + "'" : ""));

    if (cmd == "--version") {
        std::cout << "ubuntu-deep-uninstaller 0.1.0 (Phase 1-4 core)\n";
        return 0;
    }
    if (cmd == "--help" || cmd == "-h") { print_usage(); return 0; }

    if ((cmd == "--inspect-desktop" || cmd == "--dry-run" ||
         cmd == "--uninstall" || cmd == "--uninstall-by-desktop-id" ||
         cmd == "--uninstall-by-desktop-id-in-terminal" ||
         cmd == "--install-integration") && args.size() < 2) {
        std::cerr << "Missing path argument.\n";
        print_usage();
        return 1;
    }

    if (cmd == "--inspect-desktop") return cmd_inspect_or_dry_run(args[1], false);
    if (cmd == "--dry-run") return cmd_inspect_or_dry_run(args[1], true);
    if (cmd == "--uninstall" || cmd == "--uninstall-by-desktop-id") return cmd_uninstall(args[1]);

    if (cmd == "--uninstall-by-desktop-id-in-terminal") {
        // This is what the GNOME context-menu action's Exec= line actually
        // invokes. GNOME Shell runs that Exec= command directly, with no
        // terminal attached -- so if we just ran cmd_uninstall() here, its
        // interactive "type UNINSTALL to continue" prompt would be reading
        // from a stdin that has nothing typing into it, invisibly, forever.
        // Instead: find a real terminal emulator, spawn it fully detached
        // running `<self> --uninstall-by-desktop-id <path>` (the ordinary,
        // interactive command), and return immediately so GNOME Shell's
        // action-activation doesn't hang waiting on us.
        auto self = udu::security::self_executable_path();
        std::string self_path = self.value_or(args.size() > 0 ? "ubuntu-deep-uninstaller" : "");
        auto argv = udu::terminal::build_terminal_argv(
            {self_path, "--uninstall-by-desktop-id", args[1]}, /*hold_open_after=*/true);
        if (!argv) {
            std::cerr << "[ERROR] No terminal emulator found (tried ptyxis, gnome-terminal, "
                         "x-terminal-emulator, xterm).\n";
            if (udu::security::executable_exists("notify-send")) {
                udu::security::run({"notify-send", "Ubuntu Deep Uninstaller",
                                     "No terminal emulator found -- could not start the uninstall "
                                     "workflow. Install ptyxis, gnome-terminal, or xterm."});
            }
            return 1;
        }
        if (!udu::security::spawn_detached(*argv)) {
            std::cerr << "[ERROR] Failed to launch terminal.\n";
            return 1;
        }
        return 0;
    }

    if (cmd == "--install-integration") {
        auto entry = udu::parse_desktop_file(args[1]);
        if (!entry) { std::cerr << "[ERROR] Could not parse " << args[1] << "\n"; return 2; }
        auto r = udu::integration::install_override(*entry, "/usr/bin/ubuntu-deep-uninstaller");
        std::cout << (r.success ? "[SUCCESS] " : "[ERROR] ") << r.message << "\n";
        if (r.success) std::cout << "Override written to: " << r.override_path << "\n";
        return r.success ? 0 : 1;
    }

    if (cmd == "--sync-integration") {
        auto s = udu::integration::sync_all("/usr/bin/ubuntu-deep-uninstaller");
        std::cout << "[SUCCESS] created=" << s.created << " refreshed=" << s.refreshed
                  << " skipped=" << s.skipped << " errors=" << s.errors.size() << "\n";
        for (const auto& e : s.errors) std::cout << "[ERROR] " << e << "\n";
        return s.errors.empty() ? 0 : 1;
    }

    if (cmd == "--list-applications") {
        // Same XDG precedence + dedup as the GUI's scan_applications()
        // (see gui/gui_main.cpp for the full reasoning): user-local
        // desktop files -- where JetBrains Toolbox, manually registered
        // apps, and this tool's own context-menu overrides all live --
        // are scanned first and win on a desktop-id collision, then the
        // two system directories, then Flatpak/Snap export directories.
        namespace fs = std::filesystem;
        std::error_code ec;
        std::string home = udu::detector::common::home_dir();
        std::vector<std::string> dirs = {
            home + "/.local/share/applications",
            "/usr/local/share/applications",
            "/usr/share/applications",
            home + "/.local/share/flatpak/exports/share/applications",
            "/var/lib/flatpak/exports/share/applications",
            "/var/lib/snapd/desktop/applications",
        };
        std::unordered_set<std::string> seen_ids;
        for (const auto& dir : dirs) {
            if (!fs::exists(dir, ec) || !fs::is_directory(dir, ec)) continue;
            for (const auto& f : fs::directory_iterator(dir, ec)) {
                if (f.path().extension() != ".desktop") continue;
                auto entry = udu::parse_desktop_file(f.path().string());
                if (!entry || entry->no_display) continue;
                if (!seen_ids.insert(entry->desktop_id).second) continue;
                std::cout << entry->desktop_id << "\t" << entry->name << "\t" << f.path().string() << "\n";
            }
        }
        return 0;
    }

    if (cmd == "--history") {
        auto entries = udu::uninstall::read_history();
        if (entries.empty()) {
            std::cout << "No applications have been uninstalled through this tool yet.\n";
            return 0;
        }
        std::cout << "Uninstall history (" << entries.size() << " entr"
                  << (entries.size() == 1 ? "y" : "ies") << ", oldest first):\n\n";
        for (const auto& e : entries) {
            std::cout << e.timestamp << "\t" << e.app_name << "\t[" << e.source << "]\n";
        }
        std::cout << "\nStored at: " << udu::uninstall::history_file_path() << "\n";
        return 0;
    }

    std::cerr << "Unknown command: " << cmd << "\n";
    print_usage();
    return 1;
}

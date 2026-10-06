// gui/gui_main.cpp
//
// GTK4 + libadwaita front-end. Deliberately thin: every piece of real
// logic (detection, planning, execution) lives in the core library under
// src/detector, src/planner, src/uninstall, etc. and is exercised
// identically by the CLI (src/main.cpp) and by this GUI. The GUI itself:
//
//   1. Lists installed applications (read-only, unprivileged).
//   2. On selection, runs detection + builds a plan (read-only,
//      unprivileged) and displays it.
//   3. "Dry Run" re-runs the CLI's --dry-run in a terminal window, purely
//      for a consistent, copy-pasteable transcript.
//   4. "Uninstall Completely" launches a real terminal emulator running
//      `ubuntu-deep-uninstaller --uninstall <path>` -- the GUI process
///     itself NEVER escalates privileges, never prompts for a password,
//      and never performs the removal itself. sudo happens inside that
//      terminal, interactively, exactly as it would if the user typed the
//      command by hand.
//
// NOTE ON BUILD ENVIRONMENT: this file targets GTK4 (>= 4.14) and
// libadwaita (>= 1.5), matching Ubuntu 26.04's stack. The sandbox this
// project was authored in has no libgtk-4-dev/libadwaita-1-dev, so this
// file still cannot be compile-checked here -- it has instead been fixed
// iteratively against real compiler errors reported from an actual
// Ubuntu 26.04 build (see DEVLOG.md's "GUI build iteration" section for
// the exact errors and fixes). Two real bugs were found and fixed that
// way: AdwDialog*/GtkWidget* aren't interchangeable without an explicit
// cast (adw_alert_dialog_new() returns AdwDialog*), and a
// std::pair<std::string, GtkWidget*> passed directly as a g_signal_connect
// argument breaks because the C preprocessor treats the template argument
// list's comma as a macro-argument separator (replaced with a named
// struct). If your build reports further errors, they're likely similarly
// small and mechanical -- paste them back and they'll get fixed the same
// way. Everything under src/detector, src/planner, src/security,
// src/uninstall, src/verification, src/terminal, src/integration, and
// src/desktop_entry.* has been compiled and exercised against real and
// synthetic data on both the authoring sandbox and a real Ubuntu machine
// (see tests/test_core.cpp and DEVLOG.md).
#include <adwaita.h>
#include <gtk/gtk.h>

#include <string>
#include <vector>
#include <optional>
#include <filesystem>
#include <thread>
#include <atomic>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <unordered_set>

#include "../src/desktop_entry.hpp"
#include "../src/detector/detection_engine.hpp"
#include "../src/detector/common.hpp"
#include "../src/planner/removal_plan.hpp"
#include "../src/planner/plan_cache.hpp"
#include "../src/terminal/report.hpp"
#include "../src/terminal/launcher.hpp"
#include "../src/security/proc_exec.hpp"
#include "../src/security/crash_handler.hpp"
#include "../src/security/debug_log.hpp"
#include "../src/uninstall/history.hpp"

namespace fs = std::filesystem;

namespace {

struct AppEntry {
    std::string desktop_id;
    std::string name;
    std::string path;
};

struct AppState {
    GtkWidget* window = nullptr;
    GtkWidget* search_entry = nullptr;
    GtkWidget* refresh_button = nullptr;
    GtkWidget* history_button = nullptr;
    GtkWidget* memory_label = nullptr;   // "RSS: 12.3 MB", updated periodically
    GtkWidget* list_box = nullptr;
    GtkWidget* loading_box = nullptr;    // spinner + "Loading…" row, shown/hidden
    GtkWidget* spinner = nullptr;
    GtkWidget* detail_label = nullptr;
    GtkWidget* dry_run_button = nullptr;
    GtkWidget* uninstall_button = nullptr;
    std::vector<AppEntry> all_apps;
    std::optional<AppEntry> selected;

    // Bumped on every new selection. A background detection thread
    // captures the generation it was started with; when it finishes, the
    // main-thread callback discards the result if the generation has
    // since moved on (the user clicked a different app before the first
    // one finished loading), so a slow lookup can never clobber a newer
    // selection's results.
    std::atomic<uint64_t> generation{0};
};

// Finds a real terminal emulator and, via udu::terminal::build_terminal_argv,
// wraps the command so the window stays open (waiting for Enter) after it
// finishes -- otherwise a terminal that closes the instant its child exits
// would flash the removal log on screen for a fraction of a second and
// vanish, which is exactly the "I can't see what it removed" problem this
// fixes. The same helper is used by the GNOME context-menu action itself
// (see src/main.cpp's --uninstall-by-desktop-id-in-terminal), so both entry
// points behave identically.
void launch_in_terminal(const std::vector<std::string>& inner_argv, GtkWidget* window) {
    auto cmd = udu::terminal::build_terminal_argv(inner_argv, /*hold_open_after=*/true);
    if (!cmd) {
        AdwDialog* dialog = adw_alert_dialog_new(
            "No terminal emulator found",
            "Could not find ptyxis, gnome-terminal, x-terminal-emulator, or xterm on PATH. "
            "Install one of these to use the visible-terminal uninstall workflow.");
        adw_alert_dialog_add_response(ADW_ALERT_DIALOG(dialog), "ok", "OK");
        adw_dialog_present(dialog, window);
        return;
    }
    // Fire-and-forget: this is a real, visible, interactive terminal that
    // the user drives themselves (including any sudo prompt). We are not
    // capturing its output or its stdin here -- g_spawn_async with
    // G_SPAWN_SEARCH_PATH is the correct primitive for "launch a GUI-
    // adjacent interactive program and detach", as opposed to
    // security::run() (used elsewhere for non-interactive, captured
    // subprocess calls).
    std::vector<char*> raw;
    raw.reserve(cmd->size() + 1);
    for (auto& s : *cmd) raw.push_back(const_cast<char*>(s.c_str()));
    raw.push_back(nullptr);

    GError* error = nullptr;
    gboolean ok = g_spawn_async(nullptr, raw.data(), nullptr,
                                 static_cast<GSpawnFlags>(G_SPAWN_SEARCH_PATH),
                                 nullptr, nullptr, nullptr, &error);
    if (!ok) {
        std::string msg = error ? error->message : "unknown error";
        if (error) g_error_free(error);
        AdwDialog* dialog = adw_alert_dialog_new("Failed to launch terminal", msg.c_str());
        adw_alert_dialog_add_response(ADW_ALERT_DIALOG(dialog), "ok", "OK");
        adw_dialog_present(dialog, window);
    }
}

// Reads this process's own resident memory from /proc/self/status (the
// VmRSS line), so the window can show roughly how much RAM running this
// tool is actually using -- answers "how many RAM it is using currently"
// directly from the OS's own accounting rather than guessing.
std::string current_memory_usage_label() {
    std::ifstream f("/proc/self/status");
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("VmRSS:", 0) == 0) {
            std::istringstream is(line.substr(6));
            long kb = 0;
            is >> kb;
            double mb = static_cast<double>(kb) / 1024.0;
            std::ostringstream out;
            out.precision(1);
            out << std::fixed << "RSS: " << mb << " MB";
            return out.str();
        }
    }
    return "RSS: (unknown)";
}

gboolean update_memory_label(gpointer user_data) {
    auto* state = static_cast<AppState*>(user_data);
    gtk_label_set_text(GTK_LABEL(state->memory_label), current_memory_usage_label().c_str());
    return G_SOURCE_CONTINUE;  // keep firing every interval for the life of the window
}

void on_history_clicked(GtkButton*, gpointer user_data) {
    auto* state = static_cast<AppState*>(user_data);
    auto entries = udu::uninstall::read_history();

    GtkWidget* dialog_window = gtk_window_new();
    gtk_window_set_title(GTK_WINDOW(dialog_window), "Uninstall History");
    gtk_window_set_transient_for(GTK_WINDOW(dialog_window), GTK_WINDOW(state->window));
    gtk_window_set_modal(GTK_WINDOW(dialog_window), TRUE);
    gtk_window_set_default_size(GTK_WINDOW(dialog_window), 520, 420);

    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_start(box, 12);
    gtk_widget_set_margin_end(box, 12);
    gtk_widget_set_margin_top(box, 12);
    gtk_widget_set_margin_bottom(box, 12);

    std::string text;
    if (entries.empty()) {
        text = "No applications have been uninstalled through this tool yet.";
    } else {
        // Newest first is more useful to scan than the on-disk oldest-first
        // order, so reverse for display only.
        for (auto it = entries.rbegin(); it != entries.rend(); ++it) {
            text += it->timestamp + "   " + it->app_name + "   [" + it->source + "]\n";
        }
    }

    GtkWidget* scroller = gtk_scrolled_window_new();
    GtkWidget* label = gtk_label_new(text.c_str());
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    gtk_label_set_selectable(GTK_LABEL(label), TRUE);  // so the user can select + copy entries
    gtk_widget_add_css_class(label, "monospace");
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroller), label);
    gtk_widget_set_vexpand(scroller, TRUE);
    gtk_box_append(GTK_BOX(box), scroller);

    std::string footer_text = "Stored at: " + udu::uninstall::history_file_path();
    GtkWidget* footer = gtk_label_new(footer_text.c_str());
    gtk_label_set_xalign(GTK_LABEL(footer), 0.0f);
    gtk_label_set_selectable(GTK_LABEL(footer), TRUE);
    gtk_widget_add_css_class(footer, "dim-label");
    gtk_box_append(GTK_BOX(box), footer);

    gtk_window_set_child(GTK_WINDOW(dialog_window), box);
    gtk_window_present(GTK_WINDOW(dialog_window));
}

std::vector<AppEntry> scan_applications() {
    std::vector<AppEntry> apps;
    std::error_code ec;
    std::string home = udu::detector::common::home_dir();

    // XDG precedence order, highest first: a user-local desktop file with
    // the same desktop-file-ID as a system one is what actually launches
    // (this is also exactly the mechanism this tool's own
    // "Uninstall Completely" integration relies on -- see
    // integration/desktop_override.cpp). Scanning in this order and
    // skipping any desktop_id already seen means:
    //   1. This previously missed EVERY app whose only .desktop file
    //      lives under ~/.local/share/applications/ -- which is where
    //      JetBrains Toolbox, most manually-registered apps, and anything
    //      a person set up by hand with a symlink into /usr/local/bin
    //      (e.g. CLion, IDEA, Arduino IDE) actually put theirs. That
    //      directory is now scanned first.
    //   2. Flatpak and Snap apps exported outside the two directories
    //      this used to check are now included too.
    //   3. An override THIS tool wrote to ~/.local/share/applications/
    //      for a system app is correctly treated as the same app (by
    //      desktop_id), not a confusing duplicate entry.
    std::vector<std::string> dirs_in_precedence_order = {
        home + "/.local/share/applications",
        "/usr/local/share/applications",
        "/usr/share/applications",
        home + "/.local/share/flatpak/exports/share/applications",
        "/var/lib/flatpak/exports/share/applications",
        "/var/lib/snapd/desktop/applications",
    };

    std::unordered_set<std::string> seen_ids;
    for (const auto& dir : dirs_in_precedence_order) {
        if (!fs::exists(dir, ec) || !fs::is_directory(dir, ec)) continue;
        for (const auto& f : fs::directory_iterator(dir, ec)) {
            if (f.path().extension() != ".desktop") continue;
            auto entry = udu::parse_desktop_file(f.path().string());
            if (!entry || entry->no_display || entry->type != "Application") continue;
            if (!seen_ids.insert(entry->desktop_id).second) continue;  // lower-precedence duplicate
            apps.push_back({entry->desktop_id, entry->name.empty() ? entry->desktop_id : entry->name,
                             f.path().string()});
        }
    }
    std::sort(apps.begin(), apps.end(), [](const AppEntry& a, const AppEntry& b) {
        return a.name < b.name;
    });
    return apps;
}

// Result of a background detection+plan lookup, marshaled back to the
// GTK main thread via g_idle_add (GTK widgets must only ever be touched
// from the main thread -- the detection/planning work itself is plain
// C++ over subprocess calls and is safe to run on a worker thread, but
// nothing past that point is).
struct DetectionJobResult {
    AppState* state;
    uint64_t generation;
    std::string text;
};

gboolean apply_detection_result(gpointer data) {
    auto* result = static_cast<DetectionJobResult*>(data);
    UDU_LOG("apply_detection_result(): idle callback fired for generation=" +
             std::to_string(result->generation) + ", current generation=" +
             std::to_string(result->state->generation.load()));
    // Discard if the user has since selected a different app -- this is
    // what makes rapid clicking through the list safe: only the most
    // recent selection's result is ever allowed to reach the UI.
    if (result->state->generation.load() == result->generation) {
        gtk_label_set_text(GTK_LABEL(result->state->detail_label), result->text.c_str());
        gtk_spinner_stop(GTK_SPINNER(result->state->spinner));
        gtk_widget_set_visible(result->state->loading_box, FALSE);
        gtk_widget_set_sensitive(result->state->dry_run_button, TRUE);
        gtk_widget_set_sensitive(result->state->uninstall_button, TRUE);
        UDU_LOG("apply_detection_result(): applied to UI");
    } else {
        UDU_LOG("apply_detection_result(): stale (a newer selection exists), discarding");
    }
    delete result;
    return G_SOURCE_REMOVE;
}

void update_detail_pane(AppState* state) {
    uint64_t my_generation = ++state->generation;
    UDU_LOG("update_detail_pane(): generation=" + std::to_string(my_generation) +
             (state->selected ? (" selected='" + state->selected->name + "' path=" + state->selected->path)
                               : " (no selection)"));

    if (!state->selected) {
        gtk_spinner_stop(GTK_SPINNER(state->spinner));
        gtk_widget_set_visible(state->loading_box, FALSE);
        gtk_label_set_text(GTK_LABEL(state->detail_label), "Select an application to inspect it.");
        gtk_widget_set_sensitive(state->dry_run_button, FALSE);
        gtk_widget_set_sensitive(state->uninstall_button, FALSE);
        return;
    }

    // Show the spinner immediately, synchronously, before any potentially
    // slow work starts -- this is the fix for "clicking an app freezes
    // for a few seconds with no feedback": detection can shell out to
    // dpkg/apt-get/flatpak/snap, which is exactly the kind of work that
    // must never run on the UI thread.
    std::string name = state->selected->name;
    gtk_label_set_text(GTK_LABEL(state->detail_label), ("Loading details for \"" + name + "\"…").c_str());
    gtk_widget_set_visible(state->loading_box, TRUE);
    gtk_spinner_start(GTK_SPINNER(state->spinner));
    gtk_widget_set_sensitive(state->dry_run_button, FALSE);
    gtk_widget_set_sensitive(state->uninstall_button, FALSE);

    std::string path = state->selected->path;
    AppState* state_ptr = state;
    UDU_LOG("update_detail_pane(): spawning background detection thread for generation=" +
             std::to_string(my_generation));
    std::thread([state_ptr, path, my_generation]() {
        UDU_LOG("[bg thread gen=" + std::to_string(my_generation) + "] started, parsing " + path);
        std::string text;
        auto entry = udu::parse_desktop_file(path);
        if (!entry) {
            UDU_LOG("[bg thread gen=" + std::to_string(my_generation) + "] parse_desktop_file FAILED");
            text = "Could not re-parse this desktop entry.";
        } else {
            UDU_LOG("[bg thread gen=" + std::to_string(my_generation) + "] calling run_detection()...");
            auto detection = udu::detector::run_detection(*entry);
            UDU_LOG("[bg thread gen=" + std::to_string(my_generation) + "] run_detection() returned, "
                     "source=" + std::string(udu::detector::to_string(detection.source)) +
                     "; calling build_plan()...");
            auto plan = udu::planner::build_plan(*entry, detection);
            UDU_LOG("[bg thread gen=" + std::to_string(my_generation) + "] build_plan() returned, "
                     "caching plan and formatting report...");
            // This is the fix for "why does clicking Uninstall Completely
            // scan again from scratch": the terminal it opens runs a
            // brand new process, so it can't just read this plan out of
            // this thread's memory -- but it CAN read it back from disk if
            // we persist it here, keyed to this exact desktop path, right
            // after computing it. See planner/plan_cache.cpp.
            udu::planner::save_plan_cache(plan);
            text = udu::terminal::format_detection(*entry, detection) + "\n" +
                   udu::terminal::format_plan(plan);
        }
        UDU_LOG("[bg thread gen=" + std::to_string(my_generation) + "] done, posting result to main thread");
        auto* result = new DetectionJobResult{state_ptr, my_generation, std::move(text)};
        g_idle_add(apply_detection_result, result);
    }).detach();
}

void on_row_selected(GtkListBox*, GtkListBoxRow* row, gpointer user_data) {
    auto* state = static_cast<AppState*>(user_data);
    if (!row) { state->selected.reset(); update_detail_pane(state); return; }
    int index = gtk_list_box_row_get_index(row);
    if (index < 0 || static_cast<size_t>(index) >= state->all_apps.size()) return;
    state->selected = state->all_apps[static_cast<size_t>(index)];
    update_detail_pane(state);
}

void populate_list(AppState* state, const std::string& filter) {
    GtkWidget* child;
    while ((child = gtk_widget_get_first_child(state->list_box)) != nullptr) {
        gtk_list_box_remove(GTK_LIST_BOX(state->list_box), child);
    }
    state->all_apps = scan_applications();
    if (!filter.empty()) {
        std::vector<AppEntry> filtered;
        for (auto& a : state->all_apps) {
            std::string lower_name = a.name;
            std::string lower_filter = filter;
            std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
            std::transform(lower_filter.begin(), lower_filter.end(), lower_filter.begin(), ::tolower);
            if (lower_name.find(lower_filter) != std::string::npos) filtered.push_back(a);
        }
        state->all_apps = filtered;
    }
    for (const auto& app : state->all_apps) {
        GtkWidget* row_label = gtk_label_new(app.name.c_str());
        gtk_label_set_xalign(GTK_LABEL(row_label), 0.0f);
        gtk_widget_set_margin_start(row_label, 8);
        gtk_widget_set_margin_end(row_label, 8);
        gtk_widget_set_margin_top(row_label, 6);
        gtk_widget_set_margin_bottom(row_label, 6);
        gtk_list_box_append(GTK_LIST_BOX(state->list_box), row_label);
    }
}

void on_search_changed(GtkSearchEntry* entry, gpointer user_data) {
    auto* state = static_cast<AppState*>(user_data);
    const char* text = gtk_editable_get_text(GTK_EDITABLE(entry));
    populate_list(state, text ? text : "");
}

void on_refresh_clicked(GtkButton*, gpointer user_data) {
    auto* state = static_cast<AppState*>(user_data);
    // Re-scans /usr/share/applications (and /usr/local/share/applications)
    // from scratch -- this is what picks up applications installed since
    // the window opened, and drops entries for applications that were
    // just uninstalled (their .desktop file is gone, so scan_applications()
    // simply won't find it anymore; nothing needs to be "removed from a
    // cache" because there is no cache).
    const char* text = gtk_editable_get_text(GTK_EDITABLE(state->search_entry));
    populate_list(state, text ? text : "");
    state->selected.reset();
    update_detail_pane(state);
}

void on_dry_run_clicked(GtkButton*, gpointer user_data) {
    auto* state = static_cast<AppState*>(user_data);
    if (!state->selected) return;
    launch_in_terminal({"ubuntu-deep-uninstaller", "--dry-run", state->selected->path}, state->window);
}

// A plain named struct instead of std::pair<A, B> here deliberately: a
// std::pair<std::string, GtkWidget*> template argument list contains a
// top-level comma that the C preprocessor (which has no idea what a C++
// template is) sees as an additional macro argument separator when it
// appears directly inside a g_signal_connect(...) call, producing a
// "macro passed N arguments, but takes 4" error. A named struct sidesteps
// the issue entirely rather than relying on extra parentheses to hide the
// comma from the preprocessor.
struct UninstallConfirmContext {
    std::string path;
    GtkWidget* window;
};

void on_uninstall_response(AdwAlertDialog*, const char* response, gpointer data) {
    auto* ctx = static_cast<UninstallConfirmContext*>(data);
    if (std::string(response) == "continue") {
        launch_in_terminal({"ubuntu-deep-uninstaller", "--uninstall", ctx->path}, ctx->window);
    }
    delete ctx;
}

void on_uninstall_clicked(GtkButton*, gpointer user_data) {
    auto* state = static_cast<AppState*>(user_data);
    if (!state->selected) return;

    // One extra, GUI-side confirmation before we even open the terminal --
    // the terminal itself still requires typing UNINSTALL, this is just an
    // extra guard against a misclick on the button.
    AdwDialog* dialog = adw_alert_dialog_new(
        "Uninstall this application?",
        ("This will open a terminal to detect, plan, and (after you confirm again there) "
         "remove \"" + state->selected->name + "\" and its associated data. Nothing is removed "
         "yet.").c_str());
    adw_alert_dialog_add_response(ADW_ALERT_DIALOG(dialog), "cancel", "Cancel");
    adw_alert_dialog_add_response(ADW_ALERT_DIALOG(dialog), "continue", "Open Terminal");
    adw_alert_dialog_set_response_appearance(ADW_ALERT_DIALOG(dialog), "continue", ADW_RESPONSE_DESTRUCTIVE);

    auto* ctx = new UninstallConfirmContext{state->selected->path, state->window};
    g_signal_connect(dialog, "response", G_CALLBACK(on_uninstall_response), ctx);

    adw_dialog_present(dialog, state->window);
}

void activate(GtkApplication* app, gpointer) {
    auto* state = new AppState();  // intentionally leaked for app lifetime; GTK owns teardown

    state->window = adw_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(state->window), "Ubuntu Deep Uninstaller");
    gtk_window_set_default_size(GTK_WINDOW(state->window), 760, 560);

    GtkWidget* toolbar_view = adw_toolbar_view_new();
    GtkWidget* header = adw_header_bar_new();

    // History button: left side of the header bar.
    state->history_button = gtk_button_new_from_icon_name("document-open-recent-symbolic");
    gtk_widget_set_tooltip_text(state->history_button, "View uninstall history");
    g_signal_connect(state->history_button, "clicked", G_CALLBACK(on_history_clicked), state);
    adw_header_bar_pack_start(ADW_HEADER_BAR(header), state->history_button);

    // Memory usage: right side of the header bar, refreshed every 2s for
    // the life of the window.
    state->memory_label = gtk_label_new(current_memory_usage_label().c_str());
    gtk_widget_add_css_class(state->memory_label, "dim-label");
    gtk_widget_set_margin_end(state->memory_label, 6);
    adw_header_bar_pack_end(ADW_HEADER_BAR(header), state->memory_label);
    g_timeout_add_seconds(2, update_memory_label, state);

    adw_toolbar_view_add_top_bar(ADW_TOOLBAR_VIEW(toolbar_view), header);

    GtkWidget* paned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);

    // Left: search + application list.
    GtkWidget* left_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_set_margin_start(left_box, 8);
    gtk_widget_set_margin_end(left_box, 8);
    gtk_widget_set_margin_top(left_box, 8);
    gtk_widget_set_margin_bottom(left_box, 8);

    state->search_entry = gtk_search_entry_new();
    // Set via the "placeholder-text" GObject property rather than a
    // typed gtk_search_entry_set_placeholder_text() call: that function's
    // presence/name has moved around across GTK4 point releases, whereas
    // the property itself is stable, so g_object_set() here is the safer
    // bet across the GTK4 versions this project might be built against.
    g_object_set(G_OBJECT(state->search_entry), "placeholder-text", "Search applications…", nullptr);
    g_signal_connect(state->search_entry, "search-changed", G_CALLBACK(on_search_changed), state);
    gtk_widget_set_hexpand(state->search_entry, TRUE);

    // Refresh button lives right next to search: it re-scans the
    // application list from disk, which is what picks up recently
    // installed applications and drops ones that were just uninstalled
    // (via the terminal workflow, which the GUI has no other way to learn
    // finished).
    state->refresh_button = gtk_button_new_from_icon_name("view-refresh-symbolic");
    gtk_widget_set_tooltip_text(state->refresh_button, "Refresh application list");
    g_signal_connect(state->refresh_button, "clicked", G_CALLBACK(on_refresh_clicked), state);

    GtkWidget* search_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_append(GTK_BOX(search_row), state->search_entry);
    gtk_box_append(GTK_BOX(search_row), state->refresh_button);
    gtk_box_append(GTK_BOX(left_box), search_row);

    GtkWidget* scroller = gtk_scrolled_window_new();
    state->list_box = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(state->list_box), GTK_SELECTION_SINGLE);
    g_signal_connect(state->list_box, "row-selected", G_CALLBACK(on_row_selected), state);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroller), state->list_box);
    gtk_widget_set_vexpand(scroller, TRUE);
    gtk_box_append(GTK_BOX(left_box), scroller);

    gtk_paned_set_start_child(GTK_PANED(paned), left_box);
    gtk_paned_set_resize_start_child(GTK_PANED(paned), TRUE);

    // Right: detail pane + action buttons.
    GtkWidget* right_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_start(right_box, 8);
    gtk_widget_set_margin_end(right_box, 8);
    gtk_widget_set_margin_top(right_box, 8);
    gtk_widget_set_margin_bottom(right_box, 8);

    // Loading row: a spinner + label shown only while a detection lookup
    // is running in the background, so selecting an app never just
    // freezes with no feedback while dpkg/apt-get/etc. are queried.
    state->loading_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    state->spinner = gtk_spinner_new();
    GtkWidget* loading_label = gtk_label_new("Loading…");
    gtk_box_append(GTK_BOX(state->loading_box), state->spinner);
    gtk_box_append(GTK_BOX(state->loading_box), loading_label);
    gtk_widget_set_visible(state->loading_box, FALSE);
    gtk_box_append(GTK_BOX(right_box), state->loading_box);

    GtkWidget* detail_scroller = gtk_scrolled_window_new();
    state->detail_label = gtk_label_new("Select an application to inspect it.");
    gtk_label_set_xalign(GTK_LABEL(state->detail_label), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(state->detail_label), TRUE);
    gtk_label_set_selectable(GTK_LABEL(state->detail_label), TRUE);
    gtk_widget_add_css_class(state->detail_label, "monospace");
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(detail_scroller), state->detail_label);
    gtk_widget_set_vexpand(detail_scroller, TRUE);
    gtk_box_append(GTK_BOX(right_box), detail_scroller);

    GtkWidget* button_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    state->dry_run_button = gtk_button_new_with_label("Dry Run");
    state->uninstall_button = gtk_button_new_with_label("Uninstall Completely");
    gtk_widget_add_css_class(state->uninstall_button, "destructive-action");
    gtk_widget_set_sensitive(state->dry_run_button, FALSE);
    gtk_widget_set_sensitive(state->uninstall_button, FALSE);
    g_signal_connect(state->dry_run_button, "clicked", G_CALLBACK(on_dry_run_clicked), state);
    g_signal_connect(state->uninstall_button, "clicked", G_CALLBACK(on_uninstall_clicked), state);
    gtk_box_append(GTK_BOX(button_box), state->dry_run_button);
    gtk_box_append(GTK_BOX(button_box), state->uninstall_button);
    gtk_box_append(GTK_BOX(right_box), button_box);

    gtk_paned_set_end_child(GTK_PANED(paned), right_box);
    gtk_paned_set_resize_end_child(GTK_PANED(paned), TRUE);
    gtk_paned_set_position(GTK_PANED(paned), 280);

    adw_toolbar_view_set_content(ADW_TOOLBAR_VIEW(toolbar_view), paned);
    adw_application_window_set_content(ADW_APPLICATION_WINDOW(state->window), toolbar_view);

    populate_list(state, "");
    gtk_window_present(GTK_WINDOW(state->window));
}

}  // namespace

int main(int argc, char** argv) {
    // Installed first, before anything else can possibly crash: prints a
    // signal name + backtrace to stderr (visible when the GUI is launched
    // from a terminal, which is exactly how to debug it) instead of the
    // window just disappearing with no trace of why.
    udu::security::install_crash_handler();
    UDU_LOG("main(): ubuntu-deep-uninstaller-gui starting");

    // The color helpers in src/terminal/color.hpp auto-detect a tty via
    // isatty(STDOUT_FILENO) and, if true, embed raw ANSI escape codes into
    // the strings format_detection()/format_plan() return -- correct for
    // the CLI printing to a real terminal, but a GtkLabel does not
    // interpret ANSI codes, so if this GUI happens to be launched from an
    // existing terminal (e.g. someone runs it manually to test), those
    // escape codes would show up as literal garbage text in the detail
    // pane. Force them off unconditionally for this process, regardless
    // of how it was launched.
    setenv("NO_COLOR", "1", 1);

    AdwApplication* app = adw_application_new("org.uduninstaller.UbuntuDeepUninstaller",
                                               G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(activate), nullptr);
    int status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    return status;
}

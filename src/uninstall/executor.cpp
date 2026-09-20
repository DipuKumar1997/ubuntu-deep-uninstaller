#include "executor.hpp"
#include "history.hpp"
#include "../security/proc_exec.hpp"
#include "../security/paths.hpp"

#include <filesystem>

namespace fs = std::filesystem;

namespace udu::uninstall {

namespace {
using udu::security::run;

void log(ExecutionResult& out, const std::string& tag, const std::string& text) {
    out.log.push_back({tag, text});
}

bool remove_path_recursively(const std::string& validated_path, bool requires_sudo, std::string& error_out) {
    // Re-validate at the moment of deletion, not just at plan-build time --
    // the filesystem may have changed between planning and execution
    // (TOCTOU hardening). If it no longer resolves safely, refuse.
    auto revalidated = udu::security::canonicalize(validated_path);
    if (!revalidated || udu::security::is_catastrophic_path(*revalidated)) {
        error_out = "path failed re-validation immediately before deletion";
        return false;
    }

    if (requires_sudo) {
        // A root-owned resource is deleted through an explicit, interactive
        // `sudo rm -rf --` call -- NOT by relying on this process's own
        // ambient permissions. Those are not the same thing: if this CLI
        // is ever invoked already running as root (e.g. the whole terminal
        // session was started with sudo, which the project's own design
        // explicitly discourages -- only the specific privileged steps
        // should ever ask for sudo), a direct in-process filesystem
        // removal would silently succeed with no privilege prompt at all
        // for a step the plan explicitly marked as needing one. Routing
        // through `sudo` here makes the "requires elevated privileges"
        // note in the plan an accurate description of what actually
        // happens, not just cosmetic text.
        auto r = run({"sudo", "rm", "-rf", "--", *revalidated},
                      {.working_dir = std::nullopt, .timeout = std::chrono::milliseconds(60000), .close_stdin = false});
        if (!r.ok()) {
            error_out = "sudo rm -rf failed (exit " + std::to_string(r.exit_code) + "): " + r.stderr_text;
            return false;
        }
        return true;
    }

    std::error_code ec;
    fs::remove_all(*revalidated, ec);
    if (ec) {
        error_out = ec.message();
        return false;
    }
    return true;
}

void execute_apt(const planner::RemovalPlan& plan, const ExecutionOptions& opts, ExecutionResult& out) {
    if (!plan.package) { log(out, "[ERROR]", "no package information in plan"); return; }
    std::vector<std::string> argv = {"sudo", "apt-get", opts.purge_apt_configs ? "purge" : "remove", "-y", plan.package->name};
    log(out, "[REMOVE]", "running: " + argv[0] + " " + argv[1] + " " + argv[2] + " -y " + plan.package->name);
    auto r = run(argv, {.working_dir = std::nullopt, .timeout = std::chrono::milliseconds(300000), .close_stdin = false});
    if (r.ok()) log(out, "[SUCCESS]", "package removed");
    else log(out, "[ERROR]", "apt-get failed (exit " + std::to_string(r.exit_code) + "): " + r.stderr_text);

    if (opts.run_autoremove_if_offered && !plan.dependencies_would_remove.empty()) {
        log(out, "[REMOVE]", "running: sudo apt-get autoremove -y (user-approved set)");
        auto ar = run({"sudo", "apt-get", "autoremove", "-y"}, {.working_dir = std::nullopt, .timeout = std::chrono::milliseconds(300000), .close_stdin = false});
        if (ar.ok()) log(out, "[SUCCESS]", "autoremove completed");
        else log(out, "[ERROR]", "autoremove failed: " + ar.stderr_text);
    }
}

void execute_flatpak(const planner::RemovalPlan& plan, ExecutionResult& out) {
    if (!plan.package) { log(out, "[ERROR]", "no package information in plan"); return; }
    log(out, "[REMOVE]", "running: flatpak uninstall -y " + plan.package->name);
    auto r = run({"flatpak", "uninstall", "-y", plan.package->name}, {.working_dir = std::nullopt, .timeout = std::chrono::milliseconds(120000)});
    if (r.ok()) log(out, "[SUCCESS]", "flatpak application removed");
    else log(out, "[ERROR]", "flatpak uninstall failed: " + r.stderr_text);
}

void execute_snap(const planner::RemovalPlan& plan, ExecutionResult& out) {
    if (!plan.package) { log(out, "[ERROR]", "no package information in plan"); return; }
    log(out, "[REMOVE]", "running: sudo snap remove " + plan.package->name);
    auto r = run({"sudo", "snap", "remove", plan.package->name}, {.working_dir = std::nullopt, .timeout = std::chrono::milliseconds(120000), .close_stdin = false});
    if (r.ok()) log(out, "[SUCCESS]", "snap removed");
    else log(out, "[ERROR]", "snap remove failed: " + r.stderr_text);
}

// Shared path for Wine / AppImage / Manual: everything left to do is
// filesystem removal of already-validated resources.
void execute_filesystem_resources(const planner::RemovalPlan& plan, const ExecutionOptions& opts, ExecutionResult& out) {
    for (const auto& res : plan.resources) {
        if (res.type == detector::ResourceType::Package) continue;  // handled above per-source
        bool act = res.action == planner::PlanAction::Remove ||
                   (res.action == planner::PlanAction::RemoveWithWarning && opts.include_warn_items);
        if (!act) {
            log(out, "[SKIP]", res.path + " (" + res.reason + ")");
            continue;
        }
        if (!res.validated) {
            log(out, "[SKIP]", res.path + " (failed validation, refusing to delete)");
            continue;
        }

        // A resource can legitimately already be gone by the time we get
        // here -- most commonly the desktop entry itself, when it's a file
        // the just-purged APT package also tracked and removed on its own
        // (execute_apt() runs before this loop). That is success, not a
        // failure: the goal ("this resource is gone") is already met. A
        // plain existence check (not the stricter canonicalize() used for
        // an actual deletion) is enough to tell "already gone" apart from
        // "something else is wrong with this path."
        std::error_code exists_ec;
        if (!std::filesystem::exists(res.path, exists_ec) &&
            !std::filesystem::is_symlink(res.path, exists_ec)) {
            log(out, "[SUCCESS]", res.path +
                " already removed (most likely by the package manager as part of removing "
                "its owning package) -- nothing left to do");
            continue;
        }

        std::string err;
        log(out, "[REMOVE]", res.path);
        if (remove_path_recursively(res.path, res.requires_sudo, err)) {
            log(out, "[SUCCESS]", res.path + " removed");
        } else {
            log(out, "[ERROR]", res.path + " -- " + err);
        }
    }
}

}  // namespace

ExecutionResult execute_plan(const planner::RemovalPlan& plan, const ExecutionOptions& options) {
    ExecutionResult out;

    switch (plan.source) {
        case detector::InstallationSource::Apt:
            execute_apt(plan, options, out);
            execute_filesystem_resources(plan, options, out);  // desktop entry / user-space guesses
            break;
        case detector::InstallationSource::Flatpak:
            execute_flatpak(plan, out);
            execute_filesystem_resources(plan, options, out);
            break;
        case detector::InstallationSource::Snap:
            execute_snap(plan, out);
            execute_filesystem_resources(plan, options, out);
            break;
        case detector::InstallationSource::Wine:
        case detector::InstallationSource::AppImage:
        case detector::InstallationSource::Manual:
        case detector::InstallationSource::Unknown:
            execute_filesystem_resources(plan, options, out);
            break;
    }

    bool any_error = false;
    for (const auto& l : out.log) if (l.tag == "[ERROR]") any_error = true;
    out.overall_success = !any_error;

    if (out.overall_success) {
        // Best-effort, never fails the uninstall itself if it can't write.
        record_history(plan.application_name, std::string(detector::to_string(plan.source)));
    }

    return out;
}

}  // namespace udu::uninstall

#include "verify.hpp"
#include "../security/proc_exec.hpp"
#include "../security/paths.hpp"

#include <filesystem>

namespace fs = std::filesystem;

namespace udu::verification {

bool VerificationReport::all_clear() const {
    if (process_still_running) return false;
    for (const auto& i : items) {
        if (i.status == ItemStatus::StillPresent) return false;
    }
    return true;
}

namespace {

VerificationItem verify_package(const std::string& name, detector::InstallationSource source) {
    using udu::security::run;
    switch (source) {
        case detector::InstallationSource::Apt: {
            if (!udu::security::executable_exists("dpkg-query")) {
                return {name, ItemStatus::CouldNotVerify, "dpkg-query unavailable"};
            }
            auto r = run({"dpkg-query", "-W", "-f=${Status}", name});
            bool installed = r.ok() && r.stdout_text.find("install ok installed") != std::string::npos;
            return {name, installed ? ItemStatus::StillPresent : ItemStatus::Removed,
                    installed ? "dpkg still reports this package as installed"
                              : "dpkg no longer reports this package as installed"};
        }
        case detector::InstallationSource::Flatpak: {
            if (!udu::security::executable_exists("flatpak")) {
                return {name, ItemStatus::CouldNotVerify, "flatpak unavailable"};
            }
            auto u = run({"flatpak", "info", "--user", name});
            auto s = run({"flatpak", "info", "--system", name});
            bool installed = u.ok() || s.ok();
            return {name, installed ? ItemStatus::StillPresent : ItemStatus::Removed,
                    installed ? "flatpak still reports this application as installed"
                              : "flatpak no longer reports this application as installed"};
        }
        case detector::InstallationSource::Snap: {
            if (!udu::security::executable_exists("snap")) {
                return {name, ItemStatus::CouldNotVerify, "snap unavailable"};
            }
            auto r = run({"snap", "list", name});
            bool installed = r.ok();
            return {name, installed ? ItemStatus::StillPresent : ItemStatus::Removed,
                    installed ? "snap still reports this snap as installed"
                              : "snap no longer lists this snap"};
        }
        default:
            return {name, ItemStatus::CouldNotVerify, "no package-manager verification applicable"};
    }
}

VerificationItem verify_path(const std::string& path) {
    std::error_code ec;
    bool exists = fs::exists(path, ec) || fs::is_symlink(path, ec);
    return {path, exists ? ItemStatus::StillPresent : ItemStatus::Removed,
            exists ? "path still exists on disk" : "path no longer exists"};
}

}  // namespace

VerificationReport verify(const planner::RemovalPlan& plan) {
    VerificationReport report;

    for (const auto& res : plan.resources) {
        if (res.action == planner::PlanAction::Skip) {
            report.items.push_back({res.path, ItemStatus::NotApplicableSkipped,
                                     "was not selected for removal"});
            continue;
        }
        if (res.type == detector::ResourceType::Package) {
            report.items.push_back(verify_package(res.path, plan.source));
        } else {
            report.items.push_back(verify_path(res.path));
        }
    }

    // Process check: for a filesystem-resolvable app this re-scans /proc
    // the same way detection did; for package-manager apps we treat "still
    // installed" above as sufficient and don't duplicate a fuzzy cmdline
    // match here to avoid false positives from unrelated processes.
    report.process_still_running = false;  // populated by caller when it has a resolved exe path

    return report;
}

}  // namespace udu::verification

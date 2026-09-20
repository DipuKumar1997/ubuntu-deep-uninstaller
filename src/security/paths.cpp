#include "paths.hpp"

#include <climits>
#include <cstdlib>
#include <filesystem>
#include <unordered_set>

namespace fs = std::filesystem;

namespace udu::security {

bool is_catastrophic_path(const std::string& p) {
    static const std::unordered_set<std::string> forbidden = {
        "/", "/root", "/home", "/etc", "/usr", "/usr/bin", "/usr/lib",
        "/usr/share", "/usr/local", "/var", "/var/lib", "/var/log",
        "/boot", "/bin", "/lib", "/lib64", "/sbin", "/opt", "/dev",
        "/proc", "/sys", "/tmp", "/run",
    };
    if (forbidden.count(p)) return true;
    // A bare home directory (e.g. "/home/alice") is also catastrophic --
    // legitimate targets are always at least one level below it
    // (~/.config/<app>, not ~).
    if (p.rfind("/home/", 0) == 0) {
        std::string rest = p.substr(6);
        if (rest.find('/') == std::string::npos) return true;  // "/home/<user>" exactly
    }
    return false;
}

std::optional<std::string> canonicalize(const std::string& path) {
    std::error_code ec;
    fs::path canonical = fs::weakly_canonical(fs::path(path), ec);
    if (ec) return std::nullopt;
    // weakly_canonical succeeds even for paths whose final component
    // doesn't exist; for removal-target purposes we require the target to
    // actually exist (we're not creating anything).
    if (!fs::exists(canonical, ec)) return std::nullopt;
    // Fully resolve via realpath-equivalent (canonical, not weakly) now
    // that we know it exists, to collapse any remaining symlinks.
    fs::path fully = fs::canonical(canonical, ec);
    if (ec) return std::nullopt;
    return fully.string();
}

bool is_under(const std::string& child, const std::string& parent) {
    if (child == parent) return true;
    std::string prefix = parent;
    if (prefix.empty() || prefix.back() != '/') prefix += '/';
    return child.rfind(prefix, 0) == 0;
}

Owner classify_owner(const std::string& canonical_path) {
    if (canonical_path.rfind("/home/", 0) == 0 || canonical_path.rfind("/root/", 0) == 0) {
        return Owner::UserHome;
    }
    if (canonical_path.rfind("/usr/", 0) == 0 || canonical_path.rfind("/etc/", 0) == 0 ||
        canonical_path.rfind("/var/", 0) == 0 || canonical_path.rfind("/opt/", 0) == 0) {
        // Caller should further check dpkg -S to distinguish
        // SystemManagedByPackage from SystemUnmanaged; this function only
        // knows geography, not package ownership.
        return Owner::SystemUnmanaged;
    }
    return Owner::Unknown;
}

TargetValidation validate_removal_target(const std::string& raw_path,
                                          const std::vector<std::string>& allowed_roots) {
    auto canon = canonicalize(raw_path);
    if (!canon) {
        return {false, "path does not exist or could not be resolved (broken symlink, "
                        "permission denied, or already removed) -- refusing to guess"};
    }
    if (is_catastrophic_path(*canon)) {
        return {false, "resolved path is a protected system root; refusing unconditionally"};
    }
    if (allowed_roots.empty()) {
        return {false, "no evidence-derived root was supplied for this target"};
    }
    std::vector<std::string> canon_roots;
    for (const auto& r : allowed_roots) {
        if (auto c = canonicalize(r)) canon_roots.push_back(*c);
    }
    for (const auto& root : canon_roots) {
        if (is_under(*canon, root)) {
            return {true, "resolved path is under evidence-derived root: " + root};
        }
    }
    return {false, "resolved path (possibly after following a symlink) escapes every "
                    "evidence-derived root -- refusing"};
}

}  // namespace udu::security

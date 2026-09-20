// paths.hpp
//
// Path canonicalization, symlink resolution, and "is this path a sane
// deletion target" checks. These are the last line of defense before any
// filesystem mutation: every path the planner hands to the cleanup/
// uninstall layer must have passed through validate_removal_target() first.
#pragma once

#include <string>
#include <optional>
#include <vector>

namespace udu::security {

// A small set of paths we NEVER allow as removal targets, even if some
// detector's evidence chain mistakenly points at them (e.g. a bug that
// resolves Exec= to "/" or "/home/user"). This is deliberately generous
// (errs toward refusing) rather than trying to be a complete blocklist --
// the real safety property comes from requiring evidence-derived paths in
// the first place, this is a sanity backstop.
bool is_catastrophic_path(const std::string& canonical_path);

// Resolves `path` to an absolute, symlink-free canonical form using
// realpath(3) semantics. Returns std::nullopt if the path does not exist
// or cannot be resolved (caller should treat that as "cannot verify,
// therefore do not delete").
std::optional<std::string> canonicalize(const std::string& path);

// True if `child` (already canonicalized) is equal to or lexically nested
// under `parent` (already canonicalized). Used to make sure a resolved
// deletion target is actually inside a directory the evidence chain
// legitimately pointed at, and hasn't escaped via a symlink.
bool is_under(const std::string& canonical_child, const std::string& canonical_parent);

enum class Owner { UserHome, SystemManagedByPackage, SystemUnmanaged, Unknown };

// Best-effort classification of who "owns" a path, used to decide whether
// a resource needs sudo and whether dpkg needs to be consulted before
// deletion. This does not by itself authorize deletion.
Owner classify_owner(const std::string& canonical_path);

struct TargetValidation {
    bool safe_to_remove = false;
    std::string reason;  // human-readable explanation either way
};

// The single choke point every deletion must pass through:
//  - path must canonicalize (must exist, no dangling/unsafe symlink chain)
//  - must not be a catastrophic path
//  - must be under at least one of `allowed_roots` (the evidence-derived
//    directories the detector actually found, e.g. the app's own /opt/foo)
TargetValidation validate_removal_target(const std::string& raw_path,
                                          const std::vector<std::string>& allowed_roots);

}  // namespace udu::security

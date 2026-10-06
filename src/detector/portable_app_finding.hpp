// detector/portable_app_finding.hpp
//
// Handles manually-extracted "portable" application installs -- the
// common JetBrains-Toolbox-style pattern of: download an archive, extract
// it somewhere (often ~/Downloads, ~/Applications, or wherever the person
// put it), then `sudo ln -sf <extracted>/bin/idea.sh /usr/local/bin/idea`.
// manual_detector.cpp's ordinary immediate-parent-directory candidate
// only offers the `bin/` folder for removal, which leaves the rest of a
// multi-gigabyte extracted IDE untouched. This module adds two things on
// top of that:
//
//   1. If the resolved executable's immediate parent is named "bin" (the
//      near-universal convention for this kind of archive), walk up one
//      more level and offer THAT directory too -- the actual extracted
//      application root.
//   2. A best-effort, ~/Downloads-only (never a deep/recursive scan of
//      the whole filesystem) search for an archive file whose name
//      plausibly matches the application, so it can be offered for
//      removal too.
//
// Both lookups are cached to disk, keyed by the resolved executable path,
// so a given application is only ever searched once -- explicitly
// requested, to keep detection fast on repeat runs.
#pragma once

#include <string>
#include <optional>

namespace udu::detector {

struct PortableAppFinding {
    std::optional<std::string> extracted_root;         // e.g. ~/Videos/idea-IU-262.9437.185
    std::optional<std::string> matching_download_archive;  // e.g. ~/Downloads/ideaIU-2024.1.tar.gz
};

// Returns the cached finding for `resolved_exe_path` if one exists,
// regardless of age (unlike the plan cache, there's no reason for this
// one to expire: a portable app's install location and any matching
// archive in Downloads don't change on their own between runs).
std::optional<PortableAppFinding> load_cached_portable_finding(const std::string& resolved_exe_path);

// Computes a fresh finding (the actual directory-walk and ~/Downloads
// scan) and writes it to the cache before returning it.
PortableAppFinding compute_and_cache_portable_finding(const std::string& resolved_exe_path);

}  // namespace udu::detector

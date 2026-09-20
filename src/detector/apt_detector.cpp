#include "apt_detector.hpp"
#include "common.hpp"
#include "../security/proc_exec.hpp"
#include "../security/debug_log.hpp"

#include <sstream>
#include <algorithm>
#include <fstream>
#include <future>

namespace udu::detector {

namespace {
using udu::security::run;

std::vector<std::string> split_lines(const std::string& s) {
    std::vector<std::string> out;
    std::istringstream is(s);
    std::string line;
    while (std::getline(is, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) out.push_back(line);
    }
    return out;
}

std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t");
    return s.substr(a, b - a + 1);
}

// Whether `pkg` is recorded as automatically-installed, found by reading
// /var/lib/apt/extended_states DIRECTLY rather than spawning `apt-mark
// showmanual` (which dumps the name of every manually-installed package
// on the whole system just to answer a yes/no question about ONE
// package -- on a system with hundreds of packages this is real,
// measurable, and entirely avoidable work). The file is a sequence of
// stanzas like:
//   Package: foo
//   Architecture: amd64
//   Auto-Installed: 1
// A package with no stanza at all, or "Auto-Installed: 0", is manually
// installed by apt's own convention.
struct AutoInstalledLookup {
    bool found_entry = false;
    bool is_auto_installed = false;
};

AutoInstalledLookup lookup_auto_installed(const std::string& pkg) {
    AutoInstalledLookup result;
    std::ifstream f("/var/lib/apt/extended_states");
    if (!f) return result;  // file missing/unreadable: treat as "unknown", caller defaults to manual

    std::string line;
    std::string current_pkg;
    bool current_auto = false;
    bool current_has_auto_key = false;

    auto flush_stanza = [&]() {
        if (!current_pkg.empty() && current_pkg == pkg && current_has_auto_key) {
            result.found_entry = true;
            result.is_auto_installed = current_auto;
        }
    };

    while (std::getline(f, line)) {
        if (line.empty()) {
            flush_stanza();
            current_pkg.clear();
            current_auto = false;
            current_has_auto_key = false;
            continue;
        }
        if (line.rfind("Package:", 0) == 0) {
            current_pkg = trim(line.substr(8));
        } else if (line.rfind("Auto-Installed:", 0) == 0) {
            current_has_auto_key = true;
            current_auto = trim(line.substr(15)) == "1";
        }
    }
    flush_stanza();  // in case the file doesn't end with a trailing blank line
    return result;
}

}  // namespace

std::optional<DetectionResult> detect_apt(const std::string& resolved_executable) {
    UDU_LOG("detect_apt(): entry for resolved_executable=" + resolved_executable);
    if (!udu::security::executable_exists("dpkg")) return std::nullopt;

    // Reverse lookup: which package owns this exact file? This is the ONLY
    // identity link we trust -- we never infer the package from the
    // executable's filename. This one call MUST happen first and
    // sequentially: every other lookup below needs the package name it
    // produces.
    auto owns = run({"dpkg", "-S", resolved_executable});
    if (!owns.ok()) {
        // "no path found matching pattern" (exit 1) means: not a dpkg file.
        UDU_LOG("detect_apt(): dpkg -S found no owning package, returning nullopt");
        return std::nullopt;
    }

    // dpkg -S output looks like: "package-name: /usr/bin/foo" (possibly
    // multiple packages for shared paths, comma-separated on one line).
    auto first_colon = owns.stdout_text.find(':');
    if (first_colon == std::string::npos) return std::nullopt;
    std::string pkg_field = owns.stdout_text.substr(0, first_colon);
    // Multiple owning packages: take the first, but record the rest as a
    // warning -- shared-path ownership is exactly the kind of ambiguity we
    // want surfaced, not silently resolved.
    std::vector<std::string> owners;
    {
        std::istringstream is(pkg_field);
        std::string tok;
        while (std::getline(is, tok, ',')) {
            std::string t = trim(tok);
            if (!t.empty()) owners.push_back(t);
        }
    }
    if (owners.empty()) return std::nullopt;
    std::string pkg = owners.front();

    DetectionResult result;
    result.source = InstallationSource::Apt;
    result.resolved_executable = resolved_executable;
    result.evidence_trail.push_back(
        "dpkg -S " + resolved_executable + " -> owned by package '" + pkg + "'");
    if (owners.size() > 1) {
        result.warnings.push_back(
            "Multiple packages claim this path (" + pkg_field +
            "); proceeding with '" + pkg + "' but this indicates a diverted/shared file.");
    }

    // From here on, every lookup only needs `pkg` -- none of them depend
    // on each other's results, so they run CONCURRENTLY instead of one
    // after another. This is the fix for "detecting one application takes
    // 30 seconds": previously this function ran up to 4 sequential
    // subprocess calls (dpkg-query, apt-mark, apt-get simulate, dpkg -L),
    // each with its own multi-second worst case, one after another. Now
    // the three that still need a subprocess run in parallel, and the
    // apt-mark step below no longer spawns a process at all.
    UDU_LOG("detect_apt(): pkg='" + pkg + "', dispatching dpkg-query/apt-get-simulate/dpkg-L concurrently...");

    auto info_future = std::async(std::launch::async, [&pkg]() {
        return run({"dpkg-query", "-W", "-f=${Version}\t${Architecture}\t${Status}\n", pkg});
    });

    // `-o Debug::NoLocking=1` tells apt not to even attempt acquiring its
    // lock file for this read-only query -- without it, apt-get can sit
    // waiting (sometimes for a long time) if another apt/dpkg process
    // happens to be running (unattended-upgrades, Software Updater, ...),
    // which is unrelated to how complex this particular package's
    // dependency graph is but looks identical from the UI's perspective.
    auto sim_future = std::async(std::launch::async, [&pkg]() {
        return run({"apt-get", "remove", "--simulate", "-y", "-o", "Debug::NoLocking=1", pkg},
                    {.working_dir = std::nullopt, .timeout = std::chrono::milliseconds(8000)});
    });

    auto files_future = std::async(std::launch::async, [&pkg]() {
        return run({"dpkg", "-L", pkg});
    });

    // Auto-Installed lookup no longer needs a future at all -- it's a
    // direct file read on THIS thread while the three subprocess calls
    // above run concurrently in the background, effectively free.
    PackageInfo pinfo;
    pinfo.name = pkg;
    auto auto_lookup = lookup_auto_installed(pkg);
    pinfo.manually_installed = !(auto_lookup.found_entry && auto_lookup.is_auto_installed);
    result.evidence_trail.push_back(
        std::string("apt extended_states: ") + (pinfo.manually_installed
            ? "manually installed" : "marked as automatically installed (likely a dependency)"));
    if (!pinfo.manually_installed) {
        result.warnings.push_back(
            "'" + pkg + "' is marked as automatically installed. It may be a dependency "
            "pulled in by another package rather than something the user installed "
            "directly. Double-check before purging.");
    }

    auto info = info_future.get();
    if (info.ok() && !info.stdout_text.empty()) {
        std::istringstream is(info.stdout_text);
        std::string version, arch, status;
        std::getline(is, version, '\t');
        std::getline(is, arch, '\t');
        std::getline(is, status);
        pinfo.version = version;
        pinfo.architecture = arch;
        result.evidence_trail.push_back(
            "dpkg-query: version=" + version + " arch=" + arch + " status=" + trim(status));
    }

    auto sim = sim_future.get();
    if (sim.ok() || sim.exit_code == 0) {
        for (const auto& line : split_lines(sim.stdout_text)) {
            if (line.rfind("Remv ", 0) == 0) {
                std::istringstream is(line);
                std::string remv, name;
                is >> remv >> name;
                if (!name.empty() && name != pkg) pinfo.would_also_remove.push_back(name);
            }
        }
        result.evidence_trail.push_back(
            "apt-get remove --simulate: " +
            std::to_string(pinfo.would_also_remove.size()) + " other package(s) would also be removed");
    } else {
        result.warnings.push_back(
            "Could not run 'apt-get remove --simulate' to compute the full removal set "
            "(apt may need sudo in this environment); the removal set shown may be incomplete "
            "until confirmed interactively.");
    }

    result.package = pinfo;
    result.overall_confidence = Confidence::High;

    // The package itself is the primary resource.
    Resource pkg_resource;
    pkg_resource.path = pkg;
    pkg_resource.type = ResourceType::Package;
    pkg_resource.confidence = Confidence::High;
    pkg_resource.evidence = "dpkg -S identified this package as owning " + resolved_executable;
    pkg_resource.user_owned = false;
    pkg_resource.recommended_action = PlannedAction::Remove;
    result.resources.push_back(pkg_resource);

    // Enumerate every file dpkg believes this package owns, purely for the
    // report/verification step (NOT for manual deletion -- these are
    // removed by apt/dpkg itself, never rm'd by this tool).
    auto files = files_future.get();
    if (files.ok()) {
        int count = static_cast<int>(split_lines(files.stdout_text).size());
        result.evidence_trail.push_back(
            "dpkg -L " + pkg + ": " + std::to_string(count) + " file(s) tracked by the package "
            "(will be removed by apt/dpkg itself, not by this tool)");
    }

    // Conservative, EXISTENCE-CHECKED user-space guesses (Medium
    // confidence at best -- dpkg has no visibility into ~/.config).
    std::string leaf = pkg;
    for (const auto& g : udu::detector::common::existing_xdg_candidates(leaf)) {
        Resource r;
        r.path = g.path;
        r.type = g.type;
        r.confidence = Confidence::Medium;
        r.evidence = "directory name matches package name '" + pkg + "' under the standard "
                     "XDG base directory for " + std::string(to_string(g.type)) +
                     "; existence-checked but not package-tracked";
        r.user_owned = true;
        r.recommended_action = PlannedAction::Remove;  // still subject to user confirmation + purge choice
        r.allowed_roots = {g.path};
        result.resources.push_back(r);
    }

    // Autostart entries whose Exec resolves to this same binary.
    for (const auto& p : udu::detector::common::matching_autostart_entries(resolved_executable)) {
        Resource r;
        r.path = p;
        r.type = ResourceType::Autostart;
        r.confidence = Confidence::High;
        r.evidence = "autostart .desktop file whose Exec= resolves to the same binary ("
                     + resolved_executable + ")";
        r.user_owned = p.rfind(udu::detector::common::home_dir(), 0) == 0;
        r.recommended_action = PlannedAction::Remove;
        r.allowed_roots = {p};
        result.resources.push_back(r);
    }

    UDU_LOG("detect_apt(): done, package=" + result.package->name);
    return result;
}

}  // namespace udu::detector

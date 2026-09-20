#include "plan_cache.hpp"
#include "../detector/common.hpp"

#include <fstream>
#include <sstream>
#include <filesystem>
#include <ctime>
#include <cstdlib>

namespace fs = std::filesystem;

namespace udu::planner {

namespace {

// Cached plans older than this are ignored (treated as "no cache") rather
// than reused -- long enough to comfortably cover "select an app, read
// the plan, click a button", short enough that a plan left over from a
// GUI session hours ago can never be silently reused against a system
// that may have changed since.
constexpr long kMaxCacheAgeSeconds = 180;

std::string cache_file_path() {
    return udu::detector::common::home_dir() + "/.cache/ubuntu-deep-uninstaller/last_plan.cache";
}

// Minimal escaping so every field can be written as one line: backslash,
// tab, and newline are the only characters that would otherwise break the
// tab-separated, line-based format below. Everything here is internally
// generated text (evidence strings, warnings, paths), never raw untrusted
// input, so this only needs to be correct, not hardened against
// adversarial content.
std::string escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '\t': out += "\\t"; break;
            case '\n': out += "\\n"; break;
            default: out += c;
        }
    }
    return out;
}

std::string unescape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            char n = s[i + 1];
            if (n == '\\') { out += '\\'; ++i; continue; }
            if (n == 't') { out += '\t'; ++i; continue; }
            if (n == 'n') { out += '\n'; ++i; continue; }
        }
        out += s[i];
    }
    return out;
}

// Splits on literal (unescaped) tab bytes. Fields containing a logical tab
// were written as the two-character escape "\t" (backslash, t), which
// this function does NOT split on, so it correctly separates the 7
// structural columns of a RESOURCE line even if `reason` itself once
// contained a real tab character.
std::vector<std::string> split_tabs(const std::string& line) {
    std::vector<std::string> fields;
    std::istringstream is(line);
    std::string field;
    while (std::getline(is, field, '\t')) fields.push_back(field);
    return fields;
}

void write_field(std::ostream& os, const std::string& tag, const std::string& value) {
    os << tag << '\t' << escape(value) << '\n';
}

}  // namespace

void save_plan_cache(const RemovalPlan& plan) {
    std::string path = cache_file_path();
    std::error_code ec;
    fs::create_directories(fs::path(path).parent_path(), ec);

    std::ofstream f(path, std::ios::trunc);
    if (!f) return;  // best-effort

    write_field(f, "DESKTOP_PATH", plan.desktop_entry_path);
    write_field(f, "WRITTEN_AT", std::to_string(static_cast<long>(std::time(nullptr))));
    write_field(f, "APP_NAME", plan.application_name);
    f << "SOURCE\t" << static_cast<int>(plan.source) << '\n';
    f << "SOURCE_CONFIDENCE\t" << static_cast<int>(plan.source_confidence) << '\n';

    f << "HAS_PACKAGE\t" << (plan.package ? 1 : 0) << '\n';
    if (plan.package) {
        write_field(f, "PACKAGE_NAME", plan.package->name);
        write_field(f, "PACKAGE_VERSION", plan.package->version);
        write_field(f, "PACKAGE_ARCH", plan.package->architecture);
        f << "PACKAGE_MANUAL\t" << (plan.package->manually_installed ? 1 : 0) << '\n';
    }

    f << "HAS_WINE_PREFIX\t" << (plan.wine_prefix ? 1 : 0) << '\n';
    if (plan.wine_prefix) write_field(f, "WINE_PREFIX", *plan.wine_prefix);
    f << "WINE_SHARED\t" << (plan.wine_prefix_is_shared ? 1 : 0) << '\n';
    f << "APP_RUNNING\t" << (plan.app_currently_running ? 1 : 0) << '\n';

    for (const auto& l : plan.running_process_lines) write_field(f, "RUNNING_LINE", l);
    for (const auto& d : plan.dependencies_would_remove) write_field(f, "DEP_REMOVE", d);
    for (const auto& d : plan.dependencies_kept_shared) write_field(f, "DEP_KEEP", d);
    for (const auto& w : plan.warnings) write_field(f, "WARNING", w);
    for (const auto& e : plan.evidence_trail) write_field(f, "EVIDENCE", e);

    for (const auto& r : plan.resources) {
        f << "RESOURCE\t" << escape(r.path) << '\t' << static_cast<int>(r.type) << '\t'
          << static_cast<int>(r.confidence) << '\t' << static_cast<int>(r.action) << '\t'
          << (r.requires_sudo ? 1 : 0) << '\t' << (r.validated ? 1 : 0) << '\t'
          << escape(r.reason) << '\n';
    }
}

std::optional<RemovalPlan> load_plan_cache_if_fresh(const std::string& desktop_path) {
    std::ifstream f(cache_file_path());
    if (!f) return std::nullopt;

    RemovalPlan plan;
    bool has_package = false, has_wine_prefix = false;
    detector::PackageInfo pinfo;
    long written_at = 0;
    bool saw_matching_path = false;
    std::string line;

    while (std::getline(f, line)) {
        if (line.empty()) continue;
        auto tab = line.find('\t');
        if (tab == std::string::npos) continue;
        std::string tag = line.substr(0, tab);
        std::string rest = line.substr(tab + 1);

        if (tag == "DESKTOP_PATH") {
            if (unescape(rest) != desktop_path) return std::nullopt;  // wrong app, bail immediately
            saw_matching_path = true;
        } else if (tag == "WRITTEN_AT") {
            written_at = std::atol(rest.c_str());
        } else if (tag == "APP_NAME") {
            plan.application_name = unescape(rest);
            plan.desktop_entry_path = desktop_path;
        } else if (tag == "SOURCE") {
            plan.source = static_cast<detector::InstallationSource>(std::atoi(rest.c_str()));
        } else if (tag == "SOURCE_CONFIDENCE") {
            plan.source_confidence = static_cast<detector::Confidence>(std::atoi(rest.c_str()));
        } else if (tag == "HAS_PACKAGE") {
            has_package = rest == "1";
        } else if (tag == "PACKAGE_NAME") {
            pinfo.name = unescape(rest);
        } else if (tag == "PACKAGE_VERSION") {
            pinfo.version = unescape(rest);
        } else if (tag == "PACKAGE_ARCH") {
            pinfo.architecture = unescape(rest);
        } else if (tag == "PACKAGE_MANUAL") {
            pinfo.manually_installed = rest == "1";
        } else if (tag == "HAS_WINE_PREFIX") {
            has_wine_prefix = rest == "1";
        } else if (tag == "WINE_PREFIX") {
            plan.wine_prefix = unescape(rest);
        } else if (tag == "WINE_SHARED") {
            plan.wine_prefix_is_shared = rest == "1";
        } else if (tag == "APP_RUNNING") {
            plan.app_currently_running = rest == "1";
        } else if (tag == "RUNNING_LINE") {
            plan.running_process_lines.push_back(unescape(rest));
        } else if (tag == "DEP_REMOVE") {
            plan.dependencies_would_remove.push_back(unescape(rest));
        } else if (tag == "DEP_KEEP") {
            plan.dependencies_kept_shared.push_back(unescape(rest));
        } else if (tag == "WARNING") {
            plan.warnings.push_back(unescape(rest));
        } else if (tag == "EVIDENCE") {
            plan.evidence_trail.push_back(unescape(rest));
        } else if (tag == "RESOURCE") {
            auto fields = split_tabs(rest);
            if (fields.size() != 7) continue;  // malformed line: skip defensively
            PlannedResource r;
            r.path = unescape(fields[0]);
            r.type = static_cast<detector::ResourceType>(std::atoi(fields[1].c_str()));
            r.confidence = static_cast<detector::Confidence>(std::atoi(fields[2].c_str()));
            r.action = static_cast<PlanAction>(std::atoi(fields[3].c_str()));
            r.requires_sudo = fields[4] == "1";
            r.validated = fields[5] == "1";
            r.reason = unescape(fields[6]);
            plan.resources.push_back(r);
        }
    }

    if (!saw_matching_path) return std::nullopt;
    if (written_at == 0 || std::time(nullptr) - written_at > kMaxCacheAgeSeconds) return std::nullopt;

    if (has_package) plan.package = pinfo;
    if (!has_wine_prefix) plan.wine_prefix.reset();

    return plan;
}

}  // namespace udu::planner

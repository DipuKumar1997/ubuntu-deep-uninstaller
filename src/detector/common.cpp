#include "common.hpp"
#include "../security/proc_exec.hpp"
#include "../security/paths.hpp"
#include "../desktop_entry.hpp"

#include <filesystem>
#include <cstdlib>
#include <algorithm>
#include <cctype>

namespace fs = std::filesystem;

namespace udu::detector::common {

std::string home_dir() {
    const char* h = std::getenv("HOME");
    return h ? std::string(h) : std::string("/root");
}

std::vector<std::string> tokenize_exec(const std::string& s) {
    std::vector<std::string> tokens;
    std::string cur;
    bool in_quotes = false;
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '"') { in_quotes = !in_quotes; continue; }
        if (std::isspace(static_cast<unsigned char>(c)) && !in_quotes) {
            if (!cur.empty()) { tokens.push_back(cur); cur.clear(); }
            continue;
        }
        cur += c;
    }
    if (!cur.empty()) tokens.push_back(cur);
    return tokens;
}

std::optional<std::string> resolve_exec_target(const std::string& first_token) {
    if (first_token.empty()) return std::nullopt;
    if (first_token.find('/') != std::string::npos) {
        return udu::security::canonicalize(first_token);
    }
    const char* path_env = std::getenv("PATH");
    if (!path_env) return std::nullopt;
    std::string path(path_env);
    size_t start = 0;
    while (start <= path.size()) {
        size_t end = path.find(':', start);
        if (end == std::string::npos) end = path.size();
        std::string dir = path.substr(start, end - start);
        if (!dir.empty()) {
            std::string candidate = dir + "/" + first_token;
            std::error_code ec;
            if (fs::exists(candidate, ec)) {
                return udu::security::canonicalize(candidate);
            }
        }
        start = end + 1;
    }
    return std::nullopt;
}

std::vector<XdgGuess> existing_xdg_candidates(const std::string& candidate_name) {
    std::vector<XdgGuess> out;
    if (candidate_name.empty()) return out;
    std::string home = home_dir();
    struct Base { std::string dir; ResourceType type; };
    std::vector<Base> bases = {
        {home + "/.config/", ResourceType::Config},
        {home + "/.cache/", ResourceType::Cache},
        {home + "/.local/share/", ResourceType::Data},
        {home + "/.local/state/", ResourceType::State},
    };
    std::error_code ec;
    for (const auto& b : bases) {
        std::string p = b.dir + candidate_name;
        if (fs::exists(p, ec)) {
            out.push_back({p, b.type});
        }
    }
    return out;
}

std::vector<std::string> matching_autostart_entries(const std::string& resolved_executable) {
    std::vector<std::string> matches;
    if (resolved_executable.empty()) return matches;
    std::vector<std::string> dirs = {
        home_dir() + "/.config/autostart",
        "/etc/xdg/autostart",
    };
    std::error_code ec;
    for (const auto& dir : dirs) {
        if (!fs::exists(dir, ec) || !fs::is_directory(dir, ec)) continue;
        for (const auto& entry : fs::directory_iterator(dir, ec)) {
            if (entry.path().extension() != ".desktop") continue;
            auto parsed = udu::parse_desktop_file(entry.path().string());
            if (!parsed) continue;
            auto toks = tokenize_exec(parsed->exec_without_field_codes());
            if (toks.empty()) continue;
            auto target = resolve_exec_target(toks[0]);
            if (target && *target == resolved_executable) {
                matches.push_back(entry.path().string());
            }
        }
    }
    return matches;
}

}  // namespace udu::detector::common

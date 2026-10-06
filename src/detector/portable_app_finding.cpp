#include "portable_app_finding.hpp"
#include "common.hpp"
#include "../security/debug_log.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <vector>

namespace fs = std::filesystem;

namespace udu::detector {

namespace {

std::string cache_file_path() {
    return common::home_dir() + "/.cache/ubuntu-deep-uninstaller/portable_app_findings.cache";
}

std::string escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '\\') out += "\\\\";
        else if (c == '\t') out += "\\t";
        else if (c == '\n') out += "\\n";
        else out += c;
    }
    return out;
}

std::string unescape(const std::string& s) {
    std::string out;
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

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

// Strips everything but letters and digits, lowercased. Used specifically
// for the Downloads-archive match so a token like "idea-iu" (hyphenated,
// derived from a directory name) still matches a filename that renders
// the same thing without a separator ("ideaIU-2024.1.4.tar.gz") -- real
// download filenames and extracted directory names frequently differ in
// exactly this kind of punctuation, and this is a best-effort, never-
// auto-selected heuristic, so being lenient about it costs nothing in
// safety.
std::string normalize_for_matching(const std::string& s) {
    std::string out;
    for (char c : to_lower(s)) {
        if (std::isalnum(static_cast<unsigned char>(c))) out += c;
    }
    return out;
}

// "idea-IU-262.9437.185" -> "idea-iu"; "clion-2024.1.4" -> "clion";
// "PyCharm-2024" -> "pycharm". Takes everything before the first digit,
// lowercased, with trailing separators trimmed -- good enough for a
// loose, low-confidence match against a Downloads filename, never used
// for anything auto-selected.
std::string derive_search_token(const std::string& dir_name) {
    std::string lower = to_lower(dir_name);
    size_t cut = lower.size();
    for (size_t i = 0; i < lower.size(); ++i) {
        if (std::isdigit(static_cast<unsigned char>(lower[i]))) { cut = i; break; }
    }
    std::string token = lower.substr(0, cut);
    while (!token.empty() && (token.back() == '-' || token.back() == '_' || token.back() == '.')) {
        token.pop_back();
    }
    return token;
}

std::optional<std::string> find_matching_download(const std::string& search_token) {
    std::string normalized_token = normalize_for_matching(search_token);
    if (normalized_token.size() < 3) return std::nullopt;  // too short to be a meaningful match
    std::string downloads = common::home_dir() + "/Downloads";
    std::error_code ec;
    if (!fs::exists(downloads, ec) || !fs::is_directory(downloads, ec)) return std::nullopt;

    static const std::vector<std::string> archive_extensions = {
        ".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".appimage"
    };

    // Deliberately fs::directory_iterator (ONE level, not
    // recursive_directory_iterator) -- Downloads is scanned shallowly by
    // design, never descending into subfolders, to keep this bounded and
    // fast regardless of how someone organizes that directory.
    for (const auto& f : fs::directory_iterator(downloads, ec)) {
        if (!f.is_regular_file(ec)) continue;
        std::string name_lower = to_lower(f.path().filename().string());
        bool has_archive_ext = false;
        for (const auto& ext : archive_extensions) {
            if (name_lower.size() >= ext.size() &&
                name_lower.compare(name_lower.size() - ext.size(), ext.size(), ext) == 0) {
                has_archive_ext = true;
                break;
            }
        }
        if (!has_archive_ext) continue;
        // Normalized (letters+digits only) containment check: see
        // normalize_for_matching()'s comment for why punctuation
        // differences between the token and the real filename shouldn't
        // prevent a match here.
        if (normalize_for_matching(f.path().filename().string()).find(normalized_token) !=
            std::string::npos) {
            return f.path().string();
        }
    }
    return std::nullopt;
}

}  // namespace

std::optional<PortableAppFinding> load_cached_portable_finding(const std::string& resolved_exe_path) {
    std::ifstream f(cache_file_path());
    if (!f) return std::nullopt;
    std::string line;
    while (std::getline(f, line)) {
        auto t1 = line.find('\t');
        if (t1 == std::string::npos) continue;
        std::string key = unescape(line.substr(0, t1));
        if (key != resolved_exe_path) continue;
        auto t2 = line.find('\t', t1 + 1);
        if (t2 == std::string::npos) continue;
        std::string root = unescape(line.substr(t1 + 1, t2 - t1 - 1));
        std::string archive = unescape(line.substr(t2 + 1));
        PortableAppFinding finding;
        if (!root.empty()) finding.extracted_root = root;
        if (!archive.empty()) finding.matching_download_archive = archive;
        return finding;
    }
    return std::nullopt;
}

PortableAppFinding compute_and_cache_portable_finding(const std::string& resolved_exe_path) {
    UDU_LOG("compute_and_cache_portable_finding(): computing for " + resolved_exe_path +
             " (not cached yet)");
    PortableAppFinding finding;

    fs::path exe_path(resolved_exe_path);
    fs::path parent = exe_path.parent_path();
    if (to_lower(parent.filename().string()) == "bin") {
        fs::path grandparent = parent.parent_path();
        std::error_code ec;
        if (!grandparent.empty() && fs::exists(grandparent, ec) && fs::is_directory(grandparent, ec)) {
            finding.extracted_root = grandparent.string();
            UDU_LOG("compute_and_cache_portable_finding(): parent is 'bin' -- extracted root = " +
                     *finding.extracted_root);
        }
    }

    std::string token_source = finding.extracted_root
        ? fs::path(*finding.extracted_root).filename().string()
        : parent.filename().string();
    std::string token = derive_search_token(token_source);
    if (!token.empty()) {
        UDU_LOG("compute_and_cache_portable_finding(): scanning ~/Downloads (one level) for "
                 "token '" + token + "'...");
        finding.matching_download_archive = find_matching_download(token);
        if (finding.matching_download_archive) {
            UDU_LOG("compute_and_cache_portable_finding(): found candidate archive " +
                     *finding.matching_download_archive);
        }
    }

    // Persist: rewrite the whole cache with this entry inserted/replaced.
    // The file is expected to stay small (one line per portable app ever
    // inspected), so a full rewrite on each new entry is not a concern.
    std::string path = cache_file_path();
    std::error_code ec;
    fs::create_directories(fs::path(path).parent_path(), ec);

    std::vector<std::string> lines;
    {
        std::ifstream in(path);
        std::string line;
        while (std::getline(in, line)) {
            if (line.rfind(escape(resolved_exe_path) + "\t", 0) != 0) lines.push_back(line);
        }
    }
    lines.push_back(escape(resolved_exe_path) + "\t" + escape(finding.extracted_root.value_or("")) +
                     "\t" + escape(finding.matching_download_archive.value_or("")));

    std::ofstream out(path, std::ios::trunc);
    for (const auto& l : lines) out << l << "\n";

    return finding;
}

}  // namespace udu::detector

#include "desktop_entry.hpp"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace udu {

namespace {

std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> out;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        if (!item.empty()) out.push_back(item);
    }
    return out;
}

// Minimal INI-style group parser tailored to Desktop Entry files: groups
// are "[Group Name]" lines, keys are "Key=Value" (locale-suffixed keys like
// "Name[fr]=" are ignored -- we only want the unlocalized default so
// evidence text is deterministic and language-independent).
struct Group {
    std::string name;
    std::map<std::string, std::string> kv;
};

std::vector<Group> parse_groups(const std::string& content) {
    std::vector<Group> groups;
    std::istringstream stream(content);
    std::string line;
    Group* current = nullptr;
    while (std::getline(stream, line)) {
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;
        if (t.front() == '[' && t.back() == ']') {
            groups.push_back(Group{t.substr(1, t.size() - 2), {}});
            current = &groups.back();
            continue;
        }
        if (!current) continue;
        auto eq = t.find('=');
        if (eq == std::string::npos) continue;
        std::string key = trim(t.substr(0, eq));
        // Skip locale-suffixed variants: Name[de]=..., Comment[fr_FR]=...
        if (key.find('[') != std::string::npos) continue;
        std::string value = trim(t.substr(eq + 1));
        current->kv[key] = value;
    }
    return groups;
}

}  // namespace

std::string DesktopEntry::exec_without_field_codes() const {
    std::string out;
    out.reserve(exec.size());
    for (size_t i = 0; i < exec.size(); ++i) {
        if (exec[i] == '%' && i + 1 < exec.size()) {
            char code = exec[i + 1];
            // Single-token field codes we drop entirely (they expand to
            // file lists / translated names / icon names at launch time
            // and are meaningless for "what binary does this run").
            if (code == 'f' || code == 'F' || code == 'u' || code == 'U' ||
                code == 'd' || code == 'D' || code == 'n' || code == 'N' ||
                code == 'i' || code == 'c' || code == 'k' || code == 'v' ||
                code == 'm') {
                ++i;  // skip the code char too
                continue;
            }
            if (code == '%') { out += '%'; ++i; continue; }
        }
        out += exec[i];
    }
    // Collapse resulting double spaces left behind by removed field codes.
    std::string collapsed;
    bool prev_space = false;
    for (char c : out) {
        if (std::isspace(static_cast<unsigned char>(c))) {
            if (!prev_space) collapsed += ' ';
            prev_space = true;
        } else {
            collapsed += c;
            prev_space = false;
        }
    }
    return trim(collapsed);
}

std::string compute_desktop_id(const std::string& path) {
    static const std::vector<std::string> roots = {
        "/usr/share/applications/",
        "/usr/local/share/applications/",
        "/var/lib/snapd/desktop/applications/",
    };
    for (const auto& root : roots) {
        if (path.rfind(root, 0) == 0) {
            std::string rel = path.substr(root.size());
            std::replace(rel.begin(), rel.end(), '/', '-');
            return rel;
        }
    }
    // $HOME/.local/share/applications/ handled dynamically by caller who
    // knows $HOME; here we just fall back to the basename.
    auto slash = path.find_last_of('/');
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

std::optional<DesktopEntry> parse_desktop_content(const std::string& content,
                                                   const std::string& source_path_for_id) {
    auto groups = parse_groups(content);
    const Group* main = nullptr;
    for (const auto& g : groups) {
        if (g.name == "Desktop Entry") { main = &g; break; }
    }
    if (!main) return std::nullopt;

    DesktopEntry entry;
    entry.source_path = source_path_for_id;
    entry.desktop_id = compute_desktop_id(source_path_for_id);
    entry.raw_content = content;

    auto get = [&](const std::string& key) -> std::optional<std::string> {
        auto it = main->kv.find(key);
        if (it == main->kv.end()) return std::nullopt;
        return it->second;
    };

    entry.name = get("Name").value_or("");
    entry.exec = get("Exec").value_or("");
    entry.try_exec = get("TryExec");
    entry.icon = get("Icon");
    entry.working_dir = get("Path");
    entry.type = get("Type").value_or("Application");
    if (auto nd = get("NoDisplay")) entry.no_display = (*nd == "true");
    if (auto term = get("Terminal")) entry.terminal = (*term == "true");

    if (auto actions_key = get("Actions")) {
        entry.existing_action_ids = split(*actions_key, ';');
    }

    for (const auto& g : groups) {
        static const std::string prefix = "Desktop Action ";
        if (g.name.rfind(prefix, 0) == 0) {
            DesktopAction action;
            action.id = g.name.substr(prefix.size());
            auto nit = g.kv.find("Name");
            auto eit = g.kv.find("Exec");
            action.name = nit != g.kv.end() ? nit->second : "";
            action.exec = eit != g.kv.end() ? eit->second : "";
            entry.actions.push_back(action);
        }
    }

    return entry;
}

std::optional<DesktopEntry> parse_desktop_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return std::nullopt;
    std::ostringstream buf;
    buf << f.rdbuf();
    return parse_desktop_content(buf.str(), path);
}

}  // namespace udu

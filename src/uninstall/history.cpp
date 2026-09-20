#include "history.hpp"
#include "../detector/common.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <ctime>

namespace fs = std::filesystem;

namespace udu::uninstall {

std::string history_file_path() {
    return udu::detector::common::home_dir() + "/.local/state/ubuntu-deep-uninstaller/history.log";
}

namespace {
std::string now_timestamp() {
    std::time_t t = std::time(nullptr);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
    return buf;
}

// Tab-separated, one entry per line. Fields never legitimately contain a
// tab or newline (app names and source labels are short, human-readable
// strings), so no escaping is needed for this simple, append-only,
// human-readable-by-design log.
}  // namespace

void record_history(const std::string& app_name, const std::string& source) {
    std::string path = history_file_path();
    std::error_code ec;
    fs::create_directories(fs::path(path).parent_path(), ec);
    std::ofstream f(path, std::ios::app);
    if (!f) return;  // best-effort: never fail the uninstall over this
    f << now_timestamp() << '\t' << app_name << '\t' << source << '\n';
}

std::vector<HistoryEntry> read_history() {
    std::vector<HistoryEntry> out;
    std::ifstream f(history_file_path());
    if (!f) return out;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        std::istringstream is(line);
        HistoryEntry e;
        std::getline(is, e.timestamp, '\t');
        std::getline(is, e.app_name, '\t');
        std::getline(is, e.source, '\t');
        out.push_back(std::move(e));
    }
    return out;
}

}  // namespace udu::uninstall

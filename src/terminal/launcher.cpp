#include "launcher.hpp"
#include "../security/proc_exec.hpp"

namespace udu::terminal {

std::string shell_quote(const std::string& s) {
    std::string out = "'";
    for (char c : s) {
        if (c == '\'') {
            out += "'\\''";  // close quote, escaped literal quote, reopen quote
        } else {
            out += c;
        }
    }
    out += "'";
    return out;
}

std::optional<std::vector<std::string>> build_terminal_argv(
    const std::vector<std::string>& inner_argv, bool hold_open_after) {
    if (inner_argv.empty()) return std::nullopt;

    struct Candidate { std::string bin; std::vector<std::string> prefix_args; };
    static const std::vector<Candidate> candidates = {
        {"ptyxis", {"--"}},              // Ubuntu 26.04 default terminal
        {"gnome-terminal", {"--"}},
        {"x-terminal-emulator", {"-e"}},
        {"xterm", {"-e"}},
    };

    std::string terminal_bin;
    std::vector<std::string> prefix_args;
    bool found = false;
    for (const auto& c : candidates) {
        if (udu::security::executable_exists(c.bin)) {
            terminal_bin = c.bin;
            prefix_args = c.prefix_args;
            found = true;
            break;
        }
    }
    if (!found) return std::nullopt;

    std::vector<std::string> full = {terminal_bin};
    for (const auto& a : prefix_args) full.push_back(a);

    if (!hold_open_after) {
        for (const auto& a : inner_argv) full.push_back(a);
        return full;
    }

    // Build a single shell command string: run the real command, capture
    // its exit code, print a clear completion line, then block on a
    // keypress before the shell (and therefore the terminal window)
    // exits. Every piece of inner_argv is shell_quote()'d individually --
    // this is string construction for a deliberate, contained purpose, not
    // interpolation of untrusted input into a privileged command.
    std::string command;
    for (size_t i = 0; i < inner_argv.size(); ++i) {
        if (i) command += " ";
        command += shell_quote(inner_argv[i]);
    }
    command +=
        "; ec=$?; echo; "
        "if [ $ec -eq 0 ]; then "
        "printf '\\033[1;32m--- Finished successfully. Press Enter to close this window. ---\\033[0m\\n'; "
        "else "
        "printf '\\033[1;31m--- Finished with errors (exit code '$ec'). Press Enter to close this window. ---\\033[0m\\n'; "
        "fi; "
        "read -r _";

    full.push_back("bash");
    full.push_back("-c");
    full.push_back(command);
    return full;
}

}  // namespace udu::terminal

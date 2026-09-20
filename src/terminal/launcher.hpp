// terminal/launcher.hpp
//
// Builds the argv for "open a real terminal emulator, run this command in
// it, and keep the window open after the command finishes so the user can
// actually read the output" -- used by both:
//   - the GUI's Dry Run / Uninstall Completely buttons, and
//   - the GNOME context-menu action's Exec= line (via the CLI's
//     `--uninstall-by-desktop-id-in-terminal` subcommand),
// so the two code paths behave identically instead of drifting apart.
//
// This is the ONE place in the project that deliberately constructs a
// shell command string (via bash -c) rather than a plain argv array. That
// is necessary here because "run this, then wait for Enter" is shell
// sequencing, not a single program invocation -- but every value placed
// into that string is passed through shell_quote() first, so it is still
// not vulnerable to injection from any path/argument it's given.
#pragma once

#include <string>
#include <vector>
#include <optional>

namespace udu::terminal {

// Single-quotes `s` for safe inclusion in a POSIX shell command line,
// escaping any embedded single quotes. Safe for arbitrary byte content,
// including paths with spaces, quotes, or shell metacharacters.
std::string shell_quote(const std::string& s);

// Builds the full argv to hand to spawn_detached()/g_spawn_async(): a
// terminal emulator, its "run a command" flag, and (if hold_open_after)
// a bash -c wrapper that runs inner_argv, prints a completion line, and
// waits for Enter before the shell -- and therefore the terminal window
// -- exits. Returns std::nullopt if no known terminal emulator is found
// on PATH (ptyxis, gnome-terminal, x-terminal-emulator, xterm, in that
// preference order).
std::optional<std::vector<std::string>> build_terminal_argv(
    const std::vector<std::string>& inner_argv, bool hold_open_after);

}  // namespace udu::terminal

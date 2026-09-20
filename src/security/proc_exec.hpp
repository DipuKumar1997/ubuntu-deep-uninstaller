// proc_exec.hpp
//
// Safe, structured process execution.
//
// SECURITY INVARIANT: every function in this header executes a program via
// posix_spawn() with an argv ARRAY. There is no code path in this project
// that builds a command line as a string and hands it to /bin/sh. That is
// deliberate: it removes an entire class of command-injection bugs where a
// path, package name, or application name containing shell metacharacters
// (spaces, `;`, `$()`, backticks, quotes...) could be mis-parsed or abused.
//
// If a caller ever finds itself wanting to interpolate a value into a
// command string, that is a sign the call should be expressed as another
// argv element instead.
//
// posix_spawn() rather than fork()+exec(): fork() is unsafe to call from
// any thread of a process that has other threads running (every GTK/
// libadwaita GUI qualifies, even if the application itself never spawns a
// thread) -- see the implementation file's comment above run() for the
// full explanation and the real incident that made this non-optional.
#pragma once

#include <string>
#include <vector>
#include <optional>
#include <chrono>

namespace udu::security {

struct ExecResult {
    int exit_code = -1;
    bool timed_out = false;
    bool spawn_failed = false;   // true if fork/exec itself failed (e.g. binary not found)
    std::string stdout_text;
    std::string stderr_text;

    [[nodiscard]] bool ok() const noexcept {
        return !spawn_failed && !timed_out && exit_code == 0;
    }
};

struct ExecOptions {
    // Optional working directory for the child process.
    std::optional<std::string> working_dir;
    // Hard timeout; the child is killed (SIGKILL) if it runs longer than this.
    // Kept short (default calls are all read-only lookups: dpkg -S,
    // dpkg-query, apt-mark, etc.) because these run synchronously during
    // interactive detection -- e.g. every time someone clicks an app in
    // the GUI. A package with an unusually large/complex dependency graph
    // (Docker Desktop, for instance) can make apt's resolver genuinely
    // slow; individual calls should fail fast and let the caller fall back
    // to "could not fully verify" rather than each waiting out a long
    // timeout and stacking up into a multi-minute-feeling UI freeze.
    std::chrono::milliseconds timeout{6000};
    // If true, stdin is closed for the child (default: safe default for
    // non-interactive detection commands). Interactive commands (sudo apt
    // remove run inside the visible terminal) are NOT executed through this
    // helper at all -- they are launched directly by the terminal wrapper so
    // the user's real TTY is attached. This helper is for detection /
    // read-only queries and for non-interactive destructive calls that have
    // already been confirmed (e.g. `flatpak uninstall -y <id>`).
    bool close_stdin = true;
};

// Runs `argv[0]` with the remaining elements of argv as its arguments.
// argv must be non-empty. Never invokes a shell.
ExecResult run(const std::vector<std::string>& argv, const ExecOptions& opts = {});

// Convenience: returns true if `name` resolves to an executable on PATH,
// without invoking it. Used by detectors to cheaply check tool availability
// (e.g. "is flatpak installed at all") before shelling out.
bool executable_exists(const std::string& name);

// Launches argv[0] fully detached from this process, via posix_spawn()
// with POSIX_SPAWN_SETSID (detaches into a new session -- the same effect
// an explicit setsid() had in an older fork()-based implementation of
// this function, done here inside posix_spawn's thread-safe machinery
// instead). Used to launch a real terminal emulator that the user will
// drive themselves -- we do not want its lifetime tied to ours, and we do
// not want to read/capture its output (unlike run(), which is for
// non-interactive, captured, waited-for calls). The spawned process is
// deliberately not waited on; see the .cpp file for why that's fine given
// this function's only caller today. Never invokes a shell for argv[0]
// itself; if argv[0] is "bash" or similar, that is the caller's deliberate
// choice (see terminal::build_terminal_argv), not an implicit shell
// invocation by this function.
bool spawn_detached(const std::vector<std::string>& argv);

// Returns the absolute path to the currently running executable, resolved
// via /proc/self/exe. More reliable than argv[0] (which may be relative,
// or just "ubuntu-deep-uninstaller" if found via PATH) when this binary
// needs to reference itself -- e.g. a GNOME Desktop Action's Exec= line
// re-invoking us to open a terminal. Returns std::nullopt if the symlink
// cannot be read (should not normally happen on Linux).
std::optional<std::string> self_executable_path();

}  // namespace udu::security

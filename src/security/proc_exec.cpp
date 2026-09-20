#include "proc_exec.hpp"
#include "debug_log.hpp"

#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <poll.h>
#include <spawn.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <sstream>

// Declared by the C library; not always pulled in by <unistd.h> alone
// depending on feature-test macros, so declare it explicitly. posix_spawn
// needs it to pass the current environment through to the child.
extern char** environ;

namespace udu::security {

namespace {
std::string join_argv(const std::vector<std::string>& argv) {
    std::ostringstream os;
    for (size_t i = 0; i < argv.size(); ++i) {
        if (i) os << ' ';
        os << argv[i];
    }
    return os.str();
}
}  // namespace

namespace {

bool has_slash(const std::string& s) { return s.find('/') != std::string::npos; }

std::vector<char*> to_raw_argv(const std::vector<std::string>& argv) {
    std::vector<char*> raw;
    raw.reserve(argv.size() + 1);
    for (const auto& a : argv) raw.push_back(const_cast<char*>(a.c_str()));
    raw.push_back(nullptr);
    return raw;
}

}  // namespace

bool executable_exists(const std::string& name) {
    if (name.empty()) return false;
    if (has_slash(name)) {
        return ::access(name.c_str(), X_OK) == 0;
    }
    const char* path_env = ::getenv("PATH");
    if (!path_env) return false;
    std::string path(path_env);
    size_t start = 0;
    while (start <= path.size()) {
        size_t end = path.find(':', start);
        if (end == std::string::npos) end = path.size();
        std::string dir = path.substr(start, end - start);
        if (!dir.empty()) {
            std::string candidate = dir + "/" + name;
            if (::access(candidate.c_str(), X_OK) == 0) return true;
        }
        start = end + 1;
    }
    return false;
}

// IMPORTANT: this file uses posix_spawn(), never fork(), for exactly one
// reason -- fork() is not safe to call from a background thread of a
// process that has other threads running (which every GTK/libadwaita GUI
// does internally: icon loading, D-Bus, portals, etc., regardless of
// whether the application itself spawns any threads). fork() only
// duplicates the calling thread; if any OTHER thread happened to hold an
// internal lock (glibc's malloc arena lock is the classic one) at the
// moment of the fork, that lock is copied into the child in its "held"
// state forever, with no thread left to release it -- so anything the
// child does before exec() that needs that lock (which can include
// completely ordinary things like extra allocations) deadlocks
// permanently. This is intermittent and appears to depend on unrelated
// timing, which is exactly the "sometimes hangs, sometimes doesn't,
// eventually the whole app dies" symptom this project hit once detection
// started running on a background std::thread inside the GTK GUI.
// posix_spawn() is the POSIX-standard, glibc-implemented answer to this:
// it is documented and implemented to be safe to call from any thread of
// a multi-threaded process.
ExecResult run(const std::vector<std::string>& argv, const ExecOptions& opts) {
    ExecResult result;
    if (argv.empty()) {
        result.spawn_failed = true;
        result.stderr_text = "run(): empty argv";
        return result;
    }

    UDU_LOG("run(): about to spawn: " + join_argv(argv) +
             "  [timeout=" + std::to_string(opts.timeout.count()) + "ms]");

    int out_pipe[2];
    int err_pipe[2];
    if (::pipe(out_pipe) != 0 || ::pipe(err_pipe) != 0) {
        result.spawn_failed = true;
        result.stderr_text = std::string("pipe() failed: ") + std::strerror(errno);
        UDU_LOG("run(): pipe() failed: " + result.stderr_text);
        return result;
    }

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    // In the child: route stdout/stderr into our pipes, close the read
    // ends (the child only ever writes), and replace stdin with /dev/null
    // unless the caller wants it inherited. All of this happens inside
    // posix_spawn's carefully-written implementation, not in arbitrary
    // code we run post-fork -- that is the whole point.
    posix_spawn_file_actions_adddup2(&actions, out_pipe[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, err_pipe[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, out_pipe[0]);
    posix_spawn_file_actions_addclose(&actions, out_pipe[1]);
    posix_spawn_file_actions_addclose(&actions, err_pipe[0]);
    posix_spawn_file_actions_addclose(&actions, err_pipe[1]);
    if (opts.close_stdin) {
        posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    }
    if (opts.working_dir) {
        // GNU/glibc extension (available since glibc 2.29; Ubuntu 26.04's
        // glibc is far newer than that). Equivalent to a chdir() between
        // fork and exec, but done safely inside posix_spawn.
        posix_spawn_file_actions_addchdir_np(&actions, opts.working_dir->c_str());
    }

    auto raw = to_raw_argv(argv);
    pid_t pid = -1;
    int spawn_errno = ::posix_spawnp(&pid, raw[0], &actions, nullptr, raw.data(), environ);
    posix_spawn_file_actions_destroy(&actions);

    // Parent closes the write ends regardless of spawn outcome.
    ::close(out_pipe[1]);
    ::close(err_pipe[1]);

    if (spawn_errno != 0) {
        ::close(out_pipe[0]);
        ::close(err_pipe[0]);
        result.spawn_failed = true;
        result.stderr_text = std::string("posix_spawnp() failed: ") + std::strerror(spawn_errno);
        UDU_LOG("run(): posix_spawnp() failed: " + result.stderr_text);
        return result;
    }
    UDU_LOG("run(): posix_spawnp() succeeded, pid=" + std::to_string(pid) + ", waiting for output/exit...");

    auto deadline = std::chrono::steady_clock::now() + opts.timeout;
    bool killed_for_timeout = false;

    std::array<char, 4096> buf{};
    bool out_open = true, err_open = true;

    while (out_open || err_open) {
        struct pollfd fds[2];
        int nfds = 0;
        int out_idx = -1, err_idx = -1;
        if (out_open) { fds[nfds] = {out_pipe[0], POLLIN, 0}; out_idx = nfds++; }
        if (err_open) { fds[nfds] = {err_pipe[0], POLLIN, 0}; err_idx = nfds++; }

        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        if (remaining.count() < 0) remaining = std::chrono::milliseconds(0);

        int pr = ::poll(fds, nfds, static_cast<int>(remaining.count()));
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pr == 0) {
            // Timeout: kill the child and drain.
            UDU_LOG("run(): pid=" + std::to_string(pid) + " TIMED OUT after " +
                     std::to_string(opts.timeout.count()) + "ms -- sending SIGKILL");
            ::kill(pid, SIGKILL);
            killed_for_timeout = true;
            break;
        }
        if (out_idx >= 0 && (fds[out_idx].revents & (POLLIN | POLLHUP))) {
            ssize_t n = ::read(out_pipe[0], buf.data(), buf.size());
            if (n > 0) result.stdout_text.append(buf.data(), static_cast<size_t>(n));
            else { ::close(out_pipe[0]); out_open = false; }
        }
        if (err_idx >= 0 && (fds[err_idx].revents & (POLLIN | POLLHUP))) {
            ssize_t n = ::read(err_pipe[0], buf.data(), buf.size());
            if (n > 0) result.stderr_text.append(buf.data(), static_cast<size_t>(n));
            else { ::close(err_pipe[0]); err_open = false; }
        }
    }

    if (out_open) ::close(out_pipe[0]);
    if (err_open) ::close(err_pipe[0]);

    int status = 0;
    if (killed_for_timeout) {
        ::waitpid(pid, &status, 0);
        result.timed_out = true;
        result.exit_code = -1;
        UDU_LOG("run(): pid=" + std::to_string(pid) + " reaped after timeout-kill, returning");
        return result;
    }

    if (::waitpid(pid, &status, 0) < 0) {
        result.spawn_failed = true;
        result.stderr_text += std::string("waitpid() failed: ") + std::strerror(errno);
        UDU_LOG("run(): waitpid() itself failed: " + result.stderr_text);
        return result;
    }

    if (WIFEXITED(status)) {
        result.exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        result.exit_code = -WTERMSIG(status);
    }
    UDU_LOG("run(): pid=" + std::to_string(pid) + " finished, exit_code=" +
             std::to_string(result.exit_code) + ", stdout_len=" +
             std::to_string(result.stdout_text.size()) + ", stderr_len=" +
             std::to_string(result.stderr_text.size()));
    return result;
}

bool spawn_detached(const std::vector<std::string>& argv) {
    if (argv.empty()) return false;
    UDU_LOG("spawn_detached(): about to spawn: " + join_argv(argv));

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    // POSIX_SPAWN_SETSID (glibc extension) detaches the new process into
    // its own session, same effect setsid() had in the old fork()-based
    // implementation -- but done inside posix_spawn's safe machinery
    // instead of arbitrary code we'd otherwise run between fork and exec.
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSID);

    auto raw = to_raw_argv(argv);
    pid_t pid = -1;
    int spawn_errno = ::posix_spawnp(&pid, raw[0], nullptr, &attr, raw.data(), environ);
    posix_spawnattr_destroy(&attr);
    if (spawn_errno != 0) {
        UDU_LOG("spawn_detached(): posix_spawnp() failed: " + std::string(std::strerror(spawn_errno)));
        return false;
    }
    UDU_LOG("spawn_detached(): posix_spawnp() succeeded, pid=" + std::to_string(pid) + " (not waited on)");

    // Deliberately not waited on: the whole point is to launch something
    // long-lived (a terminal emulator) that outlives this call. The only
    // caller of this function today is the CLI's
    // --uninstall-by-desktop-id-in-terminal command, which returns and
    // exits immediately after this call -- once it does, the spawned
    // process is reparented to init/PID 1, which reaps it normally when
    // it eventually exits. There is no meaningful zombie-accumulation risk
    // in that usage pattern.
    return true;
}

std::optional<std::string> self_executable_path() {
    char buf[4096];
    ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return std::nullopt;
    buf[n] = '\0';
    return std::string(buf);
}

}  // namespace udu::security

#include "crash_handler.hpp"

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <execinfo.h>
#include <cstring>
#include <initializer_list>

namespace udu::security {

namespace {

constexpr int kMaxFrames = 64;

// Only async-signal-safe operations are used inside the handler itself:
// write() and backtrace_symbols_fd() (the fd-writing variant is
// documented by glibc specifically as avoiding the malloc() that
// backtrace_symbols() would otherwise need, which is what makes it
// reasonable to call from a signal handler -- unlike plain
// backtrace_symbols()). backtrace() itself can technically still touch
// the dynamic loader on its very first call in a process (to resolve
// unwinder internals), which is why install_crash_handler() does a
// one-time warm-up call below, before any crash can happen, so that cost
// is paid up front instead of inside the handler.
void handle_fatal_signal(int sig, siginfo_t* info, void* /*ucontext*/) {
    char header[256];
    int header_len = std::snprintf(header, sizeof(header),
        "\n[udu CRASH] received signal %d (%s), faulting address=%p -- backtrace follows:\n",
        sig, ::strsignal(sig), info ? info->si_addr : nullptr);
    if (header_len > 0) {
        ::write(STDERR_FILENO, header, static_cast<size_t>(header_len));
    }

    void* frames[kMaxFrames];
    int n = ::backtrace(frames, kMaxFrames);
    ::backtrace_symbols_fd(frames, n, STDERR_FILENO);

    const char* footer =
        "[udu CRASH] end of backtrace. Re-run with UDU_DEBUG=1 for step-by-step logs "
        "leading up to this point. Re-raising the default handler now.\n";
    ::write(STDERR_FILENO, footer, std::strlen(footer));

    // Restore the default handler and re-raise, so the process still
    // terminates the normal way (correct exit status, core dump if
    // ulimits allow one, etc.) rather than this handler silently
    // swallowing the crash.
    ::signal(sig, SIG_DFL);
    ::raise(sig);
}

}  // namespace

void install_crash_handler() {
    // Warm-up call: pays the dynamic-loader/unwinder initialization cost
    // for backtrace() now, outside of any signal context, so the real
    // handler's use of it during an actual crash is on already-resolved
    // machinery.
    void* warm[4];
    ::backtrace(warm, 4);

    struct sigaction sa {};
    sa.sa_sigaction = handle_fatal_signal;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;  // SA_RESETHAND: if the handler
    // itself somehow re-faults, the second occurrence falls through to the
    // default action instead of looping.
    ::sigemptyset(&sa.sa_mask);

    for (int sig : {SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL}) {
        ::sigaction(sig, &sa, nullptr);
    }
}

}  // namespace udu::security

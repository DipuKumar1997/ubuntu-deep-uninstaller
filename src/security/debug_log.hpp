// security/debug_log.hpp
//
// Opt-in, extremely lightweight tracing to stderr. Every subprocess spawn
// (run()/spawn_detached()), every detector entry, and every GUI background-
// thread step logs through here. Disabled by default (near-zero cost: one
// bool check); enable by setting UDU_DEBUG=1 in the environment before
// launching either the CLI or the GUI:
//
//   UDU_DEBUG=1 ./build/ubuntu-deep-uninstaller --dry-run <path>
//   UDU_DEBUG=1 ./build/ubuntu-deep-uninstaller-gui
//
// Output goes to stderr (not stdout) so it interleaves cleanly with a
// terminal you're watching, is never captured by anything that only reads
// stdout, and is line-buffered/flushed immediately after every write --
// important specifically because the point of this is to see exactly how
// far execution got before a hang or a crash, so nothing can be sitting
// unflushed in a buffer when that happens.
#pragma once

#include <string>
#include <cstdio>
#include <cstdlib>
#include <chrono>
#include <thread>
#include <sstream>

namespace udu::debug {

inline bool enabled() {
    static const bool cached = ([]() {
        const char* v = std::getenv("UDU_DEBUG");
        return v != nullptr && std::string(v) != "0" && std::string(v) != "";
    })();
    return cached;
}

// Not called directly -- use the UDU_LOG(...) macro below, which skips
// building the message entirely when debug logging is off.
inline void log_line(const std::string& msg) {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count() % 100000;
    std::ostringstream tid;
    tid << std::this_thread::get_id();
    // fprintf + fflush rather than std::cerr: guaranteed unbuffered-after-
    // this-call behavior without relying on std::cerr's own (usually, but
    // not contractually always) unbuffered semantics, and safe to reason
    // about right up until a potential crash on the next line of code.
    std::fprintf(stderr, "[udu %05lldms tid=%s] %s\n",
                 static_cast<long long>(ms), tid.str().c_str(), msg.c_str());
    std::fflush(stderr);
}

}  // namespace udu::debug

#define UDU_LOG(msg_expr) \
    do { if (::udu::debug::enabled()) { ::udu::debug::log_line(msg_expr); } } while (0)

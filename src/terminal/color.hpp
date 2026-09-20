// terminal/color.hpp
//
// Small ANSI color helpers for the [CHECK]/[FOUND]/[REMOVE]/... status
// tags and section banners. Colors are only ever emitted when stdout is a
// real terminal (isatty) and NO_COLOR is not set, so piping output to a
// file or another program still gets clean, uncolored text.
#pragma once

#include <string>
#include <unistd.h>
#include <cstdlib>

namespace udu::terminal::color {

inline bool enabled() {
    static const bool cached = []() {
        if (::getenv("NO_COLOR") != nullptr) return false;
        return ::isatty(STDOUT_FILENO) != 0;
    }();
    return cached;
}

inline std::string wrap(const char* code, const std::string& text) {
    if (!enabled()) return text;
    return std::string(code) + text + "\033[0m";
}

inline std::string blue_bold(const std::string& t) { return wrap("\033[1;34m", t); }
inline std::string cyan(const std::string& t)      { return wrap("\033[36m", t); }
inline std::string green(const std::string& t)     { return wrap("\033[32m", t); }
inline std::string yellow(const std::string& t)    { return wrap("\033[33m", t); }
inline std::string red(const std::string& t)       { return wrap("\033[31m", t); }
inline std::string gray(const std::string& t)      { return wrap("\033[2m", t); }

// Colorizes a known status tag such as "[REMOVE]" or "[SUCCESS]". Unknown
// tags are returned unchanged.
inline std::string tag(const std::string& t) {
    if (t == "[FOUND]" || t == "[CHECK]" || t == "[VERIFY]") return cyan(t);
    if (t.rfind("[REMOVE", 0) == 0) return yellow(t);        // "[REMOVE]" and "[REMOVE*]"
    if (t == "[SUCCESS]") return green(t);
    if (t == "[WARNING]" || t == "[ERROR]") return red(t);
    if (t.rfind("[SKIP", 0) == 0) return gray(t);
    return t;
}

}  // namespace udu::terminal::color

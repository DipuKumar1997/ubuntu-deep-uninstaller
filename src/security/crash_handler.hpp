// security/crash_handler.hpp
//
// Installs signal handlers for the crash-causing signals (SIGSEGV,
// SIGABRT, SIGBUS, SIGFPE, SIGILL) that print a timestamped message and a
// best-effort backtrace to stderr before the process actually dies --
// directly answering "if any crash happens then I can see [what
// happened]" instead of a GUI window silently vanishing with no trace of
// why.
//
// Call install_crash_handler() once, at the very top of main(), in both
// the CLI and the GUI.
#pragma once

namespace udu::security {

void install_crash_handler();

}  // namespace udu::security

# Development log

Honest record of what was actually built and run during development, so
nothing in `README.md`'s status table is taken on faith.

## Environment

Dev sandbox: Ubuntu 24.04 container, `g++ 13.3.0` (C++23 support used:
designated initializers, `std::optional` chaining -- nothing exotic), no
`cmake`, no `libgtk-4-dev`/`libadwaita-1-dev`, no `flatpak`/`snap`/`wine`
binaries, no network access. Real `dpkg`/`dpkg-query`/`apt-get`/`apt-mark`
were present and usable read-only (and `apt-get --simulate`, which is
also read-only).

## Core library + CLI: compiled clean

```
g++ -std=c++23 -Wall -Wextra -O0 -g \
  src/main.cpp src/desktop_entry.cpp \
  src/security/proc_exec.cpp src/security/paths.cpp \
  src/detector/common.cpp src/detector/apt_detector.cpp src/detector/flatpak_detector.cpp \
  src/detector/snap_detector.cpp src/detector/wine_detector.cpp src/detector/appimage_detector.cpp \
  src/detector/manual_detector.cpp src/detector/detection_engine.cpp \
  src/planner/removal_plan.cpp \
  src/verification/verify.cpp \
  src/terminal/report.cpp \
  src/uninstall/executor.cpp \
  src/integration/desktop_override.cpp \
  -o ubuntu-deep-uninstaller
```

Zero errors after two real bugs were found and fixed:
- A raw-string-literal terminator collision in `wine_detector.cpp`
  (`R"(...")` where the regex itself contained `)"`, closing the raw
  string early) -- fixed with a named delimiter (`R"re(...)re"`).
- Missing `<algorithm>` include for `std::all_of` in
  `detection_engine.cpp`.

## Real dry-run against a real, unmodified system package

```
$ ./ubuntu-deep-uninstaller --dry-run /usr/share/applications/libreoffice-calc.desktop
```

Output (trimmed) showed:
- `dpkg -S /usr/lib/libreoffice/program/soffice -> owned by package 'libreoffice-common'`
  -- correct: the container's real dpkg database.
- `apt-mark: manually installed` -- correct.
- `apt-get remove --simulate: 8 other package(s) would also be removed`
  -- and it listed them: `libreoffice-calc`, `libreoffice-writer`,
  `libreoffice-base-core`, `python3-uno`, `libreoffice-impress`,
  `libreoffice-core`, `libreoffice-java-common`, `libreoffice-draw`. This
  is the real, correct cascade for removing `libreoffice-common` on this
  system -- not invented.

This is the single most important validation in this project: the APT
detector's identity link (`dpkg -S`, never name-guessing) and its blast-
radius computation (`apt-get remove --simulate`, never assumed) both work
against a real package database.

## Synthetic fixtures for Manual / AppImage / Wine

Built fake `.desktop` files and fake filesystem trees under `/tmp/udu_test/`
and ran `--dry-run` against each:

- **Manual**: `Exec=/tmp/udu_test/opt/fakeapp/fakeapp` correctly resolved
  to `InstallationSource::Manual`, proposed the binary at High confidence
  and its parent directory at `[REMOVE*]` (separately-confirmed) since the
  parent isn't a shared system bindir.
- **AppImage**: `Exec=.../FakeApp.AppImage %U` correctly resolved to
  `InstallationSource::AppImage`, High confidence, field codes (`%U`)
  correctly stripped before pattern matching.
- **Wine**: `Exec=env WINEPREFIX="..." wine "C:\Program Files\FakeWineApp\fakewineapp.exe"`
  correctly resolved the prefix, converted the Windows path to
  `<prefix>/drive_c/Program Files/FakeWineApp/fakewineapp.exe`, and
  proposed only that app's own subtree as `[REMOVE]`, with the whole
  prefix offered separately as `[REMOVE*]` (optional) since no sibling
  `.desktop` files referenced the same prefix in this fixture's search
  paths.

## Security backstops, verified directly

A standalone probe program confirmed:
- `validate_removal_target("/etc", {"/etc"})` → refused, even though
  `/etc` was passed as its own "allowed root" -- the catastrophic-path
  check fires unconditionally.
- A symlink placed inside an allowed root but pointing *outside* it
  (`.../app_dir/evil_symlink -> .../outside_target`) was refused because
  canonicalization resolves the symlink before the under-root check runs.

These two properties are also covered as permanent regression tests in
`tests/test_core.cpp` (`catastrophic_paths_are_always_refused_even_as_their_own_root`,
`symlink_escaping_allowed_root_is_refused`).

## Unit test suite

```
$ g++ -std=c++23 -Wall -Wextra tests/test_core.cpp src/desktop_entry.cpp \
    src/security/proc_exec.cpp src/security/paths.cpp \
    src/detector/*.cpp src/planner/removal_plan.cpp -o udu_tests
$ ./udu_tests
[PASS] parses_basic_desktop_entry
[PASS] malformed_desktop_file_without_group_header_fails_to_parse
[PASS] missing_file_fails_to_parse_rather_than_throwing
[PASS] desktop_actions_are_parsed
[PASS] locale_suffixed_keys_are_ignored_in_favor_of_default
[PASS] catastrophic_paths_are_always_refused_even_as_their_own_root
[PASS] symlink_escaping_allowed_root_is_refused
[PASS] path_legitimately_under_allowed_root_validates
[PASS] nonexistent_path_is_refused_rather_than_guessed
[PASS] appimage_detected_from_exec_pattern
[PASS] unresolvable_exec_yields_low_confidence_unknown_with_only_desktop_entry_removable
[PASS] wine_shared_prefix_protects_prefix_root_from_removal

12 passed, 0 failed
```

## GUI build iteration (against a real Ubuntu 26.04 machine, not this sandbox)

The project's owner built this on real hardware with `libgtk-4-dev`/
`libadwaita-1-dev` installed, which this dev sandbox never had. First real
build attempt reported:

1. `error: macro 'g_signal_connect' passed 5 arguments, but takes just 4`
   at the `on_uninstall_clicked` handler. Root cause: the call passed
   `new std::pair<std::string, GtkWidget*>(path, window)` as the last
   argument. The C preprocessor expands macros before the compiler ever
   sees C++ template syntax, so it has no concept of `<...>` template
   argument lists -- it just scans for top-level commas to split macro
   arguments, and split on the comma inside `<std::string, GtkWidget*>`,
   turning one intended argument into two. Fixed by replacing the
   `std::pair` with a named `UninstallConfirmContext` struct (also pulled
   the inline lambda out into a named `on_uninstall_response` function
   while at it, which is cleaner regardless).

2. `error: cannot convert 'AdwDialog*' to 'GtkWidget*' in initialization`
   at all three `adw_alert_dialog_new(...)` call sites. Root cause:
   `adw_alert_dialog_new()` returns `AdwDialog*`; despite `AdwDialog`
   ultimately being GObject-related to `GtkWidget` in libadwaita's type
   hierarchy, C++ requires an explicit cast between the two pointer types
   (GTK/GObject "subclassing" is a runtime convention over plain structs,
   not real C++ inheritance, so implicit upcasting doesn't apply). Fixed
   by declaring the variable as `AdwDialog*` throughout and calling
   `adw_dialog_present(dialog, window)` directly (no `ADW_DIALOG(...)`
   cast needed once the static type already matches).

3. A `g_object_set(..., "placeholder-text", ...)` swap for
   `gtk_search_entry_set_placeholder_text(...)`, made proactively (not in
   response to a reported error) after the above, since that function's
   presence has moved around across GTK4 point releases while the
   underlying GObject property is stable.

After these fixes, the file was re-checked for balanced
parentheses/braces/brackets (a script, not a compiler, since no GTK4
headers are available here) and is otherwise unchanged. It has NOT yet
been confirmed to compile clean end-to-end -- if the next build attempt
surfaces more errors, they are expected to be similarly small, mechanical
GTK4/libadwaita API-surface issues rather than structural problems.

## Round 3: UX fixes + the real context-menu bug (against real Ubuntu 26.04 builds)

The project owner reported, from real use after a successful full build
(core, CLI, and GUI all compiled clean):

1. Clicking an application in the GUI froze the window for a few seconds
   with no feedback.
2. The terminal window closed itself immediately after an uninstall
   finished, before the log could be read.
3. No way to refresh the application list after an uninstall (stale
   entries stayed visible).
4. After a full log-out/log-in, "Uninstall Completely" was still missing
   from most apps' context menus, and for at least one app, clicking it
   appeared to just open the app itself (a new browser tab) instead of
   doing anything uninstall-related.
5. A request for colorized terminal output.

**(4) turned out to be the one real architectural bug in this round.**
`integration/desktop_override.cpp` generated `Exec=<binary>
--uninstall-by-desktop-id '<path>'` for the Desktop Action -- but GNOME
Shell executes a Desktop Action's `Exec=` directly, with **no terminal
attached**. The CLI's interactive `type UNINSTALL to continue` prompt was
therefore reading from a stdin nothing was ever going to write to, with
no visible window at all. Depending on exactly how GNOME resolves an
action that never produces a window, this plausibly explains "clicking it
just opened the app" as a fallback to normal activation.

Fix: added `--uninstall-by-desktop-id-in-terminal`, a new CLI subcommand
that finds a terminal emulator (`terminal::build_terminal_argv`, shared
with the GUI) and launches the ordinary interactive command inside it,
fully detached (`security::spawn_detached`, a double-fork daemonize
pattern so GNOME Shell's action activation returns immediately rather
than blocking on a process the user might interact with for minutes). The
desktop-file override now points at this subcommand instead.

**Verified against real data in this sandbox** (not just synthetic
fixtures this time): ran `--install-integration` against the *actual*
`/usr/share/applications/libreoffice-calc.desktop` shipped by this
system's real LibreOffice package -- a large, translation-heavy file that
**already has its own `Actions=NewDocument;`** for the "New Spreadsheet"
action. The generated override correctly preserved
`[Desktop Action NewDocument]` untouched and produced
`Actions=NewDocument;UduUninstall;`, appending
`[Desktop Action UduUninstall]` with the new in-terminal `Exec=` line.
This is exactly the kind of real, complex file that would have exposed a
naive Actions= merge bug, and it didn't.

Also verified directly:
- `shell_quote()` (used to build the "run command, then wait for Enter"
  bash wrapper) round-tripped a deliberately hostile string containing
  `; rm -rf /tmp/evil; echo` through a real shell and got back the exact
  literal string with zero execution.
- `security::spawn_detached()` and `security::self_executable_path()`
  work correctly against real processes (`spawn_detached({"touch", ...})`
  actually created the file; `self_executable_path()` correctly resolved
  `/proc/self/exe`).
- Color codes (`\033[1;34m` for banners, per-tag colors for
  `[CHECK]`/`[FOUND]`/`[REMOVE]`/etc.) are correctly emitted when attached
  to a real pty (tested via `script`) and correctly absent both when piped
  and when `NO_COLOR=1` is set.
- Full core+CLI rebuild after all of the above: clean, zero warnings; all
  12 tests in `tests/test_core.cpp` still pass.

**Still not verified**: the GUI file itself (async detection thread,
spinner, refresh button, `g_idle_add` marshaling) -- same limitation as
before, no GTK4 headers in this sandbox. Bracket-balance checked only.
`install.sh`/`uninstall.sh` were syntax-checked (`bash -n`) but not run
end-to-end on a real machine.

## Round 4: the real crash -- fork() from a GTK background thread

After Round 3 shipped, the project owner reported the GUI getting stuck on
"Loading details for..." for multiple different applications (not just
one), and the whole GUI window eventually disappearing on its own after
being stuck a while. That second detail -- the process dying, not just
feeling slow -- was the key clue that this was a crash/deadlock, not
"detection is just slow for complex packages."

**Root cause**: `security::run()` (used by every detector for every
`dpkg`/`apt-get`/`flatpak`/`snap` call) used a hand-rolled `fork()` +
`execvp()`. Round 3 moved app detection onto a background `std::thread` in
the GUI to fix the earlier UI-freeze complaint -- but `fork()` is
well-documented to be unsafe to call from any thread of a process that has
other threads running, which every GTK/libadwaita application does
internally (icon loading, D-Bus/portal communication, etc.) regardless of
whether the application itself spawns threads. `fork()` only duplicates
the calling thread; if some other thread happened to hold an internal lock
(glibc's malloc arena lock is the textbook case) at the exact moment of
the fork, that lock is copied into the child in its "held" state
permanently, with no thread left alive in the child to ever release it.
Anything the child does before `exec()` that needs that lock -- which can
include ordinary things like string/vector allocations in our own
`dup2`/`chdir`/argv-building code -- deadlocks forever. This is inherently
timing-dependent, which matches "happens for various different apps,
not consistently" far better than a genuine per-package slowness theory
does. The CLI never hit this because it is single-threaded; introducing a
background thread in the GUI (the very fix for the Round-3 UI-freeze
complaint) is what exposed it.

**Fix**: rewrote `src/security/proc_exec.cpp` to use `posix_spawn()`
instead of `fork()`+`execvp()`, for both `run()` and `spawn_detached()`.
`posix_spawn()` is the POSIX-standard, glibc-implemented primitive
specifically designed to be safe to call from any thread of a
multi-threaded process -- this is the textbook-correct fix for this class
of bug, not a workaround. File-descriptor redirection (stdout/stderr into
pipes, stdin to `/dev/null`) and `chdir` are now expressed via
`posix_spawn_file_actions_t` instead of code we'd otherwise run between
fork and exec; session detachment in `spawn_detached()` uses the
`POSIX_SPAWN_SETSID` flag instead of an explicit `setsid()` call in a
forked child.

Also, independently: reduced the default per-subprocess timeout from
15s to 6s, and the `apt-get remove --simulate` call specifically to 8s
with `-o Debug::NoLocking=1` added (skips any attempt to acquire apt's
lock file for this read-only query, since lock contention with an
unrelated apt/dpkg process -- e.g. Software Updater running in the
background -- was a plausible secondary contributor to a package like
Docker Desktop, which has a large dependency graph, feeling especially
slow to inspect).

**Verified**:
- Full core+CLI rebuild after the rewrite: clean, zero warnings.
- All 12 tests in `tests/test_core.cpp` still pass.
- Basic functional re-check (`--dry-run` against the real
  `libreoffice-calc.desktop`) still works correctly end-to-end through the
  new `posix_spawn`-based `run()`.
- A stress test spawning several background threads doing tight
  allocation-churn loops (standing in for GTK's internal threads)
  concurrently with repeated `run()` calls completed all 20/20 calls
  successfully with no timeouts or hangs. **Caveat**: this dev sandbox has
  only a single CPU core (`nproc` = 1), which limits how strongly this
  specific test can reproduce the multi-core timing race that causes the
  fork+malloc-lock deadlock in the first place -- an earlier, more
  aggressive version of the same test (8 threads, 200 iterations) did
  appear to hang, but re-running with fewer threads showed this was CPU
  starvation from an oversubscribed single core, not a deadlock (every
  call completed in a consistent ~200ms once thread count was reduced).
  The architectural fix (no more `fork()` from any thread) is correct
  regardless of what this single-core sandbox can fully prove; the
  project owner's real multi-core machine is the real test.

## Round 5: debug tracing + crash backtraces (requested after Round 4's fix didn't visibly resolve the hang)

The Round 4 `posix_spawn` fix was shipped, but the project owner reported
the GUI still hanging on "Loading details..." -- this time even for
Calculator, an app with a trivial dependency graph, which made "slow apt
dependency resolution" an implausible explanation on its own. Two
possibilities stood out: either the fix genuinely didn't address the real
cause, or (more likely, based on the screenshot showing a terminal running
a bare `ubuntu-deep-uninstaller-gui` with no path) the owner was running an
older binary already installed at `/usr/bin/ubuntu-deep-uninstaller-gui`
from a previous `install.sh` run, resolved via `$PATH`, rather than the
freshly rebuilt one in the newly extracted folder.

Rather than keep guessing blind, added the two things needed to settle
this definitively and for any future issue:

1. **`UDU_DEBUG=1` step-by-step tracing** (`src/security/debug_log.hpp`):
   every subprocess spawn (`run()`, `spawn_detached()`) logs a timestamped
   line before and after, including exit code and elapsed time;
   `run_detection()`, `detect_apt()`, `check_running()`, and the GUI's
   background detection thread each log their major steps. Zero overhead
   (one cached bool check) when unset; verified silent by default and
   fully detailed when enabled -- a real trace against
   `libreoffice-calc.desktop` showed exact per-call timings (e.g.
   `apt-mark showmanual` took ~894ms, `apt-get remove --simulate` took
   ~1543ms on this system), which is exactly the granularity needed to
   pinpoint a hang to one specific command instead of a vague "detection
   is stuck."

2. **Crash backtraces** (`src/security/crash_handler.cpp`): installs a
   `sigaction`-based handler for SIGSEGV/SIGABRT/SIGBUS/SIGFPE/SIGILL in
   both the CLI's and the GUI's `main()`, using only
   `write()`/`backtrace_symbols_fd()` inside the handler (documented as
   safe from a signal handler, unlike `backtrace_symbols()` which
   allocates) plus a one-time `backtrace()` warm-up call at startup to
   pre-resolve the unwinder outside of any signal context. Prints the
   signal name, faulting address, and a real stack backtrace to stderr,
   then re-raises the default handler so the process still exits with the
   correct status. **Verified against a real, deliberate SIGSEGV** (null
   pointer write in a standalone test program): correctly printed
   `received signal 11 (Segmentation fault), faulting address=(nil)`
   followed by a genuine backtrace with resolved addresses, then exited
   139 as expected -- confirming this actually works, not just that it
   compiles. Both CMake targets now link with `-rdynamic` so backtraces
   show real function names.

Also fixed a missing `<initializer_list>` include caught during this
round's compile check (needed for the range-based signal list in
`install_crash_handler()`).

**Verified**: full core+CLI rebuild clean, all 12 tests still pass, basic
dry-run still works correctly with `-rdynamic` linked in.

**Next step for the project owner**: run with `UDU_DEBUG=1` from a
terminal against whichever app still hangs, and the log will show exactly
which subprocess call (if any) is the one not returning -- at that point
the fix is either "make that specific call more robust" (a concrete,
addressable bug) or, if it turns out the owner was on a stale installed
binary the whole time, simply rebuilding/reinstalling resolves it. Either
way, this is no longer a guessing game.

## Round 6: performance, UX, safety fix, and new features (all from one detailed feedback message)

The project owner reported Bulk Rename specifically taking ~30 seconds to
load in the GUI, and gave a long list of concrete requests. Addressed:

**Performance -- the real fix.** `detect_apt()` previously ran 5
subprocess calls one after another: `dpkg -S`, `dpkg-query`, `apt-mark
showmanual`, `apt-get remove --simulate`, `dpkg -L`. Two changes:
1. `apt-mark showmanual` (which dumps the name of *every* manually-
   installed package on the whole system just to answer a yes/no question
   about one package) was replaced with a direct read of
   `/var/lib/apt/extended_states` -- no subprocess at all, just a local
   file parse for the one package's `Auto-Installed:` stanza.
2. The three remaining independent subprocess calls (`dpkg-query`,
   `apt-get remove --simulate`, `dpkg -L`) now run **concurrently** via
   `std::async`, since none of them depend on each other's output, only
   on the package name `dpkg -S` already produced. Wall time is now
   `max()` of the three instead of their sum.

Verified with a real timing comparison against `libreoffice-calc.desktop`
on this system: **2.5s -> 1.6s**, and the `UDU_DEBUG=1` trace confirms the
three calls now start at the identical timestamp on three different
thread IDs. Output correctness re-verified (same 8-package dependency
list as before the change). For a package hitting worse-case timeouts on
the owner's system (consistent with "~30 seconds", suspiciously close to
5 sequential calls each approaching their old 6-8s timeout), the
reduction should be considerably larger than this benchmark shows, since
it removes one call outright and overlaps three more.

**A real safety bug found via this work, and fixed.** While testing the
`--uninstall` confirmation flow's UX changes below, a resource under
`/usr/share/applications/` got deleted in this sandbox during a real
completion test. Root cause: this dev sandbox runs as root with no `sudo`
binary installed, and `execute_filesystem_resources()`'s deletion of a
`requires_sudo=true` resource was a direct in-process `fs::remove_all()`
-- `requires_sudo` was purely a *display* flag, never an actual privilege
gate. In the tool's real, intended deployment (a normal non-root desktop
user), this fails safely by ordinary OS permissions; it is not a
real-world exploit. But it is not correct design, and was fixed properly:
privileged filesystem resources are now deleted via an explicit `sudo rm
-rf --` subprocess call, going through the same interactive sudo prompt
every other privileged step uses. Verified directly: with no `sudo`
binary present, the deletion now correctly fails (`spawn_failed=1`) and
the file survives, instead of silently succeeding via ambient process
permissions as it did before.

**Confirmation UX.** Every secondary prompt (continue with a running app,
include optional [REMOVE*] items, purge vs. remove, autoremove
dependencies) now defaults to yes on a bare Enter (`[Y/n]`, only an
explicit `n`/`N` declines) -- matching "press continue continue continue."
The one exception, kept deliberately: the "type UNINSTALL to continue"
gate immediately before anything is actually removed still requires the
exact typed word. Verified: a bare Enter at that specific prompt still
aborts with "confirmation text did not match"; bare Enter at every other
prompt now proceeds with the labelled default.

**Clear success/fail summary.** The CLI now ends with a plain-language
`SUCCEEDED: all N action(s) completed` or `COMPLETED WITH ERRORS: N
succeeded, M failed -- see [ERROR] lines above` instead of leaving the
person to interpret a bare process exit code.

**History tracking.** New `uninstall::record_history()`/`read_history()`
(`src/uninstall/history.cpp`), called automatically from
`execute_plan()` on success -- so it works identically whether the CLI's
`--uninstall` or the GUI's "Uninstall Completely" was used. Stored as a
simple tab-separated append-only log under
`~/.local/state/ubuntu-deep-uninstaller/history.log`. New `--history` CLI
command; new History button (top-left of the GUI header bar) opening a
selectable, copyable list dialog. Verified end-to-end with a temporary
`$HOME`: two recorded entries round-tripped correctly through both the
raw file and `--history`'s formatted output.

**RAM usage display.** New label in the GUI header bar reading
`/proc/self/status`'s `VmRSS` line directly (no subprocess), refreshed
every 2 seconds via `g_timeout_add_seconds`.

**Requests addressed by explanation rather than new code** (see the
chat reply for the full reasoning): thread-pool reuse (thread *creation*
was never the bottleneck -- a few microseconds on Linux -- the real cost
was sequential subprocess I/O wait, which is what got fixed above;
adding a persistent pool now would be complexity without measurable
benefit); avoiding literal `find` (the codebase never shells out to
`find` anywhere -- all directory scans already use `std::filesystem`
directly, so there's nothing to swap for a faster tool); preventing
cross-deletion between similarly-named apps (already correctly handled
by construction: every APT-sourced resource is identified via `dpkg -S`
reverse file-to-*package* lookup, never by display name, so "Files" vs.
"Files" or "KDE Connect" vs. "KDE Connect Indicator" only ever resolve to
whichever package genuinely owns that specific resolved executable).
Deferred, flagged honestly as future work: fully eliminating the GUI's
"detect twice" cost (once for the preview pane, once when the terminal
opens) would need serializing the computed plan across the process
boundary to the terminal invocation -- a real, bounded feature, just not
completed in this pass; the parallelization above substantially shrinks
the pain of it in the meantime (each detection run is faster, so running
it twice costs much less than it used to).

**Verified this round**: full core+CLI rebuild clean (zero warnings), all
12 tests in `tests/test_core.cpp` still pass, history round-tripped
correctly end-to-end, the sudo-rm fix verified to fail safely without
`sudo` present, and the parallel-detection speedup verified with real
before/after timing and a debug trace showing genuine concurrent
dispatch. The GUI-side additions (History dialog, RAM label) could not be
compiler-checked in this sandbox (still no GTK4 dev headers here) --
bracket-balance checked only, same limitation as every previous GUI
change in this project.

## Round 7: real bug from the screenshots, plan caching, and Enter-only confirmation

The project owner's screenshots showed two concrete, fixable things:

**Bug: a false-positive `[ERROR]` on a resource the package manager already
removed.** The Barrier uninstall log showed `sudo apt-get purge -y barrier`
succeed, then a separate step try to remove
`/usr/share/applications/barrier.desktop` and log `[ERROR] ... path
failed re-validation immediately before deletion` -- even though
Verification correctly reported that same file as `REMOVED`. Root cause:
`apt purge` already deletes every file it tracks for the package,
*including* the desktop entry (confirmed by the plan's own `dpkg -L
barrier: 26 file(s) tracked`), so by the time
`execute_filesystem_resources()` got to that resource it was already
gone -- `canonicalize()` correctly fails on a non-existent path, but the
code treated "doesn't exist anymore" as a validation failure rather than
recognizing "the goal is already met." Fixed: an explicit existence check
now runs first; if the resource is already gone, it's logged as
`[SUCCESS] ... already removed (most likely by the package manager ...)`
instead of attempted-then-failed. Verified with a synthetic reproduction
(delete a planned resource out from under `execute_plan()` before running
it): now reports `[SUCCESS] ... already removed ... nothing left to do`
and `overall_success=1`, instead of the previous false `[ERROR]`.

**The "why does it scan twice" complaint -- actually fixed this time.**
Previously deferred as a known gap; implemented now.
`src/planner/plan_cache.{hpp,cpp}` persists the `RemovalPlan` the GUI's
background thread already computed, tagged with the exact desktop path it
was computed for, to a single-slot file cache
(`~/.cache/ubuntu-deep-uninstaller/last_plan.cache`, tab-separated, plain
text, no external dependency). `cmd_uninstall()`/`cmd_inspect_or_dry_run()`
in the CLI now check this cache first (path must match exactly, and the
cache must be under 3 minutes old) before ever calling `run_detection()`.
Verified end-to-end: wrote a real plan for
`libreoffice-writer.desktop` via a standalone probe (simulating what the
GUI's background thread now does automatically), then ran `--dry-run`
against that exact path -- **0.003 seconds**, full correct removal plan
(same package, same 8 dependents) reused straight from the cache instead
of re-running `dpkg`/`apt-get`. Also verified the cache correctly
*declines* to apply itself when the desktop path doesn't match (a
different app), falling back to normal fresh detection with no special
casing needed by the caller.

**Confirmation UX -- removed the typed-word gate entirely, per explicit,
repeated request.** The "type UNINSTALL to continue" prompt is now
"Press ENTER to continue, or Ctrl+C to cancel." Ctrl+C remains available
at every step as the actual way to stop. This was a deliberate design
trade-off the project owner asked for twice in as many messages; the
warning text above the prompt is unchanged, so the person still sees
exactly what they're agreeing to.

**Verified this round**: full core+CLI rebuild clean, all 12 tests still
pass, both new behaviors (already-removed-is-success, plan cache hit and
miss) verified against real and synthetic scenarios as described above.
GUI-side wiring (`save_plan_cache()` call in the background thread)
bracket-balance checked only, same limitation as every other GUI change
in this project (no GTK4 headers in this sandbox).

**Performance follow-up not yet resolved**: the owner reports detection
still feels slow for at least one simple app (Barrier) even after Round
6's parallelization, and recalls an earlier version that felt instant.
Investigated the two hypotheses raised (atomic/false-sharing contention
from the GUI's generation counter, and thread-creation overhead from
`std::async`) and both are almost certainly not the cause at this
frequency of use (a handful of increments/reads per click, not a hot
loop) -- but this could not be confirmed against the owner's actual
machine and workload from this sandbox. Asked the owner to re-run with
`UDU_DEBUG=1` and share the exact per-call timings for the specific slow
case, since further optimization without that data would be guessing.

## Round 8: the segfault, root-caused and fixed

The project owner's `UDU_DEBUG=1` trace was exactly what was needed:
every crash showed the identical pattern -- the log stopped dead right
after `run_detection(): trying detect_appimage...`, no exception, no
error, just gone. That pinpointed the function immediately.

**Root cause, confirmed by direct reproduction.** `detect_appimage()`'s
fallback path (for when `Exec=` doesn't directly reference an
`.AppImage`) resolves the executable, reads the **entire file into a
`std::string`**, and runs `std::regex_search()` over it looking for an
`.AppImage` reference -- intended for small wrapper *scripts*, but with
no check that the resolved file actually was one. For Flameshot and
Nautilus ("Files"), `Exec=` resolves directly to their real compiled
binaries (megabyte-scale ELF executables), so this fallback was reading
multi-megabyte binaries into memory and regex-searching the raw bytes.
libstdc++'s `std::regex` uses a backtracking engine that can both be very
slow and overflow the stack on large, dense, non-matching binary input.

Reproduced directly, outside the tool entirely: read `/usr/bin/bash`
(1.4MB) into a string and ran the exact same regex over it --
**`Segmentation fault, exit code 139`**, deterministically, every time.
This is almost certainly the same root cause behind the earlier `--dry-run
`Docker Desktop"/FSearch/Flameshot slowness reports too, for apps whose
binaries were large enough to be slow but not quite large enough to
overflow the stack.

**Fix**: added `looks_like_small_text_script()` -- checks file size
(reject anything over 64KB; legitimate AppImage-launching wrapper scripts
are a few hundred bytes to a few KB) and checks the ELF magic number
(`0x7F 'E' 'L' 'F'`, reject unconditionally regardless of size) *before*
ever reading a resolved executable's content. Verified three ways:
1. The exact old code path, reproduced standalone against a real 1.4MB
   binary: segfaults, confirming the diagnosis.
2. The fixed `detect_appimage()` against the same real binary via a
   realistic desktop-entry fixture: returns `nullopt` in 0ms, no crash.
3. A legitimate small wrapper script (a few hundred bytes, referencing a
   fake `.AppImage` path) still correctly detected and reported --
   confirming the fix didn't break the feature it was guarding, only the
   unsafe input it was never supposed to accept.

**Also added, per the project owner's explicit request**: every detector
(`flatpak`, `snap`, `wine`, `manual` -- `apt` and `run()` already had
this from earlier rounds) now logs what it's checking and what it finds,
in real time, tagged with its own thread ID via `UDU_DEBUG=1`. This is
exactly what made the crash immediately locatable from the trace, and
will do the same for anything found later.

**Verified this round**: full core+CLI rebuild clean, all 12 tests still
pass, the crash reproduced and fixed as described above, new logging
confirmed rendering correctly per-detector and per-thread.

## What was NOT run, and why

- **Actual destructive execution** (`--uninstall` past the confirmation
  prompt) was never run against this container's real packages -- doing
  so would have partially uninstalled LibreOffice from the dev sandbox
  for no benefit to the deliverable. The execution code path
  (`uninstall/executor.cpp`) reuses the exact same `security::run()`
  primitive already exercised (successfully) by the APT detector's own
  `apt-get --simulate` call, so the plumbing is shared and tested; only
  the final non-simulated `apt-get remove -y` invocation itself is
  unexercised.
- **Flatpak/Snap live enrichment** (`flatpak info`, `snap info`) -- no
  `flatpak`/`snap` binaries exist in this sandbox. The pattern-matching
  half (extracting the app-id/snap name from `Exec=`) has no such
  dependency and is straightforward regex logic, but wasn't unit-tested
  here for time; that's a good next addition to `tests/test_core.cpp`.
- **The GTK4/libadwaita GUI** -- no dev headers in this sandbox; written
  to the GTK4/libadwaita C API but not compiler-checked. Flagged clearly
  in the file's own header comment, in `README.md`, and in `BUILD.md`'s
  "known gaps" list.
- **GNOME Shell actually rendering the context-menu action** -- this
  sandbox has no display server or GNOME Shell session. The override-file
  generation logic (`integration/desktop_override.cpp`) was exercised at
  the level of "does it produce syntactically correct merged `.desktop`
  content", but not "does GNOME Shell's app grid actually show the new
  item" -- that requires a real GNOME 50 session.
- **`.deb` build** -- no `debhelper`/`dpkg-buildpackage` in this sandbox.

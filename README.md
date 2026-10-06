# Ubuntu Deep Uninstaller

An evidence-based, safety-first application uninstaller for Ubuntu 26.04
(GNOME). Right-click any application in the GNOME app grid → **Uninstall
Completely** → a visible terminal shows exactly what was detected, what is
planned, asks for confirmation, requests sudo interactively only when
needed, and verifies the result afterward.

**Never** deletes based on "the name looks similar." Every planned removal
traces back to concrete evidence (`dpkg -S`, a parsed `Exec=` target, a
Flatpak/Snap query, a Wine prefix relationship) and is shown to you before
anything happens.

## What's implemented and verified in this repository

| Component | Status |
|---|---|
| `.desktop` parser (incl. Desktop Actions) | Built, unit-tested |
| Security layer (argv-only exec, path canonicalization, symlink-escape / catastrophic-path refusal) | Built, unit-tested |
| APT/dpkg detector | Built, tested against real `dpkg`/`apt-get --simulate` on this machine (see `DEVLOG.md`) |
| Flatpak / Snap detectors | Built; pattern-matching logic tested via fixtures (no flatpak/snap binaries were available in the dev sandbox to test live queries against) |
| Wine detector (incl. shared-prefix protection) | Built, unit-tested including a synthetic shared-prefix scenario |
| AppImage detector | Built, unit-tested |
| Manual/fallback detector | Built, tested against a synthetic fixture |
| Planner (`RemovalPlan`) | Built, unit-tested |
| Executor (apt/flatpak/snap/filesystem removal) | Built; package-manager removal paths are code-complete but were not exercised destructively against a real system (deliberately -- see `DEVLOG.md`) |
| Verification | Built |
| Terminal report formatting | Built, exercised via real dry-run transcripts |
| Debug tracing (`UDU_DEBUG=1`) + crash backtraces | Built; tracing verified silent-by-default and fully detailed when enabled (real per-subprocess timings captured against LibreOffice); crash handler verified against a real, deliberate SIGSEGV -- correctly printed signal/address/backtrace and exited with the right status |
| Parallel APT detection + sudo-gated privileged deletion | Built; verified a real 2.5s->1.6s speedup on this system plus a subprocess eliminated outright (see `DEVLOG.md` Round 6); a real safety bug (privileged deletion not actually going through sudo) was found and fixed during this work, verified to fail safely with no `sudo` binary present |
| Uninstall history (`--history`, GUI History button) | Built and verified end-to-end (round-tripped through the log file and the CLI's formatted output) |
| Plan cache (avoids re-detecting when the GUI opens a terminal) | Built and verified end-to-end: a cached plan is reused in ~3ms instead of a full multi-second detection re-run, and correctly falls back to fresh detection on any mismatch or staleness (see `DEVLOG.md` Round 7) |
| AppImage-detector crash fix | A real, reproducible segfault (`std::regex` over multi-megabyte binaries) was found, root-caused, and fixed -- verified with a direct standalone reproduction of the crash, confirmation the fix eliminates it, and confirmation the underlying feature (detecting a small AppImage-launching wrapper script) still works (see `DEVLOG.md` Round 8) |
| Per-detector real-time debug logging | Every detector (APT, Flatpak, Snap, Wine, Manual) now logs what it's checking via `UDU_DEBUG=1`, tagged with its own thread ID -- this is what made the crash above immediately locatable from a user-provided trace |
| Full application listing (incl. `~/.local/share/applications`) | A real gap was found and fixed: apps registered only under the user's own local applications directory (JetBrains Toolbox, manually created `.desktop` files, anything set up by hand) were silently missing from both the GUI and `--list-applications`. Now scanned in correct XDG precedence order, with Flatpak/Snap export directories included and desktop-ID dedup |
| Portable/manually-extracted app cleanup (JetBrains-style) + caching | Detects the full extracted-archive root (not just the immediate `bin/` folder) and a plausibly matching installer archive in `~/Downloads`, both offered as separately-confirmed optional removals. Both lookups are cached per application so a repeat run never re-scans. Verified end-to-end with a realistic fixture, including catching and fixing a real matching bug (hyphen/no-hyphen filename mismatch) along the way |
| GNOME context-menu integration (`Actions=` override mechanism) | Built; verified the merge logic against a real, complex system desktop file (LibreOffice Calc's, which already has its own `Actions=`) -- correctly preserved the existing action and appended ours. The action's `Exec=` now launches a detached terminal (fixed a real bug where it previously ran headless with no terminal attached -- see `DEVLOG.md`). Still not tested against a live GNOME Shell session (this dev sandbox has no display server) |
| GTK4/libadwaita GUI | Written against the GTK4/libadwaita C API, **not compiler-verified** -- the dev sandbox has no `libgtk-4-dev`/`libadwaita-1-dev`. Build it on a real Ubuntu 26.04 box per `BUILD.md` and expect a small amount of iteration. |
| `.deb` packaging | Written, not built into an actual `.deb` in this sandbox (no `dpkg-buildpackage`/`debhelper` available) |

See `DEVLOG.md` for the actual commands run and their output during
development -- this project was built with compile-and-test-as-you-go, not
written blind.

## Quick start

The one-shot way, on a real Ubuntu 26.04 machine:

```bash
./install.sh
```

Checks/installs build dependencies, configures, builds, runs the test
suite, installs `ubuntu-deep-uninstaller` (and the GUI, if GTK4/libadwaita
were found) to `/usr/bin`, and registers the "Uninstall Completely"
context-menu action for your account. Run `./uninstall.sh` to remove
everything it installed, including an offer to clean up the per-app
context-menu overrides.

The manual way, if you'd rather see each step:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j
./build/ubuntu-deep-uninstaller --list-applications
./build/ubuntu-deep-uninstaller --dry-run /usr/share/applications/<something>.desktop
./build/ubuntu-deep-uninstaller --uninstall /usr/share/applications/<something>.desktop
```

`--dry-run` never modifies anything. `--uninstall` shows the full plan,
requires typing `UNINSTALL` to proceed, and only then executes it
(prompting for `sudo` interactively where required). Both print a
colorized log (blue section banners; cyan/yellow/green/red status tags) --
auto-disabled when piped or when `NO_COLOR` is set.

## Project layout

```
ubuntu-deep-uninstaller/
├── src/
│   ├── main.cpp                 # CLI entry point
│   ├── desktop_entry.{hpp,cpp}  # .desktop / Desktop Actions parser
│   ├── security/                # argv-exec wrapper, path validation
│   ├── detector/                # evidence model + one file per source
│   │   ├── types.hpp            # Evidence/Resource/DetectionResult
│   │   ├── common.{hpp,cpp}     # shared exec-resolution / XDG helpers
│   │   ├── apt_detector.{hpp,cpp}
│   │   ├── flatpak_detector.{hpp,cpp}
│   │   ├── snap_detector.{hpp,cpp}
│   │   ├── wine_detector.{hpp,cpp}
│   │   ├── appimage_detector.{hpp,cpp}
│   │   ├── manual_detector.{hpp,cpp}
│   │   └── detection_engine.{hpp,cpp}   # orchestrator
│   ├── planner/removal_plan.{hpp,cpp}   # evidence -> immutable plan
│   ├── uninstall/executor.{hpp,cpp}     # executes a confirmed plan
│   ├── verification/verify.{hpp,cpp}
│   ├── terminal/report.{hpp,cpp}        # [CHECK]/[FOUND]/[REMOVE]/... log
│   ├── integration/desktop_override.{hpp,cpp}  # GNOME context-menu action
│   └── gui/gui_main.cpp         # GTK4/libadwaita front-end
├── tests/test_core.cpp          # dependency-free assertion test suite
├── packaging/
│   ├── org.uduninstaller.UbuntuDeepUninstaller.desktop
│   └── debian/                  # control, rules, postinst, prerm, ...
├── CMakeLists.txt
├── BUILD.md
└── DEVLOG.md
```

## Safety model, in one paragraph

Every filesystem deletion target passes through
`security::validate_removal_target()`, which canonicalizes the path
(resolving symlinks), refuses a fixed set of catastrophic system paths
even if evidence somehow pointed there, and requires the resolved path to
land inside a directory the *evidence itself* produced (not a name guess).
Low-confidence findings are downgraded to a separately-confirmed
"optional" tier and are never included in the default removal set. Shared
Wine prefixes and dependencies still required by other packages are
detected and explicitly protected. All process execution uses argv arrays
via `posix_spawn()` (never a raw `fork()`, and never a shell) -- there is
no code path that builds a shell command string from user- or
evidence-derived text, and none of the subprocess-launching code is
vulnerable to the fork-from-a-multithreaded-process deadlock class of bug
(see `DEVLOG.md`'s "Round 4" for the real incident that motivated this).

## Uninstalling this tool itself

```bash
sudo apt purge ubuntu-deep-uninstaller   # if installed via the .deb
# then, to remove the context-menu overrides it wrote to your own account:
grep -rl UduUninstall ~/.local/share/applications | xargs rm -f
```

# Building

## Prerequisites (Ubuntu 26.04)

```bash
sudo apt update
sudo apt install build-essential cmake pkg-config \
    libgtk-4-dev libadwaita-1-dev
```

The CLI, core library, and tests only need `build-essential` + `cmake`.
`libgtk-4-dev`/`libadwaita-1-dev` are only needed for the GUI target; if
they're missing, CMake configure still succeeds and simply skips
`ubuntu-deep-uninstaller-gui` (see the `WARNING` it prints).

## Build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j"$(nproc)"
```

Produces:
- `build/ubuntu-deep-uninstaller` — CLI
- `build/ubuntu-deep-uninstaller-gui` — GUI (if GTK4/libadwaita were found)
- `build/udu_tests` — test suite

## Test

```bash
ctest --test-dir build --output-on-failure
# or directly:
./build/udu_tests
```

All 12 tests in `tests/test_core.cpp` passed during development against
this exact source tree (see `DEVLOG.md`). If you're iterating on a
detector, add a fixture-based test alongside the existing ones rather than
testing destructively against your real system.

## Try it safely (read-only)

```bash
./build/ubuntu-deep-uninstaller --list-applications
./build/ubuntu-deep-uninstaller --inspect-desktop /usr/share/applications/<app>.desktop
./build/ubuntu-deep-uninstaller --dry-run /usr/share/applications/<app>.desktop
```

None of these modify anything. `--dry-run` runs the exact same detection
and planning code path that `--uninstall` would, so its output is a
reliable preview.

## Running from the terminal only, with logs, no GUI at all

The CLI is fully self-contained -- you never need the GUI to use this
tool:

```bash
# See every installed application and its desktop-file path:
ubuntu-deep-uninstaller --list-applications

# Preview what would happen (never touches anything):
UDU_DEBUG=1 ubuntu-deep-uninstaller --dry-run /usr/share/applications/<app>.desktop

# Actually uninstall (interactive: shows the plan, "Press ENTER to
# continue, or Ctrl+C to cancel", then removes with sudo prompts as needed):
UDU_DEBUG=1 ubuntu-deep-uninstaller --uninstall /usr/share/applications/<app>.desktop

# See what this tool has uninstalled previously:
ubuntu-deep-uninstaller --history
```

`UDU_DEBUG=1` is optional on every command -- add it any time you want the
full step-by-step subprocess trace described below.

**If tab-completion doesn't show `ubuntu-deep-uninstaller`:** this almost
always means one of two things, not a bug in the tool itself:
1. The binary isn't actually on your `$PATH`. Check with
   `which ubuntu-deep-uninstaller` -- if that prints nothing, `install.sh`
   either wasn't run or didn't complete; re-run it.
2. You're typing a prefix that doesn't match. The binary is named
   `ubuntu-deep-uninstaller` (starts with "u-b-u-n-t-u"), not
   "uninstaller" or "uni-something" -- typing `uni<Tab>` won't match it
   for the same reason `uni<Tab>` wouldn't match "banana". Try
   `ubuntu-d<Tab>` instead. A brand new terminal window/tab (not a
   desktop logout) is enough to pick up a binary installed since your
   shell started; you don't need to log out of GNOME for this specifically
   -- that's only needed for the GNOME Shell context-menu integration to
   notice new/changed `.desktop` files, which is a separate mechanism.

## Debugging a hang or a crash

If something gets stuck (a detection lookup that never finishes) or the
GUI disappears unexpectedly, two things will tell you exactly what
happened -- both work identically for the CLI and the GUI:

**1. Step-by-step tracing.** Set `UDU_DEBUG=1` and run from a terminal:

```bash
UDU_DEBUG=1 ./build/ubuntu-deep-uninstaller --dry-run /usr/share/applications/<app>.desktop
# or, for the GUI -- run it from a terminal (not by double-clicking the
# launcher) so you can see the output:
UDU_DEBUG=1 ./build/ubuntu-deep-uninstaller-gui
```

Every subprocess this tool spawns (`dpkg -S`, `dpkg-query`, `apt-mark`,
`apt-get remove --simulate`, `dpkg -L`, `flatpak`/`snap` calls, ...) logs a
timestamped line *before* it spawns and another *when it returns*,
including the exit code and how long it took. If something hangs, the log
simply stops after the last "about to spawn" line -- telling you exactly
which command is stuck, which you can then reproduce and investigate
directly (`dpkg -S <path>`, `apt-get remove --simulate -y <pkg>`, etc.).
Silent (zero overhead beyond one bool check) when `UDU_DEBUG` isn't set.

**2. Crash backtraces.** Both binaries install a signal handler (for
SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL) that prints the signal name, the
faulting address, and a real stack backtrace to stderr before the process
actually dies -- so a crash shows up as diagnostic text in your terminal
instead of a window just vanishing. Combine with `UDU_DEBUG=1` to see the
full sequence of steps leading up to the crash, not just where it landed.
Both the CLI and GUI CMake targets already link with `-rdynamic`, so a
crash's backtrace will include real function names, not just addresses.
For an even fuller trace (with source lines), run under `gdb`:

```bash
gdb --args ./build/ubuntu-deep-uninstaller-gui
(gdb) run
# ... reproduce the crash ...
(gdb) bt
```

## Install the GNOME context-menu integration for one app, or all apps

```bash
./build/ubuntu-deep-uninstaller --install-integration /usr/share/applications/<app>.desktop
./build/ubuntu-deep-uninstaller --sync-integration     # do it for every application at once
```

This writes user-local override files under
`~/.local/share/applications/` (never touching the originals under
`/usr/share/applications/`). Log out/in, or run `nautilus -q` /
`killall -3 gnome-shell` (X11 only; on Wayland, log out and back in) for
GNOME Shell to notice the new files, then right-click any integrated
application in the app grid.

## Build a `.deb`

This sandbox did not have `debhelper`/`dpkg-buildpackage` available to
actually produce and test a `.deb`, so treat this as the standard,
unverified recipe:

```bash
sudo apt install debhelper
dpkg-buildpackage -us -uc -b
```

from the project root (with `packaging/debian/` symlinked or copied to
`debian/` at the root, per standard Debian packaging layout — this
project currently keeps it under `packaging/debian/` to keep the source
tree's top level clean; move or symlink it to `./debian` before running
`dpkg-buildpackage`):

```bash
ln -s packaging/debian debian
dpkg-buildpackage -us -uc -b
```

## Known gaps to close next (see README's status table)

1. Compile-verify `src/gui/gui_main.cpp` on a real GTK4/libadwaita
   environment and fix whatever the compiler finds (some API surface,
   like `AdwAlertDialog`'s exact signal signature across libadwaita point
   releases, is worth double-checking against the installed version's
   headers).
2. Exercise the Flatpak/Snap detectors against real `flatpak`/`snap`
   installations (the logic that parses `Exec=` patterns doesn't need
   the tools present, but the `flatpak info`/`snap info` enrichment path
   does).
3. Run the full uninstall flow (not just `--dry-run`) against a
   disposable VM/container for each of the Test A–M scenarios from the
   original spec, and capture the transcripts the way `DEVLOG.md` does for
   the parts already exercised here.
4. Wire a `systemd --user` path unit (referenced as a placeholder in
   `packaging/debian/postinst`) so newly installed applications get the
   context-menu action automatically instead of requiring a manual
   `--sync-integration` run.

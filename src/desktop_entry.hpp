// desktop_entry.hpp
//
// Spec-correct(ish) parser for freedesktop.org Desktop Entry files,
// including the "Desktop Actions" extension used for right-click menu
// items (https://specifications.freedesktop.org/desktop-entry-spec/).
//
// This parser is deliberately narrow: it extracts exactly the keys this
// project needs (Name, Exec, TryExec, Icon, Path, Actions, and each
// [Desktop Action X] block) rather than being a general-purpose INI
// library. It preserves the raw file content so the integration layer can
// generate a minimally-diffed override file later.
#pragma once

#include <string>
#include <vector>
#include <optional>
#include <map>

namespace udu {

struct DesktopAction {
    std::string id;     // the "X" in [Desktop Action X]
    std::string name;
    std::string exec;
};

struct DesktopEntry {
    std::string source_path;      // where this file was read from
    std::string desktop_id;       // e.g. "org.example.Foo.desktop"
    std::string name;
    std::string exec;             // raw Exec= value, WITH field codes (%f, %U, ...) intact
    std::optional<std::string> try_exec;
    std::optional<std::string> icon;
    std::optional<std::string> working_dir;  // Path=
    std::string type;             // Type= (Application, Link, Directory)
    bool no_display = false;
    bool terminal = false;
    std::vector<std::string> existing_action_ids;  // from Actions= key, in order
    std::vector<DesktopAction> actions;
    std::string raw_content;      // full original file, for override generation

    // Returns exec with %-field-codes stripped (single-file-open codes
    // removed, %c/%k left as literal substitution points handled by the
    // caller). Detectors want the plain command + argv-ish string, not the
    // launcher field codes.
    [[nodiscard]] std::string exec_without_field_codes() const;
};

// Computes the desktop-file-ID for a path per the XDG spec: the path
// relative to the applications/ directory it lives under, with '/'
// replaced by '-'. E.g. /usr/share/applications/org/gnome/Foo.desktop ->
// "org-gnome-Foo.desktop". Falls back to the bare filename if the path
// doesn't appear to sit under a recognized applications directory.
std::string compute_desktop_id(const std::string& path);

// Parses a .desktop file from disk. Returns std::nullopt (never throws) on
// I/O failure or if the file lacks a [Desktop Entry] group -- callers must
// treat a parse failure as "cannot establish identity, do not proceed".
std::optional<DesktopEntry> parse_desktop_file(const std::string& path);

// Parses already-read file content (used by tests with fixture strings,
// and internally by parse_desktop_file).
std::optional<DesktopEntry> parse_desktop_content(const std::string& content,
                                                   const std::string& source_path_for_id);

}  // namespace udu

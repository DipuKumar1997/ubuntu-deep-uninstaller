// tests/test_core.cpp
//
// Deliberately dependency-free test runner (no network access is available
// in every build environment this project targets, so we don't pull in an
// external test framework). Each TEST(...) registers a function; main()
// runs them all and reports pass/fail counts with a non-zero exit code on
// any failure, so this is CI-friendly as-is.
#include <iostream>
#include <vector>
#include <functional>
#include <string>
#include <cassert>
#include <fstream>
#include <filesystem>

#include "../src/desktop_entry.hpp"
#include "../src/security/paths.hpp"
#include "../src/detector/common.hpp"
#include "../src/detector/detection_engine.hpp"
#include "../src/planner/removal_plan.hpp"

namespace fs = std::filesystem;

namespace {

struct TestCase { std::string name; std::function<void()> fn; };
std::vector<TestCase>& registry() {
    static std::vector<TestCase> r;
    return r;
}
struct Registrar {
    Registrar(std::string name, std::function<void()> fn) {
        registry().push_back({std::move(name), std::move(fn)});
    }
};
#define TEST(name) \
    void test_##name(); \
    Registrar registrar_##name(#name, test_##name); \
    void test_##name()

void expect(bool cond, const std::string& msg) {
    if (!cond) throw std::runtime_error("FAILED: " + msg);
}

std::string write_temp_file(const std::string& dir, const std::string& name, const std::string& content) {
    fs::create_directories(dir);
    std::string path = dir + "/" + name;
    std::ofstream f(path);
    f << content;
    return path;
}

const std::string kTestRoot = "/tmp/udu_unit_test_fixtures";

}  // namespace

// ---------------------------------------------------------------------
// Desktop entry parsing
// ---------------------------------------------------------------------

TEST(parses_basic_desktop_entry) {
    auto path = write_temp_file(kTestRoot, "basic.desktop",
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=Test App\n"
        "Exec=/usr/bin/testapp --flag %U\n"
        "Icon=testapp\n");
    auto entry = udu::parse_desktop_file(path);
    expect(entry.has_value(), "expected a parsed entry");
    expect(entry->name == "Test App", "name mismatch: " + entry->name);
    expect(entry->exec == "/usr/bin/testapp --flag %U", "exec mismatch");
    expect(entry->exec_without_field_codes() == "/usr/bin/testapp --flag",
           "field-code stripping failed: '" + entry->exec_without_field_codes() + "'");
}

TEST(malformed_desktop_file_without_group_header_fails_to_parse) {
    auto path = write_temp_file(kTestRoot, "malformed.desktop",
        "Name=No Group Header\nExec=/bin/true\n");
    auto entry = udu::parse_desktop_file(path);
    expect(!entry.has_value(), "malformed file (no [Desktop Entry] group) must not parse");
}

TEST(missing_file_fails_to_parse_rather_than_throwing) {
    auto entry = udu::parse_desktop_file("/tmp/udu_unit_test_fixtures/does_not_exist.desktop");
    expect(!entry.has_value(), "nonexistent file must yield nullopt, not throw");
}

TEST(desktop_actions_are_parsed) {
    auto path = write_temp_file(kTestRoot, "actions.desktop",
        "[Desktop Entry]\n"
        "Type=Application\nName=Shutter\nExec=shutter\nActions=Redo;Select;\n\n"
        "[Desktop Action Redo]\nName=Redo last screenshot\nExec=shutter --redo\n\n"
        "[Desktop Action Select]\nName=Capture an area\nExec=shutter --select\n");
    auto entry = udu::parse_desktop_file(path);
    expect(entry.has_value(), "expected parse success");
    expect(entry->existing_action_ids.size() == 2, "expected 2 action ids");
    expect(entry->actions.size() == 2, "expected 2 parsed action blocks");
    expect(entry->actions[0].id == "Redo", "first action id mismatch");
    expect(entry->actions[0].exec == "shutter --redo", "first action exec mismatch");
}

TEST(locale_suffixed_keys_are_ignored_in_favor_of_default) {
    auto path = write_temp_file(kTestRoot, "locale.desktop",
        "[Desktop Entry]\nType=Application\nName=Default Name\nName[de]=Deutscher Name\n"
        "Exec=/bin/true\n");
    auto entry = udu::parse_desktop_file(path);
    expect(entry.has_value(), "expected parse success");
    expect(entry->name == "Default Name", "locale-suffixed key leaked into default Name: " + entry->name);
}

// ---------------------------------------------------------------------
// Security / path validation backstops
// ---------------------------------------------------------------------

TEST(catastrophic_paths_are_always_refused_even_as_their_own_root) {
    auto v = udu::security::validate_removal_target("/etc", {"/etc"});
    expect(!v.safe_to_remove, "/etc must never validate as a removal target");
    auto v2 = udu::security::validate_removal_target("/", {"/"});
    expect(!v2.safe_to_remove, "/ must never validate as a removal target");
    auto v3 = udu::security::validate_removal_target("/home/someuser", {"/home/someuser"});
    expect(!v3.safe_to_remove, "a bare /home/<user> directory must never validate");
}

TEST(symlink_escaping_allowed_root_is_refused) {
    fs::create_directories(kTestRoot + "/app_dir");
    fs::create_directories(kTestRoot + "/outside_target");
    std::string link = kTestRoot + "/app_dir/escape_link";
    std::error_code ec;
    fs::remove(link, ec);
    fs::create_symlink(kTestRoot + "/outside_target", link, ec);
    expect(!ec, "test setup: failed to create symlink");

    // Even though the symlink physically resides inside the allowed root,
    // it resolves (canonicalizes) to a path OUTSIDE that root, and must be
    // refused.
    auto v = udu::security::validate_removal_target(link, {kTestRoot + "/app_dir"});
    expect(!v.safe_to_remove, "a symlink resolving outside the allowed root must be refused");
}

TEST(path_legitimately_under_allowed_root_validates) {
    fs::create_directories(kTestRoot + "/legit_app/subdir");
    auto v = udu::security::validate_removal_target(kTestRoot + "/legit_app/subdir",
                                                      {kTestRoot + "/legit_app"});
    expect(v.safe_to_remove, "a real subdirectory of an allowed root should validate: " + v.reason);
}

TEST(nonexistent_path_is_refused_rather_than_guessed) {
    auto v = udu::security::validate_removal_target(kTestRoot + "/does/not/exist",
                                                      {kTestRoot});
    expect(!v.safe_to_remove, "a nonexistent path must never validate as safe to remove");
}

// ---------------------------------------------------------------------
// Detection engine (fixture-based, no real package managers required)
// ---------------------------------------------------------------------

TEST(appimage_detected_from_exec_pattern) {
    fs::create_directories(kTestRoot + "/appimg");
    std::string appimage_path = kTestRoot + "/appimg/Fake.AppImage";
    { std::ofstream f(appimage_path); f << "fake"; }
    auto path = write_temp_file(kTestRoot, "fakeappimage.desktop",
        "[Desktop Entry]\nType=Application\nName=Fake\nExec=" + appimage_path + " %U\n");
    auto entry = udu::parse_desktop_file(path);
    expect(entry.has_value(), "expected parse success");
    auto detection = udu::detector::run_detection(*entry);
    expect(detection.source == udu::detector::InstallationSource::AppImage,
           "expected AppImage source, got " + std::string(to_string(detection.source)));
    expect(detection.overall_confidence == udu::detector::Confidence::High, "expected High confidence");
}

TEST(unresolvable_exec_yields_low_confidence_unknown_with_only_desktop_entry_removable) {
    auto path = write_temp_file(kTestRoot, "ghost.desktop",
        "[Desktop Entry]\nType=Application\nName=Ghost\nExec=/this/path/does/not/exist/ghost\n");
    auto entry = udu::parse_desktop_file(path);
    expect(entry.has_value(), "expected parse success");
    auto detection = udu::detector::run_detection(*entry);
    expect(detection.resources.empty(), "an unresolvable exec must not produce any resource "
                                         "beyond what the planner adds for the desktop entry itself");
    auto plan = udu::planner::build_plan(*entry, detection);
    expect(plan.resources.size() == 1, "plan should only contain the desktop entry itself");
    expect(plan.resources[0].type == udu::detector::ResourceType::DesktopEntry,
           "the sole plan resource should be the desktop entry");
}

TEST(wine_shared_prefix_protects_prefix_root_from_removal) {
    // Build a fake HOME with two .desktop files sharing one WINEPREFIX,
    // both under ~/.local/share/applications so the shared-prefix scan
    // (which only looks in standard locations) can see them.
    std::string fake_home = kTestRoot + "/fake_home_shared";
    std::string apps_dir = fake_home + "/.local/share/applications";
    fs::create_directories(apps_dir);
    std::string prefix = fake_home + "/.wine";
    fs::create_directories(prefix + "/drive_c/Program Files/AppOne");
    fs::create_directories(prefix + "/drive_c/Program Files/AppTwo");
    { std::ofstream f(prefix + "/system.reg"); f << "fake"; }

    setenv("HOME", fake_home.c_str(), 1);

    write_temp_file(apps_dir, "app_two.desktop",
        "[Desktop Entry]\nType=Application\nName=App Two\n"
        "Exec=env WINEPREFIX=\"" + prefix + "\" wine \"C:\\\\Program Files\\\\AppTwo\\\\two.exe\"\n");
    auto path_one = write_temp_file(apps_dir, "app_one.desktop",
        "[Desktop Entry]\nType=Application\nName=App One\n"
        "Exec=env WINEPREFIX=\"" + prefix + "\" wine \"C:\\\\Program Files\\\\AppOne\\\\one.exe\"\n");

    auto entry_one = udu::parse_desktop_file(path_one);
    expect(entry_one.has_value(), "expected parse success");
    auto detection = udu::detector::run_detection(*entry_one);
    expect(detection.source == udu::detector::InstallationSource::Wine, "expected Wine source");
    expect(detection.wine_prefix_is_shared, "prefix should be detected as shared (App Two also uses it)");

    bool prefix_root_marked_skip = false;
    for (const auto& r : detection.resources) {
        if (r.path == fs::weakly_canonical(prefix).string() || r.path == prefix) {
            prefix_root_marked_skip = (r.recommended_action == udu::detector::PlannedAction::SkipShared);
        }
    }
    expect(prefix_root_marked_skip, "the shared prefix root itself must be recommended SkipShared, "
                                     "not offered for removal");
}

// ---------------------------------------------------------------------

int main() {
    int passed = 0, failed = 0;
    for (auto& t : registry()) {
        try {
            t.fn();
            std::cout << "[PASS] " << t.name << "\n";
            ++passed;
        } catch (const std::exception& e) {
            std::cout << "[FAIL] " << t.name << " -- " << e.what() << "\n";
            ++failed;
        }
    }
    std::cout << "\n" << passed << " passed, " << failed << " failed\n";
    return failed == 0 ? 0 : 1;
}

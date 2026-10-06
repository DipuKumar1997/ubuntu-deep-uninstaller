cmake_minimum_required(VERSION 3.25)
project(ubuntu-deep-uninstaller LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# udu_core uses std::async/std::thread internally (apt_detector.cpp
# parallelizes independent dpkg/apt subprocess calls) -- every target
# linking against it needs pthread.
find_package(Threads REQUIRED)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

add_compile_options(-Wall -Wextra)

# ---------------------------------------------------------------------
# Core library: detection, planning, execution, verification, security,
# terminal reporting, GNOME integration. No GUI dependency at all -- this
# is what both the CLI and the GTK4 GUI link against.
# ---------------------------------------------------------------------
add_library(udu_core STATIC
    src/desktop_entry.cpp
    src/security/proc_exec.cpp
    src/security/crash_handler.cpp
    src/security/paths.cpp
    src/detector/common.cpp
    src/detector/apt_detector.cpp
    src/detector/flatpak_detector.cpp
    src/detector/snap_detector.cpp
    src/detector/wine_detector.cpp
    src/detector/appimage_detector.cpp
    src/detector/manual_detector.cpp
    src/detector/portable_app_finding.cpp
    src/detector/detection_engine.cpp
    src/planner/removal_plan.cpp
    src/planner/plan_cache.cpp
    src/verification/verify.cpp
    src/terminal/report.cpp
    src/terminal/launcher.cpp
    src/uninstall/executor.cpp
    src/uninstall/history.cpp
    src/integration/desktop_override.cpp
)
target_include_directories(udu_core PUBLIC src)
target_link_libraries(udu_core PUBLIC Threads::Threads)

# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------
add_executable(ubuntu-deep-uninstaller src/main.cpp)
target_link_libraries(ubuntu-deep-uninstaller PRIVATE udu_core)
# -rdynamic: keeps enough symbol info in the binary for
# crash_handler.cpp's backtrace_symbols_fd() to print real function names
# instead of bare addresses when something crashes.
target_link_options(ubuntu-deep-uninstaller PRIVATE -rdynamic)

# ---------------------------------------------------------------------
# GUI (optional): only built if GTK4 + libadwaita dev packages are found.
# On a system missing them, configure still succeeds and just skips this
# target with a clear message -- the CLI and integration are fully usable
# without it.
# ---------------------------------------------------------------------
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(GTK4 QUIET gtk4>=4.14)
    pkg_check_modules(ADWAITA QUIET libadwaita-1>=1.5)
endif()

if(GTK4_FOUND AND ADWAITA_FOUND)
    find_package(Threads REQUIRED)
    add_executable(ubuntu-deep-uninstaller-gui src/gui/gui_main.cpp)
    target_link_libraries(ubuntu-deep-uninstaller-gui PRIVATE udu_core
        ${GTK4_LIBRARIES} ${ADWAITA_LIBRARIES} Threads::Threads)
    target_include_directories(ubuntu-deep-uninstaller-gui PRIVATE
        ${GTK4_INCLUDE_DIRS} ${ADWAITA_INCLUDE_DIRS})
    target_compile_options(ubuntu-deep-uninstaller-gui PRIVATE
        ${GTK4_CFLAGS_OTHER} ${ADWAITA_CFLAGS_OTHER})
    target_link_directories(ubuntu-deep-uninstaller-gui PRIVATE
        ${GTK4_LIBRARY_DIRS} ${ADWAITA_LIBRARY_DIRS})
    target_link_options(ubuntu-deep-uninstaller-gui PRIVATE -rdynamic)
    message(STATUS "GTK4 + libadwaita found -- building ubuntu-deep-uninstaller-gui")
else()
    message(WARNING "GTK4 (>=4.14) and/or libadwaita-1 (>=1.5) development packages were not "
                     "found (apt install libgtk-4-dev libadwaita-1-dev). Skipping the GUI target; "
                     "the CLI (ubuntu-deep-uninstaller) is still fully built and usable.")
endif()

# ---------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------
enable_testing()
add_executable(udu_tests tests/test_core.cpp)
target_link_libraries(udu_tests PRIVATE udu_core)
target_include_directories(udu_tests PRIVATE src)
add_test(NAME udu_core_tests COMMAND udu_tests)

# ---------------------------------------------------------------------
# Install rules (used by packaging/debian/rules)
# ---------------------------------------------------------------------
include(GNUInstallDirs)
install(TARGETS ubuntu-deep-uninstaller RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
if(TARGET ubuntu-deep-uninstaller-gui)
    install(TARGETS ubuntu-deep-uninstaller-gui RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
install(FILES packaging/org.uduninstaller.UbuntuDeepUninstaller.desktop
        DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)

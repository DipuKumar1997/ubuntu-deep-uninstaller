// planner/plan_cache.hpp
//
// The GUI already computes a full RemovalPlan to show in its detail pane
// the moment an application is selected. Without this, clicking
// "Uninstall Completely" opened a brand new terminal process that threw
// that work away and ran detection all over again from scratch -- the
// exact "why does it scan twice" complaint. This module lets the GUI
// persist the plan it just computed, keyed to the desktop file it's for,
// so the terminal-launched CLI invocation can load and reuse it directly.
//
// Deliberately a single-slot cache (one file, always overwritten): the
// GUI only ever has one application selected at a time, and the
// dry-run/uninstall buttons are disabled while a detection is in flight
// (see gui_main.cpp's update_detail_pane), so by the time either button
// is clickable, the cached plan is guaranteed to match what's on screen.
#pragma once

#include <optional>
#include <string>
#include "removal_plan.hpp"

namespace udu::planner {

// Overwrites the single cache slot with `plan`. Best-effort: a failure to
// write never blocks the GUI from showing the plan or launching the
// terminal -- it just means that terminal invocation falls back to
// running detection itself, exactly as if this cache didn't exist.
void save_plan_cache(const RemovalPlan& plan);

// Loads the cached plan IF AND ONLY IF it was computed for exactly
// `desktop_path` and is still fresh (written within the last few
// minutes -- see the .cpp file for the exact window). Returns
// std::nullopt on any mismatch, staleness, missing file, or parse
// failure; callers must treat that as "no cache, do a normal detection
// run" rather than an error.
std::optional<RemovalPlan> load_plan_cache_if_fresh(const std::string& desktop_path);

}  // namespace udu::planner

// verification/verify.hpp
//
// Re-checks, after execution, whether each planned resource is actually
// gone -- and re-runs the package-manager / process checks so the final
// report reflects reality rather than assuming the plan succeeded.
#pragma once

#include <string>
#include <vector>
#include "../planner/removal_plan.hpp"

namespace udu::verification {

enum class ItemStatus { Removed, StillPresent, NotApplicableSkipped, CouldNotVerify };

struct VerificationItem {
    std::string label;
    ItemStatus status;
    std::string detail;
};

struct VerificationReport {
    std::vector<VerificationItem> items;
    bool process_still_running = false;
    [[nodiscard]] bool all_clear() const;
};

VerificationReport verify(const planner::RemovalPlan& plan);

}  // namespace udu::verification

#ifndef FIRMWARE_COMPONENTS_ZEROTRUST_SRC_GATE_COMMON_H
#define FIRMWARE_COMPONENTS_ZEROTRUST_SRC_GATE_COMMON_H

#include <cstdint>

#include "esp_err.h"

#include "policy_types.h"
#include "system_controller.h"

namespace zerotrust::internal {

// Identity context stored per-task in FreeRTOS TLS slot 0.
// Set exclusively by ContextGuard at verified library entry points.
// Never set by user code.
struct TrustedContext {
    zerotrust::policy::PolicyActor  actor;
    zerotrust::policy::PolicyOrigin origin;
    zerotrust::policy::PolicyIntent intent;
};

// RAII guard: installs TrustedContext into the current task's TLS on construction
// and clears it (sets actor=Unknown) on destruction.
//
// Used ONLY at verified library entry points:
//   - Backend receive callback (after authentication)
//   - ISR gate task (deferred from ISR queue)
//   - System lifecycle tasks (boot orchestration)
//
// Never instantiated in user-facing code.
class ContextGuard {
public:
    ContextGuard(zerotrust::policy::PolicyActor  actor,
                 zerotrust::policy::PolicyOrigin origin,
                 zerotrust::policy::PolicyIntent intent);
    ~ContextGuard();

    // Copy / Move not allowed
    ContextGuard(const ContextGuard&) = delete;
    ContextGuard(ContextGuard&&) = delete;
    ContextGuard& operator=(const ContextGuard&) = delete;
    ContextGuard& operator=(ContextGuard&&) = delete;

private:
    TrustedContext ctx_;
};

// Returns the TrustedContext installed in the current task's TLS.
// Returns {Unknown, Local, NormalOperation} if no ContextGuard is active.
TrustedContext get_current_context();

// Store pointer to the SystemController so gate_check() can call authorize_action().
// Called once by ztg_init() after subsystems are initialized.
void set_gate_controller(zerotrust::system_controller::SystemController* controller);

// Single entry point for all ztg_* wrappers.
// Steps:
//   1. Read TrustedContext from current task TLS
//   2. Return ESP_ERR_NOT_ALLOWED immediately if actor == Unknown
//   3. Build PolicyContext from context + resource_id + FSM state
//   4. Call authorize_action() and return result
// Returns ESP_OK if allowed, ESP_ERR_NOT_ALLOWED if denied.
esp_err_t gate_check(zerotrust::policy::PolicyAction action, uint16_t resource_id);

} // namespace zerotrust::internal

#endif // FIRMWARE_COMPONENTS_ZEROTRUST_SRC_GATE_COMMON_H

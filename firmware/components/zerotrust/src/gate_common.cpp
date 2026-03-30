#include "gate_common.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "policy_types.h"
#include "system_controller.h"

namespace {

// FreeRTOS TLS slot used to store TrustedContext* for the current task.
// Slot 0 is reserved by this library.
static constexpr UBaseType_t TlsSlot = 0;

static zerotrust::system_controller::SystemController* sys_controller = nullptr;

} // namespace

namespace zerotrust::internal {

ContextGuard::ContextGuard(zerotrust::policy::PolicyActor  actor,
                           zerotrust::policy::PolicyOrigin origin,
                           zerotrust::policy::PolicyIntent intent)
    : ctx_{actor, origin, intent} {
    vTaskSetThreadLocalStoragePointer(nullptr, TlsSlot, &ctx_);
}

ContextGuard::~ContextGuard() {
    vTaskSetThreadLocalStoragePointer(nullptr, TlsSlot, nullptr);
}

TrustedContext get_current_context() {
    void* ptr = pvTaskGetThreadLocalStoragePointer(nullptr, TlsSlot);
    if (ptr == nullptr) {
        return TrustedContext{
            zerotrust::policy::PolicyActor::Unknown,
            zerotrust::policy::PolicyOrigin::Local,
            zerotrust::policy::PolicyIntent::NormalOperation,
        };
    }
    return *static_cast<TrustedContext*>(ptr);
}

void set_gate_controller(zerotrust::system_controller::SystemController* controller) {
    sys_controller = controller;
}

esp_err_t gate_check(zerotrust::policy::PolicyAction action, uint16_t resource_id) {
    // Step 1: Read context from TLS
    TrustedContext ctx = get_current_context();

    // Step 2: Deny immediately if actor is Unknown - no context guard is active
    if (ctx.actor == zerotrust::policy::PolicyActor::Unknown) {
        return ESP_ERR_NOT_ALLOWED;
    }

    // Step 3: Controller must be initialized (ztg_init called)
    if (sys_controller == nullptr) {
        return ESP_ERR_NOT_ALLOWED;
    }

    // Step 4: Build PolicyContext and authorize
    zerotrust::policy::PolicyContext policy_ctx{};
    policy_ctx.state             = sys_controller->get_state();
    policy_ctx.actor             = ctx.actor;
    policy_ctx.origin            = ctx.origin;
    policy_ctx.intent            = ctx.intent;
    policy_ctx.resource_id       = resource_id;
    policy_ctx.backend_connected = sys_controller->is_backend_connected();

    zerotrust::policy::PolicyDecision decision =
        sys_controller->authorize_action(action, policy_ctx);

    return (decision == zerotrust::policy::PolicyDecision::Allow) ? ESP_OK : ESP_ERR_NOT_ALLOWED;
}

} // namespace zerotrust::internal

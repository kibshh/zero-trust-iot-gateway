#include "zerotrust.h"

#include "resource_registry.h"
#include "gate_common.h"

// TODO: Boot orchestration extracted from main.cpp goes here in Phase 2.
// ztg_init() initializes all subsystems and calls set_gate_controller().
// ztg_start() runs the full boot sequence (Wi-Fi, identity, attest, authorize, policy).

namespace zerotrust {

esp_err_t ztg_init() {
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t ztg_start() {
    zerotrust::internal::close_registration();
    return ESP_ERR_NOT_SUPPORTED;
}

zerotrust::system_state::SystemState ztg_get_state() {
    return zerotrust::system_state::SystemState::Init;
}

bool ztg_is_operational() {
    return false;
}

} // namespace zerotrust

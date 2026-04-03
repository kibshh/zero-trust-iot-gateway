#ifndef FIRMWARE_COMPONENTS_ZEROTRUST_INCLUDE_ZEROTRUST_H
#define FIRMWARE_COMPONENTS_ZEROTRUST_INCLUDE_ZEROTRUST_H

#include "esp_err.h"

#include "system_state.h"

namespace zerotrust {

// Initialize the library: validate Kconfig, open NVS, initialize subsystems.
// All configuration (backend URL, public key, WiFi, provisioning) comes from
// Kconfig and NVS. Must be called after all ztg_register_*() calls and
// before ztg_start(). Returns ESP_OK on success.
esp_err_t ztg_init();

// Run the full boot sequence (Wi-Fi connect, identity, time sync, register,
// attest, authorize, load policy). Blocks until Operational state is reached
// or a terminal failure occurs (Locked/Revoked).
// Returns ESP_OK if Operational, ESP_FAIL otherwise.
esp_err_t ztg_start();

// Returns the current FSM state.
zerotrust::system_state::SystemState ztg_get_state();

// Returns true if the device is in Operational state.
bool ztg_is_operational();

} // namespace zerotrust

#endif // FIRMWARE_COMPONENTS_ZEROTRUST_INCLUDE_ZEROTRUST_H

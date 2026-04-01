#ifndef FIRMWARE_COMPONENTS_ZEROTRUST_INCLUDE_ZTG_SYSTEM_H
#define FIRMWARE_COMPONENTS_ZEROTRUST_INCLUDE_ZTG_SYSTEM_H

#include <cstddef>

#include "esp_err.h"

namespace zerotrust {

// Policy-enforced system reboot.
// Reads TrustedContext from current task, authorizes (SystemReboot).
// Does not return on allow. Returns ESP_ERR_NOT_ALLOWED if denied,
// ESP_ERR_NOT_FOUND if system resource is not registered.
esp_err_t ztg_system_reboot();

// Policy-enforced system sleep (light sleep).
// Reads TrustedContext from current task, authorizes (SystemSleep).
// Returns ESP_OK on wakeup, ESP_ERR_NOT_ALLOWED if denied,
// ESP_ERR_NOT_FOUND if system resource is not registered.
esp_err_t ztg_system_sleep();

// Policy-enforced OTA begin.
// Reads TrustedContext from current task, authorizes (FirmwareUpdate).
// image_size - size of the firmware image to be written.
// Returns ESP_OK on success, ESP_ERR_NOT_ALLOWED if denied,
// ESP_ERR_NOT_FOUND if system resource is not registered.
esp_err_t ztg_ota_begin(size_t image_size);

// Factory reset: wipes identity, keys, and policy from NVS, then reboots.
// Transitions FSM to Init state. Does not require policy authorization — intended
// for physical recovery only. Call only from a physically trusted entry point.
void ztg_factory_reset();

} // namespace zerotrust

#endif // FIRMWARE_COMPONENTS_ZEROTRUST_INCLUDE_ZTG_SYSTEM_H

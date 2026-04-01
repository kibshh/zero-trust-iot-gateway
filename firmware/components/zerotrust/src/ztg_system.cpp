#include "ztg_system.h"

#include "gate_common.h"
#include "resource_registry.h"
#include "policy_types.h"

// TODO: implement system wrappers (delegate to esp_restart / esp_light_sleep_start / esp_ota_begin).
// TODO: implement ztg_factory_reset (wipe identity/keys/policy NVS namespaces then reboot).

namespace zerotrust {

esp_err_t ztg_system_reboot() {
    uint16_t resource_id = zerotrust::internal::lookup_system();
    if (resource_id == 0) {
        return ESP_ERR_NOT_FOUND;
    }
    esp_err_t auth = zerotrust::internal::gate_check(
        zerotrust::policy::PolicyAction::SystemReboot, resource_id);
    if (auth != ESP_OK) {
        return auth;
    }
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t ztg_system_sleep() {
    uint16_t resource_id = zerotrust::internal::lookup_system();
    if (resource_id == 0) {
        return ESP_ERR_NOT_FOUND;
    }
    esp_err_t auth = zerotrust::internal::gate_check(
        zerotrust::policy::PolicyAction::SystemSleep, resource_id);
    if (auth != ESP_OK) {
        return auth;
    }
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t ztg_ota_begin(size_t image_size) {
    uint16_t resource_id = zerotrust::internal::lookup_system();
    if (resource_id == 0) {
        return ESP_ERR_NOT_FOUND;
    }
    esp_err_t auth = zerotrust::internal::gate_check(
        zerotrust::policy::PolicyAction::FirmwareUpdate, resource_id);
    if (auth != ESP_OK) {
        return auth;
    }
    (void)image_size;
    return ESP_ERR_NOT_SUPPORTED;
}

void ztg_factory_reset() {
    // TODO: erase identity, keys, and policy from NVS, then call esp_restart()
}

} // namespace zerotrust

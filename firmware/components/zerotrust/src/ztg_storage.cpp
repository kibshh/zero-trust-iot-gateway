#include "ztg_storage.h"

#include <cstddef>

#include "gate_common.h"
#include "resource_registry.h"
#include "policy_types.h"

// TODO: implement storage wrappers (delegate to nvs_get_blob / nvs_set_blob / nvs_erase_all).

namespace zerotrust {

esp_err_t ztg_storage_read(const char* ns, const char* key, void* buf, size_t* len) {
    uint16_t resource_id = zerotrust::internal::lookup_storage(ns);
    if (resource_id == 0) {
        return ESP_ERR_NOT_FOUND;
    }
    esp_err_t auth = zerotrust::internal::gate_check(
        zerotrust::policy::PolicyAction::StorageRead, resource_id);
    if (auth != ESP_OK) {
        return auth;
    }
    (void)key;
    (void)buf;
    (void)len;
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t ztg_storage_write(const char* ns, const char* key, const void* val, size_t len) {
    uint16_t resource_id = zerotrust::internal::lookup_storage(ns);
    if (resource_id == 0) {
        return ESP_ERR_NOT_FOUND;
    }
    esp_err_t auth = zerotrust::internal::gate_check(
        zerotrust::policy::PolicyAction::StorageWrite, resource_id);
    if (auth != ESP_OK) {
        return auth;
    }
    (void)key;
    (void)val;
    (void)len;
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t ztg_storage_erase(const char* ns) {
    uint16_t resource_id = zerotrust::internal::lookup_storage(ns);
    if (resource_id == 0) {
        return ESP_ERR_NOT_FOUND;
    }
    esp_err_t auth = zerotrust::internal::gate_check(
        zerotrust::policy::PolicyAction::StorageErase, resource_id);
    if (auth != ESP_OK) {
        return auth;
    }
    return ESP_ERR_NOT_SUPPORTED;
}

} // namespace zerotrust

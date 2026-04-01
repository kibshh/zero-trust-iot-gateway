#ifndef FIRMWARE_COMPONENTS_ZEROTRUST_INCLUDE_ZTG_STORAGE_H
#define FIRMWARE_COMPONENTS_ZEROTRUST_INCLUDE_ZTG_STORAGE_H

#include <cstddef>

#include "esp_err.h"

namespace zerotrust {

// Policy-enforced NVS read.
// Looks up resource_id for ns, reads TrustedContext from current task,
// authorizes (StorageRead), and reads from NVS on allow.
// len is in/out: pass buffer size, receives bytes written.
// Returns ESP_OK on success, ESP_ERR_NOT_ALLOWED if denied,
// ESP_ERR_NOT_FOUND if ns is not registered.
esp_err_t ztg_storage_read(const char* ns, const char* key, void* buf, size_t* len);

// Policy-enforced NVS write.
// Looks up resource_id for ns, reads TrustedContext from current task,
// authorizes (StorageWrite), and writes to NVS on allow.
// Returns ESP_OK on success, ESP_ERR_NOT_ALLOWED if denied,
// ESP_ERR_NOT_FOUND if ns is not registered.
esp_err_t ztg_storage_write(const char* ns, const char* key, const void* val, size_t len);

// Policy-enforced NVS namespace erase.
// Looks up resource_id for ns, reads TrustedContext from current task,
// authorizes (StorageErase), and erases the namespace on allow.
// Returns ESP_OK on success, ESP_ERR_NOT_ALLOWED if denied,
// ESP_ERR_NOT_FOUND if ns is not registered.
esp_err_t ztg_storage_erase(const char* ns);

} // namespace zerotrust

#endif // FIRMWARE_COMPONENTS_ZEROTRUST_INCLUDE_ZTG_STORAGE_H

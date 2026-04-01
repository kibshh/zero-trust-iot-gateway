#ifndef FIRMWARE_COMPONENTS_ZEROTRUST_INCLUDE_ZTG_NETWORK_H
#define FIRMWARE_COMPONENTS_ZEROTRUST_INCLUDE_ZTG_NETWORK_H

#include <cstddef>
#include <cstdint>

#include "esp_err.h"

namespace zerotrust {

// Policy-enforced network connect.
// Looks up resource_id for handle, reads TrustedContext from current task,
// authorizes (NetworkConnect), and initiates connection on allow.
// Returns ESP_OK on success, ESP_ERR_NOT_ALLOWED if denied,
// ESP_ERR_NOT_FOUND if handle is not registered.
esp_err_t ztg_network_connect(uint16_t handle);

// Policy-enforced network send.
// Looks up resource_id for handle, reads TrustedContext from current task,
// authorizes (NetworkSend), and sends data on allow.
// Returns ESP_OK on success, ESP_ERR_NOT_ALLOWED if denied,
// ESP_ERR_NOT_FOUND if handle is not registered.
esp_err_t ztg_network_send(uint16_t handle, const uint8_t* data, size_t len);

// Policy-enforced network receive (blocking).
// Looks up resource_id for handle, reads TrustedContext from current task,
// authorizes (NetworkReceive), and reads data on allow.
// Returns ESP_OK on success, ESP_ERR_NOT_ALLOWED if denied,
// ESP_ERR_NOT_FOUND if handle is not registered.
esp_err_t ztg_network_receive(uint16_t handle, uint8_t* buf, size_t max_len);

// Register a callback for incoming data on handle.
// The library's internal receive path verifies the source, then sets
// actor=Backend/origin=Network context and authorizes (NetworkReceive)
// before invoking handler. Unverified sources are never delivered.
// Returns ESP_OK on success, ESP_ERR_NOT_FOUND if handle is not registered.
esp_err_t ztg_network_on_receive(uint16_t handle,
                                 void (*handler)(const uint8_t* data, size_t len, void* ctx),
                                 void* ctx);

} // namespace zerotrust

#endif // FIRMWARE_COMPONENTS_ZEROTRUST_INCLUDE_ZTG_NETWORK_H

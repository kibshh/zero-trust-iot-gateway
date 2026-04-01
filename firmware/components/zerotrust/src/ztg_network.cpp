#include "ztg_network.h"

#include "gate_common.h"
#include "resource_registry.h"
#include "policy_types.h"

// TODO: implement network wrappers using backend_client or esp_http_client.
// TODO: implement ztg_network_on_receive with authenticated source verification
//       before setting ContextGuard(Backend, Network, NormalOperation).

namespace zerotrust {

esp_err_t ztg_network_connect(uint16_t handle) {
    uint16_t resource_id = zerotrust::internal::lookup_network(handle);
    if (resource_id == 0) {
        return ESP_ERR_NOT_FOUND;
    }
    esp_err_t auth = zerotrust::internal::gate_check(
        zerotrust::policy::PolicyAction::NetworkConnect, resource_id);
    if (auth != ESP_OK) {
        return auth;
    }
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t ztg_network_send(uint16_t handle, const uint8_t* data, size_t len) {
    uint16_t resource_id = zerotrust::internal::lookup_network(handle);
    if (resource_id == 0) {
        return ESP_ERR_NOT_FOUND;
    }
    esp_err_t auth = zerotrust::internal::gate_check(
        zerotrust::policy::PolicyAction::NetworkSend, resource_id);
    if (auth != ESP_OK) {
        return auth;
    }
    (void)data;
    (void)len;
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t ztg_network_receive(uint16_t handle, uint8_t* buf, size_t max_len) {
    uint16_t resource_id = zerotrust::internal::lookup_network(handle);
    if (resource_id == 0) {
        return ESP_ERR_NOT_FOUND;
    }
    esp_err_t auth = zerotrust::internal::gate_check(
        zerotrust::policy::PolicyAction::NetworkReceive, resource_id);
    if (auth != ESP_OK) {
        return auth;
    }
    (void)buf;
    (void)max_len;
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t ztg_network_on_receive(uint16_t handle,
                                 void (*handler)(const uint8_t* data, size_t len, void* ctx),
                                 void* ctx) {
    uint16_t resource_id = zerotrust::internal::lookup_network(handle);
    if (resource_id == 0) {
        return ESP_ERR_NOT_FOUND;
    }
    (void)handler;
    (void)ctx;
    return ESP_ERR_NOT_SUPPORTED;
}

} // namespace zerotrust

#include "ztg_uart.h"

#include "gate_common.h"
#include "resource_registry.h"
#include "policy_types.h"

// TODO: implement UART wrappers (delegate to uart_write_bytes / uart_read_bytes).

namespace zerotrust {

esp_err_t ztg_uart_write(uart_port_t port, const uint8_t* data, size_t len) {
    uint16_t resource_id = zerotrust::internal::lookup_uart(port);
    if (resource_id == 0) {
        return ESP_ERR_NOT_FOUND;
    }
    esp_err_t auth = zerotrust::internal::gate_check(
        zerotrust::policy::PolicyAction::UartWrite, resource_id);
    if (auth != ESP_OK) {
        return auth;
    }
    (void)data;
    (void)len;
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t ztg_uart_read(uart_port_t port, uint8_t* buf, size_t len, uint32_t timeout_ms) {
    uint16_t resource_id = zerotrust::internal::lookup_uart(port);
    if (resource_id == 0) {
        return ESP_ERR_NOT_FOUND;
    }
    esp_err_t auth = zerotrust::internal::gate_check(
        zerotrust::policy::PolicyAction::UartRead, resource_id);
    if (auth != ESP_OK) {
        return auth;
    }
    (void)buf;
    (void)len;
    (void)timeout_ms;
    return ESP_ERR_NOT_SUPPORTED;
}

} // namespace zerotrust

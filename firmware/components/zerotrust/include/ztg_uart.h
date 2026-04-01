#ifndef FIRMWARE_COMPONENTS_ZEROTRUST_INCLUDE_ZTG_UART_H
#define FIRMWARE_COMPONENTS_ZEROTRUST_INCLUDE_ZTG_UART_H

#include <cstddef>
#include <cstdint>

#include "esp_err.h"
#include "driver/uart.h"

namespace zerotrust {

// Policy-enforced UART write.
// Looks up resource_id for port, reads TrustedContext from current task,
// authorizes (UartWrite), and calls uart_write_bytes() on allow.
// Returns ESP_OK on success, ESP_ERR_NOT_ALLOWED if denied,
// ESP_ERR_NOT_FOUND if port is not registered.
esp_err_t ztg_uart_write(uart_port_t port, const uint8_t* data, size_t len);

// Policy-enforced UART read.
// Looks up resource_id for port, reads TrustedContext from current task,
// authorizes (UartRead), and calls uart_read_bytes() on allow.
// timeout_ms - time to wait for data.
// Returns ESP_OK on success, ESP_ERR_NOT_ALLOWED if denied,
// ESP_ERR_NOT_FOUND if port is not registered.
esp_err_t ztg_uart_read(uart_port_t port, uint8_t* buf, size_t len, uint32_t timeout_ms);

} // namespace zerotrust

#endif // FIRMWARE_COMPONENTS_ZEROTRUST_INCLUDE_ZTG_UART_H

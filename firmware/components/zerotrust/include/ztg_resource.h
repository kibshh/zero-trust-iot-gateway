#ifndef FIRMWARE_COMPONENTS_ZEROTRUST_INCLUDE_ZTG_RESOURCE_H
#define FIRMWARE_COMPONENTS_ZEROTRUST_INCLUDE_ZTG_RESOURCE_H

#include <cstdint>
#include <cstddef>

#include "driver/gpio.h"
#include "driver/i2c.h"
#include "driver/spi_common.h"
#include "driver/uart.h"

namespace zerotrust {

// Status codes returned by ztg_register_* functions.
enum class ResourceRegStatus : uint8_t {
    Ok,
    InvalidResourceId,   // resource_id not in range [1..65534]
    DuplicateResourceId, // resource_id already registered in any table
    DuplicateKey,        // physical key already registered in this table
    TableFull,           // table capacity reached
    RegistrationClosed,  // ztg_start() has already been called
    InvalidName,         // name (display label) is null or empty
    NameTooLong,         // name exceeds 31 characters
    InvalidNamespace,    // ns (NVS namespace key) is null or empty
};

// Register a GPIO pin as a named logical resource.
// Must be called before ztg_start().
ResourceRegStatus ztg_register_gpio(gpio_num_t pin, uint16_t resource_id, const char* name);

// Register an I2C device (bus + address) as a named logical resource.
// Must be called before ztg_start().
ResourceRegStatus ztg_register_i2c(i2c_port_t bus, uint8_t addr, uint16_t resource_id, const char* name);

// Register an SPI device (host + chip-select) as a named logical resource.
// Must be called before ztg_start().
ResourceRegStatus ztg_register_spi(spi_host_device_t host, int cs, uint16_t resource_id, const char* name);

// Register a UART port as a named logical resource.
// Must be called before ztg_start().
ResourceRegStatus ztg_register_uart(uart_port_t port, uint16_t resource_id, const char* name);

// Register a network handle as a named logical resource.
// Must be called before ztg_start().
ResourceRegStatus ztg_register_network(uint16_t handle, uint16_t resource_id, const char* name);

// Register a NVS namespace as a named logical resource.
// ns must be a valid NVS namespace string (max 15 chars per ESP-IDF limit).
// Must be called before ztg_start().
ResourceRegStatus ztg_register_storage(const char* ns, uint16_t resource_id, const char* name);

// Register the system resource (reboot, sleep, OTA).
// Only one system resource can be registered.
// Must be called before ztg_start().
ResourceRegStatus ztg_register_system(uint16_t resource_id, const char* name);

// Serialize all registered resources to a YAML buffer compatible with the backend's
// resource registry format. Writes up to size-1 bytes and null-terminates.
// Returns the number of bytes written (excluding null terminator), or 0 on error.
size_t ztg_export_registry_yaml(char* buf, size_t size);

} // namespace zerotrust

#endif // FIRMWARE_COMPONENTS_ZEROTRUST_INCLUDE_ZTG_RESOURCE_H

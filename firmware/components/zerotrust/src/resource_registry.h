#ifndef FIRMWARE_COMPONENTS_ZEROTRUST_SRC_RESOURCE_REGISTRY_H
#define FIRMWARE_COMPONENTS_ZEROTRUST_SRC_RESOURCE_REGISTRY_H

#include <cstdint>

#include "driver/gpio.h"
#include "driver/i2c.h"
#include "driver/spi_common.h"
#include "driver/uart.h"

namespace zerotrust::internal {

// Prevents further registration. Called by ztg_start() before spawning tasks.
void close_registration();

// Lookup functions - return resource_id for the given physical key.
// Return 0 if the resource has not been registered.
uint16_t lookup_gpio(gpio_num_t pin);
uint16_t lookup_i2c(i2c_port_t bus, uint8_t addr);
uint16_t lookup_spi(spi_host_device_t host, int cs);
uint16_t lookup_uart(uart_port_t port);
uint16_t lookup_network(uint16_t handle);
uint16_t lookup_storage(const char* ns);
uint16_t lookup_system();

} // namespace zerotrust::internal

#endif // FIRMWARE_COMPONENTS_ZEROTRUST_SRC_RESOURCE_REGISTRY_H

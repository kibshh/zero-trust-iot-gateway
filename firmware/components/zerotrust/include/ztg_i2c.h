#ifndef FIRMWARE_COMPONENTS_ZEROTRUST_INCLUDE_ZTG_I2C_H
#define FIRMWARE_COMPONENTS_ZEROTRUST_INCLUDE_ZTG_I2C_H

#include <cstddef>
#include <cstdint>

#include "esp_err.h"
#include "driver/i2c.h"

namespace zerotrust {

// Policy-enforced I2C write.
// Looks up resource_id for (bus, addr), reads TrustedContext from current task,
// authorizes (I2cWrite), and performs the transfer on allow.
// Returns ESP_OK on success, ESP_ERR_NOT_ALLOWED if denied,
// ESP_ERR_NOT_FOUND if (bus, addr) is not registered.
esp_err_t ztg_i2c_write(i2c_port_t bus, uint8_t addr,
                        const uint8_t* data, size_t len);

// Policy-enforced I2C read.
// Looks up resource_id for (bus, addr), reads TrustedContext from current task,
// authorizes (I2cRead), and performs the transfer on allow.
// Returns ESP_OK on success, ESP_ERR_NOT_ALLOWED if denied,
// ESP_ERR_NOT_FOUND if (bus, addr) is not registered.
esp_err_t ztg_i2c_read(i2c_port_t bus, uint8_t addr,
                       uint8_t* buf, size_t len);

} // namespace zerotrust

#endif // FIRMWARE_COMPONENTS_ZEROTRUST_INCLUDE_ZTG_I2C_H

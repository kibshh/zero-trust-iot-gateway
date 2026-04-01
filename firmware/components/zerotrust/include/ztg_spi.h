#ifndef FIRMWARE_COMPONENTS_ZEROTRUST_INCLUDE_ZTG_SPI_H
#define FIRMWARE_COMPONENTS_ZEROTRUST_INCLUDE_ZTG_SPI_H

#include <cstddef>
#include <cstdint>

#include "esp_err.h"
#include "driver/spi_common.h"

namespace zerotrust {

// Policy-enforced SPI write.
// Looks up resource_id for (host, cs), reads TrustedContext from current task,
// authorizes (SpiWrite), and performs the transfer on allow.
// Returns ESP_OK on success, ESP_ERR_NOT_ALLOWED if denied,
// ESP_ERR_NOT_FOUND if (host, cs) is not registered.
esp_err_t ztg_spi_write(spi_host_device_t host, int cs,
                        const uint8_t* data, size_t len);

// Policy-enforced SPI read.
// Looks up resource_id for (host, cs), reads TrustedContext from current task,
// authorizes (SpiRead), and performs the transfer on allow.
// Returns ESP_OK on success, ESP_ERR_NOT_ALLOWED if denied,
// ESP_ERR_NOT_FOUND if (host, cs) is not registered.
esp_err_t ztg_spi_read(spi_host_device_t host, int cs,
                       uint8_t* buf, size_t len);

} // namespace zerotrust

#endif // FIRMWARE_COMPONENTS_ZEROTRUST_INCLUDE_ZTG_SPI_H

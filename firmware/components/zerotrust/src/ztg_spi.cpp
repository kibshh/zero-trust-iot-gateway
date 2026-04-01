#include "ztg_spi.h"

#include "gate_common.h"
#include "resource_registry.h"
#include "policy_types.h"

// TODO: implement SPI wrappers (delegate to spi_device_transmit).

namespace zerotrust {

esp_err_t ztg_spi_write(spi_host_device_t host, int cs,
                        const uint8_t* data, size_t len) {
    uint16_t resource_id = zerotrust::internal::lookup_spi(host, cs);
    if (resource_id == 0) {
        return ESP_ERR_NOT_FOUND;
    }
    esp_err_t auth = zerotrust::internal::gate_check(
        zerotrust::policy::PolicyAction::SpiWrite, resource_id);
    if (auth != ESP_OK) {
        return auth;
    }
    (void)data;
    (void)len;
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t ztg_spi_read(spi_host_device_t host, int cs,
                       uint8_t* buf, size_t len) {
    uint16_t resource_id = zerotrust::internal::lookup_spi(host, cs);
    if (resource_id == 0) {
        return ESP_ERR_NOT_FOUND;
    }
    esp_err_t auth = zerotrust::internal::gate_check(
        zerotrust::policy::PolicyAction::SpiRead, resource_id);
    if (auth != ESP_OK) {
        return auth;
    }
    (void)buf;
    (void)len;
    return ESP_ERR_NOT_SUPPORTED;
}

} // namespace zerotrust

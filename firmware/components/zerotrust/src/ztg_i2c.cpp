#include "ztg_i2c.h"

#include "gate_common.h"
#include "resource_registry.h"
#include "policy_types.h"

// TODO: implement I2C wrappers (delegate to i2c_master_transmit / i2c_master_receive).

namespace zerotrust {

esp_err_t ztg_i2c_write(i2c_port_t bus, uint8_t addr,
                        const uint8_t* data, size_t len) {
    uint16_t resource_id = zerotrust::internal::lookup_i2c(bus, addr);
    if (resource_id == 0) {
        return ESP_ERR_NOT_FOUND;
    }
    esp_err_t auth = zerotrust::internal::gate_check(
        zerotrust::policy::PolicyAction::I2cWrite, resource_id);
    if (auth != ESP_OK) {
        return auth;
    }
    (void)data;
    (void)len;
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t ztg_i2c_read(i2c_port_t bus, uint8_t addr,
                       uint8_t* buf, size_t len) {
    uint16_t resource_id = zerotrust::internal::lookup_i2c(bus, addr);
    if (resource_id == 0) {
        return ESP_ERR_NOT_FOUND;
    }
    esp_err_t auth = zerotrust::internal::gate_check(
        zerotrust::policy::PolicyAction::I2cRead, resource_id);
    if (auth != ESP_OK) {
        return auth;
    }
    (void)buf;
    (void)len;
    return ESP_ERR_NOT_SUPPORTED;
}

} // namespace zerotrust

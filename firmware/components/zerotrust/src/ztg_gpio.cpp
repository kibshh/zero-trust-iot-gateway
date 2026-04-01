#include "ztg_gpio.h"

#include "gate_common.h"
#include "resource_registry.h"
#include "policy_types.h"

// TODO: implement GPIO wrappers (delegate to gpio_set_level / gpio_get_level).
// TODO: implement ztg_gpio_isr_register (ISR deferral via FreeRTOS queue + gate task).

namespace zerotrust {

esp_err_t ztg_gpio_write(gpio_num_t pin, uint32_t level) {
    uint16_t resource_id = zerotrust::internal::lookup_gpio(pin);
    if (resource_id == 0) {
        return ESP_ERR_NOT_FOUND;
    }
    esp_err_t auth = zerotrust::internal::gate_check(
        zerotrust::policy::PolicyAction::GpioWrite, resource_id);
    if (auth != ESP_OK) {
        return auth;
    }
    (void)level;
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t ztg_gpio_read(gpio_num_t pin, int* out_level) {
    uint16_t resource_id = zerotrust::internal::lookup_gpio(pin);
    if (resource_id == 0) {
        return ESP_ERR_NOT_FOUND;
    }
    esp_err_t auth = zerotrust::internal::gate_check(
        zerotrust::policy::PolicyAction::GpioRead, resource_id);
    if (auth != ESP_OK) {
        return auth;
    }
    (void)out_level;
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t ztg_gpio_isr_register(gpio_num_t pin,
                                void (*handler)(gpio_num_t pin, void* ctx),
                                void* ctx) {
    uint16_t resource_id = zerotrust::internal::lookup_gpio(pin);
    if (resource_id == 0) {
        return ESP_ERR_NOT_FOUND;
    }
    (void)handler;
    (void)ctx;
    return ESP_ERR_NOT_SUPPORTED;
}

} // namespace zerotrust

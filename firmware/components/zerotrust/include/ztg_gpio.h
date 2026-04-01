#ifndef FIRMWARE_COMPONENTS_ZEROTRUST_INCLUDE_ZTG_GPIO_H
#define FIRMWARE_COMPONENTS_ZEROTRUST_INCLUDE_ZTG_GPIO_H

#include "esp_err.h"
#include "driver/gpio.h"

namespace zerotrust {

// Policy-enforced GPIO write.
// Looks up resource_id for pin, reads TrustedContext from current task,
// authorizes (GpioWrite), and calls gpio_set_level() on allow.
// Returns ESP_OK on success, ESP_ERR_NOT_ALLOWED if denied,
// ESP_ERR_NOT_FOUND if pin is not registered.
esp_err_t ztg_gpio_write(gpio_num_t pin, uint32_t level);

// Policy-enforced GPIO read.
// Looks up resource_id for pin, reads TrustedContext from current task,
// authorizes (GpioRead), and calls gpio_get_level() on allow.
// out_level receives the pin state on success.
// Returns ESP_OK on success, ESP_ERR_NOT_ALLOWED if denied,
// ESP_ERR_NOT_FOUND if pin is not registered.
esp_err_t ztg_gpio_read(gpio_num_t pin, int* out_level);

// Register an ISR-deferred GPIO input handler.
// The library installs an ISR for pin, defers events to an internal gate task,
// authorizes (GpioRead, actor=Peripheral, origin=Local) before invoking handler.
// handler is called from the gate task (not ISR context) on allow.
// Returns ESP_OK on success, ESP_ERR_NOT_FOUND if pin is not registered.
esp_err_t ztg_gpio_isr_register(gpio_num_t pin,
                                void (*handler)(gpio_num_t pin, void* ctx),
                                void* ctx);

} // namespace zerotrust

#endif // FIRMWARE_COMPONENTS_ZEROTRUST_INCLUDE_ZTG_GPIO_H

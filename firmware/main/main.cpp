#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

extern "C" void app_main(void)
{
    while (true) {
        printf("Zero-Trust IoT Gateway booted\n");
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

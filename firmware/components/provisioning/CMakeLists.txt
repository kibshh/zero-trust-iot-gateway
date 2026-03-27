idf_component_register(
    SRCS "provisioning.cpp"
    INCLUDE_DIRS "include"
    REQUIRES esp_wifi esp_event esp_netif esp_http_server esp_driver_gpio nvs_flash esp_system
)

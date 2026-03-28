idf_component_register(
    SRCS "identity.cpp"
    INCLUDE_DIRS "include"
    REQUIRES nvs_flash mbedtls esp_hw_support utils
)


idf_component_register(
    SRCS "policy.cpp" "policy_manager.cpp"
    INCLUDE_DIRS "include"
    REQUIRES system_state identity nvs_flash mbedtls
)


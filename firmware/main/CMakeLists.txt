idf_component_register(
    SRCS "main.cpp"
    INCLUDE_DIRS "."
    REQUIRES systemcontroller system_state identity attestation policy backend_client time_sync nvs_flash
)

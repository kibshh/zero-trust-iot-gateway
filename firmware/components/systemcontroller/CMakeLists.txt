idf_component_register(
    SRCS "system_controller.cpp"
    INCLUDE_DIRS "include"
    REQUIRES system_state identity attestation
)


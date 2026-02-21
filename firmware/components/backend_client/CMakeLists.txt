idf_component_register(
    SRCS "backend_client.cpp"
    INCLUDE_DIRS "include"
    REQUIRES esp_http_client json attestation policy
)


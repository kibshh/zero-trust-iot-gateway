#include "backend_client.h"

#include "esp_http_client.h"
#include "cJSON.h"

#include <cstring>
#include <cstdio>

namespace zerotrust::backend {

namespace {

// HTTP response buffer
struct HttpBuffer {
    char* data;
    size_t len;
    size_t capacity;
};

// HTTP event handler for collecting response body
esp_err_t http_event_handler(esp_http_client_event_t* evt)
{
    HttpBuffer* buf = static_cast<HttpBuffer*>(evt->user_data);
    
    switch (evt->event_id) {
        case HTTP_EVENT_ON_DATA:
            if (buf && evt->data_len > 0) {
                size_t new_len = buf->len + evt->data_len;
                if (new_len < buf->capacity) {
                    memcpy(buf->data + buf->len, evt->data, evt->data_len);
                    buf->len = new_len;
                    buf->data[buf->len] = '\0';
                }
                else {
                    return ESP_ERR_HTTP_RESPONSE_TOO_LARGE;
                }
            }
            break;
        default:
            break;
    }
    return ESP_OK;
}

// Convert hex string to bytes
bool hex_to_bytes(const char* hex, size_t hex_len, uint8_t* out, size_t out_capacity)
{
    if (hex_len % 2 != 0) return false;
    size_t byte_len = hex_len / 2;
    if (byte_len > out_capacity) return false;
    
    for (size_t i = 0; i < byte_len; i++) {
        unsigned int byte_val;
        if (sscanf(hex + (i * 2), "%2x", &byte_val) != 1) {
            return false;
        }
        out[i] = static_cast<uint8_t>(byte_val);
    }
    return true;
}

// Convert bytes to hex string
void bytes_to_hex(const uint8_t* bytes, size_t len, char* out)
{
    for (size_t i = 0; i < len; i++) {
        sprintf(out + (i * 2), "%02x", bytes[i]);
    }
    out[len * 2] = '\0';
}

} // anonymous namespace

void BackendClient::init(const BackendConfig& config)
{
    config_ = config;
    if (config_.timeout_ms == 0) {
        config_.timeout_ms = BackendClient::DefaultTimeoutMs;
    }
    initialized_ = true;
}

BackendStatus BackendClient::request_attestation_challenge(
    const uint8_t* device_id,
    size_t device_id_len,
    ChallengeResponse& out_response)
{
    if (!initialized_) {
        return BackendStatus::NotInitialized;
    }

    if (!device_id || device_id_len != BackendClient::DeviceIdSize) {
        return BackendStatus::InvalidArgument;
    }

    char url[BackendClient::UrlBufferSize];
    snprintf(url, BackendClient::UrlBufferSize, "%s%s",
             config_.base_url, BackendClient::EndpointAttestationChallenge);

    // Build JSON body: {"device_id":"<hex>"}
    char device_id_hex[BackendClient::DeviceIdSize * 2 + 1]; // +1 for null terminator
    bytes_to_hex(device_id, BackendClient::DeviceIdSize, device_id_hex); 
    char json_body[BackendClient::AttestationChallengeReqJsonBodyBufferSize];
    snprintf(json_body, BackendClient::AttestationChallengeReqJsonBodyBufferSize,
             "{\"device_id\":\"%s\"}", device_id_hex);
             
    char response_buf[BackendClient::ResponseBufferSize];
    HttpBuffer http_buf = { response_buf, 0, BackendClient::ResponseBufferSize - 1 };

    // Configure HTTP client
    esp_http_client_config_t http_config = {};
    http_config.url = url;
    http_config.method = HTTP_METHOD_POST;
    http_config.timeout_ms = static_cast<int>(config_.timeout_ms);
    http_config.event_handler = http_event_handler;
    http_config.user_data = &http_buf;

    esp_http_client_handle_t client = esp_http_client_init(&http_config);
    if (!client) {
        return BackendStatus::NetworkError;
    }
    // POST + JSON body instead of GET + query params.
    // This is more secure and explicit.
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, json_body, strlen(json_body));

    // Perform HTTP request, handler will be called when data is available.
    // The user data is the HttpBuffer struct, which contains the response buffer.
    // This function will block until the request is complete.
    esp_err_t err = esp_http_client_perform(client);
    if (err != ESP_OK) {
        esp_http_client_cleanup(client);
        if (err == ESP_ERR_HTTP_RESPONSE_TOO_LARGE) {
            return BackendStatus::InvalidResponse;
        }
        if (err == ESP_ERR_HTTP_TIMEOUT) {
            return BackendStatus::Timeout;
        }
        return BackendStatus::NetworkError;
    }

    int status_code = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);

    if (status_code != static_cast<int>(HttpStatusCode::Ok)) {
        switch (status_code) {
            case static_cast<int>(HttpStatusCode::BadRequest):
            case static_cast<int>(HttpStatusCode::Unauthorized):
            case static_cast<int>(HttpStatusCode::Forbidden):
            case static_cast<int>(HttpStatusCode::NotFound):
                return BackendStatus::InvalidResponse;
            case static_cast<int>(HttpStatusCode::InternalServerError):
                return BackendStatus::ServerError;
            default:
                return BackendStatus::InvalidResponse;
        }
    }

    // Pointer to the root of the JSON object.
    cJSON* root = cJSON_Parse(response_buf);
    if (!root) {
        return BackendStatus::InvalidResponse;
    }

    cJSON* nonce_item = cJSON_GetObjectItem(root, BackendClient::JsonKeyNonce);
    if (!nonce_item || !cJSON_IsString(nonce_item)) {
        cJSON_Delete(root);
        return BackendStatus::InvalidResponse;
    }

    const char* nonce_hex = nonce_item->valuestring;
    size_t nonce_hex_len = strlen(nonce_hex);

    // Nonce must be exactly 32 bytes (64 hex chars)
    if (nonce_hex_len != BackendClient::NonceSize * 2) {
        cJSON_Delete(root);
        return BackendStatus::InvalidResponse;
    }

    if (!hex_to_bytes(nonce_hex, nonce_hex_len, out_response.nonce, BackendClient::NonceSize)) {
        cJSON_Delete(root);
        return BackendStatus::InvalidResponse;
    }

    cJSON_Delete(root);
    return BackendStatus::Ok;
}

BackendStatus BackendClient::verify_attestation(const attestation::AttestationResponse& response)
{
    if (!initialized_) {
        return BackendStatus::NotInitialized;
    }

    if (!response.device_id || response.device_id_len != BackendClient::DeviceIdSize ||
        !response.firmware_hash || response.firmware_hash_len != BackendClient::FirmwareHashSize ||
        !response.signature || response.signature_len == 0 || 
        response.signature_len > BackendClient::MaxSignatureSize) {
        return BackendStatus::InvalidArgument;
    }

    char url[BackendClient::UrlBufferSize];
    snprintf(url, BackendClient::UrlBufferSize, "%s%s", config_.base_url, BackendClient::EndpointAttestationVerify);

    // Encode binary fields as hex strings
    char device_id_hex[BackendClient::DeviceIdSize * 2 + 1];
    bytes_to_hex(response.device_id, BackendClient::DeviceIdSize, device_id_hex);

    char firmware_hash_hex[BackendClient::FirmwareHashSize * 2 + 1];
    bytes_to_hex(response.firmware_hash, BackendClient::FirmwareHashSize, firmware_hash_hex);

    char signature_hex[BackendClient::MaxSignatureSize * 2 + 1];
    bytes_to_hex(response.signature, response.signature_len, signature_hex);

    // Build JSON body: {"device_id":"<hex>","firmware_hash":"<hex>","signature":"<hex>"}
    char json_body[BackendClient::AttestationVerifyJsonBodyBufferSize];
    snprintf(json_body, BackendClient::AttestationVerifyJsonBodyBufferSize,
             "{\"device_id\":\"%s\",\"firmware_hash\":\"%s\",\"signature\":\"%s\"}",
             device_id_hex, firmware_hash_hex, signature_hex);

    char response_buf[BackendClient::ResponseBufferSize];
    HttpBuffer http_buf = { response_buf, 0, BackendClient::ResponseBufferSize - 1 };

    esp_http_client_config_t http_config = {};
    http_config.url = url;
    http_config.method = HTTP_METHOD_POST;
    http_config.timeout_ms = static_cast<int>(config_.timeout_ms);
    http_config.event_handler = http_event_handler;
    http_config.user_data = &http_buf;

    esp_http_client_handle_t client = esp_http_client_init(&http_config);
    if (!client) {
        return BackendStatus::NetworkError;
    }

    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, json_body, strlen(json_body));

    esp_err_t err = esp_http_client_perform(client);
    if (err != ESP_OK) {
        esp_http_client_cleanup(client);
        if (err == ESP_ERR_HTTP_RESPONSE_TOO_LARGE) {
            return BackendStatus::InvalidResponse;
        }
        if (err == ESP_ERR_HTTP_TIMEOUT) {
            return BackendStatus::Timeout;
        }
        return BackendStatus::NetworkError;
    }

    int status_code = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);

    if (status_code != static_cast<int>(HttpStatusCode::Ok)) {
        switch (status_code) {
            case static_cast<int>(HttpStatusCode::BadRequest):
            case static_cast<int>(HttpStatusCode::Unauthorized):
            case static_cast<int>(HttpStatusCode::Forbidden):
            case static_cast<int>(HttpStatusCode::NotFound):
                return BackendStatus::InvalidResponse;
            case static_cast<int>(HttpStatusCode::InternalServerError):
                return BackendStatus::ServerError;
            default:
                return BackendStatus::InvalidResponse;
        }
    }

    cJSON* root = cJSON_Parse(response_buf);
    if (!root) {
        return BackendStatus::InvalidResponse;
    }

    cJSON* granted_item = cJSON_GetObjectItem(root, BackendClient::JsonKeyGranted);
    if (!granted_item || !cJSON_IsBool(granted_item)) {
        cJSON_Delete(root);
        return BackendStatus::InvalidResponse;
    }

    bool granted = cJSON_IsTrue(granted_item);
    cJSON_Delete(root);

    return granted ? BackendStatus::Ok : BackendStatus::Denied;
}

BackendStatus BackendClient::register_device(
    const uint8_t* device_id,
    size_t device_id_len,
    const uint8_t* public_key_der,
    size_t public_key_len)
{
    if (!initialized_) {
        return BackendStatus::NotInitialized;
    }

    if (!device_id || device_id_len != BackendClient::DeviceIdSize ||
        !public_key_der || public_key_len == 0 || 
        public_key_len > BackendClient::PublicKeyDerMax) {
        return BackendStatus::InvalidArgument;
    }

    char url[BackendClient::UrlBufferSize];
    snprintf(url, BackendClient::UrlBufferSize, "%s%s",
             config_.base_url, BackendClient::EndpointDeviceRegister);

    char device_id_hex[BackendClient::DeviceIdSize * 2 + 1];
    bytes_to_hex(device_id, BackendClient::DeviceIdSize, device_id_hex);

    char public_key_hex[BackendClient::PublicKeyDerMax * 2 + 1];
    bytes_to_hex(public_key_der, public_key_len, public_key_hex);

    char json_body[BackendClient::RegisterDeviceJsonBodyBufferSize];
    snprintf(json_body, BackendClient::RegisterDeviceJsonBodyBufferSize,
             "{\"device_id\":\"%s\",\"public_key\":\"%s\"}",
             device_id_hex, public_key_hex);

    esp_http_client_config_t http_config = {};
    http_config.url = url;
    http_config.method = HTTP_METHOD_POST;
    http_config.timeout_ms = static_cast<int>(config_.timeout_ms);

    esp_http_client_handle_t client = esp_http_client_init(&http_config);
    if (!client) {
        return BackendStatus::NetworkError;
    }

    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, json_body, strlen(json_body));

    esp_err_t err = esp_http_client_perform(client);
    if (err != ESP_OK) {
        esp_http_client_cleanup(client);
        memset(public_key_hex, 0, sizeof(public_key_hex));
        if (err == ESP_ERR_HTTP_TIMEOUT) {
            return BackendStatus::Timeout;
        }
        return BackendStatus::NetworkError;
    }

    int status_code = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);
    memset(public_key_hex, 0, sizeof(public_key_hex));

    if (status_code == static_cast<int>(HttpStatusCode::Created)) {
        return BackendStatus::Ok;
    }

    switch (status_code) {
        case static_cast<int>(HttpStatusCode::Conflict):
            return BackendStatus::AlreadyExists;
        case static_cast<int>(HttpStatusCode::InternalServerError):
            return BackendStatus::ServerError;
        case static_cast<int>(HttpStatusCode::BadRequest):
        case static_cast<int>(HttpStatusCode::Unauthorized):
        case static_cast<int>(HttpStatusCode::Forbidden):
        case static_cast<int>(HttpStatusCode::NotFound):
        default:
            return BackendStatus::InvalidResponse;
    }
}

BackendStatus BackendClient::request_authorization(
    const uint8_t* device_id,
    size_t device_id_len,
    const uint8_t* firmware_hash,
    size_t firmware_hash_len)
{
    if (!initialized_) {
        return BackendStatus::NotInitialized;
    }

    if (!device_id || device_id_len != BackendClient::DeviceIdSize ||
        !firmware_hash || firmware_hash_len != BackendClient::FirmwareHashSize) {
        return BackendStatus::InvalidArgument;
    }

    char url[BackendClient::UrlBufferSize];
    snprintf(url, BackendClient::UrlBufferSize, "%s%s",
             config_.base_url, BackendClient::EndpointAuthorizationRequest);

    char device_id_hex[BackendClient::DeviceIdSize * 2 + 1];
    bytes_to_hex(device_id, BackendClient::DeviceIdSize, device_id_hex);

    char firmware_hash_hex[BackendClient::FirmwareHashSize * 2 + 1];
    bytes_to_hex(firmware_hash, BackendClient::FirmwareHashSize, firmware_hash_hex);

    char json_body[BackendClient::AuthorizationRequestJsonBodyBufferSize];
    snprintf(json_body, BackendClient::AuthorizationRequestJsonBodyBufferSize,
             "{\"device_id\":\"%s\",\"firmware_hash\":\"%s\"}",
             device_id_hex, firmware_hash_hex);

    char response_buf[BackendClient::ResponseBufferSize];
    HttpBuffer http_buf = { response_buf, 0, BackendClient::ResponseBufferSize - 1 };

    esp_http_client_config_t http_config = {};
    http_config.url = url;
    http_config.method = HTTP_METHOD_POST;
    http_config.timeout_ms = static_cast<int>(config_.timeout_ms);
    http_config.event_handler = http_event_handler;
    http_config.user_data = &http_buf;

    esp_http_client_handle_t client = esp_http_client_init(&http_config);
    if (!client) {
        return BackendStatus::NetworkError;
    }

    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, json_body, strlen(json_body));

    esp_err_t err = esp_http_client_perform(client);
    if (err != ESP_OK) {
        esp_http_client_cleanup(client);
        if (err == ESP_ERR_HTTP_RESPONSE_TOO_LARGE) {
            return BackendStatus::InvalidResponse;
        }
        if (err == ESP_ERR_HTTP_TIMEOUT) {
            return BackendStatus::Timeout;
        }
        return BackendStatus::NetworkError;
    }

    int status_code = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);

    if (status_code != static_cast<int>(HttpStatusCode::Ok)) {
        switch (status_code) {
            case static_cast<int>(HttpStatusCode::BadRequest):
            case static_cast<int>(HttpStatusCode::Unauthorized):
            case static_cast<int>(HttpStatusCode::Forbidden):
            case static_cast<int>(HttpStatusCode::NotFound):
                return BackendStatus::InvalidResponse;
            case static_cast<int>(HttpStatusCode::InternalServerError):
                return BackendStatus::ServerError;
            default:
                return BackendStatus::InvalidResponse;
        }
    }

    cJSON* root = cJSON_Parse(response_buf);
    if (!root) {
        return BackendStatus::InvalidResponse;
    }

    cJSON* authorized_item = cJSON_GetObjectItem(root, BackendClient::JsonKeyAuthorized);
    if (!authorized_item || !cJSON_IsBool(authorized_item)) {
        cJSON_Delete(root);
        return BackendStatus::InvalidResponse;
    }

    bool authorized = cJSON_IsTrue(authorized_item);
    cJSON_Delete(root);

    return authorized ? BackendStatus::Ok : BackendStatus::Denied;
}

} // namespace zerotrust::backend


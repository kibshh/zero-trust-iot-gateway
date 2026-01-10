#ifndef FIRMWARE_COMPONENTS_BACKEND_CLIENT_INCLUDE_BACKEND_CLIENT_H
#define FIRMWARE_COMPONENTS_BACKEND_CLIENT_INCLUDE_BACKEND_CLIENT_H

#include <cstdint>
#include <cstddef>

namespace zerotrust::backend {

enum class BackendStatus : uint8_t {
    Ok,
    InvalidArgument,
    NotInitialized,
    NetworkError,
    Timeout,
    ServerError,
    InvalidResponse
};

enum class HttpStatusCode : int {
    Ok = 200,
    BadRequest = 400,
    Unauthorized = 401,
    Forbidden = 403,
    NotFound = 404,
    InternalServerError = 500
};

struct BackendConfig {
    // String must have static lifetime (e.g., const char* or string literal)
    // String must be null-terminated
    const char* base_url;       // e.g., "https://192.168.1.100:8080"
    uint32_t timeout_ms;        // Request timeout
};

// Received challenge from backend
struct ChallengeResponse {
    uint8_t nonce[32];          // 32-byte nonce from backend (fixed size)
};

class BackendClient {
public:
    static constexpr size_t DeviceIdSize = 16;
    static constexpr size_t NonceSize = 32;
    static constexpr size_t UrlBufferSize = 256;
    static constexpr size_t JsonBodyBufferSize = 64; // {"device_id":"<hex>"}
    static constexpr size_t ResponseBufferSize = 256;
    static constexpr uint32_t DefaultTimeoutMs = 10000;
    static constexpr const char* EndpointAttestationChallenge = "/api/v1/attestation/challenge";
    static constexpr const char* JsonKeyNonce = "nonce";

    explicit BackendClient() : initialized_(false), config_{ nullptr, 0 } {}
    ~BackendClient() = default;

    // Initialize client with backend URL and settings
    void init(const BackendConfig& config);

    // Request attestation challenge from backend
    // device_id: 16-byte device identifier (hex-encoded for HTTP)
    // out_response: populated with nonce on success
    BackendStatus request_attestation_challenge(
        const uint8_t* device_id,
        size_t device_id_len,
        ChallengeResponse& out_response);

private:
    bool initialized_;
    BackendConfig config_;
};

} // namespace zerotrust::backend

#endif


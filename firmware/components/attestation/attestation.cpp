#include "attestation.h"

#include "esp_partition.h"
#include "mbedtls/md.h"

#include <cstring>

namespace zerotrust::attestation {

namespace {

// Hash currently running firmware (app partition) to produce attestation measurement
// Reads firmware in chunks and computes SHA-256 hash of entire partition
bool compute_firmware_hash(uint8_t* out_hash)
{
    // Find the application partition (currently running firmware)
    const esp_partition_t* app = esp_partition_find_first(ESP_PARTITION_TYPE_APP,
                                                          ESP_PARTITION_SUBTYPE_ANY,
                                                          nullptr); // Label filter - nullptr means any app partition
    if (!app) {
        return false;
    }

    // Initialize mbedTLS hashing context for incremental hashing
    // Context allows hashing large data in multiple steps without loading everything into memory
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    // Configure context for SHA-256 hashing (not HMAC)
    // HMAC parameter = 0 means standard hash, 1 would mean HMAC with secret key
    if (mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0) != 0) {
        mbedtls_md_free(&ctx);
        return false;
    }

    // Initialize hashing state - must be called before any updates
    if (mbedtls_md_starts(&ctx) != 0) {
        mbedtls_md_free(&ctx);
        return false;
    }

    // Read firmware partition in chunks to avoid loading entire partition into memory
    uint8_t buffer[AttestationEngine::FirmwareReadChunkSize];
    size_t offset = 0;
    while (offset < app->size) {
        // Calculate how much to read - use full buffer size or remaining bytes
        size_t to_read = sizeof(buffer);
        if (offset + to_read > app->size) {
            // Last chunk may be smaller than buffer size
            to_read = app->size - offset;
        }

        // Read chunk of firmware data from flash partition
        if (esp_partition_read(app, offset, buffer, to_read) != ESP_OK) {
            mbedtls_md_free(&ctx);
            return false;
        }

        // Update hash state with this chunk of data
        // Hash accumulates across all chunks until finish() is called
        if (mbedtls_md_update(&ctx, buffer, to_read) != 0) {
            mbedtls_md_free(&ctx);
            return false;
        }

        offset += to_read;
    }

    // Finalize hashing and write SHA-256 hash (32 bytes) to output buffer
    if (mbedtls_md_finish(&ctx, out_hash) != 0) {
        mbedtls_md_free(&ctx);
        return false;
    }

    mbedtls_md_free(&ctx);
    return true;
}

} // anonymous namespace

AttestationStatus AttestationEngine::generate_response(
    const AttestationChallenge& challenge,
    AttestationResponse& response)
{
    // Validate challenge input - nonce must be present and non-empty
    if (!challenge.nonce || challenge.nonce_len == 0) {
        return AttestationStatus::InternalError;
    }

    // Verify identity is ready (device ID must exist)
    if (identity_.get_identity_status() != identity::IdentityStatus::Present) {
        return AttestationStatus::IdentityMissing;
    }

    // Verify cryptographic keys are ready (required for signing)
    if (identity_.get_key_status() != identity::KeyStatus::Present) {
        return AttestationStatus::KeyMissing;
    }

    // Step 1: Compute firmware hash (attestation measurement)
    // This proves what firmware version is running on the device
    static uint8_t firmware_hash[identity::IdentityManager::Sha256HashSize];
    if (!compute_firmware_hash(firmware_hash)) {
        return AttestationStatus::InternalError;
    }

    // Step 2: Build canonical buffer for signing
    // Format: nonce || device_id || firmware_hash
    // This ensures the signature binds nonce, identity, and firmware state together
    static uint8_t sign_buffer[AttestationEngine::CanonicalSignBufferSize];
    size_t offset = 0;

    // Append nonce (prevents replay attacks - each challenge is unique)
    if (offset + challenge.nonce_len > AttestationEngine::CanonicalSignBufferSize) {
        return AttestationStatus::InternalError;
    }
    memcpy(sign_buffer + offset, challenge.nonce, challenge.nonce_len);
    offset += challenge.nonce_len;

    // Retrieve device ID from identity manager
    static uint8_t device_id[identity::IdentityManager::DeviceIdSize];
    if (!identity_.get_device_id(device_id, identity::IdentityManager::DeviceIdSize)) {
        return AttestationStatus::InternalError;
    }

    // Append device ID to canonical buffer
    if (offset + identity::IdentityManager::DeviceIdSize > AttestationEngine::CanonicalSignBufferSize) {
        return AttestationStatus::InternalError;
    }
    memcpy(sign_buffer + offset,
           device_id,
           identity::IdentityManager::DeviceIdSize);
    offset += identity::IdentityManager::DeviceIdSize;

    // Append firmware hash to canonical buffer
    if (offset + identity::IdentityManager::Sha256HashSize > AttestationEngine::CanonicalSignBufferSize) {
        return AttestationStatus::InternalError;
    }
    memcpy(sign_buffer + offset, firmware_hash, identity::IdentityManager::Sha256HashSize);
    offset += identity::IdentityManager::Sha256HashSize;

    // Step 3: Sign canonical buffer using device private key
    // Signature proves the response came from this specific device
    static uint8_t signature[AttestationEngine::MaxSignatureDerSize];
    size_t sig_len = AttestationEngine::MaxSignatureDerSize;

    if (!identity_.sign(sign_buffer, offset, signature, &sig_len)) {
        return AttestationStatus::InternalError;
    }
    memset(sign_buffer, 0, offset);

    // Step 4: Populate response structure with all attestation data
    // Backend will verify signature and firmware hash to authorize device
    response.device_id = device_id;
    response.device_id_len = identity::IdentityManager::DeviceIdSize;

    response.firmware_hash = firmware_hash;
    response.firmware_hash_len = identity::IdentityManager::Sha256HashSize;

    response.signature = signature;
    response.signature_len = sig_len;

    return AttestationStatus::Ok;
}

} // namespace zerotrust::attestation


#include "policy_verifier.h"

#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "mbedtls/error.h"
#include <cstring>

namespace zerotrust::policy {

namespace {

// Read uint64_t from big-endian byte array
inline uint64_t read_u64_be(const uint8_t* data)
{
    return (static_cast<uint64_t>(data[0]) << 56) |
           (static_cast<uint64_t>(data[1]) << 48) |
           (static_cast<uint64_t>(data[2]) << 40) |
           (static_cast<uint64_t>(data[3]) << 32) |
           (static_cast<uint64_t>(data[4]) << 24) |
           (static_cast<uint64_t>(data[5]) << 16) |
           (static_cast<uint64_t>(data[6]) << 8) |
           static_cast<uint64_t>(data[7]);
}

// Read uint16_t from little-endian byte array
inline uint16_t read_u16_le(const uint8_t* data)
{
    return static_cast<uint16_t>(data[0]) |
           (static_cast<uint16_t>(data[1]) << 8);
}

// Constant-time memory comparison (prevents timing attacks)
bool secure_compare(const uint8_t* a, const uint8_t* b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

// Secure memory zeroization
void secure_zero(void* ptr, size_t len)
{
    if (!ptr || len == 0) return;
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (len--) {
        *p++ = 0;
    }
}

} // anonymous namespace

bool PolicyVerifier::split_signed_blob(
    const uint8_t* blob,
    size_t blob_len,
    SignedAuthPolicy& out)
{
    // Wire format: [payload_len:2 LE][payload][sig_len:2 LE][signature]
    if (!blob || blob_len < AuthPolicyFormat::MinBlobSize) {
        return false;
    }

    size_t offset = 0;

    // Read payload length
    uint16_t payload_len = read_u16_le(blob + offset);
    offset += AuthPolicyFormat::LengthFieldSize;

    // Validate payload length bounds
    if (payload_len < AuthPolicyFormat::MinPayloadSize || 
        payload_len > AuthPolicyFormat::MaxPayloadSize) {
        return false;
    }

    // Check we have enough bytes for payload + sig_len field
    if (blob_len < offset + payload_len + AuthPolicyFormat::LengthFieldSize) {
        return false;
    }

    // Payload pointer
    const uint8_t* payload_ptr = blob + offset;
    offset += payload_len;

    // Read signature length
    uint16_t sig_len = read_u16_le(blob + offset);
    offset += AuthPolicyFormat::LengthFieldSize;

    // Validate signature length bounds
    if (sig_len < AuthPolicyFormat::SignatureMinSize || 
        sig_len > AuthPolicyFormat::SignatureMaxSize) {
        return false;
    }

    // Verify total size matches exactly
    if (blob_len != offset + sig_len) {
        return false;
    }

    // Signature pointer
    const uint8_t* sig_ptr = blob + offset;

    out.payload = payload_ptr;
    out.payload_len = payload_len;
    out.signature = sig_ptr;
    out.signature_len = sig_len;

    return true;
}

AuthPolicyParseResult PolicyVerifier::parse(
    const uint8_t* payload,
    size_t payload_len,
    AuthPolicy& out) const
{
    // Clear output
    memset(&out, 0, sizeof(out));

    if (!payload) {
        return AuthPolicyParseResult::NullPointer;
    }

    if (payload_len < AuthPolicyFormat::MinPayloadSize) {
        return AuthPolicyParseResult::PayloadTooSmall;
    }

    if (payload_len > AuthPolicyFormat::MaxPayloadSize) {
        return AuthPolicyParseResult::PayloadTooLarge;
    }

    size_t offset = 0;

    // Magic bytes
    if (memcmp(payload + offset, AuthPolicyFormat::Magic, AuthPolicyFormat::MagicSize) != 0) {
        return AuthPolicyParseResult::InvalidMagic;
    }
    offset += AuthPolicyFormat::MagicSize;

    // Version
    if (payload[offset] != AuthPolicyFormat::FormatVersion) {
        return AuthPolicyParseResult::UnsupportedVersion;
    }
    offset += AuthPolicyFormat::VersionSize;

    // Flags (skip for now)
    offset += AuthPolicyFormat::FlagsSize;

    // Device ID
    memcpy(out.device_id, payload + offset, AuthPolicyFormat::DeviceIdSize);
    offset += AuthPolicyFormat::DeviceIdSize;

    // MinFirmwareVersion (big-endian)
    out.min_firmware_version = read_u64_be(payload + offset);
    offset += AuthPolicyFormat::MinFirmwareVersionSize;

    // IssuedAt (big-endian)
    out.issued_at = read_u64_be(payload + offset);
    offset += AuthPolicyFormat::TimestampSize;

    // ExpiresAt (big-endian)
    out.expires_at = read_u64_be(payload + offset);
    offset += AuthPolicyFormat::TimestampSize;

    // HashCount
    out.hash_count = payload[offset];
    offset += AuthPolicyFormat::HashCountSize;

    if (out.hash_count > AuthPolicyFormat::MaxHashes) {
        return AuthPolicyParseResult::TooManyHashes;
    }

    // Verify payload size matches expected
    size_t expected_size = AuthPolicyFormat::HeaderSize + out.hash_count * AuthPolicyFormat::FirmwareHashSize;
    if (payload_len != expected_size) {
        return AuthPolicyParseResult::PayloadSizeMismatch;
    }

    // AllowedHashes
    for (uint8_t i = 0; i < out.hash_count; ++i) {
        memcpy(out.allowed_hashes[i], payload + offset, AuthPolicyFormat::FirmwareHashSize);
        offset += AuthPolicyFormat::FirmwareHashSize;
    }

    return AuthPolicyParseResult::Ok;
}

AuthPolicyVerifyResult PolicyVerifier::verify_signature(
    const uint8_t* payload,
    size_t payload_len,
    const uint8_t* signature,
    size_t signature_len,
    const uint8_t* backend_pubkey,
    size_t backend_pubkey_len) const
{
    if (!payload || payload_len == 0 ||
        !signature || signature_len == 0 ||
        !backend_pubkey || backend_pubkey_len == 0) {
        return AuthPolicyVerifyResult::CryptoError;
    }

    // Hash the payload (SHA-256)
    uint8_t hash[AuthPolicyFormat::FirmwareHashSize];
    if (mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                   payload, payload_len, hash) != 0) {
        return AuthPolicyVerifyResult::CryptoError;
    }

    // Parse backend public key
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    AuthPolicyVerifyResult result = AuthPolicyVerifyResult::InvalidSignature;

    do {
        if (mbedtls_pk_parse_public_key(&pk, backend_pubkey, backend_pubkey_len) != 0) {
            result = AuthPolicyVerifyResult::InvalidPublicKey;
            break;
        }

        // Enforce ECDSA key type
        if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_ECDSA)) {
            result = AuthPolicyVerifyResult::InvalidPublicKey;
            break;
        }

        // Verify signature
        int ret = mbedtls_pk_verify(&pk,
                                    MBEDTLS_MD_SHA256,
                                    hash,
                                    sizeof(hash),
                                    signature,
                                    signature_len);
        if (ret == 0) {
            result = AuthPolicyVerifyResult::Ok;
        } else {
            result = AuthPolicyVerifyResult::InvalidSignature;
        }
    } while (false);

    mbedtls_pk_free(&pk);
    secure_zero(hash, sizeof(hash));

    return result;
}

AuthPolicyValidateResult PolicyVerifier::validate(
    const AuthPolicy& policy,
    const uint8_t* device_id,
    const uint8_t* current_firmware_hash,
    uint64_t current_firmware_version,
    uint64_t current_time) const
{
    if (!device_id || !current_firmware_hash) {
        return AuthPolicyValidateResult::FirmwareHashNotAllowed;
    }

    // Check device ID match (all zeros = any device)
    bool device_id_is_any = true;
    for (size_t i = 0; i < AuthPolicyFormat::DeviceIdSize; ++i) {
        if (policy.device_id[i] != 0) {
            device_id_is_any = false;
            break;
        }
    }

    if (!device_id_is_any) {
        if (!secure_compare(policy.device_id, device_id, AuthPolicyFormat::DeviceIdSize)) {
            return AuthPolicyValidateResult::DeviceIdMismatch;
        }
    }

    // Time-based checks (skip if clock not set)
    if (current_time > 0) {
        // Check if policy has expired
        if (policy.expires_at > 0 && current_time > policy.expires_at) {
            return AuthPolicyValidateResult::PolicyExpired;
        }

        // Check if policy is not yet valid (issued in future)
        if (policy.issued_at > current_time) {
            return AuthPolicyValidateResult::PolicyNotYetValid;
        }
    } else {
        // Clock not set - can't verify time constraints
        // This is a security trade-off: fail-open for availability
        // In production, consider requiring synced time
        if (policy.expires_at > 0 || policy.issued_at > 0) {
            // Policy has time constraints but we can't verify them
            return AuthPolicyValidateResult::ClockNotSet;
        }
    }

    // Check firmware version (anti-rollback)
    if (current_firmware_version < policy.min_firmware_version) {
        return AuthPolicyValidateResult::FirmwareVersionTooOld;
    }

    // Check firmware hash whitelist
    if (!is_hash_allowed(policy, current_firmware_hash)) {
        return AuthPolicyValidateResult::FirmwareHashNotAllowed;
    }

    return AuthPolicyValidateResult::Ok;
}

bool PolicyVerifier::is_hash_allowed(
    const AuthPolicy& policy,
    const uint8_t* firmware_hash) const
{
    // Empty whitelist = no firmware allowed
    if (policy.hash_count == 0) {
        return false;
    }

    for (uint8_t i = 0; i < policy.hash_count; ++i) {
        if (secure_compare(policy.allowed_hashes[i], firmware_hash, AuthPolicyFormat::FirmwareHashSize)) {
            return true;
        }
    }

    return false;
}

bool PolicyVerifier::verify_and_validate(
    const uint8_t* blob,
    size_t blob_len,
    const uint8_t* backend_pubkey,
    size_t backend_pubkey_len,
    const uint8_t* device_id,
    const uint8_t* current_firmware_hash,
    uint64_t current_firmware_version,
    uint64_t current_time,
    AuthPolicy* out_policy)
{
    // Split blob into payload and signature
    SignedAuthPolicy signed_policy{};
    if (!split_signed_blob(blob, blob_len, signed_policy)) {
        return false;
    }

    // Parse payload
    AuthPolicy policy{};
    AuthPolicyParseResult parse_result = parse(
        signed_policy.payload,
        signed_policy.payload_len,
        policy);
    if (parse_result != AuthPolicyParseResult::Ok) {
        return false;
    }

    // Verify signature
    AuthPolicyVerifyResult verify_result = verify_signature(
        signed_policy.payload,
        signed_policy.payload_len,
        signed_policy.signature,
        signed_policy.signature_len,
        backend_pubkey,
        backend_pubkey_len);
    if (verify_result != AuthPolicyVerifyResult::Ok) {
        return false;
    }

    // Validate against device state
    AuthPolicyValidateResult validate_result = validate(
        policy,
        device_id,
        current_firmware_hash,
        current_firmware_version,
        current_time);
    if (validate_result != AuthPolicyValidateResult::Ok) {
        return false;
    }

    // Copy to output if requested
    if (out_policy) {
        *out_policy = policy;
    }

    return true;
}

} // namespace zerotrust::policy


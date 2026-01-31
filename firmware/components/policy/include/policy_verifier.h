#ifndef FIRMWARE_COMPONENTS_POLICY_INCLUDE_POLICY_VERIFIER_H
#define FIRMWARE_COMPONENTS_POLICY_INCLUDE_POLICY_VERIFIER_H

#include <cstdint>
#include <cstddef>

namespace zerotrust::policy {

// Canonical policy format constants (matches backend builder.go)
// Format: ZTPL (Zero Trust PoLicy) for firmware authorization
namespace AuthPolicyFormat {
    // Field sizes
    static constexpr size_t MagicSize = 4;
    static constexpr size_t VersionSize = 1;
    static constexpr size_t FlagsSize = 1;
    static constexpr size_t DeviceIdSize = 16;
    static constexpr size_t MinFirmwareVersionSize = 8;
    static constexpr size_t TimestampSize = 8;
    static constexpr size_t HashCountSize = 1;
    static constexpr size_t FirmwareHashSize = 32;
    static constexpr size_t MaxHashes = 16;
    
    // Wire format: [payload_len:2 LE][payload][sig_len:2 LE][signature]
    static constexpr size_t LengthFieldSize = 2;        // uint16_t LE for both lengths
    static constexpr size_t SignatureMinSize = 8;       // Minimum valid ECDSA signature
    static constexpr size_t SignatureMaxSize = 72;      // ECDSA P-256 DER max
    
    // Minimum blob size: len(2) + min_header(47) + len(2) + min_sig(8)
    static constexpr size_t MinBlobSize = LengthFieldSize + HeaderSize + 
                                          LengthFieldSize + SignatureMinSize;

    static constexpr char Magic[AuthPolicyFormat::MagicSize] = {'Z', 'T', 'P', 'L'};
    static constexpr uint8_t FormatVersion = 1;

    // Header layout:
    // Magic:              MagicSize bytes
    // Version:            VersionSize byte
    // Flags:              FlagsSize byte (reserved)
    // DeviceID:           DeviceIdSize bytes
    // MinFirmwareVersion: MinFirmwareVersionSize bytes (big-endian)
    // IssuedAt:           TimestampSize bytes (big-endian, unix timestamp)
    // ExpiresAt:          TimestampSize bytes (big-endian, unix timestamp)
    // HashCount:          HashCountSize byte
    // AllowedHashes:      HashCount * FirmwareHashSize bytes
    static constexpr size_t HeaderSize = MagicSize + VersionSize + FlagsSize + 
                                         DeviceIdSize + MinFirmwareVersionSize + 
                                         TimestampSize + TimestampSize + HashCountSize;
    static constexpr size_t MinPayloadSize = HeaderSize;  // At least header (0 hashes valid)
    static constexpr size_t MaxPayloadSize = HeaderSize + MaxHashes * FirmwareHashSize;
}

// Parsed authorization policy
struct AuthPolicy {
    uint8_t device_id[AuthPolicyFormat::DeviceIdSize];
    uint64_t min_firmware_version;
    uint64_t issued_at;     // Unix timestamp
    uint64_t expires_at;    // Unix timestamp
    uint8_t hash_count;
    uint8_t allowed_hashes[AuthPolicyFormat::MaxHashes][AuthPolicyFormat::FirmwareHashSize];
};

// Result of policy parsing
enum class AuthPolicyParseResult : uint8_t {
    Ok,
    NullPointer,
    PayloadTooSmall,
    PayloadTooLarge,
    InvalidMagic,
    UnsupportedVersion,
    TooManyHashes,
    PayloadSizeMismatch,
};

// Result of signature verification
enum class AuthPolicyVerifyResult : uint8_t {
    Ok,
    InvalidSignature,
    InvalidPublicKey,
    CryptoError,
};

// Result of policy validation (business logic)
enum class AuthPolicyValidateResult : uint8_t {
    Ok,
    DeviceIdMismatch,
    PolicyExpired,
    PolicyNotYetValid,
    FirmwareVersionTooOld,
    FirmwareHashNotAllowed,
    ClockNotSet,
};

// Signed authorization policy (payload + signature)
struct SignedAuthPolicy {
    const uint8_t* payload;
    size_t payload_len;
    const uint8_t* signature;
    size_t signature_len;
};

// Policy verifier for ZTPL format authorization policies
// Verifies signature and validates policy against device state
class PolicyVerifier {
public:
    PolicyVerifier() = default;
    ~PolicyVerifier() = default;

    // Non-copyable
    PolicyVerifier(const PolicyVerifier&) = delete;
    PolicyVerifier& operator=(const PolicyVerifier&) = delete;

    // Parse a signed policy blob into payload and signature
    // Format: [payload][signature_len:2 bytes LE][signature]
    // Returns: true if successfully split, false on format error
    static bool split_signed_blob(
        const uint8_t* blob,
        size_t blob_len,
        SignedAuthPolicy& out);

    // Parse canonical payload into AuthPolicy struct
    // Does NOT verify signature - call verify_signature() separately
    AuthPolicyParseResult parse(
        const uint8_t* payload,
        size_t payload_len,
        AuthPolicy& out) const;

    // Verify ECDSA P-256 signature over payload
    // backend_pubkey: DER-encoded SPKI public key
    AuthPolicyVerifyResult verify_signature(
        const uint8_t* payload,
        size_t payload_len,
        const uint8_t* signature,
        size_t signature_len,
        const uint8_t* backend_pubkey,
        size_t backend_pubkey_len) const;

    // Validate policy against device state (after signature verification)
    // device_id: this device's ID (16 bytes)
    // current_firmware_hash: SHA-256 of running firmware (32 bytes)
    // current_firmware_version: monotonic version counter
    // current_time: unix timestamp (0 = clock not set, skip time checks)
    AuthPolicyValidateResult validate(
        const AuthPolicy& policy,
        const uint8_t* device_id,
        const uint8_t* current_firmware_hash,
        uint64_t current_firmware_version,
        uint64_t current_time) const;

    // Convenience: parse + verify + validate in one call
    // Returns true only if ALL checks pass
    bool verify_and_validate(
        const uint8_t* blob,
        size_t blob_len,
        const uint8_t* backend_pubkey,
        size_t backend_pubkey_len,
        const uint8_t* device_id,
        const uint8_t* current_firmware_hash,
        uint64_t current_firmware_version,
        uint64_t current_time,
        AuthPolicy* out_policy = nullptr);

private:
    // Check if firmware hash is in allowed list
    bool is_hash_allowed(
        const AuthPolicy& policy,
        const uint8_t* firmware_hash) const;
};

} // namespace zerotrust::policy

#endif // FIRMWARE_COMPONENTS_POLICY_INCLUDE_POLICY_VERIFIER_H


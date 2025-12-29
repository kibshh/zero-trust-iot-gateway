#ifndef FIRMWARE_COMPONENTS_IDENTITY_INCLUDE_IDENTITY_H
#define FIRMWARE_COMPONENTS_IDENTITY_INCLUDE_IDENTITY_H

#include <cstdint>
#include <cstddef>

namespace zerotrust::identity {

enum class IdentityStatus : uint8_t {
    NotPresent,     // No identity stored
    Present,        // Identity exists locally
    Corrupted       // Identity data invalid / unreadable
};

enum class KeyStatus : uint8_t {
    NotPresent,     // No key material stored
    Present,        // Key material exists
    Corrupted       // Key material unreadable / invalid
};

enum class KeyAlgorithm : uint8_t {
    None = 0,
    ECDSA_P256 = 1,
};

// Metadata about NVS keys
struct KeyMeta {
    uint8_t algorithm;
};

// Device identity manager
// Manages cryptographic device identity
class IdentityManager {
public:
    static constexpr size_t DeviceIdSize = 16;
    static constexpr size_t PrivateKeyDerMax = 512;
    static constexpr size_t PublicKeyDerMax  = 256;
    static constexpr size_t Sha256HashSize = 32;  // SHA-256 produces 256 bits = 32 bytes
    // NVS namespace and key names
    static constexpr const char* NvsNamespace = "identity";
    static constexpr const char* NvsKeyDeviceId = "device_id";
    static constexpr const char* NvsKeyPrivateKey = "private_key";
    static constexpr const char* NvsKeyPublicKey = "public_key";
    static constexpr const char* NvsKeyKeyMeta = "key_meta";

    explicit IdentityManager();
    ~IdentityManager();

    // Initialize identity manager by probing NVS for existing identity data
    // Sets identity_status_ based on what is found in NVS (present, not present, or corrupted)
    void init();

    // Create a new device identity (generates random device ID)
    // Does not overwrite existing identity - returns true if identity already exists
    bool generate_identity();

    // Generate cryptographic keypair (ECDSA P-256) if keys are not already present
    // Keys are stored in NVS in DER format
    bool generate_keys();

    // Sign arbitrary data using device private key
    // - data: pointer to input buffer
    // - len: length of input buffer
    // - sig: output buffer (DER encoded signature)
    // - sig_len: in/out, size of buffer / actual signature length
    //
    // Returns false if identity or key is missing or corrupted
    bool sign(const uint8_t* data, size_t len, uint8_t* sig, size_t* sig_len);

    // Factory reset: permanently erases device identity from NVS
    // This is a destructive, irreversible operation
    bool factory_reset();

    IdentityStatus get_identity_status() const { return identity_status_; }
    KeyStatus get_key_status() const { return key_status_; }
    KeyAlgorithm get_key_algorithm() const { return key_algorithm_; }

    // Get device ID from NVS
    // id_out: Output buffer for device ID
    // device_id_len: Size of output buffer (must equal DeviceIdSize for safety)
    // Returns true on success, false if identity is not present, len mismatch, or read fails
    bool get_device_id(uint8_t* id_out, size_t device_id_len) const;

private:
    IdentityStatus identity_status_;
    KeyStatus key_status_;
    KeyAlgorithm key_algorithm_;
};

} // namespace zerotrust::identity

#endif // FIRMWARE_COMPONENTS_IDENTITY_INCLUDE_IDENTITY_H


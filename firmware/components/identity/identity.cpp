#include "identity.h"

#include "nvs.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

namespace zerotrust::identity {

IdentityManager::IdentityManager()
    : identity_status_(IdentityStatus::NotPresent),
      key_status_(KeyStatus::NotPresent),
      key_algorithm_(KeyAlgorithm::None) {}

IdentityManager::~IdentityManager()
{
    // Private key should be cleared from memory on destruction
    // Implementation will zero out sensitive data
}

void IdentityManager::init()
{
    // Robustness - start from a safe baseline
    identity_status_ = IdentityStatus::NotPresent;
    key_status_ = KeyStatus::NotPresent;
    key_algorithm_ = KeyAlgorithm::None;

    // NVS flash must be initialized by the caller (app_main) before calling init()
    // IdentityManager only opens its own namespace
    nvs_handle_t handle;
    // Open identity namespace in read-only mode to probe for existing data
    error = nvs_open(IdentityManager::NvsNamespace, NVS_READONLY, &handle);
    if (error == ESP_ERR_NVS_NOT_FOUND) {
        // Namespace does not exist - no identity has been created yet
        identity_status_ = IdentityStatus::NotPresent;
        return;
    }
    if (error != ESP_OK) {
        // Failed to open namespace - storage is corrupted
        identity_status_ = IdentityStatus::Corrupted;
        return;
    }

    // Probe for device_id blob to determine if identity exists
    size_t device_id_size = 0;
    error = nvs_get_blob(handle, IdentityManager::NvsKeyDeviceId, nullptr, &device_id_size);

    if (error == ESP_ERR_NVS_NOT_FOUND) {
        // No entry under device_id key
        identity_status_ = IdentityStatus::NotPresent;
        nvs_close(handle);
        return;
    }
    if (error != ESP_OK || device_id_size != IdentityManager::DeviceIdSize) {
        identity_status_ = IdentityStatus::Corrupted;
        nvs_close(handle);
        return;
    }

    // Contents exist, mark identity as present
    identity_status_ = IdentityStatus::Present;

    // Load key metadata
    size_t key_meta_size = 0;
    error = nvs_get_blob(handle, IdentityManager::NvsKeyKeyMeta, nullptr, &key_meta_size);
    if (error == ESP_ERR_NVS_NOT_FOUND) {
        // Identity exists but no keys yet 
        key_status_ = KeyStatus::NotPresent;
        key_algorithm_ = KeyAlgorithm::None;
        nvs_close(handle);
        return;
    }
    if (error != ESP_OK || key_meta_size != sizeof(KeyMeta)) {
        key_status_ = KeyStatus::Corrupted;
        key_algorithm_ = KeyAlgorithm::None;
        nvs_close(handle);
        return;
    }
    
    KeyMeta meta;
    error = nvs_get_blob(handle, IdentityManager::NvsKeyKeyMeta, &meta, &key_meta_size);
    if (error != ESP_OK) {
        key_status_ = KeyStatus::Corrupted;
        key_algorithm_ = KeyAlgorithm::None;
        nvs_close(handle);
        return;
    }
    // Verify presence of actual key material
    size_t priv_size = 0;
    size_t pub_size  = 0;

    if (nvs_get_blob(handle, NvsKeyPrivateKey, nullptr, &priv_size) != ESP_OK ||
        nvs_get_blob(handle, NvsKeyPublicKey,  nullptr, &pub_size)  != ESP_OK ||
        priv_size == 0 || pub_size == 0) {
        // Metadata exists but key material is incomplete
        key_status_ = KeyStatus::Corrupted;
        key_algorithm_ = KeyAlgorithm::None;
        nvs_close(handle);
        return;
    }
    // Validate algorithm to protect from downgrade attacks
    if (meta.algorithm != static_cast<uint8_t>(KeyAlgorithm::ECDSA_P256)) {
        key_status_ = KeyStatus::Corrupted;
        key_algorithm_ = KeyAlgorithm::None;
    } else {
        key_status_ = KeyStatus::Present;
        key_algorithm_ = KeyAlgorithm::ECDSA_P256;
    }

    nvs_close(handle);
}

bool IdentityManager::generate_identity()
{
    nvs_handle_t handle;
    // Open identity namespace in read-write mode
    esp_err_t error = nvs_open(IdentityManager::NvsNamespace, NVS_READWRITE, &handle);
    // The difference from IdentityManager::init here is that if the mode 
    // is read write and if identity doesn't exist we expect it to be created.
    // That's why we don't tolerate any error in this step.
    if (error != ESP_OK) {
        identity_status_ = IdentityStatus::Corrupted;
        return false;
    }

    // Check if identity already exists (no overwrite allowed)
    size_t existing_size = 0;
    error = nvs_get_blob(handle, IdentityManager::NvsKeyDeviceId, nullptr, &existing_size);
    if (error == ESP_OK && existing_size > 0) {
        // Identity already exists, do NOT overwrite
        nvs_close(handle);
        identity_status_ = IdentityStatus::Present;
        return true;
    }
    if (error != ESP_OK && error != ESP_ERR_NVS_NOT_FOUND) {
        // Unexpected error while checking
        nvs_close(handle);
        identity_status_ = IdentityStatus::Corrupted;
        return false;
    }

    // Generate cryptographically secure random device ID
    uint8_t device_id[IdentityManager::DeviceIdSize];
    esp_fill_random(device_id, IdentityManager::DeviceIdSize);
    // Persist device ID to NVS
    error = nvs_set_blob(handle, IdentityManager::NvsKeyDeviceId, device_id, IdentityManager::DeviceIdSize);
    if (error != ESP_OK) {
        nvs_close(handle);
        identity_status_ = IdentityStatus::Corrupted;
        return false;
    }

    // IMPORTANT: Commit changes to flash - without this, writes are not persistent
    error = nvs_commit(handle);
    if (error != ESP_OK) {
        nvs_close(handle);
        identity_status_ = IdentityStatus::Corrupted;
        return false;
    }

    // Identity successfully created and persisted
    nvs_close(handle);
    identity_status_ = IdentityStatus::Present;
    return true;
}

bool IdentityManager::generate_keys()
{
    bool success = true;

    // Don't generate keys without identity
    if (identity_status_ != IdentityStatus::Present) {
        return false;
    }    

    // Generate only if keys are not present
    if (key_status_ == KeyStatus::Present) {
        return true;
    } else if (key_status_ == KeyStatus::Corrupted) {
        return false;
    }

    nvs_handle_t handle;
    esp_err_t error = nvs_open(IdentityManager::NvsNamespace, NVS_READWRITE, &handle);
    // Unlike init(), we use READWRITE mode here because we may need to create the namespace
    // Any error opening NVS indicates storage corruption
    if (error != ESP_OK) {
        key_status_ = KeyStatus::Corrupted;
        return false;
    }

    // Initialize mbedTLS contexts for key generation
    mbedtls_pk_context pk;                 // Public key container - supports ECC and RSA keys
    mbedtls_entropy_context entropy;       // Hardware entropy source for cryptographic randomness
    mbedtls_ctr_drbg_context ctr_drbg;     // Deterministic Random Bit Generator - seeded from entropy
    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // Use do-while(false) pattern for structured error handling without goto
    do {
        // Personalization string seeds the DRBG with application-specific data
        // This mitigates low-entropy startup conditions and ensures each application
        // instance has a unique DRBG state even with identical hardware entropy
        const unsigned char personalization_label[] = "zt-identity";
        if (mbedtls_ctr_drbg_seed(&ctr_drbg, 
                                  mbedtls_entropy_func, // mbedTLS callback to collect hardware entropy
                                  &entropy,
                                  personalization_label,
                                  sizeof(personalization_label) - 1) != 0) {
            // DRBG seeding failed - insufficient entropy or hardware fault
            success = false;
            break;
        }

        // Configure pk context to hold an ECC (elliptic curve) key
        // ECC is the standard for device identity, TLS, and attestation
        if (mbedtls_pk_setup(&pk,
                mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) != 0) {
            // Key type not supported - configuration error
            success = false;
            break;
        }

        // Generate ECC keypair on NIST P-256 curve (provides 128-bit security level)
        // P-256 is the standard curve for TLS, device identity, and attestation protocols
        if (mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,
                                mbedtls_pk_ec(pk), // Extract ECC-specific structure from pk context
                                mbedtls_ctr_drbg_random, // Use DRBG as randomness source for key generation
                                &ctr_drbg) != 0) {
            // Key generation failed - pk context is invalid from this point
            success = false;
            break;
        }

        // Keys are currently in mbedTLS internal format and cannot be stored directly
        // Convert to DER (Distinguished Encoding Rules) format - ASN.1 binary encoding
        // DER is the standard format for key serialization and interoperability
        uint8_t priv_buf[IdentityManager::PrivateKeyDerMax];
        uint8_t pub_buf[IdentityManager::PublicKeyDerMax];

        // Extract private key in DER format - mbedTLS writes backwards from end of buffer
        // Returns number of bytes written, or negative value on error
        int priv_len = mbedtls_pk_write_key_der(&pk, priv_buf, IdentityManager::PrivateKeyDerMax);
        if (priv_len <= 0) {
            success = false;
            break;
        }
        // Extract public key in DER format
        int pub_len = mbedtls_pk_write_pubkey_der(&pk, pub_buf, IdentityManager::PublicKeyDerMax);
        if (pub_len <= 0) {
            success = false;
            break;
        }
        // DER writers write backwards, so valid data starts at (buffer_end - length)
        const uint8_t* priv_key = priv_buf + IdentityManager::PrivateKeyDerMax - priv_len;
        const uint8_t* pub_key  = pub_buf  + IdentityManager::PublicKeyDerMax  - pub_len;

        // Persist keys to NVS
        error = nvs_set_blob(handle, IdentityManager::NvsKeyPrivateKey, priv_key, priv_len);
        if (error != ESP_OK) {
            success = false;
            break;
        }
        error = nvs_set_blob(handle, IdentityManager::NvsKeyPublicKey, pub_key, pub_len);
        if (error != ESP_OK) {
            success = false;
            break;
        }

        // IMPORTANT: Write key metadata LAST - it serves as a validity indicator
        // If key_meta exists and is valid, we assume all key data is complete and correct
        KeyMeta meta {
            .algorithm = static_cast<uint8_t>(KeyAlgorithm::ECDSA_P256)
        };
        error = nvs_set_blob(handle, IdentityManager::NvsKeyKeyMeta, &meta, sizeof(meta));
        if (error != ESP_OK) {
            success = false;
            break;
        }

        // IMPORTANT: Commit changes to flash - without this, writes are not persistent
        error = nvs_commit(handle);
        if (error != ESP_OK) {
            success = false;
            break;
        }
    } while (false);

    // Cleanup mbedTLS contexts and NVS handle
    nvs_close(handle);
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    if (success) {
        key_status_ = KeyStatus::Present;
        key_algorithm_ = KeyAlgorithm::ECDSA_P256;
        return true;
    } else {
        key_status_ = KeyStatus::Corrupted;
        key_algorithm_ = KeyAlgorithm::None;
        return false;
    }
}

bool IdentityManager::sign(const uint8_t* data, size_t datalen, uint8_t* sig, size_t* sig_len)
{
    // Validate input parameters
    if (!data || !sig || !sig_len || datalen == 0) {
        return false;
    }

    // Verify identity and cryptographic keys are ready for signing
    // All three conditions must be met: identity exists, keys exist, and algorithm matches
    if (identity_status_ != IdentityStatus::Present ||
        key_status_ != KeyStatus::Present ||
        key_algorithm_ != KeyAlgorithm::ECDSA_P256) {
        return false;
    }

    // Open NVS namespace in read-only mode to retrieve private key
    nvs_handle_t handle;
    esp_err_t error = nvs_open(IdentityManager::NvsNamespace, NVS_READONLY, &handle);
    if (error != ESP_OK) {
        return false;
    }

    // Probe for private key blob size (first call with nullptr to get required size)
    size_t priv_size = 0;
    error = nvs_get_blob(handle, IdentityManager::NvsKeyPrivateKey, nullptr, &priv_size);
    if (error != ESP_OK || priv_size == 0) {
        nvs_close(handle);
        return false;
    }

    // Allocate variable-length array for private key DER data
    uint8_t priv_buf[priv_size];
    error = nvs_get_blob(handle, IdentityManager::NvsKeyPrivateKey, priv_buf, &priv_size);
    nvs_close(handle); // Close handle immediately after loading - key is now in memory

    if (error != ESP_OK) {
        return false;
    }

    // Initialize mbedTLS contexts for cryptographic operations
    mbedtls_pk_context pk;                 // Public key container - supports ECC and RSA keys
    mbedtls_entropy_context entropy;       // Hardware entropy source for cryptographic randomness
    mbedtls_ctr_drbg_context ctr_drbg;     // Deterministic Random Bit Generator - seeded from entropy

    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    bool success = false;

    // Use do-while(false) pattern for structured error handling
    do {
        // Parse private key from DER format into mbedTLS pk context
        // After this, pk context can be used for signing operations
        if (mbedtls_pk_parse_key(&pk,
                                 priv_buf,
                                 priv_size,
                                 nullptr,                 // Password - keys are not encrypted
                                 0,                       // Password length
                                 mbedtls_ctr_drbg_random, // DRBG callback (required but unused for unencrypted keys)
                                 &ctr_drbg) != 0) {
            break;
        }

        // Seed DRBG with hardware entropy for signature randomness
        // Personalization string ensures unique state for signing operations
        const unsigned char personalization[] = "zt-sign";
        if (mbedtls_ctr_drbg_seed(&ctr_drbg,
                                  mbedtls_entropy_func, // mbedTLS callback to collect hardware entropy
                                  &entropy,
                                  personalization,
                                  sizeof(personalization) - 1) != 0) {
            break;
        }

        // Hash input data with SHA-256 before signing
        // ECDSA signs the hash, not the raw data directly
        uint8_t hash[IdentityManager::Sha256HashSize];
        if (mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), // Get SHA-256 algorithm descriptor
                       data,
                       datalen,
                       hash) != 0) {
            break;
        }

        // Sign the hash using ECDSA P-256 private key
        // Signature is written to sig buffer, actual length returned in out_len
        size_t out_len = 0;
        if (mbedtls_pk_sign(&pk,
                            MBEDTLS_MD_SHA256,
                            hash,
                            IdentityManager::Sha256HashSize,
                            sig,
                            *sig_len,                // Maximum signature size (input)
                            &out_len,                // Actual signature size (output, <= sig_len)
                            mbedtls_ctr_drbg_random, // DRBG for ECDSA nonce generation
                            &ctr_drbg) != 0) {
            break;
        }

        *sig_len = out_len; // Update caller's signature length with actual size
        success = true;
    } while (false);

    // Release mbedTLS resources
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    // Zero out private key buffer to prevent memory leaks of sensitive data
    // Critical security practice - private key material must be cleared
    memset(priv_buf, 0, sizeof(priv_buf));

    return success;
}

bool IdentityManager::factory_reset()
{
    nvs_handle_t handle;
    // Open namespace in read-write mode to perform destructive operations
    esp_err_t error = nvs_open(IdentityManager::NvsNamespace, NVS_READWRITE, &handle);
    // Unlike init(), we use READWRITE mode because we need to erase data
    // Any error opening NVS indicates storage corruption
    if (error != ESP_OK) {
        identity_status_ = IdentityStatus::Corrupted;
        key_status_ = KeyStatus::Corrupted;
        key_algorithm_ = KeyAlgorithm::None;
        return false;
    }

    // Erase all identity-related keys
    // ESP_ERR_NVS_NOT_FOUND is acceptable (keys may already be absent)
    const char* keys_to_erase[] = {
        IdentityManager::NvsKeyDeviceId,
        IdentityManager::NvsKeyPrivateKey,
        IdentityManager::NvsKeyPublicKey,
        IdentityManager::NvsKeyKeyMeta
    };

    for (const char* key : keys_to_erase) {
        error = nvs_erase_key(handle, key);
        if (error != ESP_OK && error != ESP_ERR_NVS_NOT_FOUND) {
            // Unexpected error - storage corruption
            nvs_close(handle);
            identity_status_ = IdentityStatus::Corrupted;
            key_status_ = KeyStatus::Corrupted;
            key_algorithm_ = KeyAlgorithm::None;
            return false;
        }
    }

    // IMPORTANT: Commit all erasures to flash - without this, changes are not persistent
    error = nvs_commit(handle);
    if (error != ESP_OK) {
        nvs_close(handle);
        identity_status_ = IdentityStatus::Corrupted;
        key_status_ = KeyStatus::Corrupted;
        key_algorithm_ = KeyAlgorithm::None;
        return false;
    }

    // Factory reset complete - all identity data is now erased
    nvs_close(handle);
    identity_status_ = IdentityStatus::NotPresent;
    key_status_ = KeyStatus::NotPresent;
    key_algorithm_ = KeyAlgorithm::None;
    return true;
}

bool IdentityManager::get_device_id(uint8_t* id_out, size_t device_id_len) const
{
    // Validate output buffer and length matches expected device ID size
    if (!id_out || device_id_len != IdentityManager::DeviceIdSize) {
        return false;
    }

    // Identity needs to be present to read it
    if (identity_status_ != IdentityStatus::Present) {
        return false;
    }

    nvs_handle_t handle;
    esp_err_t error = nvs_open(IdentityManager::NvsNamespace, NVS_READONLY, &handle);
    if (error != ESP_OK) {
        return false;
    }

    size_t device_id_size = IdentityManager::DeviceIdSize;
    error = nvs_get_blob(handle, IdentityManager::NvsKeyDeviceId, id_out, &device_id_size);
    nvs_close(handle);

    // Verify NVS read succeeded and returned expected size
    if (error != ESP_OK || device_id_size != IdentityManager::DeviceIdSize) {
        return false;
    }

    return true;
}

bool IdentityManager::get_public_key_der(uint8_t* pub_key_out, size_t* pub_key_len) const
{
    if (!pub_key_out || !pub_key_len || *pub_key_len == 0) {
        return false;
    }

    if (key_status_ != KeyStatus::Present) {
        return false;
    }

    nvs_handle_t handle;
    esp_err_t error = nvs_open(IdentityManager::NvsNamespace, NVS_READONLY, &handle);
    if (error != ESP_OK) {
        return false;
    }

    size_t stored_size = 0;
    error = nvs_get_blob(handle, IdentityManager::NvsKeyPublicKey, nullptr, &stored_size);
    if (error != ESP_OK || stored_size == 0 || stored_size > *pub_key_len) {
        nvs_close(handle);
        return false;
    }

    error = nvs_get_blob(handle, IdentityManager::NvsKeyPublicKey, pub_key_out, &stored_size);
    nvs_close(handle);

    if (error != ESP_OK) {
        return false;
    }

    *pub_key_len = stored_size;
    return true;
}

} // namespace zerotrust::identity


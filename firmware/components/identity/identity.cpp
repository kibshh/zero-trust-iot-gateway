#include "identity.h"

#include "nvs_flash.h"
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

    esp_err_t error = nvs_flash_init();
    if (error == ESP_ERR_NVS_NO_FREE_PAGES || 
        error == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        // NVS partition is full or NVS needs to be updated to new version
        // Both errors are normal and expected in NVS lifecycle
        error = nvs_flash_erase();
        if (error != ESP_OK) {
            // Flash write doesn't work, faulty hardware
            identity_status_ = IdentityStatus::Corrupted;
            return;
        }
        // Retry initialization
        error = nvs_flash_init();
    }
    if (error != ESP_OK) {
        // NVS itself is broken, identity cannot be trusted
        identity_status_ = IdentityStatus::Corrupted;
        return;
    }

    // NVS is now initialized successfully
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

} // namespace zerotrust::identity


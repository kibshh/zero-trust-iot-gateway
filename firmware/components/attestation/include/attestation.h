#ifndef FIRMWARE_COMPONENTS_ATTESTATION_INCLUDE_ATTESTATION_H
#define FIRMWARE_COMPONENTS_ATTESTATION_INCLUDE_ATTESTATION_H

#include <cstdint>
#include <cstddef>

#include "identity.h"

namespace zerotrust::attestation {

enum class AttestationStatus : uint8_t {
    Ok,
    IdentityMissing,
    KeyMissing,
    InternalError
};

// Input from backend in form of Nonce (Random number used ONCE)
struct AttestationChallenge {
    const uint8_t* nonce;
    size_t nonce_len; // Nonce length has fixed size per protocol but size can vary from protocol to protocol
};

// Output sent back to backend
struct AttestationResponse {
    const uint8_t* device_id;
    size_t device_id_len;
    const uint8_t* firmware_hash;
    size_t firmware_hash_len;
    const uint8_t* signature;
    size_t signature_len;
};

// Stateless attestation engine
// NOT THREAD-SAFE: generate_response() uses static buffers for firmware_hash,
// sign_buffer, signature, and device_id to avoid stack allocation.
// Only call from a single thread (main task) or protect with mutex.
class AttestationEngine {
public:
    static constexpr size_t FirmwareReadChunkSize = 256;  // Buffer size for reading firmware partition in chunks
    static constexpr size_t CanonicalSignBufferSize = 256;  // Buffer size for canonical attestation data (nonce || device_id || firmware_hash)
    static constexpr size_t MaxSignatureDerSize = 72;  // Maximum size for ECDSA P-256 signature in DER format

    explicit AttestationEngine(identity::IdentityManager& identity) : identity_(identity) {};

    // Generate an attestation response for a given challenge
    // challenge: The challenge to sign
    // response: The response to populate
    // Returns the status of the attestation operation
    AttestationStatus generate_response(
        const AttestationChallenge& challenge,
        AttestationResponse& response);

private:
    identity::IdentityManager& identity_; // Reference because identity is system-owned
};

} // namespace zerotrust::attestation

#endif


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
class AttestationEngine {
public:
    explicit AttestationEngine(identity::IdentityManager& identity) : identity_(identity) {};

    AttestationStatus generate_response(
        const AttestationChallenge& challenge,
        AttestationResponse& response);

private:
    identity::IdentityManager& identity_; // Reference because identity is system-owned
};

} // namespace zerotrust::attestation

#endif


#ifndef FIRMWARE_COMPONENTS_SYSTEM_CONTROLLER_INCLUDE_SYSTEM_CONTROLLER_H
#define FIRMWARE_COMPONENTS_SYSTEM_CONTROLLER_INCLUDE_SYSTEM_CONTROLLER_H

#include <cstddef>
#include <cstdint>

#include "system_state.h"
#include "identity.h"
#include "attestation.h"
#include "policy.h"

namespace zerotrust::system_controller {

// High-level orchestrator for system behavior
// Owns no resources, only coordinates subsystems, thats why it uses references
class SystemController {
public:
    SystemController(system_state::SystemStateMachine& fsm,
                     identity::IdentityManager& identity,
                     attestation::AttestationEngine& attestation);

    // Called once at boot
    void on_boot();

    // Called when backend sends attestation challenge
    bool on_attestation_challenge(const uint8_t* nonce,
                                  size_t nonce_len,
                                  attestation::AttestationResponse& response);

    // Called when backend responds with authorization decision
    void on_authorization_result(bool granted);

    // Called when policy result is available
    void on_policy_result(policy::PolicyLoadResult result);


private:
    system_state::SystemStateMachine& fsm_;
    identity::IdentityManager& identity_;
    attestation::AttestationEngine& attestation_;
};

} // namespace zerotrust::system_controller

#endif // FIRMWARE_COMPONENTS_SYSTEM_CONTROLLER_INCLUDE_SYSTEM_CONTROLLER_H


#ifndef FIRMWARE_COMPONENTS_SYSTEM_CONTROLLER_INCLUDE_SYSTEM_CONTROLLER_H
#define FIRMWARE_COMPONENTS_SYSTEM_CONTROLLER_INCLUDE_SYSTEM_CONTROLLER_H

#include <cstddef>
#include <cstdint>

#include "system_state.h"
#include "identity.h"
#include "attestation.h"
#include "policy_types.h"
#include "policy_manager.h"

namespace zerotrust::system_controller {

// High-level orchestrator for system behavior
// Owns no resources, only coordinates subsystems, thats why it uses references
class SystemController {
public:
    SystemController(system_state::SystemStateMachine& fsm,
                     identity::IdentityManager& identity,
                     attestation::AttestationEngine& attestation,
                     policy::PolicyManager& policy_mgr);

    // Called once at boot
    void on_boot();

    // Called when backend sends attestation challenge
    bool on_attestation_challenge(const uint8_t* nonce,
                                  size_t nonce_len,
                                  attestation::AttestationResponse& response);

    // Called when backend responds with authorization decision
    void on_authorization_result(bool granted);

    // Called when policy blob is received from backend
    // Loads, verifies, persists and activates the policy
    void on_policy_blob_received(const uint8_t* data, size_t len);

    // Called when policy load result is available (if loading done externally)
    void on_policy_result(policy::PolicyLoadResult result);

    // Called periodically
    void on_periodic_tick();

    // Centralized policy-enforced action execution
    // Evaluates action against policy and triggers FSM events on violations
    policy::PolicyDecision authorize_action(policy::PolicyAction action,
                                            const policy::PolicyContext& ctx);

private:
    // Handle policy decision outcome
    // Triggers PolicyViolation event if policy explicitly denies action
    void on_policy_decision(policy::PolicyDecision decision,
                            policy::PolicyDecisionSource source);
    system_state::SystemStateMachine& fsm_;
    identity::IdentityManager& identity_;
    attestation::AttestationEngine& attestation_;
    policy::PolicyManager& policy_mgr_;
};

} // namespace zerotrust::system_controller

#endif // FIRMWARE_COMPONENTS_SYSTEM_CONTROLLER_INCLUDE_SYSTEM_CONTROLLER_H


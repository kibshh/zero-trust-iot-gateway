#include "system_controller.h"

namespace zerotrust::system_controller {

namespace {

// Try to process event, if it fails lock the device
// This ensures fail-safe behavior - any unexpected state results in lock
void process_event_or_lock(system_state::SystemStateMachine& fsm,
                           system_state::SystemEvent event)
{
    if (!fsm.process_event(event)) {
        // Manual lock is allowed in any state so we can ignore the return value
        (void)fsm.process_event(system_state::SystemEvent::ManualLock);
    }
}

} // anonymous namespace

SystemController::SystemController(system_state::SystemStateMachine& fsm,
                                   identity::IdentityManager& identity,
                                   attestation::AttestationEngine& attestation)
    : fsm_(fsm),
      identity_(identity),
      attestation_(attestation) {}

void SystemController::on_boot()
{
    if (fsm_.get_state() != system_state::SystemState::Init) {
        // Boot is only allowed in Init state
        return;
    }

    // Initialize identity manager (probes NVS for existing identity)
    identity_.init();

    if (identity_.get_identity_status() == identity::IdentityStatus::Corrupted ||
        identity_.get_key_status() == identity::KeyStatus::Corrupted) {
        // Identity or key is corrupted, so we need to lock the device, hard security failure
        process_event_or_lock(fsm_, system_state::SystemEvent::ManualLock);
        return;
    }

    // Ensure identity exists
    if (identity_.get_identity_status() == identity::IdentityStatus::NotPresent) {
        if (!identity_.generate_identity()) {
            // Identity generation failed, so we need to lock the device, hard security failure
            process_event_or_lock(fsm_, system_state::SystemEvent::ManualLock);
            return;
        }
    }

    // Ensure keys exist
    if (identity_.get_key_status() == identity::KeyStatus::NotPresent) {
        if (!identity_.generate_keys()) {
            // Key generation failed, so we need to lock the device, hard security failure
            process_event_or_lock(fsm_, system_state::SystemEvent::ManualLock);
            return;
        }
    }

    // Boot is successful
    process_event_or_lock(fsm_, system_state::SystemEvent::BootCompleted);
}

bool SystemController::on_attestation_challenge(const uint8_t* nonce,
                                                size_t nonce_len,
                                                attestation::AttestationResponse& response)
{
    if (fsm_.get_state() != system_state::SystemState::IdentityReady &&
        fsm_.get_state() != system_state::SystemState::Attested) {
        // Attestation is only allowed in IdentityReady or Attested state
        return false;
    }

    // Build challenge structure
    attestation::AttestationChallenge challenge {
        .nonce = nonce,
        .nonce_len = nonce_len
    };

    // Generate attestation response
    auto status = attestation_.generate_response(challenge, response);

    switch (status) {
        case attestation::AttestationStatus::Ok:
            process_event_or_lock(fsm_, system_state::SystemEvent::AttestationSucceeded);
            return true;
        case attestation::AttestationStatus::IdentityMissing:
        case attestation::AttestationStatus::KeyMissing:
            // Identity or key is missing, so we need to lock the device
            // This is a security feature to prevent the device from being used if the identity or key is missing
            process_event_or_lock(fsm_, system_state::SystemEvent::ManualLock);
            return false;
        case attestation::AttestationStatus::InternalError:
            // Transient error (e.g. invalid nonce, flash read glitch)
            // Do NOT change FSM state, allow retry
            return false;
        default:
            // Unreachable, silences compiler warning
            return false;
    }
}

void SystemController::on_authorization_result(bool granted)
{
    if (fsm_.get_state() != system_state::SystemState::Attested) {
        // Authorization is only allowed in Attested state
        return;
    }

    if (granted) {
        process_event_or_lock(fsm_, system_state::SystemEvent::AuthorizationGranted);
    } else {
        process_event_or_lock(fsm_, system_state::SystemEvent::AuthorizationDenied);
    }
}

void SystemController::on_policy_result(policy::PolicyLoadResult result)
{
    if (fsm_.get_state() != system_state::SystemState::Authorized) {
        // Policy handling is only valid in Authorized state
        return;
    }

    switch (result) {
        case policy::PolicyLoadResult::Ok:
            // Policy verified, persisted and activated
            // Device is now fully operational
            process_event_or_lock(fsm_, system_state::SystemEvent::PolicyLoaded);
            break;

        case policy::PolicyLoadResult::TransientError:
            // Network / timing / partial delivery issue
            // Stay in Authorized and wait for backend retry
            // DO NOT change FSM state
            break;

        case policy::PolicyLoadResult::SecurityViolation:
            // Invalid signature, rollback attempt, device mismatch
            // Trust is broken -> immediate lock
            process_event_or_lock(fsm_, system_state::SystemEvent::ManualLock);
            break;

        default:
            // Defensive: unknown result -> fail closed
            process_event_or_lock(
                fsm_,
                system_state::SystemEvent::ManualLock
            );
            break;
    }
}


} // namespace zerotrust::system_controller


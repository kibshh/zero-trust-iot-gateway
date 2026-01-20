#include "system_controller.h"

#include <cstring>

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
                                   attestation::AttestationEngine& attestation,
                                   policy::PolicyManager& policy_mgr,
                                   backend::BackendClient& backend_client)
    : fsm_(fsm),
      identity_(identity),
      attestation_(attestation),
      policy_mgr_(policy_mgr),
      backend_client_(backend_client) {}

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
            // Not finished yet, wait for backend response
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

void SystemController::on_attestation_verify_result(backend::BackendStatus status)
{
    switch (status) {
        case backend::BackendStatus::Ok:
            process_event_or_lock(fsm_, system_state::SystemEvent::AttestationSucceeded);
            break;

        case backend::BackendStatus::Denied:
            // Attestation rejected - could be firmware update in progress
            // Allow retry, main loop can implement backoff
            break;

        case backend::BackendStatus::Timeout:
        case backend::BackendStatus::NetworkError:
            // Transient error - retry allowed
            break;

        case backend::BackendStatus::InvalidResponse:
        case backend::BackendStatus::ServerError:
        default:
            // Protocol / backend violation - lock device
            process_event_or_lock(fsm_, system_state::SystemEvent::ManualLock);
            break;
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

void SystemController::on_policy_blob_received(const uint8_t* data, size_t len)
{
    // Basic sanity check (backend bug / transport corruption)
    if (!data || len == 0) {
        return;  // Ignore silently, backend can retry
    }

    // Policy must only be processed in Authorized state
    if (fsm_.get_state() != system_state::SystemState::Authorized) {
        return;
    }

    policy::PolicyBlob blob{data, len};
    policy::PolicyLoadResult result = policy_mgr_.load_policy(blob);

    // Delegate to on_policy_result for FSM transitions
    on_policy_result(result);
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
            process_event_or_lock(fsm_, system_state::SystemEvent::PolicyViolation);
            break;
        default:
            // Unreachable, silences compiler warning
            break;
    }
}

void SystemController::on_periodic_tick()
{
    system_state::SystemState state = fsm_.get_state();

    // Policy expiration is relevant only in runtime states
    if (state != system_state::SystemState::Operational &&
        state != system_state::SystemState::Degraded) {
        return;
    }

    if (policy_mgr_.is_policy_expired()) {
        // Policy has expired, lock the device
        process_event_or_lock(fsm_, system_state::SystemEvent::PolicyExpired);
    }
}

policy::PolicyDecision SystemController::authorize_action(
    policy::PolicyAction action,
    const policy::PolicyContext& ctx)
{
    policy::PolicyDecision decision = policy_mgr_.evaluate(action, ctx);

    // Get the engine that made the decision to retrieve audit record
    const policy::PolicyEngine& engine =
        (policy_mgr_.is_policy_active())
            ? policy_mgr_.get_policy_engine()
            : policy_mgr_.get_baseline_engine();

    // Retrieve the most recent audit record (just written by evaluate)
    const policy::PolicyAuditRecord* record =
        engine.get_audit_record(engine.get_audit_count() - 1);

    if (record) {
        on_policy_decision(record->decision, record->source);
    }

    return decision;
}

void SystemController::on_policy_decision(
    policy::PolicyDecision decision,
    policy::PolicyDecisionSource source)
{
    // Only trigger violation event if policy explicitly denied the action
    // Baseline denials don't trigger violations (expected behavior)
    if (decision == policy::PolicyDecision::Deny &&
        source == policy::PolicyDecisionSource::Policy)
    {
        process_event_or_lock(fsm_, system_state::SystemEvent::PolicyViolation);
    }
}

bool SystemController::try_register_device()
{
    if (fsm_.get_state() != system_state::SystemState::IdentityReady) {
        return false;
    }

    uint8_t device_id[identity::IdentityManager::DeviceIdSize];
    if (!identity_.get_device_id(device_id, sizeof(device_id))) {
        return false;
    }

    uint8_t public_key[identity::IdentityManager::PublicKeyDerMax];
    size_t public_key_len = sizeof(public_key);
    if (!identity_.get_public_key_der(public_key, &public_key_len)) {
        return false;
    }

    backend::BackendStatus status = backend_client_.register_device(
        device_id, sizeof(device_id),
        public_key, public_key_len);

    memset(public_key, 0, public_key_len); // Secure zero after use

    switch (status) {
        case backend::BackendStatus::Ok:
        case backend::BackendStatus::AlreadyExists:
            // Success or already registered - both are valid
            return true;
        case backend::BackendStatus::Timeout:
        case backend::BackendStatus::NetworkError:
            // Transient error - retry allowed
            return false;
        case backend::BackendStatus::InvalidArgument:
        case backend::BackendStatus::InvalidResponse:
        case backend::BackendStatus::ServerError:
        default:
            // Protocol / backend violation - lock device
            process_event_or_lock(fsm_, system_state::SystemEvent::ManualLock);
            return false;
    }
}

bool SystemController::try_attest()
{
    if (fsm_.get_state() != system_state::SystemState::IdentityReady) {
        return false;
    }

    // Step 1: Get device ID for challenge request
    uint8_t device_id[identity::IdentityManager::DeviceIdSize];
    if (!identity_.get_device_id(device_id, sizeof(device_id))) {
        process_event_or_lock(fsm_, system_state::SystemEvent::ManualLock);
        return false;
    }

    // Step 2: Request attestation challenge from backend
    backend::ChallengeResponse challenge_resp{};
    backend::BackendStatus status = backend_client_.request_attestation_challenge(
        device_id, sizeof(device_id), challenge_resp);

    if (status != backend::BackendStatus::Ok) {
        // Handle challenge request failure
        switch (status) {
            case backend::BackendStatus::Timeout:
            case backend::BackendStatus::NetworkError:
                // Transient error - retry allowed
                return false;
            case backend::BackendStatus::Denied:
            case backend::BackendStatus::InvalidResponse:
            case backend::BackendStatus::ServerError:
            default:
                // Protocol / backend violation - lock device
                process_event_or_lock(fsm_, system_state::SystemEvent::ManualLock);
                return false;
        }
    }

    // Step 3: Generate attestation response using the nonce
    attestation::AttestationResponse attest_resp{};
    if (!on_attestation_challenge(challenge_resp.nonce, backend::BackendClient::NonceSize, attest_resp)) {
        // on_attestation_challenge handles FSM transitions on critical failures
        // Return false to indicate attestation did not complete
        return false;
    }

    // Step 4: Send attestation response to backend for verification
    status = backend_client_.verify_attestation(attest_resp);

    // Step 5: Process verification result (handles FSM transitions)
    on_attestation_verify_result(status);

    // Return true only if we transitioned to Attested
    return fsm_.get_state() == system_state::SystemState::Attested;
}

} // namespace zerotrust::system_controller


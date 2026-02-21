#include "system_controller.h"

#include <cstring>

#include "time_sync.h"

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

    // Step 1: Get device ID
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
        switch (status) {
            case backend::BackendStatus::Timeout:
            case backend::BackendStatus::NetworkError:
                // Transient error - retry allowed
                return false;
            default:
                // Protocol / backend violation - lock device
                process_event_or_lock(fsm_, system_state::SystemEvent::ManualLock);
                return false;
        }
    }

    // Step 3: Generate attestation response
    // Delegates to on_attestation_challenge (handles FSM transitions on critical failures)
    attestation::AttestationResponse attest_resp{};
    if (!on_attestation_challenge(challenge_resp.nonce, backend::BackendClient::NonceSize, attest_resp)) {
        return false;
    }

    // Step 4: Send attestation response to backend for verification
    status = backend_client_.verify_attestation(attest_resp);

    // Step 5: Process verification result
    // Denied = retry allowed (boot-time, firmware update may be in progress)
    on_attestation_verify_result(status);

    return fsm_.get_state() == system_state::SystemState::Attested;
}

bool SystemController::try_authorize()
{
    if (fsm_.get_state() != system_state::SystemState::Attested) {
        return false;
    }

    // Step 1: Get device ID
    uint8_t device_id[identity::IdentityManager::DeviceIdSize];
    if (!identity_.get_device_id(device_id, sizeof(device_id))) {
        process_event_or_lock(fsm_, system_state::SystemEvent::ManualLock);
        return false;
    }

    // Step 2: Get firmware hash
    uint8_t firmware_hash[attestation::AttestationEngine::FirmwareHashSize];
    if (!attestation::AttestationEngine::get_firmware_hash(firmware_hash)) {
        process_event_or_lock(fsm_, system_state::SystemEvent::ManualLock);
        return false;
    }

    // Step 3: Request authorization from backend
    backend::AuthorizationResponse auth_resp{};
    backend::BackendStatus status = backend_client_.request_authorization(
        device_id, sizeof(device_id),
        firmware_hash, sizeof(firmware_hash),
        auth_resp);

    if (status != backend::BackendStatus::Ok) {
        // Handle backend request failure
        switch (status) {
            case backend::BackendStatus::Timeout:
            case backend::BackendStatus::NetworkError:
                // Transient error - retry allowed
                return false;
            case backend::BackendStatus::InvalidResponse:
            case backend::BackendStatus::ServerError:
            default:
                // Protocol / backend violation - lock device
                process_event_or_lock(fsm_, system_state::SystemEvent::ManualLock);
                return false;
        }
    }

    // Step 4: Check if authorized
    if (!auth_resp.authorized) {
        // Backend explicitly denied authorization
        process_event_or_lock(fsm_, system_state::SystemEvent::AuthorizationDenied);
        return false;
    }

    // Step 5: Verify the policy blob
    if (auth_resp.policy_blob_len == 0) {
        // Authorized but no policy blob - protocol error
        process_event_or_lock(fsm_, system_state::SystemEvent::ManualLock);
        return false;
    }

    // Step 6: Get backend public key for signature verification
    uint8_t backend_pubkey[policy::PolicyManager::MaxBackendPubKeySize];
    size_t pubkey_len = policy_mgr_.get_backend_public_key(
        backend_pubkey, sizeof(backend_pubkey));
    if (pubkey_len == 0) {
        // No backend public key - cannot verify policy
        // This is a provisioning issue, not a transient error
        process_event_or_lock(fsm_, system_state::SystemEvent::ManualLock);
        return false;
    }

    // Step 7: Verify policy blob using PolicyVerifier
    policy::AuthPolicy auth_policy{};
    
    // Get current time from NTP (0 if not synchronized - policy verifier will skip time checks)
    uint64_t current_time = time_sync::TimeSync::get_unix_time();
    
    // Firmware version for anti-rollback (reads secure_version from app descriptor)
    uint64_t firmware_version = attestation::AttestationEngine::get_firmware_version();

    if (!policy_verifier_.verify_and_validate(
            auth_resp.policy_blob, auth_resp.policy_blob_len,
            backend_pubkey, pubkey_len,
            device_id,
            firmware_hash,
            firmware_version,
            current_time,
            &auth_policy)) {
        // Policy verification failed - security violation
        process_event_or_lock(fsm_, system_state::SystemEvent::ManualLock);
        return false;
    }

    // Step 8: Authorization successful - transition to Authorized state
    process_event_or_lock(fsm_, system_state::SystemEvent::AuthorizationGranted);

    // Return true only if we transitioned to Authorized
    return fsm_.get_state() == system_state::SystemState::Authorized;
}

bool SystemController::try_re_attest_periodic()
{
    system_state::SystemState state = fsm_.get_state();
    if (state != system_state::SystemState::Operational &&
        state != system_state::SystemState::Degraded) {
        return false;
    }

    // Step 1: Get device ID
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
        switch (status) {
            case backend::BackendStatus::Timeout:
            case backend::BackendStatus::NetworkError:
                // Transient error - retry allowed
                return false;
            default:
                // Protocol / backend violation - lock device
                process_event_or_lock(fsm_, system_state::SystemEvent::ManualLock);
                return false;
        }
    }

    // Step 3: Generate attestation response
    // Calls generate_response() directly (on_attestation_challenge restricts to IdentityReady/Attested)
    attestation::AttestationChallenge challenge{
        .nonce = challenge_resp.nonce,
        .nonce_len = backend::BackendClient::NonceSize
    };

    attestation::AttestationResponse attest_resp{};
    auto attest_status = attestation_.generate_response(challenge, attest_resp);

    if (attest_status != attestation::AttestationStatus::Ok) {
        if (attest_status == attestation::AttestationStatus::IdentityMissing ||
            attest_status == attestation::AttestationStatus::KeyMissing) {
            process_event_or_lock(fsm_, system_state::SystemEvent::ManualLock);
        }
        return false;
    }

    // Step 4: Send attestation response to backend for verification
    status = backend_client_.verify_attestation(attest_resp);

    // Step 5: Process verification result
    // Denied = lock (runtime, firmware already running — denial means compromise)
    switch (status) {
        case backend::BackendStatus::Ok:
            return true;
        case backend::BackendStatus::Denied:
            process_event_or_lock(fsm_, system_state::SystemEvent::ManualLock);
            return false;
        case backend::BackendStatus::Timeout:
        case backend::BackendStatus::NetworkError:
            // Transient error - retry allowed
            return false;
        default:
            // Protocol / backend violation - lock device
            process_event_or_lock(fsm_, system_state::SystemEvent::ManualLock);
            return false;
    }
}

bool SystemController::try_refresh_policy()
{
    system_state::SystemState state = fsm_.get_state();
    if (state != system_state::SystemState::Operational &&
        state != system_state::SystemState::Degraded) {
        return false;
    }

    if (!policy_mgr_.is_policy_active()) {
        return false;
    }

    // Only refresh if policy is nearing expiration
    int64_t remaining = policy_mgr_.get_policy_seconds_remaining();
    if (remaining < 0) {
        // No expiration set or time unavailable — nothing to refresh
        return false;
    }
    if (remaining > policy::PolicyManager::PolicyRefreshThresholdSec) {
        return false;
    }

    // Step 1: Get device ID
    uint8_t device_id[identity::IdentityManager::DeviceIdSize];
    if (!identity_.get_device_id(device_id, sizeof(device_id))) {
        return false;
    }

    // Step 2: Request new runtime policy from backend
    backend::RuntimePolicyResponse policy_resp{};
    backend::BackendStatus status = backend_client_.request_runtime_policy(
        device_id, sizeof(device_id), policy_resp);

    if (status != backend::BackendStatus::Ok || policy_resp.policy_blob_len == 0) {
        // Transient failure — old policy still valid
        return false;
    }

    // Step 3: Load new policy through PolicyManager directly
    // (on_policy_blob_received restricts to Authorized state, we're Operational/Degraded)
    policy::PolicyBlob blob{policy_resp.policy_blob, policy_resp.policy_blob_len};
    policy::PolicyLoadResult result = policy_mgr_.load_policy(blob);

    switch (result) {
        case policy::PolicyLoadResult::Ok:
            return true;
        case policy::PolicyLoadResult::SecurityViolation:
            process_event_or_lock(fsm_, system_state::SystemEvent::PolicyViolation);
            return false;
        case policy::PolicyLoadResult::TransientError:
        default:
            return false;
    }
}

bool SystemController::try_flush_audit()
{
    system_state::SystemState state = fsm_.get_state();
    if (state != system_state::SystemState::Operational &&
        state != system_state::SystemState::Degraded) {
        return false;
    }

    // Collect records from both engines
    policy::PolicyAuditRecord records[policy::PolicyManager::MaxAuditCollectSize];
    size_t count = policy_mgr_.collect_audit(records,
                                             policy::PolicyManager::MaxAuditCollectSize);

    if (count == 0) {
        return true;
    }

    // Get device ID
    uint8_t device_id[identity::IdentityManager::DeviceIdSize];
    if (!identity_.get_device_id(device_id, sizeof(device_id))) {
        return false;
    }

    backend::BackendStatus status = backend_client_.send_audit_records(
        device_id, sizeof(device_id), records, count);

    if (status == backend::BackendStatus::Ok) {
        // Only clear after successful send to avoid losing records
        policy_mgr_.clear_all_audit();
        return true;
    }

    return false;
}

bool SystemController::try_load_runtime_policy()
{
    // Must be in Authorized state (authorization completed, no runtime policy yet)
    if (fsm_.get_state() != system_state::SystemState::Authorized) {
        return false;
    }

    // Step 1: Get device ID
    uint8_t device_id[identity::IdentityManager::DeviceIdSize];
    if (!identity_.get_device_id(device_id, sizeof(device_id))) {
        process_event_or_lock(fsm_, system_state::SystemEvent::ManualLock);
        return false;
    }

    // Step 2: Request runtime policy from backend
    backend::RuntimePolicyResponse policy_resp{};
    backend::BackendStatus status = backend_client_.request_runtime_policy(
        device_id, sizeof(device_id),
        policy_resp);

    if (status != backend::BackendStatus::Ok) {
        switch (status) {
            case backend::BackendStatus::Timeout:
            case backend::BackendStatus::NetworkError:
            case backend::BackendStatus::Denied:
            case backend::BackendStatus::ServerError:
                // Transient or policy not yet available - stay in Authorized, retry later
                return false;

            case backend::BackendStatus::InvalidResponse:
            default:
                // Protocol violation - lock device
                process_event_or_lock(fsm_, system_state::SystemEvent::ManualLock);
                return false;
        }
    }

    // Step 3: Validate we got a non-empty blob
    if (policy_resp.policy_blob_len == 0) {
        // Empty policy from backend - protocol error
        process_event_or_lock(fsm_, system_state::SystemEvent::ManualLock);
        return false;
    }

    // Step 4: Pass blob to on_policy_blob_received which handles:
    //   Parse → Verify signature → Anti-rollback → Persist to NVS → Activate
    //   On success fires PolicyLoaded → Operational
    on_policy_blob_received(policy_resp.policy_blob, policy_resp.policy_blob_len);

    // Step 5: Check if we reached Operational
    return fsm_.get_state() == system_state::SystemState::Operational;
}

bool SystemController::init_time_sync(const time_sync::TimeSyncConfig* config,
                                      bool wait_for_sync,
                                      uint32_t timeout_ms)
{
    if (!time_sync::TimeSync::init(config)) {
        return false;
    }

    if (wait_for_sync) {
        return time_sync::TimeSync::wait_for_sync(timeout_ms);
    }

    return true;
}

bool SystemController::is_time_synchronized() const
{
    return time_sync::TimeSync::is_synchronized();
}

} // namespace zerotrust::system_controller


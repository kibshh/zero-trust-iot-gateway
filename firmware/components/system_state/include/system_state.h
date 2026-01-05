#ifndef FIRMWARE_COMPONENTS_SYSTEM_STATE_INCLUDE_SYSTEM_STATE_H
#define FIRMWARE_COMPONENTS_SYSTEM_STATE_INCLUDE_SYSTEM_STATE_H

#include <cstdint>

namespace zerotrust::system_state {

enum class SystemState : uint8_t {
    Init,           // Initial state - system starting up
    IdentityReady,  // Device identity established, keys generated
    Attested,       // Firmware attestation completed
    Authorized,     // Backend authorization received
    Operational,    // Fully operational, enforcing policies
    Degraded,       // Partial functionality, some features unavailable
    Locked,         // System locked - all actions denied (policy expired/offline)
    Revoked,        // Device revoked by backend - permanent lockout
    _Count          // Number of states (for validation)
};

enum class SystemEvent : uint8_t {
    // Available for Init
    BootCompleted,          // System startup finished successfully
    BootFailed,             // Hardware / integrity failure during boot
    // Available for IdentityReady
    AttestationSucceeded,   // Firmware attestation passed
    AttestationFailed,      // Firmware attestation failed
    IdentityLoadFailed,     // Identity missing or corrupted
    // Available for Attested
    AuthorizationGranted,   // Backend explicitly authorized device
    AuthorizationDenied,    // Backend denied authorization
    // Available for Authorized
    PolicyLoaded,           // Valid policy received and verified
    AuthorizationExpired,   // Backend authorization lease expired (independent of policy)
    // Available for Authorized or Operational
    BackendUnavailable,     // Backend lost / unreachable
    DegradationDetected,    // Partial failure (sensor missing, limited mode)
    // Available for Operational or Degraded
    PolicyViolation,        // Runtime policy violation detected
    PolicyExpired,          // Policy expired
    // Available for Degraded
    BackendAvailable,       // Backend connection restored
    // Available for Locked
    FactoryReset,           // Physical / authenticated factory reset
    // Available for all states
    ManualLock,             // Explicit lock command (admin / backend)
    RevocationReceived      // Permanent backend revocation (no recovery)
};


// System state machine controller
// Manages state transitions and enforces explicit transition rules.
// Undefined transitions are treated as errors.
class SystemStateMachine {
public:
    explicit SystemStateMachine() : current_state_(SystemState::Init) {}
    ~SystemStateMachine() = default;

    // Get current system state
    SystemState get_state() const { return current_state_; }

    // Process an event and transition state if valid
    // Returns true if transition occurred, false if event is invalid for current state
    bool process_event(SystemEvent event);

private:
    SystemState current_state_;
};

} // namespace zerotrust::system_state

#endif // FIRMWARE_COMPONENTS_SYSTEM_STATE_INCLUDE_SYSTEM_STATE_H
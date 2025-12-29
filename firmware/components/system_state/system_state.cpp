#include "system_state.h"

#include <cstddef>

namespace zerotrust::system_state {

namespace {
    
// Transition definition for state machine (internal)
struct Transition {
    SystemState from_state;
    SystemEvent event;
    SystemState to_state;
};

// State machine transition table (internal)
constexpr Transition transitions[] = {
    // Init
    { SystemState::Init,          SystemEvent::BootCompleted,        SystemState::IdentityReady },
    { SystemState::Init,          SystemEvent::BootFailed,           SystemState::Locked },
    // IdentityReady
    { SystemState::IdentityReady, SystemEvent::AttestationSucceeded, SystemState::Attested },
    { SystemState::IdentityReady, SystemEvent::AttestationFailed,    SystemState::Locked },
    { SystemState::IdentityReady, SystemEvent::IdentityLoadFailed,   SystemState::Locked },
    { SystemState::IdentityReady, SystemEvent::ManualLock,           SystemState::Locked },
    { SystemState::IdentityReady, SystemEvent::RevocationReceived,   SystemState::Revoked },
    // Attested
    { SystemState::Attested,      SystemEvent::AuthorizationGranted, SystemState::Authorized },
    { SystemState::Attested,      SystemEvent::AuthorizationDenied,  SystemState::Locked },
    { SystemState::Attested,      SystemEvent::ManualLock,           SystemState::Locked },
    { SystemState::Attested,      SystemEvent::RevocationReceived,   SystemState::Revoked },
    // Authorized
    { SystemState::Authorized,    SystemEvent::PolicyLoaded,         SystemState::Operational },
    { SystemState::Authorized,    SystemEvent::BackendUnavailable,   SystemState::Degraded },
    { SystemState::Authorized,    SystemEvent::AuthorizationExpired, SystemState::Locked },
    { SystemState::Authorized,    SystemEvent::ManualLock,           SystemState::Locked },
    { SystemState::Authorized,    SystemEvent::RevocationReceived,   SystemState::Revoked },
    { SystemState::Authorized,    SystemEvent::DegradationDetected,  SystemState::Degraded },
    // Operational
    { SystemState::Operational,   SystemEvent::PolicyViolation,      SystemState::Locked },
    { SystemState::Operational,   SystemEvent::PolicyExpired,        SystemState::Locked },
    { SystemState::Operational,   SystemEvent::BackendUnavailable,   SystemState::Degraded },
    { SystemState::Operational,   SystemEvent::ManualLock,           SystemState::Locked },
    { SystemState::Operational,   SystemEvent::RevocationReceived,   SystemState::Revoked },
    { SystemState::Operational,   SystemEvent::DegradationDetected,  SystemState::Degraded },
    // Degraded
    { SystemState::Degraded,      SystemEvent::BackendAvailable,     SystemState::Operational },
    { SystemState::Degraded,      SystemEvent::PolicyExpired,        SystemState::Locked },
    { SystemState::Degraded,      SystemEvent::PolicyViolation,      SystemState::Locked },
    { SystemState::Degraded,      SystemEvent::ManualLock,           SystemState::Locked },
    { SystemState::Degraded,      SystemEvent::RevocationReceived,   SystemState::Revoked },
    // Locked
    { SystemState::Locked,        SystemEvent::FactoryReset,         SystemState::Init },
    { SystemState::Locked,        SystemEvent::RevocationReceived,   SystemState::Revoked },
    // Revoked
    // terminal state, no exits
};

constexpr size_t transition_count = sizeof(transitions) / sizeof(transitions[0]);

// Find target state for given current state and event
// Returns true and sets target_state if transition exists, false otherwise
bool find_transition(SystemState current, SystemEvent event, SystemState& target_state) {
    for (size_t i = 0; i < transition_count; ++i) {
        if (transitions[i].from_state == current && 
            transitions[i].event == event) {
            target_state = transitions[i].to_state;
            return true;
        }
    }
    return false;
}

} // anonymous namespace

bool SystemStateMachine::process_event(SystemEvent event) {
    SystemState target_state;
    if (!find_transition(current_state_, event, target_state)) {
        current_state_ = SystemState::Locked; // Lock in case of invalid transition
        return false;
    }
    current_state_ = target_state;
    return true;
}

} // namespace zerotrust::system_state


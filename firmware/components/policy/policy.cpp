#include "policy.h"

namespace zerotrust::policy {

void PolicyEngine::audit(const PolicyAuditRecord& record)
{
    audit_buffer_[audit_head_] = record;
    audit_head_ = (audit_head_ + 1) % AuditBufferSize;
    if (audit_count_ < AuditBufferSize) {
        ++audit_count_;
    }
}

const PolicyAuditRecord* PolicyEngine::get_audit_record(size_t index) const
{
    if (index >= audit_count_) {
        return nullptr;
    }

    // Calculate actual position in circular buffer
    // oldest record is at (head - count) mod size
    size_t oldest_pos = (audit_head_ + AuditBufferSize - audit_count_) % AuditBufferSize;
    size_t actual_pos = (oldest_pos + index) % AuditBufferSize;
    return &audit_buffer_[actual_pos];
}

void PolicyEngine::clear_audit()
{
    audit_head_ = 0;
    audit_count_ = 0;
}

PolicyDecision PolicyEngine::evaluate(PolicyAction action, const PolicyContext& ctx) const
{
    // Zero-trust policy evaluation
    // Default deny unless explicitly allowed by state, actor, and action checks

    // Unknown actors are never trusted under any circumstances
    if (ctx.actor == PolicyActor::Unknown) {
        return PolicyDecision::Deny;
    }

    switch (ctx.state) {
        case system_state::SystemState::Revoked:
            // Permanent lockout - deny everything unconditionally
            return PolicyDecision::Deny;

        case system_state::SystemState::Locked:
            // Recoverable lockout - only System/Backend can perform safe actions
            // Used for integrity failures, policy violations, or manual lock.
            // Only trusted control planes may perform minimal safe actions.
            if (ctx.actor != PolicyActor::System &&
                ctx.actor != PolicyActor::Backend) {
                return PolicyDecision::Deny;
            }
            if (ctx.actor == PolicyActor::Backend && !ctx.backend_connected) { // Prevent spoofing
                return PolicyDecision::Deny;
            }
            switch (action) {
                case PolicyAction::SystemReboot: // Recover from fault
                case PolicyAction::SystemSleep:  // Power saving
                case PolicyAction::StorageRead:  // Diagnostics / forensics
                case PolicyAction::NetworkSend:  // Error reporting to backend
                    return PolicyDecision::Allow;
                default:
                    return PolicyDecision::Deny;
            }

        case system_state::SystemState::Init:
            // Identity, storage, and cryptographic primitives only.
            // No external influence allowed.
            if (ctx.actor != PolicyActor::System) {
                return PolicyDecision::Deny;
            }
            switch (action) {
                case PolicyAction::StorageRead:   // Load identity, keys, configuration
                case PolicyAction::StorageWrite:  // Generate identity, keys
                case PolicyAction::SystemReboot:  // Allow recovery during boot failures
                    return PolicyDecision::Allow;
                default:
                    return PolicyDecision::Deny;
            }

        case system_state::SystemState::IdentityReady:
            // System or connected backend - preparing for attestation
            if (ctx.actor != PolicyActor::System &&
                ctx.actor != PolicyActor::Backend) {
                return PolicyDecision::Deny;
            }
            if (ctx.actor == PolicyActor::Backend && !ctx.backend_connected) {
                return PolicyDecision::Deny;
            }
            switch (action) {
                case PolicyAction::GpioRead:        // Safe observation
                case PolicyAction::SensorRead:      // Safe observation
                case PolicyAction::StorageRead:     // Read configuration
                case PolicyAction::NetworkSend:     // Send attestation or diagnostics
                case PolicyAction::NetworkReceive:  // Receive attestation challenge
                case PolicyAction::SystemReboot:    // Allow controlled restart
                    return PolicyDecision::Allow;
                default:
                    return PolicyDecision::Deny;
            }

        case system_state::SystemState::Attested:
            // Attestation complete, awaiting backend authorization
            if (ctx.actor != PolicyActor::System &&
                ctx.actor != PolicyActor::Backend) {
                return PolicyDecision::Deny;
            }
            if (ctx.actor == PolicyActor::Backend && !ctx.backend_connected) {
                return PolicyDecision::Deny;
            }
            switch (action) {
                case PolicyAction::GpioRead:        // Safe observation
                case PolicyAction::SensorRead:      // Safe observation
                case PolicyAction::StorageRead:     // Read configuration
                case PolicyAction::ConfigRead:      // Read configuration
                case PolicyAction::NetworkSend:     // Authorization exchange
                case PolicyAction::NetworkReceive:  // Authorization exchange
                case PolicyAction::SystemReboot:    // Allow controlled restart
                    return PolicyDecision::Allow;
                default:
                    return PolicyDecision::Deny;
            }

        case system_state::SystemState::Authorized:
            // Backend authorized, policy not yet loaded
            if (ctx.actor != PolicyActor::System &&
                ctx.actor != PolicyActor::Backend) {
                return PolicyDecision::Deny;
            }
            if (ctx.actor == PolicyActor::Backend && !ctx.backend_connected) {
                return PolicyDecision::Deny;
            }
            switch (action) {
                case PolicyAction::GpioRead:        // Safe observation
                case PolicyAction::SensorRead:      // Safe observation
                case PolicyAction::StorageRead:     // Read configuration
                case PolicyAction::StorageWrite:    // DIFFERENCE from Authorized state, to persist policy
                case PolicyAction::ConfigRead:      // Read configuration
                case PolicyAction::NetworkSend:     // Control-plane communication
                case PolicyAction::NetworkReceive:  // Control-plane communication
                case PolicyAction::SystemReboot:    // Allow controlled restart
                    return PolicyDecision::Allow;
                default:
                    return PolicyDecision::Deny;
            }

        case system_state::SystemState::Operational:
            // Fully operational - most actions permitted
            if (ctx.actor == PolicyActor::System) {  // System is always allowed
                return PolicyDecision::Allow;
            }
            if (ctx.actor == PolicyActor::Backend) {
                // Backend is trusted ONLY if connection is authenticated
                if (!ctx.backend_connected) {
                    return PolicyDecision::Deny;
                }
                return PolicyDecision::Allow;
            }
            // LocalUser / Peripheral actors
            // Allow only physically safe and local operations
            // No configuration, no firmware, no inbound network control
            switch (action) {
                case PolicyAction::GpioRead:
                case PolicyAction::GpioWrite:
                case PolicyAction::SensorRead:
                case PolicyAction::ActuatorWrite:
                    // Local interaction with hardware is allowed
                    return PolicyDecision::Allow;

                default:
                    // Anything that affects system integrity,
                    // configuration, or remote control is denied
                    return PolicyDecision::Deny;
            }

        case system_state::SystemState::Degraded:
            // Backend unreachable - offline-safe local operations only
            if (ctx.actor != PolicyActor::System) {
                return PolicyDecision::Deny;
            }
            switch (action) {
                case PolicyAction::GpioRead:        // Safe observation
                case PolicyAction::SensorRead:      // Safe observation
                case PolicyAction::ActuatorWrite:   // Safety-critical local control
                case PolicyAction::StorageRead:     // Diagnostics / forensics
                case PolicyAction::NetworkSend:     // Buffered telemetry
                case PolicyAction::SystemReboot:    // Allow controlled restart
                case PolicyAction::SystemSleep:     // Power saving
                    return PolicyDecision::Allow;
                default:
                    return PolicyDecision::Deny;
            }

        default:
            // Unknown state - fail closed
            return PolicyDecision::Deny;
    }
}

} // namespace zerotrust::policy

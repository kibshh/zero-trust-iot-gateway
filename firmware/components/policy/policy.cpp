#include "policy.h"

namespace zerotrust::policy {

PolicyDecision PolicyEngine::evaluate(PolicyAction action, const PolicyContext& ctx) const
{
    // Zero-trust policy evaluation
    // Default deny unless explicitly allowed by both state and context checks

    bool allowed = false;

    // Phase 1: State-based allow-list
    // Each state defines a minimal set of permitted actions
    switch (ctx.state) {
        case system_state::SystemState::Revoked:
            // Terminal security state - deny all actions unconditionally
            allowed = false;
            break;

        case system_state::SystemState::Locked:
            // Default deny for non-system actors
            if (ctx.actor != PolicyActor::System &&
                ctx.actor != PolicyActor::Backend) {
                allowed = false;
                break;
            }
            // Backend must actually be connected
            if (ctx.actor == PolicyActor::Backend && !ctx.backend_connected) {
                allowed = false;
                break;
            }
            // Allow minimal safe actions only
            switch (action) {
                case PolicyAction::SystemReboot: // Reboot the device (safe)
                case PolicyAction::SystemSleep:  // Sleep the device
                case PolicyAction::StorageRead:  // Read from storage
                case PolicyAction::NetworkSend:  // Send data to network (audit-only heartbeat)
                    allowed = true;
                    break;

                default:
                    allowed = false;
                    break;
            }
            break;  // Exit outer switch after Locked case

        case system_state::SystemState::Init:
        case system_state::SystemState::IdentityReady:
        case system_state::SystemState::Attested:
            // Pre-authorization states - read-only, non-invasive operations
            // Device identity not yet verified by backend
            allowed =
                action == PolicyAction::GpioRead ||
                action == PolicyAction::SensorRead;
            break;

        case system_state::SystemState::Authorized:
            // Backend authorized device but policy not yet loaded
            // Allow reads and outbound network (for policy fetch)
            allowed =
                action == PolicyAction::GpioRead ||
                action == PolicyAction::SensorRead ||
                action == PolicyAction::NetworkSend ||
                action == PolicyAction::ConfigRead;
            break;

        case system_state::SystemState::Operational:
            // Fully operational - all actions permitted (subject to Phase 2 gates)
            allowed = true;
            break;

        case system_state::SystemState::Degraded:
            // Backend unreachable - allow only offline-safe local operations
            // No network, no persistent writes, no config changes
            allowed =
                action == PolicyAction::GpioRead ||
                action == PolicyAction::SensorRead ||
                action == PolicyAction::ActuatorWrite;
            break;

        default:
            // Unknown state - fail closed
            return PolicyDecision::Deny;
    }

    if (!allowed) {
        return PolicyDecision::Deny;
    }

    // Phase 2: Backend-dependent security gates
    // These actions require active backend connection regardless of state
    // Prevents unauthorized firmware updates, config changes, and command injection
    if (!ctx.backend_connected) {
        switch (action) {
            case PolicyAction::FirmwareUpdate:   // Firmware integrity requires backend verification
            case PolicyAction::NetworkReceive:   // Inbound commands must come from verified backend
            case PolicyAction::ConfigWrite:      // Config changes require backend audit trail
            case PolicyAction::NetworkConnect:   // New connections require backend authorization
                return PolicyDecision::Deny;
            default:
                // NetworkSend allowed without backend (outbound telemetry can queue locally)
                break;
        }
    }

    return PolicyDecision::Allow;
}

} // namespace zerotrust::policy

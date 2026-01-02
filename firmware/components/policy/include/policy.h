#ifndef FIRMWARE_COMPONENTS_POLICY_INCLUDE_POLICY_H
#define FIRMWARE_COMPONENTS_POLICY_INCLUDE_POLICY_H

#include "policy_types.h"

namespace zerotrust::policy {

// Policy enforcement engine
// Evaluates access requests based on system state and context
// This is the stateless evaluation logic - PolicyManager handles lifecycle
class PolicyEngine {
public:
    virtual ~PolicyEngine() = default;

    // Record an audit event for policy enforcement
    virtual void audit(const PolicyAuditRecord& record) = 0;

    // Evaluate an action request against current context
    // Returns Allow only if all conditions are met, Deny otherwise
    PolicyDecision evaluate(PolicyAction action, const PolicyContext& ctx) const;
};

} // namespace zerotrust::policy

#endif // FIRMWARE_COMPONENTS_POLICY_INCLUDE_POLICY_H

#ifndef FIRMWARE_COMPONENTS_POLICY_INCLUDE_POLICY_H
#define FIRMWARE_COMPONENTS_POLICY_INCLUDE_POLICY_H

#include "policy_types.h"

namespace zerotrust::policy {

// Policy enforcement engine with audit ring buffer
// Evaluates access requests based on system state and context
// This is the stateless evaluation logic - PolicyManager handles lifecycle
class PolicyEngine {
public:
    static constexpr size_t AuditBufferSize = 32;  // Circular buffer capacity

    PolicyEngine() : audit_head_(0), audit_count_(0) {}
    virtual ~PolicyEngine() = default;

    // Record an audit event for policy enforcement
    // Stores in circular buffer, oldest entries overwritten when full
    virtual void audit(const PolicyAuditRecord& record);

    // Get audit record by index (0 = oldest, audit_count-1 = newest)
    // Returns nullptr if index out of range
    const PolicyAuditRecord* get_audit_record(size_t index) const;

    // Number of audit records currently stored
    size_t get_audit_count() const { return audit_count_; }

    // Clear all audit records
    void clear_audit();

    // Evaluate an action request against current context
    // Returns Allow only if all conditions are met, Deny otherwise
    PolicyDecision evaluate(PolicyAction action, const PolicyContext& ctx) const;

private:
    PolicyAuditRecord audit_buffer_[AuditBufferSize];
    size_t audit_head_;   // Next write position
    size_t audit_count_;  // Number of records stored (max AuditBufferSize)
};

} // namespace zerotrust::policy

#endif // FIRMWARE_COMPONENTS_POLICY_INCLUDE_POLICY_H

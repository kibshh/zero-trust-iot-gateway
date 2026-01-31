#ifndef FIRMWARE_COMPONENTS_POLICY_INCLUDE_POLICY_MANAGER_H
#define FIRMWARE_COMPONENTS_POLICY_INCLUDE_POLICY_MANAGER_H

#include <cstdint>
#include <cstddef>

#include "identity.h"
#include "policy_types.h"
#include "policy.h"

namespace zerotrust::policy {

// Policy lifecycle manager
// Handles policy loading, verification, persistence, and evaluation
// NOT THREAD-SAFE: All methods must be called from a single thread
class PolicyManager {
public:
    // NVS keys
    static constexpr const char* NvsNamespace = "policy";
    static constexpr const char* NvsKeyPolicyBlob = "policy_blob";
    static constexpr const char* NvsKeyPolicyVersion = "policy_ver";
    static constexpr const char* NvsKeyBackendPubKey = "backend_pk";

    // Size limits (not strict, used for bounds checking)
    static constexpr size_t MaxPolicyBlobSize = 2048;
    static constexpr size_t MinPolicyBlobSize = 64;
    static constexpr size_t MaxBackendPubKeySize = 256;

    PolicyManager(identity::IdentityManager& identity, PolicyEngine& baseline_engine);
    ~PolicyManager() = default;

    bool is_policy_active() const { return policy_active_; }
    uint32_t get_policy_version() const { return policy_version_; }
    bool has_backend_public_key() const;
    bool is_policy_expired() const;

    // Get backend public key (DER-encoded ECDSA P-256)
    // Returns actual key length, or 0 if not available
    size_t get_backend_public_key(uint8_t* out_key, size_t out_capacity) const;

    // Provision backend public key (DER-encoded ECDSA P-256, called once during provisioning)
    bool set_backend_public_key(const uint8_t* key, size_t len);

    // Load, verify and activate policy blob received from backend
    PolicyLoadResult load_policy(const PolicyBlob& policy_blob);

    // Evaluate action using active policy
    PolicyDecision evaluate(PolicyAction action, const PolicyContext& ctx) const;

    // Remove policy from memory and NVS (factory reset / revocation)
    void clear_policy();

    // Load and verify previously persisted policy from NVS
    // Call during system initialization after identity is ready
    bool load_persisted_policy();

    // Access audit logs
    const PolicyEngine& get_policy_engine() const { return policy_engine_; }
    const PolicyEngine& get_baseline_engine() const { return baseline_engine_; }

private:
    identity::IdentityManager& identity_;
    PolicyEngine& baseline_engine_;      // External baseline engine
    mutable PolicyEngine policy_engine_; // Owned engine for policy decisions (mutable for audit in const methods)
    bool policy_active_;
    uint32_t policy_version_;
    ParsedPolicy parsed_policy_;
};

} // namespace zerotrust::policy

#endif // FIRMWARE_COMPONENTS_POLICY_INCLUDE_POLICY_MANAGER_H


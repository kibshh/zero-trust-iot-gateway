#include "policy_manager.h"
#include "policy.h"

#include "nvs_flash.h"
#include "nvs.h"
#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "mbedtls/error.h"
#include <cstring>
#include <ctime>

namespace zerotrust::policy {

namespace {

// Helper to read uint32_t from little-endian byte array
inline uint32_t read_u32_le(const uint8_t* data)
{
    return static_cast<uint32_t>(data[0]) |
           (static_cast<uint32_t>(data[1]) << 8) |
           (static_cast<uint32_t>(data[2]) << 16) |
           (static_cast<uint32_t>(data[3]) << 24);
}

// Helper to read uint16_t from little-endian byte array
inline uint16_t read_u16_le(const uint8_t* data)
{
    return static_cast<uint16_t>(data[0]) |
           (static_cast<uint16_t>(data[1]) << 8);
}

// Validate enum value: must be < count OR equal to any_value (wildcard)
inline bool is_valid_or_any(uint8_t value, uint8_t count, uint8_t any_value)
{
    return value < count || value == any_value;
}

// Validate enum value: must be < count (no wildcard allowed)
inline bool is_valid_enum(uint8_t value, uint8_t count)
{
    return value < count;
}

// Portable secure memory zeroization
// Uses volatile to prevent compiler from optimizing away the writes
void secure_zero(void* ptr, size_t len)
{
    if (!ptr || len == 0) {
        return;
    }

    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (len--) {
        *p++ = 0;
    }
}

// Check if policy has expired (internal helper)
// Returns true if expired, false if still valid or expiration not applicable
bool check_expiration(uint32_t expires_at)
{
    // expires_at == 0 means no expiration
    if (expires_at == 0) {
        return false;
    }

    // Get current time
    time_t now = time(nullptr);
    if (now <= 0) {
        return false; // Invalid time, skip expiration check
    }

    // If system clock is not set (before MinValidTimestamp), skip expiration check
    // This handles cold boot before NTP sync - fail-open for availability
    // Security trade-off: expired policy may be accepted until clock syncs
    if (now < static_cast<time_t>(ParsedPolicy::MinValidTimestamp)) {
        return false;
    }

    // Policy is expired if current time exceeds expires_at
    return static_cast<uint32_t>(now) > expires_at;
}

// Record audit event for policy decision
inline void audit_decision(PolicyDecision decision,
                           PolicyAction action,
                           const PolicyContext& ctx,
                           PolicyEngine& engine,
                           PolicyDecisionSource source)
{
    PolicyAuditRecord record{
        .action = action,
        .decision = decision,
        .actor = ctx.actor,
        .origin = ctx.origin,
        .intent = ctx.intent,
        .state = ctx.state,
        .source = source
    };

    engine.audit(record);
}

// Verify policy signature and device_id match
PolicyVerifyResult verify_policy(
    const PolicyBlob& blob,
    const ParsedPolicy& policy,
    const identity::IdentityManager& identity)
{
    // Defensive check: verify_policy() must be safe even if called
    // with partially-initialized ParsedPolicy (API misuse / fault injection)
    if (!blob.data || blob.len == 0 ||
        !policy.signature || policy.signature_len == 0) {
        return PolicyVerifyResult::InternalError;
    }

    // Calculate signed data length (everything before signature bytes)
    // Signature can't sign itself, so it must be before the signature bytes
    size_t signed_len = policy.signature - blob.data;
    if (signed_len == 0 || signed_len >= blob.len) { // Minimum size check
        return PolicyVerifyResult::InternalError;
    }

    // Verify device_id (all zeros = any device, otherwise must match)
    bool device_id_is_any = true;
    for (size_t i = 0; i < ParsedPolicy::DeviceIdSize; ++i) {
        if (policy.device_id[i] != 0) {
            device_id_is_any = false;
            break;
        }
    }

    if (!device_id_is_any) { // Backend policy is for a specific device
        uint8_t our_device_id[identity::IdentityManager::DeviceIdSize];
        if (!identity.get_device_id(our_device_id, sizeof(our_device_id))) {
            return PolicyVerifyResult::InternalError;
        }

        if (memcmp(policy.device_id, our_device_id, ParsedPolicy::DeviceIdSize) != 0) {
            return PolicyVerifyResult::InvalidSignature;  // Policy is for different device
        }
    }

    // Load backend public key from NVS
    nvs_handle_t handle;
    esp_err_t error = nvs_open(PolicyManager::NvsNamespace, NVS_READONLY, &handle);
    if (error != ESP_OK) {
        return PolicyVerifyResult::InvalidKey;
    }

    size_t key_size = 0;
    error = nvs_get_blob(handle, PolicyManager::NvsKeyBackendPubKey, nullptr, &key_size);
    if (error != ESP_OK || key_size == 0 || key_size > PolicyManager::MaxBackendPubKeySize) {
        nvs_close(handle);
        return PolicyVerifyResult::InvalidKey;
    }

    uint8_t backend_pubkey[PolicyManager::MaxBackendPubKeySize];
    error = nvs_get_blob(handle, PolicyManager::NvsKeyBackendPubKey, backend_pubkey, &key_size);
    nvs_close(handle);

    if (error != ESP_OK) {
        return PolicyVerifyResult::InvalidKey;
    }

    // Hash signed portion (everything before signature)
    uint8_t hash[identity::IdentityManager::Sha256HashSize];
    if (mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                   blob.data, signed_len, hash) != 0) {
        // Zeroize sensitive data before returning
        secure_zero(backend_pubkey, sizeof(backend_pubkey));
        return PolicyVerifyResult::InternalError;
    }

    // Parse and validate backend public key
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    PolicyVerifyResult result = PolicyVerifyResult::InvalidSignature;

    do {
        if (mbedtls_pk_parse_public_key(&pk, backend_pubkey, key_size) != 0) {
            result = PolicyVerifyResult::InvalidKey;
            break;
        }

        // Enforce ECDSA key type (fail if RSA or other)
        if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_ECDSA)) {
            result = PolicyVerifyResult::InvalidKey;
            break;
        }

        // Verify signature
        if (mbedtls_pk_verify(&pk,
                              MBEDTLS_MD_SHA256,
                              hash,
                              identity::IdentityManager::Sha256HashSize,
                              policy.signature,
                              policy.signature_len) == 0) {
            result = PolicyVerifyResult::Ok;
        }
    } while (false);

    mbedtls_pk_free(&pk);

    // Zeroize ALL sensitive data before returning
    secure_zero(hash, sizeof(hash));
    secure_zero(backend_pubkey, sizeof(backend_pubkey));

    return result;
}

// Persist policy blob and version to NVS
PolicyLoadResult persist_policy(const PolicyBlob& blob, const ParsedPolicy& policy)
{
    nvs_handle_t handle;
    esp_err_t error = nvs_open(PolicyManager::NvsNamespace, NVS_READWRITE, &handle);
    if (error != ESP_OK) {
        return PolicyLoadResult::TransientError;
    }

    bool success = true;

    do {
        // Store policy blob
        error = nvs_set_blob(handle, PolicyManager::NvsKeyPolicyBlob, blob.data, blob.len);
        if (error != ESP_OK) {
            success = false;
            break;
        }

        // Store policy_version separately for quick anti-rollback checks
        error = nvs_set_u32(handle, PolicyManager::NvsKeyPolicyVersion, policy.policy_version);
        if (error != ESP_OK) {
            success = false;
            break;
        }

        // Commit all changes atomically
        error = nvs_commit(handle);
        if (error != ESP_OK) {
            success = false;
            break;
        }
    } while (false);

    nvs_close(handle);

    return success ? PolicyLoadResult::Ok : PolicyLoadResult::TransientError;
}

// Check anti-rollback: new version must be > current version
bool check_anti_rollback(uint32_t new_version, bool policy_active, uint32_t current_version)
{
    // If no policy is active, check persisted version in NVS
    if (!policy_active) {
        nvs_handle_t handle;
        esp_err_t error = nvs_open(PolicyManager::NvsNamespace, NVS_READONLY, &handle);
        if (error == ESP_ERR_NVS_NOT_FOUND) {
            // No policy namespace exists - first policy, any version allowed
            return true;
        }
        if (error != ESP_OK) {
            // NVS error - fail safe, reject policy
            return false;
        }

        uint32_t stored_version = 0;
        error = nvs_get_u32(handle, PolicyManager::NvsKeyPolicyVersion, &stored_version);
        nvs_close(handle);

        if (error == ESP_ERR_NVS_NOT_FOUND) {
            // No version stored - first policy
            return true;
        }
        if (error != ESP_OK) {
            // Read error - fail safe
            return false;
        }

        // New version must be strictly greater
        return new_version > stored_version;
    }

    // Policy is active in memory - compare against memory version
    return new_version > current_version;
}

// Parse policy blob into structured format (does NOT verify signature)
PolicyParseResult parse(const PolicyBlob& blob, ParsedPolicy& out)
{
    // Hard reset output (fail-closed)
    memset(&out, 0, sizeof(out));

    // Null check BEFORE any pointer arithmetic
    if (!blob.data || blob.len < ParsedPolicy::MinHeaderSize) {
        return PolicyParseResult::SizeError;
    }

    const uint8_t* blob_ptr = blob.data;
    const uint8_t* blob_end = blob.data + blob.len;

    // Magic
    uint32_t magic = read_u32_le(blob_ptr);
    if (magic != ParsedPolicy::Magic) {
        return PolicyParseResult::InvalidMagic;
    }
    blob_ptr += sizeof(uint32_t);

    // Format version
    out.format_version = read_u32_le(blob_ptr);
    if (out.format_version != ParsedPolicy::CurrentFormatVersion) {
        return PolicyParseResult::UnsupportedVersion;
    }
    blob_ptr += sizeof(uint32_t);

    // Policy version
    out.policy_version = read_u32_le(blob_ptr);
    if (out.policy_version == 0) {
        return PolicyParseResult::InvalidFormat; // Policy version must be non-zero
    }
    blob_ptr += sizeof(uint32_t);

    // Device ID
    memcpy(out.device_id, blob_ptr, ParsedPolicy::DeviceIdSize);
    blob_ptr += ParsedPolicy::DeviceIdSize;

    // Expires at
    out.expires_at = read_u32_le(blob_ptr);
    blob_ptr += sizeof(uint32_t);

    // Validate expires_at: 0 = no expiry, otherwise must be >= MinValidTimestamp
    if (out.expires_at != 0 && out.expires_at < ParsedPolicy::MinValidTimestamp) {
        return PolicyParseResult::InvalidFormat;
    }

    // Rule count
    out.rule_count = read_u16_le(blob_ptr);
    blob_ptr += sizeof(uint16_t);

    // Validate rule count (must have at least 1 rule)
    if (out.rule_count == 0 || out.rule_count > ParsedPolicy::MaxRules) {
        return PolicyParseResult::RuleLimitExceeded;
    }

    // Rules
    // Bounds check required: rules section is variable-size (rule_count * 6 bytes)
    size_t rules_bytes = out.rule_count * ParsedPolicy::RuleSize;
    if (blob_ptr + rules_bytes > blob_end) {
        return PolicyParseResult::SizeError;
    }

    // Parse rules byte-by-byte (avoids struct padding issues)
    for (uint16_t i = 0; i < out.rule_count; ++i) {
        // Validate all enum fields before assignment (fail-closed)
        // state, actor, origin, intent support wildcards (0xFF = any)
        // action, decision must be exact valid values
        if (!is_valid_or_any(blob_ptr[0], static_cast<uint8_t>(system_state::SystemState::_Count), ParsedPolicy::AnyState) ||
            !is_valid_or_any(blob_ptr[1], static_cast<uint8_t>(PolicyActor::_Count), ParsedPolicy::AnyActor) ||
            !is_valid_or_any(blob_ptr[2], static_cast<uint8_t>(PolicyOrigin::_Count), ParsedPolicy::AnyOrigin) ||
            !is_valid_or_any(blob_ptr[3], static_cast<uint8_t>(PolicyIntent::_Count), ParsedPolicy::AnyIntent) ||
            !is_valid_enum(blob_ptr[4], static_cast<uint8_t>(PolicyAction::_Count)) ||
            !is_valid_enum(blob_ptr[5], static_cast<uint8_t>(PolicyDecision::_Count))) {
            return PolicyParseResult::InvalidFormat;
        }

        out.rules[i].state = static_cast<system_state::SystemState>(blob_ptr[0]);
        out.rules[i].actor = static_cast<PolicyActor>(blob_ptr[1]);
        out.rules[i].origin = static_cast<PolicyOrigin>(blob_ptr[2]);
        out.rules[i].intent = static_cast<PolicyIntent>(blob_ptr[3]);
        out.rules[i].action = static_cast<PolicyAction>(blob_ptr[4]);
        out.rules[i].decision = static_cast<PolicyDecision>(blob_ptr[5]);

        blob_ptr += ParsedPolicy::RuleSize;
    }

    // Signature length
    // Bounds check required: we're past the fixed header, in variable-size territory
    if (blob_ptr + sizeof(uint16_t) > blob_end) {
        return PolicyParseResult::SignatureError;
    }
    uint16_t sig_len = read_u16_le(blob_ptr);
    blob_ptr += sizeof(uint16_t);

    // Validate signature length
    if (sig_len == 0 || sig_len > ParsedPolicy::MaxSignatureSize) {
        return PolicyParseResult::SignatureError;
    }

    // Signature must be exactly the remaining bytes (no trailing garbage)
    if (blob_ptr + sig_len != blob_end) {
        return PolicyParseResult::SizeError;
    }

    out.signature = blob_ptr;
    out.signature_len = sig_len;

    return PolicyParseResult::Ok;
}

} // anonymous namespace

PolicyManager::PolicyManager(identity::IdentityManager& identity, PolicyEngine& baseline_engine)
    : identity_(identity),
      baseline_engine_(baseline_engine),
      policy_active_(false),
      policy_version_(0),
      parsed_policy_{} {}

PolicyLoadResult PolicyManager::load_policy(const PolicyBlob& policy_blob)
{
    // Validate input parameters
    if (!policy_blob.data || policy_blob.len == 0) {
        return PolicyLoadResult::TransientError;
    }

    // Check size bounds
    if (policy_blob.len < PolicyManager::MinPolicyBlobSize || policy_blob.len > PolicyManager::MaxPolicyBlobSize) {
        return PolicyLoadResult::TransientError;
    }

    // Identity must be present to verify policy signatures
    if (identity_.get_identity_status() != identity::IdentityStatus::Present) {
        return PolicyLoadResult::TransientError;
    }

    // Parse policy blob
    ParsedPolicy parsed;
    PolicyParseResult parse_result = parse(policy_blob, parsed);
    if (parse_result != PolicyParseResult::Ok) {
        // Map parse errors to load results
        // Security-sensitive errors - SecurityViolation (triggers lock)
        // Size/format errors - TransientError (allows retry)
        switch (parse_result) {
            case PolicyParseResult::InvalidMagic:
            case PolicyParseResult::SignatureError:
                return PolicyLoadResult::SecurityViolation;
            case PolicyParseResult::InvalidFormat:
            default:
                return PolicyLoadResult::TransientError;
        }
    }   

    // Verify policy signature and device_id
    PolicyVerifyResult verify_result = verify_policy(policy_blob, parsed, identity_);
    if (verify_result != PolicyVerifyResult::Ok) {
        // Map verify errors to load results
        switch (verify_result) {
            case PolicyVerifyResult::InvalidKey:
            case PolicyVerifyResult::InternalError:
                return PolicyLoadResult::TransientError;
            case PolicyVerifyResult::InvalidSignature:
            default:
                return PolicyLoadResult::SecurityViolation;
        }
    }

    // Check anti-rollback
    if (!check_anti_rollback(parsed.policy_version, policy_active_, policy_version_)) {
        return PolicyLoadResult::SecurityViolation;
    }

    // Check expiration - reject already-expired policies
    if (check_expiration(parsed.expires_at)) {
        return PolicyLoadResult::SecurityViolation;
    }

    // Persist policy to NVS
    PolicyLoadResult persist_result = persist_policy(policy_blob, parsed);
    if (persist_result != PolicyLoadResult::Ok) {
        return persist_result;
    }

    // Activate policy in memory
    parsed_policy_ = parsed;
    policy_active_ = true;
    policy_version_ = parsed.policy_version;

    // Clear old audit records - new policy starts fresh
    policy_engine_.clear_audit();

    return PolicyLoadResult::Ok;
}

PolicyDecision PolicyManager::evaluate(PolicyAction action, const PolicyContext& ctx) const
{
    PolicyDecision decision = PolicyDecision::Deny;

    // 1. No policy active → baseline only
    if (!policy_active_) {
        decision = baseline_engine_.evaluate(action, ctx);
        audit_decision(decision, action, ctx, baseline_engine_, PolicyDecisionSource::Baseline);
        return decision;
    }

    // 2. Policy expired at runtime → baseline fallback
    if (check_expiration(parsed_policy_.expires_at)) {
        decision = baseline_engine_.evaluate(action, ctx);
        audit_decision(decision, action, ctx, baseline_engine_, PolicyDecisionSource::Baseline);
        return decision;
    }

    // 3. Evaluate against parsed policy rules (first match wins)
    for (uint16_t i = 0; i < parsed_policy_.rule_count; ++i) {
        const PolicyRule& rule = parsed_policy_.rules[i];

        if (static_cast<uint8_t>(rule.state) != ParsedPolicy::AnyState &&
            rule.state != ctx.state) {
            continue;
        }

        if (static_cast<uint8_t>(rule.actor) != ParsedPolicy::AnyActor &&
            rule.actor != ctx.actor) {
            continue;
        }

        if (static_cast<uint8_t>(rule.origin) != ParsedPolicy::AnyOrigin &&
            rule.origin != ctx.origin) {
            continue;
        }

        if (static_cast<uint8_t>(rule.intent) != ParsedPolicy::AnyIntent &&
            rule.intent != ctx.intent) {
            continue;
        }

        if (rule.action != action) {
            continue;
        }

        decision = rule.decision;
        audit_decision(decision, action, ctx, policy_engine_, PolicyDecisionSource::Policy);
        return decision;
    }

    // 4. No matching rule → baseline fallback
    decision = baseline_engine_.evaluate(action, ctx);
    audit_decision(decision, action, ctx, baseline_engine_, PolicyDecisionSource::Baseline);
    return decision;
}

void PolicyManager::clear_policy()
{
    // Clear policy from memory
    policy_active_ = false;
    policy_version_ = 0;

    // Secure-zero parsed policy before clearing (may contain sensitive rule data)
    secure_zero(&parsed_policy_, sizeof(parsed_policy_));
    parsed_policy_ = ParsedPolicy{};

    // Clear policy from NVS
    nvs_handle_t handle;
    esp_err_t error = nvs_open(PolicyManager::NvsNamespace, NVS_READWRITE, &handle);
    if (error != ESP_OK) {
        // NVS open failed - policy may remain in storage
        // This is acceptable as policy_active_ is already false
        return;
    }

    // Erase policy blob and version
    // Backend public key is a provisioning-time trust anchor.
    // It is intentionally NOT removable at runtime.
    // Removal requires factory reset / secure reprovisioning.
    nvs_erase_key(handle, PolicyManager::NvsKeyPolicyBlob);
    nvs_erase_key(handle, PolicyManager::NvsKeyPolicyVersion);
    nvs_commit(handle);
    nvs_close(handle);
}

bool PolicyManager::set_backend_public_key(const uint8_t* key, size_t len)
{
    if (!key || len == 0 || len > PolicyManager::MaxBackendPubKeySize) {
        return false;
    }

    // Validate that it's a valid ECDSA public key
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    bool valid = false;
    do {
        if (mbedtls_pk_parse_public_key(&pk, key, len) != 0) {
            break;  // Invalid key format
        }
        // Enforce ECDSA key type - reject RSA or other types
        if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_ECDSA)) {
            break;  // Not ECDSA
        }
        valid = true;
    } while (false);

    mbedtls_pk_free(&pk);

    if (!valid) {
        return false;
    }

    // Store in NVS
    nvs_handle_t handle;
    esp_err_t error = nvs_open(PolicyManager::NvsNamespace, NVS_READWRITE, &handle);
    if (error != ESP_OK) {
        return false;
    }

    error = nvs_set_blob(handle, PolicyManager::NvsKeyBackendPubKey, key, len);
    if (error != ESP_OK) {
        nvs_close(handle);
        return false;
    }

    error = nvs_commit(handle);
    nvs_close(handle);

    return error == ESP_OK;
}

bool PolicyManager::has_backend_public_key() const
{
    nvs_handle_t handle;
    esp_err_t error = nvs_open(PolicyManager::NvsNamespace, NVS_READONLY, &handle);
    if (error != ESP_OK) {
        return false;
    }

    size_t key_size = 0;
    error = nvs_get_blob(handle, PolicyManager::NvsKeyBackendPubKey, nullptr, &key_size);
    nvs_close(handle);

    return error == ESP_OK && key_size > 0;
}

size_t PolicyManager::get_backend_public_key(uint8_t* out_key, size_t out_capacity) const
{
    if (!out_key || out_capacity == 0) {
        return 0;
    }

    nvs_handle_t handle;
    esp_err_t error = nvs_open(PolicyManager::NvsNamespace, NVS_READONLY, &handle);
    if (error != ESP_OK) {
        return 0;
    }

    size_t key_size = 0;
    error = nvs_get_blob(handle, PolicyManager::NvsKeyBackendPubKey, nullptr, &key_size);
    if (error != ESP_OK || key_size == 0 || key_size > out_capacity) {
        nvs_close(handle);
        return 0;
    }

    error = nvs_get_blob(handle, PolicyManager::NvsKeyBackendPubKey, out_key, &key_size);
    nvs_close(handle);

    return (error == ESP_OK) ? key_size : 0;
}

bool PolicyManager::is_policy_expired() const
{
    if (!policy_active_) {
        return false;
    }
    return check_expiration(parsed_policy_.expires_at);
}

int64_t PolicyManager::get_policy_seconds_remaining() const
{
    if (!policy_active_ || parsed_policy_.expires_at == 0) {
        return -1;
    }

    time_t now = time(nullptr);
    if (now <= 0 || now < static_cast<time_t>(ParsedPolicy::MinValidTimestamp)) {
        return -1;
    }

    int64_t remaining = static_cast<int64_t>(parsed_policy_.expires_at) - static_cast<int64_t>(now);
    return remaining > 0 ? remaining : 0;
}

size_t PolicyManager::collect_audit(PolicyAuditRecord* out_records, size_t max_records) const
{
    if (!out_records || max_records == 0) {
        return 0;
    }

    size_t total = 0;

    size_t policy_count = policy_engine_.get_audit_count();
    for (size_t i = 0; i < policy_count && total < max_records; ++i) {
        const PolicyAuditRecord* record = policy_engine_.get_audit_record(i);
        if (record) {
            out_records[total++] = *record;
        }
    }

    size_t baseline_count = baseline_engine_.get_audit_count();
    for (size_t i = 0; i < baseline_count && total < max_records; ++i) {
        const PolicyAuditRecord* record = baseline_engine_.get_audit_record(i);
        if (record) {
            out_records[total++] = *record;
        }
    }

    return total;
}

void PolicyManager::clear_all_audit()
{
    policy_engine_.clear_audit();
    baseline_engine_.clear_audit();
}

bool PolicyManager::load_persisted_policy()
{
    // Load policy from NVS into memory on startup
    // Called during system initialization

    nvs_handle_t handle;
    esp_err_t error = nvs_open(PolicyManager::NvsNamespace, NVS_READONLY, &handle);
    if (error != ESP_OK) {
        // No policy stored or NVS error
        policy_active_ = false;
        policy_version_ = 0;
        return false;
    }

    // Read policy version from NVS
    uint32_t nvs_version = 0;
    error = nvs_get_u32(handle, PolicyManager::NvsKeyPolicyVersion, &nvs_version);
    if (error != ESP_OK) {
        nvs_close(handle);
        policy_active_ = false;
        policy_version_ = 0;
        return false;
    }

    // Get policy blob size
    size_t blob_size = 0;
    error = nvs_get_blob(handle, PolicyManager::NvsKeyPolicyBlob, nullptr, &blob_size);
    if (error != ESP_OK || blob_size < PolicyManager::MinPolicyBlobSize || blob_size > PolicyManager::MaxPolicyBlobSize) {
        nvs_close(handle);
        policy_active_ = false;
        policy_version_ = 0;
        return false;
    }

    // Static buffer to avoid stack overflow and keep signature pointer valid
    // IMPORTANT: parsed_policy_.signature will point into this buffer
    // This is safe because PolicyManager is NOT THREAD-SAFE (single-threaded access)
    static uint8_t blob_buffer[PolicyManager::MaxPolicyBlobSize];
    error = nvs_get_blob(handle, PolicyManager::NvsKeyPolicyBlob, blob_buffer, &blob_size);
    nvs_close(handle);

    if (error != ESP_OK) {
        policy_active_ = false;
        policy_version_ = 0;
        return false;
    }

    // Parse the blob
    PolicyBlob blob{blob_buffer, blob_size};
    PolicyParseResult parse_result = parse(blob, parsed_policy_);
    if (parse_result != PolicyParseResult::Ok) {
        policy_active_ = false;
        policy_version_ = 0;
        parsed_policy_ = ParsedPolicy{};
        return false;
    }

    // Verify NVS version matches parsed version (detect corruption/tampering)
    if (nvs_version != parsed_policy_.policy_version) {
        policy_active_ = false;
        policy_version_ = 0;
        parsed_policy_ = ParsedPolicy{};
        return false;
    }

    // Verify signature and device_id match
    PolicyVerifyResult vr = verify_policy(blob, parsed_policy_, identity_);
    if (vr != PolicyVerifyResult::Ok) {
        policy_active_ = false;
        policy_version_ = 0;
        parsed_policy_ = ParsedPolicy{};
        return false;
    }

    // Check if persisted policy has expired
    // Don't activate expired policies - device needs fresh policy from backend
    if (check_expiration(parsed_policy_.expires_at)) {
        policy_active_ = false;
        policy_version_ = 0;
        parsed_policy_ = ParsedPolicy{};
        return false;
    }

    policy_active_ = true;
    policy_version_ = nvs_version;
    return true;
}

} // namespace zerotrust::policy

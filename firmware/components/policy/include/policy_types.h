#ifndef FIRMWARE_COMPONENTS_POLICY_INCLUDE_POLICY_TYPES_H
#define FIRMWARE_COMPONENTS_POLICY_INCLUDE_POLICY_TYPES_H

#include <cstdint>
#include <cstddef>

#include "system_state.h"

namespace zerotrust::policy {

enum class PolicyActor : uint8_t {
    System,         // Firmware / internal logic
    Backend,        // Authenticated backend command
    LocalUser,      // Physical input (button, knob)
    Peripheral,     // Sensor / bus-triggered
    Unknown,        // Anything suspicious
    _Count          // Number of actors (for validation)
};

// Concrete device actions that can be evaluated by the policy engine
enum class PolicyAction : uint8_t {
    // GPIO
    GpioRead,           // Read GPIO pin state
    GpioWrite,          // Write GPIO pin state
    // Sensors
    SensorRead,         // Read sensor measurement
    SensorConfig,       // Configure sensor parameters
    // Actuators
    ActuatorWrite,      // Control actuator (motor, relay, valve)
    // Peripheral buses
    I2cRead,            // Read from I2C device
    I2cWrite,           // Write to I2C device
    SpiRead,            // Read from SPI device
    SpiWrite,           // Write to SPI device
    UartRead,           // Read from UART
    UartWrite,          // Write to UART
    // Network
    NetworkConnect,     // Establish network connection
    NetworkSend,        // Send data to network
    NetworkReceive,     // Inbound commands / config
    // Storage
    StorageRead,        // Read from persistent storage
    StorageWrite,       // Write to persistent storage
    StorageErase,       // Erase storage region
    // System
    FirmwareUpdate,     // Initiate firmware update
    SystemReboot,       // Reboot device
    SystemSleep,        // Enter low-power sleep mode
    // Configuration - SECURITY SENSITIVE
    ConfigRead,         // Read device configuration
    ConfigWrite,        // Modify device configuration
    _Count              // Number of actions (for validation)
};

enum class PolicyOrigin : uint8_t {
    Local,          // Same MCU
    Network,        // TCP/MQTT/HTTP
    Bus,            // I2C/SPI/UART
    Storage,        // Flash / NVS
    _Count          // Number of origins (for validation)
};

enum class PolicyIntent : uint8_t {
    NormalOperation,    // Expected, authorized behavior
    Provisioning,       // Initial setup / configuration
    Recovery,           // Error recovery / repair
    FirmwareUpdate,     // Update to new version
    Diagnostics,        // System monitoring / troubleshooting
    _Count              // Number of intents (for validation)
};

// Enforcement decision returned by policy engine
enum class PolicyDecision : uint8_t {
    Allow,
    Deny,
    _Count              // Number of decisions (for validation)
};

// Result of policy load operation
enum class PolicyLoadResult : uint8_t {
    Ok,                 // Policy verified, persisted and activated
    TransientError,     // Network / timing / partial delivery issue (retry allowed)
    SecurityViolation,  // Invalid signature, rollback attempt, device mismatch (lock)
};

// Context for policy evaluation
struct PolicyContext {
    system_state::SystemState state;    // Current system state
    PolicyActor actor;                  // Who is requesting the action
    PolicyOrigin origin;                // Where the request originated from
    PolicyIntent intent;                // Why the request is being made
    bool backend_connected;             // Backend reachable
    bool physical_presence;             // Physical presence detected
    bool secure_boot_enabled;           // Secure boot enabled
    bool attested;                      // Device has been attested
};

// Audit record for policy enforcement
struct PolicyAuditRecord {
    PolicyAction action;               // What was attempted
    PolicyDecision decision;           // Allow or Deny
    PolicyActor actor;                 // Who initiated the action
    PolicyOrigin origin;               // Where the action originated
    PolicyIntent intent;               // Why the action was taken
    system_state::SystemState state;   // System state at time of action
};

// Raw policy blob received from backend
struct PolicyBlob {
    const uint8_t* data;
    size_t len;
};

// Single policy rule: allows or denies a specific action based on context
struct PolicyRule {
    system_state::SystemState state;  // Target state (0xFF = any)
    PolicyActor actor;                // Target actor (0xFF = any)
    PolicyOrigin origin;              // Target origin (0xFF = any)
    PolicyIntent intent;              // Target intent (0xFF = any)
    PolicyAction action;              // Target action
    PolicyDecision decision;          // Allow or Deny
};

// Parsed policy structure
struct ParsedPolicy {
    // Magic number can be hardcoded, holds no cryptographic meaning
    static constexpr uint32_t Magic = 0x5A545056;  // "ZTPV" in little-endian
    // Minimum valid timestamp: Jan 1, 2020 00:00:00 UTC (Unix epoch)
    // Any non-zero expires_at below this is considered invalid/corrupted
    static constexpr uint32_t MinValidTimestamp = 1577836800;
    // Current format version, future use
    static constexpr uint32_t CurrentFormatVersion = 1;
    // Binary format sizes, used for bounds checking
    static constexpr size_t DeviceIdSize = 16;
    static constexpr size_t RuleSize = 6;
    static constexpr size_t MaxRules = 64;
    static constexpr size_t MaxSignatureSize = 72;
    static constexpr size_t MinHeaderSize =
                            sizeof(uint32_t) + // magic, only in blob
                            sizeof(uint32_t) + // format_version
                            sizeof(uint32_t) + // policy_version
                            DeviceIdSize +
                            sizeof(uint32_t) + // expires_at
                            sizeof(uint16_t);  // rule_count
    // Wildcard values for rule matching
    static constexpr uint8_t AnyState = 0xFF;
    static constexpr uint8_t AnyActor = 0xFF;
    static constexpr uint8_t AnyOrigin = 0xFF;
    static constexpr uint8_t AnyIntent = 0xFF;
    // Header
    uint32_t format_version;                   // Must be == 1 for now
    uint32_t policy_version;                   // Monotonic (anti-rollback)
    uint8_t device_id[DeviceIdSize];
    uint32_t expires_at;                       // Unix timestamp, 0 = no expiry
    // Rules
    PolicyRule rules[MaxRules];
    uint16_t rule_count;
    // Signature (pointer into blob)
    const uint8_t* signature;
    size_t signature_len;
};

// Result of policy parsing
enum class PolicyParseResult : uint8_t {
    Ok,
    SizeError,           // Blob too small or size mismatch
    InvalidMagic,        // Magic number mismatch
    UnsupportedVersion,  // Format version != 1
    RuleLimitExceeded,   // rule_count == 0 or > MaxRules
    InvalidFormat,       // Malformed data (bad enum values, etc.)
    SignatureError,      // Signature missing or too large
};

// Result of policy signature verification
enum class PolicyVerifyResult : uint8_t {
    Ok,
    InvalidSignature,    // Signature verification failed
    InvalidKey,          // Backend public key missing or invalid
    InternalError        // Crypto operation failed
};

} // namespace zerotrust::policy

#endif // FIRMWARE_COMPONENTS_POLICY_INCLUDE_POLICY_TYPES_H


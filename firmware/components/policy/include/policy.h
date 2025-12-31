#ifndef FIRMWARE_COMPONENTS_POLICY_INCLUDE_POLICY_H
#define FIRMWARE_COMPONENTS_POLICY_INCLUDE_POLICY_H

#include <cstdint>

#include "system_state.h"

namespace zerotrust::policy {

enum class PolicyActor: uint8_t {
    System,         // firmware / internal logic
    Backend,        // authenticated backend command
    LocalUser,      // physical input (button, knob)
    Peripheral,     // sensor / bus-triggered
    Unknown         // anything suspicious
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
};

enum class PolicyOrigin : uint8_t {
    Local,          // same MCU
    Network,        // TCP/MQTT/HTTP
    Bus,            // I2C/SPI/UART
    Storage,        // flash / NVS
};

enum class PolicyIntent : uint8_t {
    NormalOperation,    // expected, authorized behavior
    Provisioning,       // initial setup / configuration
    Recovery,           // error recovery / repair
    FirmwareUpdate,     // update to new version
    Diagnostics,        // system monitoring / troubleshooting
};

// Enforcement decision returned by policy engine
enum class PolicyDecision : uint8_t {
    Allow,
    Deny
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

// Policy enforcement engine
// Evaluates access requests based on system state and context
class PolicyEngine {
public:
    // Record an audit event for policy enforcement
    virtual void audit(const PolicyAuditRecord& record) = 0;
    // Evaluate an action request against current context
    // Returns Allow only if all conditions are met, Deny otherwise
    PolicyDecision evaluate(PolicyAction action, const PolicyContext& ctx) const;
};

} // namespace zerotrust::policy

#endif // FIRMWARE_COMPONENTS_POLICY_INCLUDE_POLICY_H

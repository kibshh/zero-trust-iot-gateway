#ifndef FIRMWARE_COMPONENTS_POLICY_INCLUDE_POLICY_H
#define FIRMWARE_COMPONENTS_POLICY_INCLUDE_POLICY_H

#include <cstdint>

#include "system_state.h"

namespace zerotrust::policy {

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

// Enforcement decision returned by policy engine
enum class PolicyDecision : uint8_t {
    Allow,
    Deny
};

// Context for policy evaluation
struct PolicyContext {
    system_state::SystemState state;    // Current system state
    bool backend_connected;             // Backend reachable
    bool attested;                      // Device has been attested
};

// Policy enforcement engine
// Evaluates access requests based on system state and context
class PolicyEngine {
public:
    // Evaluate an action request against current context
    // Returns Allow only if all conditions are met, Deny otherwise
    PolicyDecision evaluate(PolicyAction action, const PolicyContext& ctx) const;
};

} // namespace zerotrust::policy

#endif // FIRMWARE_COMPONENTS_POLICY_INCLUDE_POLICY_H

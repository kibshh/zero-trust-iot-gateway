#ifndef FIRMWARE_COMPONENTS_PROVISIONING_INCLUDE_PROVISIONING_H
#define FIRMWARE_COMPONENTS_PROVISIONING_INCLUDE_PROVISIONING_H

#include <cstddef>
#include <cstdint>

namespace zerotrust::provisioning {

// ProvisioningManager launches a softAP + HTTP web UI when the device has no
// Wi-Fi credentials. The user connects to the AP, opens any URL in a browser
// (captive portal redirect lands on the form), fills in SSID + password, and
// submits. On success the credentials are persisted to NVS and the device
// reboots into station mode.
//
// Physical button reset: holding the configured GPIO pin LOW for at least
// ResetHoldMs milliseconds at boot clears NVS credentials and forces
// provisioning mode on the next boot.
//
// Lifecycle:
//   1. Call check_reset_button() once at boot (after NVS is initialised but
//      before load_config). It returns true if credentials were just erased.
//   2. Call run() when credentials are absent. It blocks until the user
//      submits valid credentials, then reboots.
class ProvisioningManager {
public:
    static constexpr const char* NvsNamespace   = "wifi";   // shared with WiFiManager
    static constexpr const char* NvsKeySsid     = "ssid";
    static constexpr const char* NvsKeyPassword = "password";

    // 802.11 limits: SSID ≤ 32 bytes, WPA2 passphrase ≤ 63 bytes, +1 for null.
    static constexpr size_t SsidMaxLen     = 33;
    static constexpr size_t PasswordMaxLen = 64;

    ProvisioningManager() = default;
    ~ProvisioningManager() = default;

    // Check the reset button GPIO and erase NVS credentials if held long enough.
    // Must be called after NVS is initialised. Returns true if credentials were
    // erased (the caller should continue to boot normally — load_config will then
    // find nothing and return NoCredentials, triggering provisioning).
    bool check_reset_button() const;

    // Launch the softAP and HTTP server (captive portal via 302 redirect).
    // Blocks until the user submits credentials. Persists them to NVS and
    // calls esp_restart() — this function never returns on success.
    // Returns false only if the AP or HTTP server could not be started
    // (driver error), leaving the caller to handle the fatal condition.
    bool run() const;
};

} // namespace zerotrust::provisioning

#endif

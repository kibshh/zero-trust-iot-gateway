#ifndef FIRMWARE_COMPONENTS_WIFI_MANAGER_INCLUDE_WIFI_MANAGER_H
#define FIRMWARE_COMPONENTS_WIFI_MANAGER_INCLUDE_WIFI_MANAGER_H

#include <cstdint>
#include "esp_event.h"

namespace zerotrust::wifi {

// Forward declaration — full definition follows WiFiManager so it can use
// WiFiManager::SsidMaxLen and WiFiManager::PasswordMaxLen for array sizes.
struct WifiConfig;

// Connection outcome returned by WiFiManager::connect()
enum class ConnectResult : uint8_t {
    Connected,      // IP address obtained successfully
    NoCredentials,  // SSID is empty - provisioning mode required
    AuthFailed,     // Wrong password or AP rejected association
    Timeout,        // connect_timeout_ms elapsed before IP was assigned
    DriverError,    // esp_wifi_* or netif API returned an error
    _Count          // Number of results (for validation)
};

// WiFiManager owns the Wi-Fi driver, the default STA netif, and its event
// handlers. It does NOT own the TCP/IP stack or the default event loop —
// those are global resources initialised once in main.cpp before any module
// registers handlers. This keeps the architecture scalable: Bluetooth, custom
// app events, etc. all share the same loop with separate focused handlers.
//
// Lifecycle:
//   0. main.cpp calls esp_netif_init() and esp_event_loop_create_default()
//      exactly once at boot.
//   1. Call init() to create the default STA netif, initialise the Wi-Fi
//      driver, and register WIFI_EVENT / IP_EVENT handlers.
//   2. Call connect(cfg) to attempt a connection; it blocks until ConnectResult.
//   3. On disconnect during operation, the DISCONNECTED event is fired but no
//      automatic reconnect is attempted — the caller decides what to do.
class WiFiManager {
public:
    static constexpr size_t       SsidMaxLen     = 33;   // 802.11 max SSID is 32 bytes + null terminator
    static constexpr size_t       PasswordMaxLen = 64;   // WPA2 max passphrase is 63 bytes + null terminator
    static constexpr const char*  NvsNamespace   = "wifi";
    static constexpr const char*  NvsKeySsid     = "ssid";
    static constexpr const char*  NvsKeyPassword = "password";

    WiFiManager();
    ~WiFiManager() = default;

    // Create default STA netif, initialise the Wi-Fi driver, and register
    // WIFI_EVENT / IP_EVENT handlers. The TCP/IP stack and event loop must
    // already be initialised. Must be called exactly once before connect().
    // Returns false if any ESP-IDF call fails.
    bool init();

    // Attempt to connect using the supplied config. Blocks until:
    //   - GOT_IP event fires  - Connected
    //   - max_retry exhausted - AuthFailed
    //   - connect_timeout_ms elapses - Timeout
    //   - SSID is empty - NoCredentials (returned immediately, no driver call)
    ConnectResult connect(const WifiConfig& cfg);

    // Returns true if the station currently holds an IP address.
    bool is_connected() const;

private:
    bool initialised_;
    bool connected_;

    static void event_handler(
        void* arg, esp_event_base_t base, int32_t id, void* data);
};

// Configuration for a single connection attempt.
struct WifiConfig {
    char     ssid[WiFiManager::SsidMaxLen];
    char     password[WiFiManager::PasswordMaxLen];
    uint32_t connect_timeout_ms;
    uint32_t max_retry;
};

// Load Wi-Fi credentials: NVS takes priority over Kconfig defaults.
// NVS must be initialised before calling this function.
// Sets out.ssid to empty when no credentials exist — caller enters provisioning.
bool load_config(WifiConfig& out);

} // namespace zerotrust::wifi

#endif // FIRMWARE_COMPONENTS_WIFI_MANAGER_INCLUDE_WIFI_MANAGER_H

#include "wifi_manager.h"

#include <cstring>
#include <cstdio>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "nvs.h"

namespace zerotrust::wifi {

namespace {

constexpr EventBits_t BitConnected = BIT0;
constexpr EventBits_t BitFailed    = BIT1;

// Module-level state shared between event_handler() and connect().
// Only valid while a connect() call is in progress.
static EventGroupHandle_t event_group = nullptr;
static uint32_t           retry_count = 0;
static uint32_t           max_retry   = 0;

} // anonymous namespace

WiFiManager::WiFiManager()
    : initialised_(false), connected_(false) {}

bool WiFiManager::init()
{
    if (initialised_) {
        return true;
    }

    esp_netif_create_default_wifi_sta();

    wifi_init_config_t driver_cfg = WIFI_INIT_CONFIG_DEFAULT();
    if (esp_wifi_init(&driver_cfg) != ESP_OK) {
        return false;
    }

    // Register our unified event handler for Wi-Fi association and IP events.
    // The handler only acts while connect() is waiting on the EventGroup.
    if (esp_event_handler_instance_register(
            WIFI_EVENT, ESP_EVENT_ANY_ID, &WiFiManager::event_handler, this, nullptr) != ESP_OK) {
        return false;
    }
    if (esp_event_handler_instance_register(
            IP_EVENT, IP_EVENT_STA_GOT_IP, &WiFiManager::event_handler, this, nullptr) != ESP_OK) {
        return false;
    }

    initialised_ = true;
    return true;
}

ConnectResult WiFiManager::connect(const WifiConfig& cfg)
{
    // Reject empty SSID immediately — provisioning mode is needed
    if (cfg.ssid[0] == '\0') {
        return ConnectResult::NoCredentials;
    }

    if (!initialised_) {
        return ConnectResult::DriverError;
    }

    // Set up shared state for the event handler
    event_group = xEventGroupCreate();
    retry_count = 0;
    max_retry   = cfg.max_retry;
    connected_  = false;

    // Build station config from our WifiConfig
    wifi_config_t wifi_cfg = {};
    strncpy(reinterpret_cast<char*>(wifi_cfg.sta.ssid),
            cfg.ssid, sizeof(wifi_cfg.sta.ssid) - 1);
    strncpy(reinterpret_cast<char*>(wifi_cfg.sta.password),
            cfg.password, sizeof(wifi_cfg.sta.password) - 1);
    // Require WPA2 minimum — rejects open and WEP/WPA networks
    wifi_cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    if (esp_wifi_set_mode(WIFI_MODE_STA) != ESP_OK ||
        esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg) != ESP_OK ||
        esp_wifi_start() != ESP_OK) {
        vEventGroupDelete(event_group);
        event_group = nullptr;
        return ConnectResult::DriverError;
    }

    printf("[WIFI] Connecting to SSID: %s\n", cfg.ssid);

    // Block until the event handler signals a result or the timeout elapses
    EventBits_t bits = xEventGroupWaitBits(
        event_group,
        BitConnected | BitFailed,
        pdFALSE,                              // do not clear bits on return
        pdFALSE,                              // wake on any bit (not all)
        pdMS_TO_TICKS(cfg.connect_timeout_ms));

    vEventGroupDelete(event_group);
    event_group = nullptr;

    if (bits & BitConnected) {
        return ConnectResult::Connected;
    }
    if (bits & BitFailed) {
        return ConnectResult::AuthFailed;
    }
    // Neither bit set — timeout
    printf("[WIFI] Connection timed out after %lu ms\n",
           static_cast<unsigned long>(cfg.connect_timeout_ms));
    return ConnectResult::Timeout;
}

bool WiFiManager::is_connected() const
{
    return connected_;
}

void WiFiManager::event_handler(
    void* arg, esp_event_base_t base, int32_t id, void* data)
{
    WiFiManager* self = static_cast<WiFiManager*>(arg);

    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();

    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        self->connected_ = false;

        // Only retry during an active connect() call
        if (event_group == nullptr) {
            // Disconnected during normal operation — caller handles this
            printf("[WIFI] Disconnected from AP\n");
            return;
        }

        if (retry_count < max_retry) {
            ++retry_count;
            printf("[WIFI] Reconnect attempt %lu/%lu\n",
                   static_cast<unsigned long>(retry_count),
                   static_cast<unsigned long>(max_retry));
            esp_wifi_connect();
        } else {
            printf("[WIFI] Max retries (%lu) exhausted\n",
                   static_cast<unsigned long>(max_retry));
            xEventGroupSetBits(event_group, BitFailed);
        }

    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = static_cast<ip_event_got_ip_t*>(data);
        printf("[WIFI] Got IP: " IPSTR "\n", IP2STR(&event->ip_info.ip));
        retry_count      = 0;
        self->connected_ = true;
        if (event_group != nullptr) {
            xEventGroupSetBits(event_group, BitConnected);
        }
    }
}

bool load_config(WifiConfig& out)
{
    memset(&out, 0, sizeof(out));
    out.connect_timeout_ms = CONFIG_ZTGW_WIFI_CONNECT_TIMEOUT_MS;
    out.max_retry          = CONFIG_ZTGW_WIFI_MAX_RETRY;

    nvs_handle_t handle;
    bool nvs_has_ssid = false;
    if (nvs_open(WiFiManager::NvsNamespace, NVS_READONLY, &handle) == ESP_OK) {
        size_t ssid_len = WiFiManager::SsidMaxLen;
        size_t pass_len = WiFiManager::PasswordMaxLen;

        bool ssid_ok = nvs_get_str(handle, WiFiManager::NvsKeySsid, out.ssid, &ssid_len) == ESP_OK && out.ssid[0] != '\0';
        bool pass_ok = nvs_get_str(handle, WiFiManager::NvsKeyPassword, out.password, &pass_len) == ESP_OK;

        if (ssid_ok && pass_ok) {
            nvs_has_ssid = true;
            printf("[WIFI] Credentials loaded from NVS\n");
        } else {
            // SSID and/or password missing — clear both
            memset(out.ssid,     0, WiFiManager::SsidMaxLen);
            memset(out.password, 0, WiFiManager::PasswordMaxLen);
            printf("[WIFI] NVS SSID present but password missing — falling back to Kconfig\n");
        }

        nvs_close(handle);
    }

    if (!nvs_has_ssid) {
        strncpy(out.ssid, CONFIG_ZTGW_WIFI_SSID, WiFiManager::SsidMaxLen - 1);
        strncpy(out.password, CONFIG_ZTGW_WIFI_PASSWORD, WiFiManager::PasswordMaxLen - 1);

        if (out.ssid[0] == '\0') {
            printf("[WIFI] No credentials found — provisioning mode required\n");
        } else {
            printf("[WIFI] SSID loaded from Kconfig default\n");
        }
    }

    return true;
}

} // namespace zerotrust::wifi

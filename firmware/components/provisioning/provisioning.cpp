#include "provisioning.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_http_server.h"
#include "nvs.h"
#include "driver/gpio.h"
#include "esp_system.h"

#include <cstring>
#include <cstdio>
#include <cstdlib>

namespace zerotrust::provisioning {

namespace {

// Captive portal via HTTP 302: the HTTP server redirects any unrecognised
// URI to /provision. Browsers that detect a captive portal open the system
// browser automatically.

constexpr char       ApSsid[]      = CONFIG_ZTGW_PROV_AP_SSID;
constexpr uint8_t    ApChannel     = CONFIG_ZTGW_PROV_AP_CHANNEL;
constexpr gpio_num_t ResetGpio     = static_cast<gpio_num_t>(CONFIG_ZTGW_PROV_RESET_GPIO);
constexpr gpio_num_t LedGpio       = static_cast<gpio_num_t>(CONFIG_ZTGW_PROV_LED_GPIO);
constexpr uint32_t   ResetHoldMs   = CONFIG_ZTGW_PROV_RESET_HOLD_MS;
constexpr uint32_t   ResetWindowMs = CONFIG_ZTGW_PROV_RESET_WINDOW_MS;

// Default IP assigned to the softAP interface by lwIP (not configurable at runtime).
constexpr char ApIpAddr[] = "192.168.4.1";

// URI served by the provisioning HTTP server.
constexpr char ProvisionUri[] = "/provision";

// "http://" + ApIpAddr + ProvisionUri + null
constexpr size_t RedirectUrlMaxLen = 7 + sizeof(ApIpAddr) + sizeof(ProvisionUri);

// ESP-IDF provides HTTPD_200, HTTPD_400, etc. but not 302.
constexpr char HttpStatus302[] = "302 Found";

// Set by handle_post_provision once credentials are persisted to NVS.
// Polled by run() so the restart happens outside the HTTP handler context.
volatile bool credentials_saved = false;

// softAP: maximum simultaneous client connections.
constexpr uint8_t ApMaxConnections = 4;

// Maximum size of the POST body from the provisioning form.
// ssid (32) + '=' + password (63) + '&' + field names (8+9) + null ≈ 115 bytes;
// 256 gives comfortable headroom for URL-encoded characters.
constexpr size_t PostBodyMaxLen = 256;

// How long to wait after sending the success page before rebooting, so the
// browser has time to receive the full HTTP response before the TCP connection drops.
constexpr uint32_t RebootDelayMs = 1500;

// Tick interval for the reset-button polling loop (ms).
// Short enough to detect button press promptly; long enough not to busy-spin.
constexpr uint32_t TickMs = 10;

// Delay between loops in the main provisioning loop (ms).
constexpr uint32_t LoopDelayMs = 100;

// LED blink half-period during the detection window (ms).
// 100ms on + 100ms off = 5 Hz — visually distinct "attention" pattern.
constexpr uint32_t LedBlinkHalfPeriodMs = 100;

void led_init()
{
    gpio_config_t cfg = {};
    cfg.pin_bit_mask = (1ULL << LedGpio);
    cfg.mode         = GPIO_MODE_OUTPUT;
    cfg.pull_up_en   = GPIO_PULLUP_DISABLE;
    cfg.pull_down_en = GPIO_PULLDOWN_DISABLE;
    cfg.intr_type    = GPIO_INTR_DISABLE;
    gpio_config(&cfg);
    gpio_set_level(LedGpio, 0);
}

void led_set(bool on)
{
    gpio_set_level(LedGpio, on ? 1 : 0);
}

void led_off()
{
    gpio_set_level(LedGpio, 0);
}

constexpr char ProvisionHtml[] =
    "<!DOCTYPE html><html><head>"
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>ZT Gateway Setup</title>"
    "<style>"
    "*{box-sizing:border-box;margin:0;padding:0}"
    "body{font-family:system-ui,-apple-system,sans-serif;"
      "background:linear-gradient(135deg,#0a1628,#1a365d);"
      "display:flex;align-items:center;justify-content:center;"
      "min-height:100vh;padding:16px}"
    ".card{background:#fff;padding:32px 28px;border-radius:16px;"
      "width:100%;max-width:380px;box-shadow:0 20px 60px rgba(0,0,0,.3)}"
    ".hdr{text-align:center;margin-bottom:24px}"
    ".hdr svg{width:44px;height:44px;margin-bottom:10px}"
    ".hdr h1{font-size:18px;color:#1a365d;letter-spacing:-.3px}"
    ".hdr p{font-size:13px;color:#64748b;margin-top:4px}"
    "label{display:block;font-size:13px;font-weight:600;color:#334155;margin-bottom:4px}"
    "input{width:100%;padding:10px 12px;margin-bottom:16px;"
      "border:1.5px solid #e2e8f0;border-radius:8px;font-size:14px;outline:none}"
    "input:focus{border-color:#3b82f6}"
    "button{width:100%;padding:12px;margin-top:4px;"
      "background:linear-gradient(135deg,#3b82f6,#1d4ed8);"
      "color:#fff;border:none;border-radius:8px;font-size:15px;"
      "font-weight:600;cursor:pointer}"
    "button:disabled{opacity:.7;cursor:wait}"
    ".ft{text-align:center;margin-top:16px;font-size:11px;color:#94a3b8}"
    "</style>"
    "<script>function s(b){b.disabled=true;b.innerText='Connecting\\u2026';}</script>"
    "</head><body>"
    "<div class='card'>"
      "<div class='hdr'>"
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' "
          "stroke='#1a365d' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'>"
          "<path d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'/>"
          "<polyline points='9 12 11 14 15 10'/>"
        "</svg>"
        "<h1>Zero&#8209;Trust Gateway</h1>"
        "<p>Wi&#8209;Fi Configuration</p>"
      "</div>"
      "<form method='POST' action='/provision' onsubmit=\"s(this.querySelector('button'))\">"
        "<label>Network Name (SSID)</label>"
        "<input name='ssid' maxlength='32' required autocomplete='off' autofocus>"
        "<label>Password</label>"
        "<input name='password' type='password' maxlength='63'>"
        "<button type='submit'>Save &amp; Connect</button>"
      "</form>"
      "<div class='ft'>Credentials stored locally on device</div>"
    "</div>"
    "</body></html>";

constexpr char SuccessHtml[] =
    "<!DOCTYPE html><html><head>"
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>ZT Gateway</title>"
    "<style>"
    "*{box-sizing:border-box;margin:0;padding:0}"
    "body{font-family:system-ui,-apple-system,sans-serif;"
      "background:linear-gradient(135deg,#0a1628,#1a365d);"
      "display:flex;align-items:center;justify-content:center;"
      "min-height:100vh;padding:16px}"
    ".card{background:#fff;padding:32px 28px;border-radius:16px;"
      "width:100%;max-width:380px;box-shadow:0 20px 60px rgba(0,0,0,.3);"
      "text-align:center}"
    "svg{width:56px;height:56px;margin-bottom:16px}"
    "h1{font-size:20px;color:#1a365d;margin-bottom:8px}"
    "p{font-size:14px;color:#64748b;line-height:1.5}"
    "</style></head><body>"
    "<div class='card'>"
      "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' "
        "stroke='#16a34a' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'>"
        "<path d='M22 11.08V12a10 10 0 1 1-5.93-9.14'/>"
        "<polyline points='22 4 12 14.01 9 11.01'/>"
      "</svg>"
      "<h1>Saved!</h1>"
      "<p>The device will now reboot and connect to your Wi&#8209;Fi network.</p>"
    "</div>"
    "</body></html>";

// Extract a URL-encoded field value from a form body.
// dst must be at least dst_max bytes. Returns true on success.
bool extract_field(const char* body, const char* key, char* dst, size_t dst_max)
{
    size_t key_len = strlen(key);
    const char* pos = strstr(body, key);
    if (!pos) {
        return false;
    }
    pos += key_len;
    if (*pos != '=') {
        return false;
    }
    ++pos;

    size_t out = 0;
    while (*pos && *pos != '&' && out < dst_max - 1) {
        if (*pos == '+') {
            dst[out++] = ' ';
            ++pos;
        } else if (*pos == '%' && pos[1] && pos[2]) {
            char hex[3] = { pos[1], pos[2], '\0' };
            dst[out++] = static_cast<char>(strtol(hex, nullptr, 16));
            pos += 3;
        } else {
            dst[out++] = *pos++;
        }
    }
    dst[out] = '\0';
    return out > 0 || (out == 0 && *pos != '=');
}

// HTTP handlers
esp_err_t handle_get_provision(httpd_req_t* req)
{
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, ProvisionHtml, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

esp_err_t handle_post_provision(httpd_req_t* req)
{
    char body[PostBodyMaxLen] = {};

    int total = 0;
    while (total < req->content_len && total < static_cast<int>(sizeof(body) - 1)) {
        int r = httpd_req_recv(req, body + total, sizeof(body) - 1 - total);
        if (r <= 0) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Empty body");
            return ESP_FAIL;
        }
        total += r;
    }
    body[total] = '\0';

    char ssid[ProvisioningManager::SsidMaxLen] = {};
    char password[ProvisioningManager::PasswordMaxLen] = {};

    if (!extract_field(body, "ssid", ssid, sizeof(ssid)) || ssid[0] == '\0') {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "SSID required");
        return ESP_FAIL;
    }
    // Password is optional (open networks allowed at provisioning time)
    extract_field(body, "password", password, sizeof(password));

    // Persist to NVS
    nvs_handle_t handle;
    if (nvs_open(ProvisioningManager::NvsNamespace, NVS_READWRITE, &handle) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "NVS open failed");
        return ESP_FAIL;
    }
    bool ok = nvs_set_str(handle, ProvisioningManager::NvsKeySsid, ssid) == ESP_OK
           && nvs_set_str(handle, ProvisioningManager::NvsKeyPassword, password) == ESP_OK
           && nvs_commit(handle) == ESP_OK;
    nvs_close(handle);

    if (!ok) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "NVS write failed");
        return ESP_FAIL;
    }

    printf("[PROV] Credentials saved (SSID: %s)\n", ssid);
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, SuccessHtml, HTTPD_RESP_USE_STRLEN);

    credentials_saved = true;
    return ESP_OK;
}

// Redirect any unrecognised URI to /provision (captive portal behaviour).
esp_err_t handle_catchall(httpd_req_t* req)
{
    char redirect_url[RedirectUrlMaxLen];
    snprintf(redirect_url, sizeof(redirect_url), "http://%s%s", ApIpAddr, ProvisionUri);
    httpd_resp_set_status(req, HttpStatus302);
    httpd_resp_set_hdr(req, "Location", redirect_url);
    httpd_resp_send(req, nullptr, 0);
    return ESP_OK;
}

// softAP setup
bool start_softap()
{
    esp_netif_create_default_wifi_ap();

    wifi_config_t ap_cfg = {};
    strncpy(reinterpret_cast<char*>(ap_cfg.ap.ssid), ApSsid, sizeof(ap_cfg.ap.ssid) - 1);
    ap_cfg.ap.ssid_len       = static_cast<uint8_t>(strlen(ApSsid));
    ap_cfg.ap.channel        = ApChannel;
    ap_cfg.ap.authmode       = WIFI_AUTH_OPEN;  // open AP — no password needed to reach UI
    ap_cfg.ap.max_connection = ApMaxConnections;

    if (esp_wifi_set_mode(WIFI_MODE_AP) != ESP_OK ||
        esp_wifi_set_config(WIFI_IF_AP, &ap_cfg) != ESP_OK ||
        esp_wifi_start() != ESP_OK) {
        return false;
    }

    printf("[PROV] SoftAP started: SSID='%s' channel=%u\n", ApSsid, ApChannel);
    return true;
}

httpd_handle_t start_http_server()
{
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.uri_match_fn   = httpd_uri_match_wildcard;

    httpd_handle_t server = nullptr;
    if (httpd_start(&server, &cfg) != ESP_OK) {
        return nullptr;
    }

    httpd_uri_t get_uri   = { ProvisionUri, HTTP_GET,  handle_get_provision,  nullptr };
    httpd_uri_t post_uri  = { ProvisionUri, HTTP_POST, handle_post_provision, nullptr };
    httpd_uri_t catch_uri = { "/*",         HTTP_GET,  handle_catchall,       nullptr };

    httpd_register_uri_handler(server, &get_uri);
    httpd_register_uri_handler(server, &post_uri);
    httpd_register_uri_handler(server, &catch_uri);

    printf("[PROV] HTTP server started on http://%s%s\n", ApIpAddr, ProvisionUri);
    return server;
}

} // anonymous namespace

bool ProvisioningManager::check_reset_button() const
{
    // Configure reset button input (active LOW, internal pull-up).
    gpio_config_t btn_cfg = {};
    btn_cfg.pin_bit_mask = (1ULL << ResetGpio);
    btn_cfg.mode         = GPIO_MODE_INPUT;
    btn_cfg.pull_up_en   = GPIO_PULLUP_ENABLE;
    btn_cfg.pull_down_en = GPIO_PULLDOWN_DISABLE;
    btn_cfg.intr_type    = GPIO_INTR_DISABLE;
    if (gpio_config(&btn_cfg) != ESP_OK) {
        return false;
    }

    led_init();

    printf("[PROV] Reset window open (%lu ms) — hold GPIO %d LOW for %lu ms to clear credentials\n",
           static_cast<unsigned long>(ResetWindowMs),
           static_cast<int>(ResetGpio),
           static_cast<unsigned long>(ResetHoldMs));

    // Detection loop.
    //
    // We tick every TickMs milliseconds for the full ResetWindowMs window.
    // The user may start pressing at any point during the window. Once the
    // button goes LOW we track how long it stays LOW. If it stays LOW for
    // ResetHoldMs (even past the window end) the reset is triggered.
    // Releasing early resets the hold counter — the user must start again
    // within the remaining window time.
    //
    // LED blinks at LedBlinkHalfPeriodMs during the window and turns off
    // as soon as the window closes (reset or timeout).

    uint32_t window_elapsed_ms = 0;
    uint32_t hold_elapsed_ms   = 0;
    uint32_t led_phase_ms      = 0;
    bool     led_state         = false;
    bool     button_was_down   = false;

    // Run until the window expires AND no active hold is in progress.
    // If the user started pressing near the end of the window, we let the
    // hold measurement complete before giving up.
    while (window_elapsed_ms < ResetWindowMs || button_was_down) {

        // Blink LED (only while inside the window)
        if (window_elapsed_ms < ResetWindowMs) {
            led_phase_ms += TickMs;
            if (led_phase_ms >= LedBlinkHalfPeriodMs) {
                led_state = !led_state;
                led_set(led_state);
                led_phase_ms = 0;
            }
        }

        bool button_down = (gpio_get_level(ResetGpio) == 0);

        if (button_down) {
            if (!button_was_down) {
                // Rising edge of press — start counting hold time
                hold_elapsed_ms = 0;
                button_was_down = true;
                printf("[PROV] Button pressed — hold for %lu ms\n",
                       static_cast<unsigned long>(ResetHoldMs));
            }
            hold_elapsed_ms += TickMs;

            if (hold_elapsed_ms >= ResetHoldMs) {
                // Held long enough — trigger reset
                led_off();
                printf("[PROV] Reset triggered after %lu ms hold — clearing credentials\n",
                       static_cast<unsigned long>(hold_elapsed_ms));

                nvs_handle_t handle;
                if (nvs_open(ProvisioningManager::NvsNamespace, NVS_READWRITE, &handle) != ESP_OK) {
                    return false;
                }
                nvs_erase_key(handle, ProvisioningManager::NvsKeySsid);
                nvs_erase_key(handle, ProvisioningManager::NvsKeyPassword);
                nvs_commit(handle);
                nvs_close(handle);

                printf("[PROV] Credentials erased\n");
                return true;
            }
        } else {
            if (button_was_down) {
                // Button released before hold time — cancel this attempt
                printf("[PROV] Button released early (%lu ms) — reset cancelled\n",
                       static_cast<unsigned long>(hold_elapsed_ms));
                hold_elapsed_ms = 0;
                button_was_down = false;
                // If the window has already elapsed, stop waiting
                if (window_elapsed_ms >= ResetWindowMs) {
                    break;
                }
            }
        }

        vTaskDelay(pdMS_TO_TICKS(TickMs));
        window_elapsed_ms += TickMs;
    }

    led_off();
    printf("[PROV] Reset window closed — no reset\n");
    return false;
}

bool ProvisioningManager::run() const
{
    printf("[PROV] No Wi-Fi credentials — starting provisioning mode\n");
    printf("[PROV] Connect to SSID '%s' and open http://%s%s\n", ApSsid, ApIpAddr, ProvisionUri);

    if (!start_softap()) {
        printf("[PROV] FATAL: Failed to start softAP\n");
        return false;
    }

    httpd_handle_t server = start_http_server();
    if (!server) {
        printf("[PROV] FATAL: Failed to start HTTP server\n");
        return false;
    }

    while (!credentials_saved) {
        vTaskDelay(pdMS_TO_TICKS(LoopDelayMs));
    }

    printf("[PROV] Credentials received — rebooting into station mode\n");
    vTaskDelay(pdMS_TO_TICKS(RebootDelayMs));
    esp_restart();

    return true; // unreachable
}

} // namespace zerotrust::provisioning

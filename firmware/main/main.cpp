// TODO: Migrate printf to ESP_LOGx (ESP_LOGI, ESP_LOGW, ESP_LOGE) project-wide
//       for log-level filtering, compile-time stripping, and timestamps

#include <cstdio>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"

#include "system_state.h"
#include "identity.h"
#include "attestation.h"
#include "policy_types.h"
#include "policy.h"
#include "policy_manager.h"
#include "backend_client.h"
#include "system_controller.h"
#include "time_sync.h"

namespace {

// Boot sequence retry configuration
struct RetryConfig {
    static constexpr uint32_t InitialDelayMs = 1000;
    static constexpr uint32_t MaxDelayMs = 30000;
    static constexpr uint32_t BackoffMultiplier = 2;
    static constexpr uint32_t MaxAttempts = 0; // 0 = unlimited
};

// Main loop tick interval (milliseconds)
constexpr uint32_t MainLoopIntervalMs = 1000;

// Operational main loop intervals (in ticks, each tick = MainLoopIntervalMs)
struct OperationalIntervals {
    static constexpr uint32_t ReAttestTicks = 3600;      // Re-attest every 1 hour
    static constexpr uint32_t PolicyRefreshTicks = 300;  // Check policy refresh every 5 minutes
    static constexpr uint32_t AuditFlushTicks = 300;     // Flush audit records every 5 minutes
};

// Elapsed-since-last-run check that handles uint32_t wrap-around correctly
// Works because unsigned subtraction wraps: if tick=5 and last=0xFFFFFFF0, (5 - 0xFFFFFFF0) = 21
bool is_interval_elapsed(uint32_t tick, uint32_t last_tick, uint32_t interval)
{
    return (tick - last_tick) >= interval;
}

// Backend configuration
// TODO: Load from NVS or Kconfig in production
constexpr zerotrust::backend::BackendConfig DefaultBackendConfig = {
    .base_url = "https://192.168.1.100:8080",
    .timeout_ms = zerotrust::backend::BackendClient::DefaultTimeoutMs
};

// Check if device is in a terminal state (locked or revoked)
bool is_terminal_state(zerotrust::system_state::SystemState state)
{
    return state == zerotrust::system_state::SystemState::Locked ||
           state == zerotrust::system_state::SystemState::Revoked;
}

// Delay with exponential backoff, returns next delay value
uint32_t delay_with_backoff(uint32_t current_delay_ms)
{
    vTaskDelay(pdMS_TO_TICKS(current_delay_ms));

    uint32_t next_delay = current_delay_ms * RetryConfig::BackoffMultiplier;
    if (next_delay > RetryConfig::MaxDelayMs) {
        next_delay = RetryConfig::MaxDelayMs;
    }
    return next_delay;
}

// Retry a boot step until success, terminal state, or max attempts
// step_fn: returns true on success, false to retry
// step_name: human-readable name for logging
// fsm: state machine to check for terminal states
bool retry_step(
    bool (*step_fn)(zerotrust::system_controller::SystemController&),
    zerotrust::system_controller::SystemController& controller,
    zerotrust::system_state::SystemStateMachine& fsm,
    const char* step_name)
{
    uint32_t delay_ms = RetryConfig::InitialDelayMs;
    uint32_t attempts = 0;

    while (true) {
        if (is_terminal_state(fsm.get_state())) {
            printf("[BOOT] %s: device entered terminal state, aborting\n", step_name);
            return false;
        }

        if (step_fn(controller)) {
            printf("[BOOT] %s: success\n", step_name);
            return true;
        }

        attempts++;
        if (RetryConfig::MaxAttempts > 0 && attempts >= RetryConfig::MaxAttempts) {
            printf("[BOOT] %s: max attempts (%lu) reached\n",
                   step_name, static_cast<unsigned long>(RetryConfig::MaxAttempts));
            return false;
        }

        // Check terminal state again after failed attempt (step may have locked)
        if (is_terminal_state(fsm.get_state())) {
            printf("[BOOT] %s: device locked after failure, aborting\n", step_name);
            return false;
        }

        printf("[BOOT] %s: retrying in %lu ms (attempt %lu)\n",
               step_name,
               static_cast<unsigned long>(delay_ms),
               static_cast<unsigned long>(attempts));
        delay_ms = delay_with_backoff(delay_ms);
    }
}

// Step wrappers for retry_step (function pointer compatible)
bool step_register(zerotrust::system_controller::SystemController& ctrl) { return ctrl.try_register_device(); }
bool step_attest(zerotrust::system_controller::SystemController& ctrl) { return ctrl.try_attest(); }
bool step_authorize(zerotrust::system_controller::SystemController& ctrl) { return ctrl.try_authorize(); }
bool step_load_policy(zerotrust::system_controller::SystemController& ctrl) { return ctrl.try_load_runtime_policy(); }

// Initialize NVS flash
// Returns true on success
bool init_nvs()
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        // NVS partition was truncated, erase and retry
        err = nvs_flash_erase();
        if (err != ESP_OK) {
            return false;
        }
        err = nvs_flash_init();
    }
    return err == ESP_OK;
}

// Initialize WiFi and connect to network
// TODO: Implement proper WiFi initialization (station mode, WPA2, etc.)
// Returns true on success
bool init_wifi()
{
    // Placeholder - must be implemented with actual WiFi driver
    // Should: init netif, create default station, set SSID/password, connect, wait for IP
    printf("[BOOT] WiFi init: NOT IMPLEMENTED (placeholder)\n");
    return true;
}

} // anonymous namespace

extern "C" void app_main(void)
{
    printf("[BOOT] Zero-Trust IoT Gateway starting\n");

    // Phase 0: Hardware initialization
    if (!init_nvs()) {
        printf("[BOOT] FATAL: NVS initialization failed\n");
        return;
    }

    if (!init_wifi()) {
        printf("[BOOT] FATAL: WiFi initialization failed\n");
        return;
    }

    // Instantiate all subsystems (stack-allocated, no heap fragmentation)
    zerotrust::system_state::SystemStateMachine fsm;
    zerotrust::identity::IdentityManager identity;
    zerotrust::attestation::AttestationEngine attestation(identity);
    zerotrust::policy::PolicyEngine baseline_engine;
    zerotrust::policy::PolicyManager policy_mgr(identity, baseline_engine);
    zerotrust::backend::BackendClient backend_client;

    backend_client.init(DefaultBackendConfig);

    zerotrust::system_controller::SystemController controller(
        fsm, identity, attestation, policy_mgr, backend_client);

    // Boot sequence — breaks out on any fatal / terminal failure
    bool boot_ok = false;

    do {
        // Phase 1: Identity initialization (Init → IdentityReady)
        printf("[BOOT] Phase 1: Identity initialization\n");
        controller.on_boot();

        if (is_terminal_state(fsm.get_state())) {
            printf("[BOOT] FATAL: Identity initialization failed, device locked\n");
            break;
        }

        if (fsm.get_state() != zerotrust::system_state::SystemState::IdentityReady) {
            printf("[BOOT] FATAL: Unexpected state after boot: %u\n",
                   static_cast<unsigned>(fsm.get_state()));
            break;
        }

        // Phase 2: Time synchronization (non-blocking on failure)
        printf("[BOOT] Phase 2: Time synchronization\n");
        if (!controller.init_time_sync(nullptr, true, 30000)) {
            // Time sync failure is NOT fatal - policy verifier handles missing time
            printf("[BOOT] WARNING: Time synchronization failed, continuing without accurate time\n");
        }

        // Phase 3: Device registration (IdentityReady, no state change)
        printf("[BOOT] Phase 3: Device registration\n");
        if (!retry_step(step_register, controller, fsm, "register")) {
            break;
        }

        // Phase 4: Attestation (IdentityReady → Attested)
        printf("[BOOT] Phase 4: Attestation\n");
        if (!retry_step(step_attest, controller, fsm, "attest")) {
            break;
        }

        // Phase 5: Authorization (Attested → Authorized)
        printf("[BOOT] Phase 5: Authorization\n");
        if (!retry_step(step_authorize, controller, fsm, "authorize")) {
            break;
        }

        // Phase 6: Runtime policy (Authorized → Operational)
        printf("[BOOT] Phase 6: Loading runtime policy\n");
        if (!retry_step(step_load_policy, controller, fsm, "load_policy")) {
            break;
        }

        boot_ok = true;
    } while (false);

    // Main loop
    // TODO: Replace single-loop with FreeRTOS tasks in Phase 3:
    //   - Main/Controller task (medium priority): orchestrates state, periodic tick
    //   - Sensor task (high priority): fixed-interval reads via queue
    //   - Network task (medium priority): telemetry, backend commands (MQTT/HTTP)
    //   - Audit task (low priority): batches and flushes audit logs
    //   All tasks gate operations through controller.authorize_action()
    if (boot_ok) {
        printf("[BOOT] Boot sequence complete — device is Operational\n");

        uint32_t tick = 0;
        uint32_t last_audit_tick = 0;
        uint32_t last_refresh_tick = 0;
        uint32_t last_attest_tick = 0;

        while (!is_terminal_state(fsm.get_state())) {
            // Per-tick: policy expiration check
            controller.on_periodic_tick();

            // Flush audit records before policy refresh (avoids losing records on policy reload)
            // TODO: Use retvals (try_flush_audit, try_refresh_policy, try_re_attest_periodic)
            // for backoff, logging, or Degraded transition
            if (is_interval_elapsed(tick, last_audit_tick, OperationalIntervals::AuditFlushTicks)) {
                controller.try_flush_audit();
                last_audit_tick = tick;
            }

            // Policy refresh (only requests new policy when nearing expiration)
            if (is_interval_elapsed(tick, last_refresh_tick, OperationalIntervals::PolicyRefreshTicks)) {
                controller.try_refresh_policy();
                last_refresh_tick = tick;
            }

            // Periodic re-attestation
            if (is_interval_elapsed(tick, last_attest_tick, OperationalIntervals::ReAttestTicks)) {
                controller.try_re_attest_periodic();
                last_attest_tick = tick;
            }

            ++tick;
            vTaskDelay(pdMS_TO_TICKS(MainLoopIntervalMs));
        }

        printf("[MAIN] Device entered terminal state, halting operations\n");
    }

    // Terminal state: device is locked or revoked
    // Stay alive but do nothing (hardware watchdog will handle true failures)
    printf("[BOOT] Device is in terminal state: %u\n",
           static_cast<unsigned>(fsm.get_state()));
    while (true) {
        vTaskDelay(pdMS_TO_TICKS(MainLoopIntervalMs));
    }
}

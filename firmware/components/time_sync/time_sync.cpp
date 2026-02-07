#include "time_sync.h"

#include "esp_sntp.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <ctime>
#include <sys/time.h>

namespace zerotrust::time_sync {

namespace {

// Module state
TimeSyncStatus sync_status = TimeSyncStatus::NotStarted;
TimeSyncConfig active_config = DefaultConfig;

// SNTP synchronization callback
void sntp_sync_callback(struct timeval* tv)
{
    (void)tv;
    sync_status = TimeSyncStatus::Synchronized;
}

} // namespace

bool TimeSync::init(const TimeSyncConfig* config)
{
    if (sync_status != TimeSyncStatus::NotStarted) {
        return false;
    }

    if (config != nullptr) {
        active_config = *config;
    }

    // Primary NTP server is required
    if (active_config.ntp_server_primary == nullptr) {
        return false;
    }

    // Configure SNTP
    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, active_config.ntp_server_primary);
    
    if (active_config.ntp_server_secondary != nullptr) {
        esp_sntp_setservername(1, active_config.ntp_server_secondary);
    }

    // Set callback for sync notification
    sntp_set_time_sync_notification_cb(sntp_sync_callback);

    // Set sync interval if specified
    if (active_config.sync_interval_ms > 0) {
        sntp_set_sync_interval(active_config.sync_interval_ms);
    }

    // Start SNTP
    esp_sntp_init();

    sync_status = TimeSyncStatus::InProgress;
    return true;
}

void TimeSync::deinit()
{
    if (sync_status == TimeSyncStatus::NotStarted) {
        return;
    }

    esp_sntp_stop();
    sync_status = TimeSyncStatus::NotStarted;
}

bool TimeSync::is_synchronized()
{
    if (sync_status != TimeSyncStatus::Synchronized) {
        return false;
    }

    // Double-check by verifying timestamp is reasonable
    uint64_t now = get_unix_time();
    return now >= MinValidTimestamp;
}

TimeSyncStatus TimeSync::get_status()
{
    return sync_status;
}

uint64_t TimeSync::get_unix_time()
{
    if (sync_status != TimeSyncStatus::Synchronized) {
        return 0;
    }

    time_t now;
    time(&now);

    // Sanity check
    if (static_cast<uint64_t>(now) < MinValidTimestamp) {
        return 0;
    }

    return static_cast<uint64_t>(now);
}

uint64_t TimeSync::get_unix_time_ms()
{
    if (sync_status != TimeSyncStatus::Synchronized) {
        return 0;
    }

    struct timeval tv;
    gettimeofday(&tv, nullptr);

    // Sanity check
    if (static_cast<uint64_t>(tv.tv_sec) < MinValidTimestamp) {
        return 0;
    }

    return static_cast<uint64_t>(tv.tv_sec) * TimeUnits::MillisecondsPerSecond + 
           static_cast<uint64_t>(tv.tv_usec) / TimeUnits::MicrosecondsPerMillisecond;
}

bool TimeSync::wait_for_sync(uint32_t timeout_ms)
{
    if (sync_status == TimeSyncStatus::NotStarted) {
        return false;
    }

    if (sync_status == TimeSyncStatus::Synchronized && is_synchronized()) {
        return true;
    }

    const uint32_t poll_interval_ms = TimeSync::PollIntervalMs;
    uint32_t elapsed_ms = 0;

    while (elapsed_ms < timeout_ms) {
        if (sync_status == TimeSyncStatus::Synchronized && is_synchronized()) {
            return true;
        }

        vTaskDelay(pdMS_TO_TICKS(poll_interval_ms));
        elapsed_ms += poll_interval_ms;
    }

    sync_status = TimeSyncStatus::Failed;
    return false;
}

} // namespace zerotrust::time_sync

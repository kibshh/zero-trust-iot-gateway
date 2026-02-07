#ifndef FIRMWARE_COMPONENTS_TIME_SYNC_INCLUDE_TIME_SYNC_H
#define FIRMWARE_COMPONENTS_TIME_SYNC_INCLUDE_TIME_SYNC_H

#include <cstdint>

namespace zerotrust::time_sync {

enum class TimeSyncStatus : uint8_t {
    NotStarted,      // SNTP not initialized
    InProgress,      // Waiting for NTP response
    Synchronized,    // Time is synchronized
    Failed           // Synchronization failed
};

struct TimeSyncConfig {
    const char* ntp_server_primary;    // Primary NTP server (e.g., "pool.ntp.org")
    const char* ntp_server_secondary;  // Secondary NTP server (optional, can be nullptr)
    uint32_t sync_interval_ms;         // Re-sync interval in milliseconds (0 = no auto resync)
    uint32_t timeout_ms;               // Timeout for initial sync
};

// Time unit conversion constants
struct TimeUnits {
    static constexpr uint32_t SecondsPerMinute = 60;
    static constexpr uint32_t MinutesPerHour = 60;
    static constexpr uint32_t HoursPerDay = 24;
    static constexpr uint32_t SecondsPerHour = SecondsPerMinute * MinutesPerHour;
    static constexpr uint32_t SecondsPerDay = SecondsPerHour * HoursPerDay;
    
    static constexpr uint32_t MillisecondsPerSecond = 1000;
    static constexpr uint32_t MicrosecondsPerMillisecond = 1000;
    static constexpr uint32_t NanosecondsPerMicrosecond = 1000;
    
    static constexpr uint32_t MillisecondsPerMinute = MillisecondsPerSecond * SecondsPerMinute;
    static constexpr uint32_t MillisecondsPerHour = MillisecondsPerSecond * SecondsPerHour;
    
    static constexpr uint64_t MicrosecondsPerSecond = static_cast<uint64_t>(MicrosecondsPerMillisecond) * MillisecondsPerSecond;
    
private:
    TimeUnits() = delete;  // Static-only struct
};

// Default configuration
constexpr TimeSyncConfig DefaultConfig = {
    .ntp_server_primary = "pool.ntp.org",
    .ntp_server_secondary = "time.google.com",
    .sync_interval_ms = TimeUnits::MillisecondsPerHour,  // 1 hour
    .timeout_ms = 30 * TimeUnits::MillisecondsPerSecond  // 30 seconds
};

// Time synchronization manager
// Uses NTP to synchronize system time
// Must be initialized after network is connected
class TimeSync {
public:
    // Minimum valid timestamp (Jan 1, 2024 00:00:00 UTC)
    // Used to detect if time is actually set
    static constexpr uint64_t MinValidTimestamp = 1704067200;

    // Poll interval for wait_for_sync (milliseconds)
    static constexpr uint32_t PollIntervalMs = 100;

    // Initialize time synchronization with given config
    // config: configuration (uses defaults if nullptr)
    // Returns true if initialization started successfully
    static bool init(const TimeSyncConfig* config = nullptr);

    // Stop time synchronization
    static void deinit();

    // Check if time is synchronized
    // Returns true if time has been synchronized at least once
    static bool is_synchronized();

    // Get current synchronization status
    static TimeSyncStatus get_status();

    // Get current Unix timestamp (seconds since 1970-01-01 00:00:00 UTC)
    // Returns 0 if time is not synchronized
    static uint64_t get_unix_time();

    // Get current Unix timestamp in milliseconds
    // Returns 0 if time is not synchronized
    static uint64_t get_unix_time_ms();

    // Wait for time to synchronize (blocking)
    // timeout_ms: maximum time to wait in milliseconds
    // Returns true if synchronized within timeout, false otherwise
    static bool wait_for_sync(uint32_t timeout_ms);

private:
    TimeSync() = delete;  // Static-only class
};

} // namespace zerotrust::time_sync

#endif // FIRMWARE_COMPONENTS_TIME_SYNC_INCLUDE_TIME_SYNC_H

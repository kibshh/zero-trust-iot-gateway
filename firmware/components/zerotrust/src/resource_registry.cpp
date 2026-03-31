#include "resource_registry.h"

#include <cstdio>
#include <cstring>

#include "ztg_resource.h"

namespace {

// Maximum name length including null terminator
static constexpr uint8_t NameBufSize = 32;
// NVS namespace max length per ESP-IDF limit
static constexpr uint8_t NvsNsMaxLen = 15;
// Valid resource_id range: 1..65534. 0x0000 = wildcard (any resource), 0xFFFF = reserved.
static constexpr uint16_t MaxResourceId = 65534;
// Table capacities - adjust these to match your project's resource count
static constexpr uint8_t MaxGpioEntries    = 40;
static constexpr uint8_t MaxI2cEntries     = 16;
static constexpr uint8_t MaxSpiEntries     = 8;
static constexpr uint8_t MaxUartEntries    = 4;
static constexpr uint8_t MaxNetworkEntries = 8;
static constexpr uint8_t MaxStorageEntries = 8;
// Derived: total slots for the cross-table uniqueness check (+ 1 for system entry)
static constexpr uint8_t MaxTotalEntries   = MaxGpioEntries + MaxI2cEntries + MaxSpiEntries +
                                             MaxUartEntries + MaxNetworkEntries + MaxStorageEntries + 1;

struct GpioEntry {
    gpio_num_t pin;
    uint16_t resource_id;
    char name[NameBufSize];
};

struct I2cEntry {
    i2c_port_t bus;
    uint8_t addr;
    uint16_t resource_id;
    char name[NameBufSize];
};

struct SpiEntry {
    spi_host_device_t host;
    int cs;
    uint16_t resource_id;
    char name[NameBufSize];
};

struct UartEntry {
    uart_port_t port;
    uint16_t resource_id;
    char name[NameBufSize];
};

struct NetworkEntry {
    uint16_t handle;
    uint16_t resource_id;
    char name[NameBufSize];
};

struct StorageEntry {
    char ns[NvsNsMaxLen + 1];
    uint16_t resource_id;
    char name[NameBufSize];
};

struct SystemEntry {
    uint16_t resource_id;
    char name[NameBufSize];
    bool used;
};

static GpioEntry    gpio_table[MaxGpioEntries];
static uint8_t      gpio_count = 0;

static I2cEntry     i2c_table[MaxI2cEntries];
static uint8_t      i2c_count = 0;

static SpiEntry     spi_table[MaxSpiEntries];
static uint8_t      spi_count = 0;

static UartEntry    uart_table[MaxUartEntries];
static uint8_t      uart_count = 0;

static NetworkEntry network_table[MaxNetworkEntries];
static uint8_t      network_count = 0;

static StorageEntry storage_table[MaxStorageEntries];
static uint8_t      storage_count = 0;

static SystemEntry  system_entry{};

// Flat list of all registered resource_ids for cross-table uniqueness check
static uint16_t used_ids[MaxTotalEntries];
static uint8_t  used_ids_count = 0;

static bool registration_open = true;

// Step 1 validation common to all register calls
static zerotrust::ResourceRegStatus validate_common(uint16_t resource_id, const char* name) {
    if (!registration_open) {
        return zerotrust::ResourceRegStatus::RegistrationClosed;
    }
    if (resource_id < 1 || resource_id > MaxResourceId) {
        return zerotrust::ResourceRegStatus::InvalidResourceId;
    }
    if (name == nullptr || name[0] == '\0') {
        return zerotrust::ResourceRegStatus::InvalidName;
    }
    if (strlen(name) > NameBufSize - 1) {
        return zerotrust::ResourceRegStatus::NameTooLong;
    }
    for (uint8_t i = 0; i < used_ids_count; i++) {
        if (used_ids[i] == resource_id) {
            return zerotrust::ResourceRegStatus::DuplicateResourceId;
        }
    }
    return zerotrust::ResourceRegStatus::Ok;
}

static void record_id(uint16_t resource_id) {
    used_ids[used_ids_count++] = resource_id;
}

} // namespace

namespace zerotrust {

ResourceRegStatus ztg_register_gpio(gpio_num_t pin, uint16_t resource_id, const char* name) {
    ResourceRegStatus status = validate_common(resource_id, name);
    if (status != ResourceRegStatus::Ok) {
        return status;
    }
    if (gpio_count >= MaxGpioEntries) {
        return ResourceRegStatus::TableFull;
    }
    for (uint8_t i = 0; i < gpio_count; i++) {
        if (gpio_table[i].pin == pin) {
            return ResourceRegStatus::DuplicateKey;
        }
    }
    gpio_table[gpio_count] = {pin, resource_id, {}};
    strncpy(gpio_table[gpio_count].name, name, NameBufSize - 1);
    gpio_table[gpio_count].name[NameBufSize - 1] = '\0';
    gpio_count++;
    record_id(resource_id);
    return ResourceRegStatus::Ok;
}

ResourceRegStatus ztg_register_i2c(i2c_port_t bus, uint8_t addr, uint16_t resource_id, const char* name) {
    ResourceRegStatus status = validate_common(resource_id, name);
    if (status != ResourceRegStatus::Ok) {
        return status;
    }
    if (i2c_count >= MaxI2cEntries) {
        return ResourceRegStatus::TableFull;
    }
    for (uint8_t i = 0; i < i2c_count; i++) {
        if (i2c_table[i].bus == bus && i2c_table[i].addr == addr) {
            return ResourceRegStatus::DuplicateKey;
        }
    }
    i2c_table[i2c_count] = {bus, addr, resource_id, {}};
    strncpy(i2c_table[i2c_count].name, name, NameBufSize - 1);
    i2c_table[i2c_count].name[NameBufSize - 1] = '\0';
    i2c_count++;
    record_id(resource_id);
    return ResourceRegStatus::Ok;
}

ResourceRegStatus ztg_register_spi(spi_host_device_t host, int cs, uint16_t resource_id, const char* name) {
    ResourceRegStatus status = validate_common(resource_id, name);
    if (status != ResourceRegStatus::Ok) {
        return status;
    }
    if (spi_count >= MaxSpiEntries) {
        return ResourceRegStatus::TableFull;
    }
    for (uint8_t i = 0; i < spi_count; i++) {
        if (spi_table[i].host == host && spi_table[i].cs == cs) {
            return ResourceRegStatus::DuplicateKey;
        }
    }
    spi_table[spi_count] = {host, cs, resource_id, {}};
    strncpy(spi_table[spi_count].name, name, NameBufSize - 1);
    spi_table[spi_count].name[NameBufSize - 1] = '\0';
    spi_count++;
    record_id(resource_id);
    return ResourceRegStatus::Ok;
}

ResourceRegStatus ztg_register_uart(uart_port_t port, uint16_t resource_id, const char* name) {
    ResourceRegStatus status = validate_common(resource_id, name);
    if (status != ResourceRegStatus::Ok) {
        return status;
    }
    if (uart_count >= MaxUartEntries) {
        return ResourceRegStatus::TableFull;
    }
    for (uint8_t i = 0; i < uart_count; i++) {
        if (uart_table[i].port == port) {
            return ResourceRegStatus::DuplicateKey;
        }
    }
    uart_table[uart_count] = {port, resource_id, {}};
    strncpy(uart_table[uart_count].name, name, NameBufSize - 1);
    uart_table[uart_count].name[NameBufSize - 1] = '\0';
    uart_count++;
    record_id(resource_id);
    return ResourceRegStatus::Ok;
}

ResourceRegStatus ztg_register_network(uint16_t handle, uint16_t resource_id, const char* name) {
    ResourceRegStatus status = validate_common(resource_id, name);
    if (status != ResourceRegStatus::Ok) {
        return status;
    }
    if (network_count >= MaxNetworkEntries) {
        return ResourceRegStatus::TableFull;
    }
    for (uint8_t i = 0; i < network_count; i++) {
        if (network_table[i].handle == handle) {
            return ResourceRegStatus::DuplicateKey;
        }
    }
    network_table[network_count] = {handle, resource_id, {}};
    strncpy(network_table[network_count].name, name, NameBufSize - 1);
    network_table[network_count].name[NameBufSize - 1] = '\0';
    network_count++;
    record_id(resource_id);
    return ResourceRegStatus::Ok;
}

ResourceRegStatus ztg_register_storage(const char* ns, uint16_t resource_id, const char* name) {
    ResourceRegStatus status = validate_common(resource_id, name);
    if (status != ResourceRegStatus::Ok) {
        return status;
    }
    if (ns == nullptr || ns[0] == '\0') {
        return ResourceRegStatus::InvalidNamespace;
    }
    if (storage_count >= MaxStorageEntries) {
        return ResourceRegStatus::TableFull;
    }
    for (uint8_t i = 0; i < storage_count; i++) {
        if (strncmp(storage_table[i].ns, ns, NvsNsMaxLen) == 0) {
            return ResourceRegStatus::DuplicateKey;
        }
    }
    storage_table[storage_count] = {};
    strncpy(storage_table[storage_count].ns, ns, NvsNsMaxLen);
    storage_table[storage_count].ns[NvsNsMaxLen] = '\0';
    storage_table[storage_count].resource_id = resource_id;
    strncpy(storage_table[storage_count].name, name, NameBufSize - 1);
    storage_table[storage_count].name[NameBufSize - 1] = '\0';
    storage_count++;
    record_id(resource_id);
    return ResourceRegStatus::Ok;
}

ResourceRegStatus ztg_register_system(uint16_t resource_id, const char* name) {
    ResourceRegStatus status = validate_common(resource_id, name);
    if (status != ResourceRegStatus::Ok) {
        return status;
    }
    if (system_entry.used) {
        return ResourceRegStatus::DuplicateKey;
    }
    system_entry.resource_id = resource_id;
    strncpy(system_entry.name, name, NameBufSize - 1);
    system_entry.name[NameBufSize - 1] = '\0';
    system_entry.used = true;
    record_id(resource_id);
    return ResourceRegStatus::Ok;
}

size_t ztg_export_registry_yaml(char* buf, size_t size) {
    if (buf == nullptr || size == 0) {
        return 0;
    }
    size_t written = 0;

    // Step 1: Write header
    int n = snprintf(buf + written, size - written, "resources:\n");
    if (n < 0 || static_cast<size_t>(n) >= size - written) {
        return 0;
    }
    written += static_cast<size_t>(n);

    // Step 2: GPIO entries
    for (uint8_t i = 0; i < gpio_count; i++) {
        n = snprintf(buf + written, size - written,
                     "  - id: %u\n    name: %s\n",
                     gpio_table[i].resource_id, gpio_table[i].name);
        if (n < 0 || static_cast<size_t>(n) >= size - written) {
            return 0;
        }
        written += static_cast<size_t>(n);
    }

    // Step 3: I2C entries
    for (uint8_t i = 0; i < i2c_count; i++) {
        n = snprintf(buf + written, size - written,
                     "  - id: %u\n    name: %s\n",
                     i2c_table[i].resource_id, i2c_table[i].name);
        if (n < 0 || static_cast<size_t>(n) >= size - written) {
            return 0;
        }
        written += static_cast<size_t>(n);
    }

    // Step 4: SPI entries
    for (uint8_t i = 0; i < spi_count; i++) {
        n = snprintf(buf + written, size - written,
                     "  - id: %u\n    name: %s\n",
                     spi_table[i].resource_id, spi_table[i].name);
        if (n < 0 || static_cast<size_t>(n) >= size - written) {
            return 0;
        }
        written += static_cast<size_t>(n);
    }

    // Step 5: UART entries
    for (uint8_t i = 0; i < uart_count; i++) {
        n = snprintf(buf + written, size - written,
                     "  - id: %u\n    name: %s\n",
                     uart_table[i].resource_id, uart_table[i].name);
        if (n < 0 || static_cast<size_t>(n) >= size - written) {
            return 0;
        }
        written += static_cast<size_t>(n);
    }

    // Step 6: Network entries
    for (uint8_t i = 0; i < network_count; i++) {
        n = snprintf(buf + written, size - written,
                     "  - id: %u\n    name: %s\n",
                     network_table[i].resource_id, network_table[i].name);
        if (n < 0 || static_cast<size_t>(n) >= size - written) {
            return 0;
        }
        written += static_cast<size_t>(n);
    }

    // Step 7: Storage entries
    for (uint8_t i = 0; i < storage_count; i++) {
        n = snprintf(buf + written, size - written,
                     "  - id: %u\n    name: %s\n",
                     storage_table[i].resource_id, storage_table[i].name);
        if (n < 0 || static_cast<size_t>(n) >= size - written) {
            return 0;
        }
        written += static_cast<size_t>(n);
    }

    // Step 8: System entry
    if (system_entry.used) {
        n = snprintf(buf + written, size - written,
                     "  - id: %u\n    name: %s\n",
                     system_entry.resource_id, system_entry.name);
        if (n < 0 || static_cast<size_t>(n) >= size - written) {
            return 0;
        }
        written += static_cast<size_t>(n);
    }

    return written;
}

} // namespace zerotrust

namespace zerotrust::internal {

void close_registration() {
    registration_open = false;
}

uint16_t lookup_gpio(gpio_num_t pin) {
    for (uint8_t i = 0; i < gpio_count; i++) {
        if (gpio_table[i].pin == pin) {
            return gpio_table[i].resource_id;
        }
    }
    return 0;
}

uint16_t lookup_i2c(i2c_port_t bus, uint8_t addr) {
    for (uint8_t i = 0; i < i2c_count; i++) {
        if (i2c_table[i].bus == bus && i2c_table[i].addr == addr) {
            return i2c_table[i].resource_id;
        }
    }
    return 0;
}

uint16_t lookup_spi(spi_host_device_t host, int cs) {
    for (uint8_t i = 0; i < spi_count; i++) {
        if (spi_table[i].host == host && spi_table[i].cs == cs) {
            return spi_table[i].resource_id;
        }
    }
    return 0;
}

uint16_t lookup_uart(uart_port_t port) {
    for (uint8_t i = 0; i < uart_count; i++) {
        if (uart_table[i].port == port) {
            return uart_table[i].resource_id;
        }
    }
    return 0;
}

uint16_t lookup_network(uint16_t handle) {
    for (uint8_t i = 0; i < network_count; i++) {
        if (network_table[i].handle == handle) {
            return network_table[i].resource_id;
        }
    }
    return 0;
}

uint16_t lookup_storage(const char* ns) {
    if (ns == nullptr) {
        return 0;
    }
    for (uint8_t i = 0; i < storage_count; i++) {
        if (strncmp(storage_table[i].ns, ns, NvsNsMaxLen) == 0) {
            return storage_table[i].resource_id;
        }
    }
    return 0;
}

uint16_t lookup_system() {
    return system_entry.used ? system_entry.resource_id : 0;
}

} // namespace zerotrust::internal

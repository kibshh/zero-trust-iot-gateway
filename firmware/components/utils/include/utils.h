#ifndef FIRMWARE_COMPONENTS_UTILS_INCLUDE_UTILS_H
#define FIRMWARE_COMPONENTS_UTILS_INCLUDE_UTILS_H

#include <cstddef>
#include <cstdint>
#include <cstdio>

namespace zerotrust::utils {

// Portable secure memory zeroization.
// Uses volatile writes to prevent the compiler from optimizing them away.
// Use instead of memset() for clearing sensitive material (keys, signatures).
inline void secure_zero(void* ptr, size_t len)
{
    if (!ptr || len == 0) {
        return;
    }
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (len--) {
        *p++ = 0;
    }
}

// Constant-time memory comparison to prevent timing side-channel attacks.
// Returns true if the two buffers are equal.
inline bool secure_compare(const uint8_t* a, const uint8_t* b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

// Read uint16_t from little-endian byte array.
inline uint16_t read_u16_le(const uint8_t* data)
{
    return static_cast<uint16_t>(data[0]) |
           (static_cast<uint16_t>(data[1]) << 8);
}

// Read uint32_t from little-endian byte array.
inline uint32_t read_u32_le(const uint8_t* data)
{
    return static_cast<uint32_t>(data[0]) |
           (static_cast<uint32_t>(data[1]) << 8) |
           (static_cast<uint32_t>(data[2]) << 16) |
           (static_cast<uint32_t>(data[3]) << 24);
}

// Read uint64_t from big-endian byte array.
inline uint64_t read_u64_be(const uint8_t* data)
{
    return (static_cast<uint64_t>(data[0]) << 56) |
           (static_cast<uint64_t>(data[1]) << 48) |
           (static_cast<uint64_t>(data[2]) << 40) |
           (static_cast<uint64_t>(data[3]) << 32) |
           (static_cast<uint64_t>(data[4]) << 24) |
           (static_cast<uint64_t>(data[5]) << 16) |
           (static_cast<uint64_t>(data[6]) << 8) |
           static_cast<uint64_t>(data[7]);
}

// Convert a hex string (with explicit length) to bytes.
// hex_len must be even. Returns false on invalid input or insufficient capacity.
inline bool hex_to_bytes(const char* hex, size_t hex_len, uint8_t* out, size_t out_capacity)
{
    if (hex_len % 2 != 0) {
        return false;
    }
    size_t byte_len = hex_len / 2;
    if (byte_len > out_capacity) {
        return false;
    }
    for (size_t i = 0; i < byte_len; i++) {
        unsigned int byte_val;
        if (sscanf(hex + (i * 2), "%2x", &byte_val) != 1) {
            return false;
        }
        out[i] = static_cast<uint8_t>(byte_val);
    }
    return true;
}

// Convert bytes to a lowercase hex string.
// out must be at least len * 2 + 1 bytes.
inline void bytes_to_hex(const uint8_t* bytes, size_t len, char* out)
{
    for (size_t i = 0; i < len; i++) {
        sprintf(out + (i * 2), "%02x", bytes[i]);
    }
    out[len * 2] = '\0';
}

// Validate enum value: value must be < count (wildcard not allowed).
inline bool is_valid_enum(uint8_t value, uint8_t count)
{
    return value < count;
}

// Validate enum value: value must be < count OR equal to any_value (wildcard).
inline bool is_valid_or_any(uint8_t value, uint8_t count, uint8_t any_value)
{
    return value < count || value == any_value;
}

} // namespace zerotrust::utils

#endif // FIRMWARE_COMPONENTS_UTILS_INCLUDE_UTILS_H

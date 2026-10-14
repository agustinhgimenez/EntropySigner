#pragma once

#include <stddef.h>
#include <stdint.h>

#include <mbedtls/sha256.h>

namespace es {
namespace crypto {

constexpr size_t kSha256DigestSize = 32;

// One-shot SHA-256. Returns false on invalid arguments or mbedTLS failure, in
// which case out is zeroed.
bool sha256(const uint8_t* data, size_t len, uint8_t out[kSha256DigestSize]);

// Incremental SHA-256 over mbedTLS (hardware-accelerated on the ESP32).
// Usage: init() -> update()* -> finish(). The internal state, which may depend
// on secret input, is wiped by finish(), reset() and the destructor.
class SHA256 {
public:
    SHA256();
    ~SHA256();

    SHA256(const SHA256&) = delete;
    SHA256& operator=(const SHA256&) = delete;

    // Starts a new hash, discarding any previous state.
    bool init();

    // Feeds len bytes. Fails if init() was not called or data is null with len > 0.
    bool update(const uint8_t* data, size_t len);

    // Writes the digest to out and wipes the state. On failure out is zeroed.
    bool finish(uint8_t out[kSha256DigestSize]);

    // Wipes the state; init() must be called again before update().
    void reset();

private:
    mbedtls_sha256_context ctx_;
    bool started_;
};

}  // namespace crypto
}  // namespace es

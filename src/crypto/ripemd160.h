#pragma once

#include <stddef.h>
#include <stdint.h>

namespace es {
namespace crypto {

constexpr size_t kRipemd160DigestSize = 20;

// One-shot RIPEMD-160. Uses mbedTLS when it was built with MBEDTLS_RIPEMD160_C;
// the prebuilt mbedTLS shipped with Arduino-ESP32 2.0.x leaves it disabled, so
// otherwise a portable implementation of the reference specification is used
// (verified against the official test vectors in tests/test_crypto).
// Returns false on invalid arguments or failure, in which case out is zeroed.
bool ripemd160(const uint8_t* data, size_t len, uint8_t out[kRipemd160DigestSize]);

// HASH160(data) = RIPEMD160(SHA256(data)), used for BIP-32 key fingerprints and
// Bitcoin P2PKH addresses. Same failure contract as ripemd160().
bool hash160(const uint8_t* data, size_t len, uint8_t out[kRipemd160DigestSize]);

}  // namespace crypto
}  // namespace es

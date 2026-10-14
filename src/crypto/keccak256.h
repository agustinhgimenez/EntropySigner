#pragma once

#include <stddef.h>
#include <stdint.h>

// Keccak-256 as used by Ethereum: the original Keccak submission with
// multi-rate padding 0x01 ... 0x80, NOT FIPS 202 SHA3-256 (domain padding
// 0x06). Both share the Keccak-f[1600] permutation and rate (136 bytes), so
// they only differ in the padding byte, which changes every digest.
// Portable, self-contained (mbedTLS 2.x has no SHA-3), no Arduino dependency.

namespace es {
namespace crypto {

constexpr size_t kKeccak256DigestSize = 32;

// One-shot Keccak-256. data may be null only when len is 0. Returns false on
// invalid arguments, in which case out is zeroed (when non-null).
bool keccak256(const uint8_t* data, size_t len, uint8_t out[kKeccak256DigestSize]);

}  // namespace crypto
}  // namespace es

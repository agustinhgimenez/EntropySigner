#pragma once

#include <stddef.h>
#include <stdint.h>

namespace es {
namespace entropy {

constexpr size_t kEntropySize = 32;  // 256 bits

// Generates 256 bits of conditioned entropy from the ESP32 hardware RNG:
//   out = SHA-256(domain tag || HW RNG (64 bytes))
// 512 input bits for 256 output bits gives the h_in >= n_out + 64 margin of
// NIST SP 800-90C. SHA-256 conditions the input, it does not create entropy.
// All intermediate buffers are wiped before returning.
// Returns false (and zeroes out) on failure.
bool generateEntropy256(uint8_t out[kEntropySize]);

}  // namespace entropy
}  // namespace es

#pragma once

#include <stddef.h>
#include <stdint.h>

namespace es {
namespace entropy {

constexpr size_t kEntropySize = 32;  // 256 bits

// Generates 256 bits of conditioned entropy:
//   out = SHA-256(domain tag || HW RNG (32 bytes) || LDR samples)
// The HW RNG is the primary source; the LDR (include_ldr) only adds defense in
// depth and can never make the output weaker. SHA-256 conditions the input, it
// does not create entropy. All intermediate buffers are wiped before returning.
// Returns false (and zeroes out) on failure.
bool generateEntropy256(uint8_t out[kEntropySize], bool include_ldr = true);

}  // namespace entropy
}  // namespace es

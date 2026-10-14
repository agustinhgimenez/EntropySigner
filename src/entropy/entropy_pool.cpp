#include "entropy/entropy_pool.h"

#include "crypto/sha256.h"
#include "entropy/hw_rng.h"
#include "entropy/ldr_entropy.h"
#include "security/secure_mem.h"

namespace es {
namespace entropy {

namespace {

static_assert(kEntropySize == crypto::kSha256DigestSize, "entropy size must match the SHA-256 digest");

// Domain separation: this digest cannot collide with SHA-256 used elsewhere.
constexpr char kDomainTag[] = "EntropySigner/entropy-pool/v1";

// 64 bytes (512 bits) of HW TRNG data guarantees h_in >= n_out + 64 (SP 800-90C)
// so that the SHA-256 conditioned output achieves full 256-bit min-entropy.
constexpr size_t kHwRngBytes = 64;
constexpr size_t kLdrSampleCount = 128;
constexpr uint32_t kLdrSampleDelayUs = 200;

}  // namespace

bool generateEntropy256(uint8_t out[kEntropySize], bool include_ldr) {
    if (out == nullptr) {
        return false;
    }

    uint8_t rng_bytes[kHwRngBytes];
    uint16_t ldr_samples[kLdrSampleCount];
    size_t ldr_count = 0;

    // The LDR is sampled before the HW RNG because the RNG's SAR ADC noise
    // source and the ADC driver cannot be active at the same time.
    if (include_ldr) {
        ldr_count = collectLdrSamples(ldr_samples, kLdrSampleCount, kLdrSampleDelayUs);
    }
    fillRandomBytes(rng_bytes, sizeof(rng_bytes));

    // Samples are hashed in native byte order (little-endian on the ESP32).
    const uint8_t ldr_flag = include_ldr ? 1 : 0;
    crypto::SHA256 hash;
    const bool ok = hash.init() &&
                    hash.update(reinterpret_cast<const uint8_t*>(kDomainTag), sizeof(kDomainTag) - 1) &&
                    hash.update(rng_bytes, sizeof(rng_bytes)) && hash.update(&ldr_flag, sizeof(ldr_flag)) &&
                    hash.update(reinterpret_cast<const uint8_t*>(ldr_samples), ldr_count * sizeof(ldr_samples[0])) &&
                    hash.finish(out);

    security::secureMemzero(rng_bytes, sizeof(rng_bytes));
    security::secureMemzero(ldr_samples, sizeof(ldr_samples));
    if (!ok) {
        security::secureMemzero(out, kEntropySize);
    }
    return ok;
}

}  // namespace entropy
}  // namespace es

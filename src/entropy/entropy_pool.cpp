#include "entropy/entropy_pool.h"

#include "crypto/sha256.h"
#include "entropy/hw_rng.h"
#include "security/secure_mem.h"

namespace es {
namespace entropy {

namespace {

static_assert(kEntropySize == crypto::kSha256DigestSize, "entropy size must match the SHA-256 digest");

// Domain separation: this digest cannot collide with SHA-256 used elsewhere.
// v2: input is the HW RNG only (v1 also hashed an LDR flag and samples).
constexpr char kDomainTag[] = "EntropySigner/entropy-pool/v2";

// 64 bytes (512 bits) of HW TRNG data guarantees h_in >= n_out + 64 (SP 800-90C)
// so that the SHA-256 conditioned output achieves full 256-bit min-entropy.
constexpr size_t kHwRngBytes = 64;

}  // namespace

bool generateEntropy256(uint8_t out[kEntropySize]) {
    if (out == nullptr) {
        return false;
    }

    uint8_t rng_bytes[kHwRngBytes];
    fillRandomBytes(rng_bytes, sizeof(rng_bytes));

    crypto::SHA256 hash;
    const bool ok = hash.init() &&
                    hash.update(reinterpret_cast<const uint8_t*>(kDomainTag), sizeof(kDomainTag) - 1) &&
                    hash.update(rng_bytes, sizeof(rng_bytes)) && hash.finish(out);

    security::secureMemzero(rng_bytes, sizeof(rng_bytes));
    if (!ok) {
        security::secureMemzero(out, kEntropySize);
    }
    return ok;
}

}  // namespace entropy
}  // namespace es

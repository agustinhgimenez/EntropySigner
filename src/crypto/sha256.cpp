#include "crypto/sha256.h"

#include <mbedtls/version.h>

#include "security/secure_mem.h"

// mbedTLS 2.x (ESP-IDF 4.4, Arduino-ESP32 2.0.x) exposes the int-returning
// API with a _ret suffix; mbedTLS 3.x (ESP-IDF 5.x) dropped the suffix.
#if MBEDTLS_VERSION_MAJOR >= 3
#define ES_SHA256_STARTS mbedtls_sha256_starts
#define ES_SHA256_UPDATE mbedtls_sha256_update
#define ES_SHA256_FINISH mbedtls_sha256_finish
#else
#define ES_SHA256_STARTS mbedtls_sha256_starts_ret
#define ES_SHA256_UPDATE mbedtls_sha256_update_ret
#define ES_SHA256_FINISH mbedtls_sha256_finish_ret
#endif

namespace es {
namespace crypto {

namespace {

constexpr int kIs224 = 0;  // mbedTLS flag: 0 selects SHA-256, 1 selects SHA-224

}  // namespace

bool sha256(const uint8_t* data, size_t len, uint8_t out[kSha256DigestSize]) {
    if (out == nullptr) {
        return false;
    }
    SHA256 hash;
    return hash.init() && hash.update(data, len) && hash.finish(out);
}

SHA256::SHA256() : started_(false) {
    mbedtls_sha256_init(&ctx_);
}

SHA256::~SHA256() {
    reset();
}

bool SHA256::init() {
    reset();
    started_ = ES_SHA256_STARTS(&ctx_, kIs224) == 0;
    return started_;
}

bool SHA256::update(const uint8_t* data, size_t len) {
    if (!started_ || (data == nullptr && len > 0)) {
        return false;
    }
    if (len == 0) {
        return true;
    }
    if (ES_SHA256_UPDATE(&ctx_, data, len) != 0) {
        reset();
        return false;
    }
    return true;
}

bool SHA256::finish(uint8_t out[kSha256DigestSize]) {
    if (out == nullptr) {
        reset();
        return false;
    }
    const bool ok = started_ && ES_SHA256_FINISH(&ctx_, out) == 0;
    if (!ok) {
        security::secureMemzero(out, kSha256DigestSize);
    }
    reset();
    return ok;
}

void SHA256::reset() {
    mbedtls_sha256_free(&ctx_);  // zeroizes the context
    security::secureMemzero(&ctx_, sizeof(ctx_));
    mbedtls_sha256_init(&ctx_);
    started_ = false;
}

}  // namespace crypto
}  // namespace es

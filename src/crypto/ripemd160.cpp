#include "crypto/ripemd160.h"

#include <string.h>

#include <mbedtls/ripemd160.h>
#include <mbedtls/version.h>

#include "crypto/sha256.h"
#include "security/secure_mem.h"

// mbedTLS 2.x (ESP-IDF 4.4, Arduino-ESP32 2.0.x) exposes the int-returning
// API with a _ret suffix; mbedTLS 3.x (ESP-IDF 5.x) dropped the suffix.
#if MBEDTLS_VERSION_MAJOR >= 3
#define ES_RIPEMD160 mbedtls_ripemd160
#else
#define ES_RIPEMD160 mbedtls_ripemd160_ret
#endif

namespace es {
namespace crypto {

namespace {

#if !defined(MBEDTLS_RIPEMD160_C)

// Portable RIPEMD-160 following Dobbertin, Bosselaers and Preneel,
// "RIPEMD-160: A Strengthened Version of RIPEMD" (1996). Only compiled when
// the linked mbedTLS lacks the module.

constexpr size_t kBlockBytes = 64;
constexpr size_t kRounds = 80;

// Message word selection, left and right lines.
constexpr uint8_t kR[kRounds] = {
    0, 1, 2,  3,  4,  5,  6,  7,  8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1,  10, 6,  15, 3,  12, 0, 9,  5,  2,  14, 11, 8,
    3, 10, 14, 4, 9,  15, 8,  1,  2, 7, 0,  6,  13, 11, 5,  12,
    1, 9, 11, 10, 0,  8,  12, 4,  13, 3, 7,  15, 14, 5,  6,  2,
    4, 0, 5,  9,  7,  12, 2,  10, 14, 1, 3,  8,  11, 6,  15, 13};
constexpr uint8_t kRp[kRounds] = {
    5,  14, 7,  0, 9, 2,  11, 4,  13, 6,  15, 8,  1,  10, 3,  12,
    6,  11, 3,  7, 0, 13, 5,  10, 14, 15, 8,  12, 4,  9,  1,  2,
    15, 5,  1,  3, 7, 14, 6,  9,  11, 8,  12, 2,  10, 0,  4,  13,
    8,  6,  4,  1, 3, 11, 15, 0,  5,  12, 2,  13, 9,  7,  10, 14,
    12, 15, 10, 4, 1, 5,  8,  7,  6,  2,  13, 14, 0,  3,  9,  11};

// Left rotation amounts, left and right lines.
constexpr uint8_t kS[kRounds] = {
    11, 14, 15, 12, 5,  8,  7,  9,  11, 13, 14, 15, 6,  7,  9,  8,
    7,  6,  8,  13, 11, 9,  7,  15, 7,  12, 15, 9,  11, 7,  13, 12,
    11, 13, 6,  7,  14, 9,  13, 15, 14, 8,  13, 6,  5,  12, 7,  5,
    11, 12, 14, 15, 14, 15, 9,  8,  9,  14, 5,  6,  8,  6,  5,  12,
    9,  15, 5,  11, 6,  8,  13, 12, 5,  12, 13, 14, 11, 8,  5,  6};
constexpr uint8_t kSp[kRounds] = {
    8,  9,  9,  11, 13, 15, 15, 5,  7,  7,  8,  11, 14, 14, 12, 6,
    9,  13, 15, 7,  12, 8,  9,  11, 7,  7,  12, 7,  6,  15, 13, 11,
    9,  7,  15, 11, 8,  6,  6,  14, 12, 13, 5,  14, 13, 13, 7,  5,
    15, 5,  8,  11, 14, 14, 6,  14, 6,  9,  12, 9,  12, 5,  15, 8,
    8,  5,  12, 9,  12, 5,  14, 6,  8,  13, 6,  5,  15, 13, 11, 11};

constexpr uint32_t kK[5] = {0x00000000u, 0x5A827999u, 0x6ED9EBA1u, 0x8F1BBCDCu, 0xA953FD4Eu};
constexpr uint32_t kKp[5] = {0x50A28BE6u, 0x5C4DD124u, 0x6D703EF3u, 0x7A6D76E9u, 0x00000000u};

inline uint32_t rotl(uint32_t x, unsigned n) {
    return (x << n) | (x >> (32 - n));
}

// Boolean function of round group g (0..4).
inline uint32_t f(unsigned g, uint32_t x, uint32_t y, uint32_t z) {
    switch (g) {
        case 0: return x ^ y ^ z;
        case 1: return (x & y) | (~x & z);
        case 2: return (x | ~y) ^ z;
        case 3: return (x & z) | (y & ~z);
        default: return x ^ (y | ~z);
    }
}

void compress(uint32_t h[5], const uint8_t block[kBlockBytes]) {
    uint32_t x[16];
    for (size_t i = 0; i < 16; ++i) {
        x[i] = static_cast<uint32_t>(block[4 * i]) | (static_cast<uint32_t>(block[4 * i + 1]) << 8) |
               (static_cast<uint32_t>(block[4 * i + 2]) << 16) | (static_cast<uint32_t>(block[4 * i + 3]) << 24);
    }

    uint32_t al = h[0], bl = h[1], cl = h[2], dl = h[3], el = h[4];
    uint32_t ar = h[0], br = h[1], cr = h[2], dr = h[3], er = h[4];
    for (unsigned j = 0; j < kRounds; ++j) {
        const unsigned g = j / 16;
        uint32_t t = rotl(al + f(g, bl, cl, dl) + x[kR[j]] + kK[g], kS[j]) + el;
        al = el;
        el = dl;
        dl = rotl(cl, 10);
        cl = bl;
        bl = t;

        t = rotl(ar + f(4 - g, br, cr, dr) + x[kRp[j]] + kKp[g], kSp[j]) + er;
        ar = er;
        er = dr;
        dr = rotl(cr, 10);
        cr = br;
        br = t;
    }

    const uint32_t t = h[1] + cl + dr;
    h[1] = h[2] + dl + er;
    h[2] = h[3] + el + ar;
    h[3] = h[4] + al + br;
    h[4] = h[0] + bl + cr;
    h[0] = t;

    security::secureMemzero(x, sizeof(x));
}

void portableRipemd160(const uint8_t* data, size_t len, uint8_t out[kRipemd160DigestSize]) {
    uint32_t h[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};

    size_t remaining = len;
    const uint8_t* p = data;
    while (remaining >= kBlockBytes) {
        compress(h, p);
        p += kBlockBytes;
        remaining -= kBlockBytes;
    }

    // Padding: 0x80, zeros, then the 64-bit little-endian bit length. Needs a
    // second block when fewer than 9 bytes are left in the current one.
    uint8_t tail[2 * kBlockBytes] = {0};
    if (remaining > 0) {
        memcpy(tail, p, remaining);
    }
    tail[remaining] = 0x80;
    const size_t tail_len = remaining + 9 <= kBlockBytes ? kBlockBytes : 2 * kBlockBytes;
    const uint64_t bit_len = static_cast<uint64_t>(len) << 3;
    for (size_t i = 0; i < 8; ++i) {
        tail[tail_len - 8 + i] = static_cast<uint8_t>(bit_len >> (8 * i));
    }
    for (size_t off = 0; off < tail_len; off += kBlockBytes) {
        compress(h, tail + off);
    }

    for (size_t i = 0; i < 5; ++i) {
        for (size_t b = 0; b < 4; ++b) {
            out[4 * i + b] = static_cast<uint8_t>(h[i] >> (8 * b));
        }
    }
    security::secureMemzero(tail, sizeof(tail));
    security::secureMemzero(h, sizeof(h));
}

#endif  // !MBEDTLS_RIPEMD160_C

}  // namespace

bool ripemd160(const uint8_t* data, size_t len, uint8_t out[kRipemd160DigestSize]) {
    if (out == nullptr) {
        return false;
    }
    if (data == nullptr && len > 0) {
        security::secureMemzero(out, kRipemd160DigestSize);
        return false;
    }
#if defined(MBEDTLS_RIPEMD160_C)
    if (ES_RIPEMD160(data, len, out) != 0) {  // mbedTLS zeroizes its own context
        security::secureMemzero(out, kRipemd160DigestSize);
        return false;
    }
#else
    portableRipemd160(data, len, out);
#endif
    return true;
}

bool hash160(const uint8_t* data, size_t len, uint8_t out[kRipemd160DigestSize]) {
    if (out == nullptr) {
        return false;
    }
    uint8_t sha[kSha256DigestSize];
    const bool ok = sha256(data, len, sha) && ripemd160(sha, sizeof(sha), out);
    if (!ok) {
        security::secureMemzero(out, kRipemd160DigestSize);
    }
    security::secureMemzero(sha, sizeof(sha));
    return ok;
}

}  // namespace crypto
}  // namespace es

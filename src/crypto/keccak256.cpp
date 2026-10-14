#include "crypto/keccak256.h"

#include <string.h>

#include "security/secure_mem.h"

namespace es {
namespace crypto {

namespace {

// Keccak-f[1600] following "The Keccak reference" v3.0 (Bertoni, Daemen,
// Peeters, Van Assche, 2011). The state is 25 64-bit lanes, lane (x, y) at
// index x + 5 * y, loaded little-endian from the input bytes.

constexpr size_t kLanes = 25;
constexpr size_t kRounds = 24;
constexpr size_t kRateBytes = 136;  // 1600 - 2 * 256 bits of capacity
constexpr uint8_t kPadFirst = 0x01;  // Keccak; FIPS 202 SHA3 would use 0x06
constexpr uint8_t kPadLast = 0x80;

constexpr uint64_t kRoundConstants[kRounds] = {
    0x0000000000000001ull, 0x0000000000008082ull, 0x800000000000808Aull, 0x8000000080008000ull,
    0x000000000000808Bull, 0x0000000080000001ull, 0x8000000080008081ull, 0x8000000000008009ull,
    0x000000000000008Aull, 0x0000000000000088ull, 0x0000000080008009ull, 0x000000008000000Aull,
    0x000000008000808Bull, 0x800000000000008Bull, 0x8000000000008089ull, 0x8000000000008003ull,
    0x8000000000008002ull, 0x8000000000000080ull, 0x000000000000800Aull, 0x800000008000000Aull,
    0x8000000080008081ull, 0x8000000000008080ull, 0x0000000080000001ull, 0x8000000080008008ull};

// rho rotation offsets and pi lane order, walked along the (1, 0) lane's orbit
// so that rho and pi are applied in a single in-place pass.
constexpr uint8_t kRho[kLanes - 1] = {1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
                                      27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44};
constexpr uint8_t kPi[kLanes - 1] = {10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
                                     15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1};

inline uint64_t rotl64(uint64_t x, unsigned n) {
    return (x << n) | (x >> (64 - n));  // n is never 0 in kRho
}

inline uint64_t loadLe64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) {
        v = (v << 8) | p[i];
    }
    return v;
}

void keccakF1600(uint64_t st[kLanes]) {
    uint64_t c[5];
    for (size_t round = 0; round < kRounds; ++round) {
        // theta
        for (size_t x = 0; x < 5; ++x) {
            c[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
        }
        for (size_t x = 0; x < 5; ++x) {
            const uint64_t d = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
            for (size_t y = 0; y < kLanes; y += 5) {
                st[x + y] ^= d;
            }
        }
        // rho and pi
        uint64_t carry = st[1];
        for (size_t i = 0; i < kLanes - 1; ++i) {
            const size_t j = kPi[i];
            const uint64_t tmp = st[j];
            st[j] = rotl64(carry, kRho[i]);
            carry = tmp;
        }
        // chi
        for (size_t y = 0; y < kLanes; y += 5) {
            for (size_t x = 0; x < 5; ++x) {
                c[x] = st[y + x];
            }
            for (size_t x = 0; x < 5; ++x) {
                st[y + x] = c[x] ^ (~c[(x + 1) % 5] & c[(x + 2) % 5]);
            }
        }
        // iota
        st[0] ^= kRoundConstants[round];
    }
    security::secureMemzero(c, sizeof(c));
}

// XORs one rate-sized block into the state and permutes.
void absorbBlock(uint64_t st[kLanes], const uint8_t block[kRateBytes]) {
    for (size_t i = 0; i < kRateBytes / 8; ++i) {
        st[i] ^= loadLe64(block + 8 * i);
    }
    keccakF1600(st);
}

}  // namespace

bool keccak256(const uint8_t* data, size_t len, uint8_t out[kKeccak256DigestSize]) {
    if (out == nullptr) {
        return false;
    }
    if (data == nullptr && len > 0) {
        memset(out, 0, kKeccak256DigestSize);
        return false;
    }

    uint64_t st[kLanes];
    memset(st, 0, sizeof(st));
    while (len >= kRateBytes) {
        absorbBlock(st, data);
        data += kRateBytes;
        len -= kRateBytes;
    }

    // Final block: remaining bytes, then pad10*1 with the Keccak domain byte.
    // When only one padding byte fits, both marks land on it (0x81).
    uint8_t block[kRateBytes];
    memset(block, 0, sizeof(block));
    if (len > 0) {
        memcpy(block, data, len);
    }
    block[len] ^= kPadFirst;
    block[kRateBytes - 1] ^= kPadLast;
    absorbBlock(st, block);

    // Squeeze: the digest is shorter than the rate, so one permutation suffices.
    for (size_t i = 0; i < kKeccak256DigestSize; ++i) {
        out[i] = static_cast<uint8_t>(st[i / 8] >> (8 * (i % 8)));
    }
    security::secureMemzero(st, sizeof(st));
    security::secureMemzero(block, sizeof(block));
    return true;
}

}  // namespace crypto
}  // namespace es

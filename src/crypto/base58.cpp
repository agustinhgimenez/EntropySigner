#include "crypto/base58.h"

#include <string.h>

#include "crypto/sha256.h"
#include "security/secure_mem.h"

namespace es {
namespace crypto {

namespace {

constexpr char kAlphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
constexpr uint32_t kBase = 58;

// log(256) / log(58) ~= 1.365, rounded up: base-58 digits needed per byte.
constexpr size_t kMaxDigits = kMaxBase58InputBytes * 138 / 100 + 1;

void zeroOut(char* out, size_t out_max) {
    if (out != nullptr && out_max > 0) {
        memset(out, 0, out_max);
    }
}

}  // namespace

bool encodeBase58(const uint8_t* data, size_t len, char* out, size_t out_max) {
    if (out == nullptr || out_max == 0) {
        return false;
    }
    if ((data == nullptr && len > 0) || len > kMaxBase58InputBytes) {
        zeroOut(out, out_max);
        return false;
    }

    size_t zeros = 0;
    while (zeros < len && data[zeros] == 0) {
        ++zeros;
    }

    // Big-endian base-58 digits of the number, filled from the end; length is
    // the count of significant digits written so far.
    uint8_t digits[kMaxDigits];
    memset(digits, 0, sizeof(digits));
    const size_t size = (len - zeros) * 138 / 100 + 1;
    size_t length = 0;
    for (size_t i = zeros; i < len; ++i) {
        // digits = digits * 256 + data[i]
        uint32_t carry = data[i];
        size_t k = 0;
        for (size_t pos = size; (carry != 0 || k < length) && pos > 0; --pos, ++k) {
            carry += 256u * digits[pos - 1];
            digits[pos - 1] = static_cast<uint8_t>(carry % kBase);
            carry /= kBase;
        }
        length = k;
    }

    size_t first = size - length;
    while (first < size && digits[first] == 0) {
        ++first;
    }
    const size_t needed = zeros + (size - first) + 1;  // + NUL
    bool ok = needed <= out_max;
    if (ok) {
        size_t o = 0;
        for (size_t i = 0; i < zeros; ++i) {
            out[o++] = kAlphabet[0];
        }
        for (size_t i = first; i < size; ++i) {
            out[o++] = kAlphabet[digits[i]];
        }
        out[o] = '\0';
    } else {
        zeroOut(out, out_max);
    }
    security::secureMemzero(digits, sizeof(digits));
    return ok;
}

bool encodeBase58Check(uint8_t version, const uint8_t* payload, size_t payload_len, char* out, size_t out_max) {
    if (out == nullptr || out_max == 0) {
        return false;
    }
    if ((payload == nullptr && payload_len > 0) || payload_len > kMaxBase58CheckPayloadBytes) {
        zeroOut(out, out_max);
        return false;
    }

    uint8_t buf[kMaxBase58InputBytes];
    uint8_t hash[kSha256DigestSize];
    const size_t body_len = 1 + payload_len;
    buf[0] = version;
    if (payload_len > 0) {
        memcpy(buf + 1, payload, payload_len);
    }
    bool ok = sha256(buf, body_len, hash) && sha256(hash, sizeof(hash), hash);
    if (ok) {
        memcpy(buf + body_len, hash, kBase58ChecksumBytes);
        ok = encodeBase58(buf, body_len + kBase58ChecksumBytes, out, out_max);
    } else {
        zeroOut(out, out_max);
    }
    security::secureMemzero(buf, sizeof(buf));
    security::secureMemzero(hash, sizeof(hash));
    return ok;
}

}  // namespace crypto
}  // namespace es

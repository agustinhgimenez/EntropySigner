#include "bip39/bip39.h"

#include <string.h>

#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/version.h>

#include "bip39/bip39_wordlist.h"
#include "crypto/sha256.h"
#include "security/secure_mem.h"

namespace es {
namespace bip39 {

namespace {

constexpr size_t kBitsPerWord = 11;
constexpr size_t kPackedBytes = kEntropyBytes + 1;  // 256 entropy bits + 8 checksum bits

static_assert(kWordCount * kBitsPerWord == kEntropyBytes * 8 + kChecksumBits, "264 bits must split into 24 words");
static_assert(kChecksumBits == 8, "the checksum is stored as one whole byte");
static_assert(kWordlistSize == (1u << kBitsPerWord), "each word encodes 11 bits");
static_assert(kMaxMnemonicLength >= kWordCount * (kMaxWordLength + 1), "mnemonic buffer too small");

// "mnemonic" prefix of the PBKDF2 salt, without the NUL terminator.
constexpr char kSaltPrefix[] = "mnemonic";
constexpr size_t kSaltPrefixLength = sizeof(kSaltPrefix) - 1;

inline uint8_t getBit(const uint8_t* bytes, size_t pos) {
    return (bytes[pos >> 3] >> (7 - (pos & 7))) & 1;
}

inline void setBit(uint8_t* bytes, size_t pos) {
    bytes[pos >> 3] |= static_cast<uint8_t>(0x80 >> (pos & 7));
}

// Splits packed (264 bits, MSB first) into 24 indices of 11 bits.
void packedToIndices(const uint8_t packed[kPackedBytes], uint16_t indices[kWordCount]) {
    for (size_t w = 0; w < kWordCount; ++w) {
        uint16_t index = 0;
        for (size_t b = 0; b < kBitsPerWord; ++b) {
            index = static_cast<uint16_t>((index << 1) | getBit(packed, w * kBitsPerWord + b));
        }
        indices[w] = index;
    }
}

// Inverse of packedToIndices().
void indicesToPacked(const uint16_t indices[kWordCount], uint8_t packed[kPackedBytes]) {
    memset(packed, 0, kPackedBytes);
    for (size_t w = 0; w < kWordCount; ++w) {
        for (size_t b = 0; b < kBitsPerWord; ++b) {
            if ((indices[w] >> (kBitsPerWord - 1 - b)) & 1) {
                setBit(packed, w * kBitsPerWord + b);
            }
        }
    }
}

// Parses a canonical mnemonic (see bip39.h) into word indices. Rejects null,
// wrong word counts, empty words, repeated/leading/trailing spaces, characters
// outside a-z, words longer than kMaxWordLength and words not in the list.
bool parseMnemonic(const char* mnemonic, uint16_t indices[kWordCount]) {
    if (mnemonic == nullptr) {
        return false;
    }
    char word[kMaxWordLength + 1];
    const char* p = mnemonic;
    bool ok = true;
    for (size_t w = 0; w < kWordCount && ok; ++w) {
        size_t len = 0;
        while (*p >= 'a' && *p <= 'z') {
            if (len == kMaxWordLength) {
                ok = false;
                break;
            }
            word[len++] = *p++;
        }
        if (!ok || len == 0) {
            ok = false;
            break;
        }
        word[len] = '\0';

        const int index = findWordIndex(word);
        if (index < 0) {
            ok = false;
            break;
        }
        indices[w] = static_cast<uint16_t>(index);

        // Exactly one space between words, end of string after the last one.
        const char expected = (w + 1 < kWordCount) ? ' ' : '\0';
        if (*p != expected) {
            ok = false;
            break;
        }
        if (expected == ' ') {
            ++p;
        }
    }
    security::secureMemzero(word, sizeof(word));
    if (!ok) {
        security::secureMemzero(indices, kWordCount * sizeof(indices[0]));
    }
    return ok;
}

// Parses mnemonic, checks its checksum and writes the entropy. On failure
// entropy_out is zeroed. All temporaries are wiped.
bool decodeMnemonic(const char* mnemonic, uint8_t entropy_out[kEntropyBytes]) {
    uint16_t indices[kWordCount];
    uint8_t packed[kPackedBytes];
    uint8_t digest[crypto::kSha256DigestSize];

    bool ok = parseMnemonic(mnemonic, indices);
    if (ok) {
        indicesToPacked(indices, packed);
        ok = crypto::sha256(packed, kEntropyBytes, digest) && digest[0] == packed[kEntropyBytes];
    }
    if (ok) {
        memcpy(entropy_out, packed, kEntropyBytes);
    } else {
        security::secureMemzero(entropy_out, kEntropyBytes);
    }

    security::secureMemzero(indices, sizeof(indices));
    security::secureMemzero(packed, sizeof(packed));
    security::secureMemzero(digest, sizeof(digest));
    return ok;
}

bool isPrintableAscii(const char* s, size_t* len_out) {
    size_t len = 0;
    for (; s[len] != '\0'; ++len) {
        if (len == kMaxPassphraseLength || s[len] < 0x20 || s[len] > 0x7E) {
            return false;
        }
    }
    *len_out = len;
    return true;
}

// mbedTLS 2.x takes a prepared HMAC context; mbedTLS 3.x deprecates that in
// favor of the _ext variant that takes the digest type directly.
int pbkdf2HmacSha512(const uint8_t* password, size_t password_len, const uint8_t* salt, size_t salt_len,
                     uint8_t out[kSeedBytes]) {
#if MBEDTLS_VERSION_MAJOR >= 3
    return mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA512, password, password_len, salt, salt_len,
                                         kPbkdf2Iterations, kSeedBytes, out);
#else
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    if (info == nullptr) {
        return -1;
    }
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    constexpr int kUseHmac = 1;
    int ret = mbedtls_md_setup(&ctx, info, kUseHmac);
    if (ret == 0) {
        ret = mbedtls_pkcs5_pbkdf2_hmac(&ctx, password, password_len, salt, salt_len, kPbkdf2Iterations,
                                        kSeedBytes, out);
    }
    mbedtls_md_free(&ctx);  // zeroizes and frees the HMAC pads
    security::secureMemzero(&ctx, sizeof(ctx));
    return ret;
#endif
}

}  // namespace

bool entropyToMnemonic(const uint8_t entropy[kEntropyBytes], char* mnemonic_out, size_t out_size) {
    if (mnemonic_out == nullptr) {
        return false;
    }
    if (entropy == nullptr || out_size < kMaxMnemonicLength) {
        security::secureMemzero(mnemonic_out, out_size);
        return false;
    }

    uint8_t packed[kPackedBytes];
    uint8_t digest[crypto::kSha256DigestSize];
    uint16_t indices[kWordCount];

    bool ok = crypto::sha256(entropy, kEntropyBytes, digest);
    if (ok) {
        memcpy(packed, entropy, kEntropyBytes);
        packed[kEntropyBytes] = digest[0];  // first 8 bits of SHA-256(entropy)
        packedToIndices(packed, indices);

        size_t pos = 0;
        for (size_t w = 0; w < kWordCount; ++w) {
            const char* word = getWord(indices[w]);
            const size_t len = strlen(word);
            if (w > 0) {
                mnemonic_out[pos++] = ' ';
            }
            memcpy(mnemonic_out + pos, word, len);
            pos += len;
        }
        mnemonic_out[pos] = '\0';
    } else {
        security::secureMemzero(mnemonic_out, out_size);
    }

    security::secureMemzero(packed, sizeof(packed));
    security::secureMemzero(digest, sizeof(digest));
    security::secureMemzero(indices, sizeof(indices));
    return ok;
}

bool validateMnemonic(const char* mnemonic) {
    uint8_t entropy[kEntropyBytes];
    const bool ok = decodeMnemonic(mnemonic, entropy);
    security::secureMemzero(entropy, sizeof(entropy));
    return ok;
}

bool mnemonicToEntropy(const char* mnemonic, uint8_t entropy_out[kEntropyBytes]) {
    if (entropy_out == nullptr) {
        return false;
    }
    return decodeMnemonic(mnemonic, entropy_out);
}

bool mnemonicToSeed(const char* mnemonic, const char* passphrase, uint8_t seed_out[kSeedBytes]) {
    if (seed_out == nullptr) {
        return false;
    }
    if (passphrase == nullptr) {
        passphrase = "";
    }
    size_t passphrase_len = 0;
    if (!validateMnemonic(mnemonic) || !isPrintableAscii(passphrase, &passphrase_len)) {
        security::secureMemzero(seed_out, kSeedBytes);
        return false;
    }

    uint8_t salt[kSaltPrefixLength + kMaxPassphraseLength];
    memcpy(salt, kSaltPrefix, kSaltPrefixLength);
    memcpy(salt + kSaltPrefixLength, passphrase, passphrase_len);

    const bool ok = pbkdf2HmacSha512(reinterpret_cast<const uint8_t*>(mnemonic), strlen(mnemonic), salt,
                                     kSaltPrefixLength + passphrase_len, seed_out) == 0;
    if (!ok) {
        security::secureMemzero(seed_out, kSeedBytes);
    }
    security::secureMemzero(salt, sizeof(salt));
    return ok;
}

}  // namespace bip39
}  // namespace es

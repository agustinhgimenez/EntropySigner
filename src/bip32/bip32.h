#pragma once

#include <stddef.h>
#include <stdint.h>

// BIP-32 hierarchical deterministic keys over secp256k1.
// Pure C++ over mbedTLS (HMAC-SHA512, ECP), no Arduino dependency.
//
// Every function returns false on invalid arguments or failure and then zeroes
// its output (when non-null). Outputs may alias inputs: results are computed in
// local buffers and copied at the end.

namespace es {
namespace bip32 {

constexpr uint32_t kHardenedFlag = 0x80000000u;
constexpr size_t kPrivateKeyBytes = 32;
constexpr size_t kPublicKeyBytes = 33;  // compressed: 02/03 || X
constexpr size_t kUncompressedPublicKeyBytes = 65;  // 04 || X || Y
constexpr size_t kChainCodeBytes = 32;
constexpr size_t kMinSeedBytes = 16;  // 128 bits, BIP-32 minimum
constexpr size_t kMaxSeedBytes = 64;  // 512 bits, BIP-32 maximum (BIP-39 seed size)
constexpr uint8_t kMaxDepth = 255;

struct ExtendedPrivateKey {
    uint8_t key[kPrivateKeyBytes];
    uint8_t chain_code[kChainCodeBytes];
    uint8_t depth;
    uint32_t parent_fingerprint;
    uint32_t child_number;
};

struct ExtendedPublicKey {
    uint8_t key[kPublicKeyBytes];  // 33 bytes compressed: 02/03 || X
    uint8_t chain_code[kChainCodeBytes];
    uint8_t depth;
    uint32_t parent_fingerprint;
    uint32_t child_number;
};

// Master key from a seed: I = HMAC-SHA512(key = "Bitcoin seed", seed),
// key = I[0..32), chain code = I[32..64). seed_len must be in
// [kMinSeedBytes, kMaxSeedBytes]. Fails if I_L is 0 or >= n (BIP-32 says the
// seed must then be discarded; probability < 2^-127).
bool createMasterKey(const uint8_t* seed, size_t seed_len, ExtendedPrivateKey* out_master);

// CKDpriv. index >= kHardenedFlag selects hardened derivation. Fails if the
// child would be invalid (I_L >= n or k = 0, probability < 2^-127): BIP-32
// says to move on to the next index, which is left to the caller rather than
// silently returning a key for a different index. Also fails at depth 255.
bool derivePrivateChild(const ExtendedPrivateKey* parent, uint32_t index, ExtendedPrivateKey* out_child);

// CKDpub. Only non-hardened indexes (< kHardenedFlag) can be derived from a
// public parent; hardened ones fail.
bool derivePublicChild(const ExtendedPublicKey* parent, uint32_t index, ExtendedPublicKey* out_child);

// N(): the extended public key matching priv (same chain code and metadata).
bool toPublic(const ExtendedPrivateKey* priv, ExtendedPublicKey* out_pub);

// Compressed public key point(k) for a private key k in [1, n).
bool privateToPublicKey(const uint8_t priv[kPrivateKeyBytes], uint8_t pub_out[kPublicKeyBytes]);

// Expands a compressed public key to 04 || X || Y, recovering Y on the curve.
// Fails (zeroing pub_out) if the prefix is not 02/03 or X is not on secp256k1.
bool decompressPublicKey(const uint8_t pub[kPublicKeyBytes], uint8_t pub_out[kUncompressedPublicKeyBytes]);

// Key identifier fingerprint: first 4 bytes of HASH160(pub), big-endian.
bool fingerprint(const uint8_t pub[kPublicKeyBytes], uint32_t* out_fingerprint);

// Derives path from root, e.g. "m/44'/0'/0'/0/0". Hardened components may be
// marked with ', h or H. The path must start with "m", root must be a master
// key (depth 0), and each index must be below 2^31 before the hardened mark.
bool derivePath(const ExtendedPrivateKey* root, const char* path, ExtendedPrivateKey* out_key);

// Zeroes the whole structure (key, chain code and metadata).
void wipe(ExtendedPrivateKey* key);
void wipe(ExtendedPublicKey* key);

}  // namespace bip32
}  // namespace es

#pragma once

#include <stddef.h>
#include <stdint.h>

// BIP-39 for 256-bit entropy / 24-word mnemonics (English wordlist only).
// Pure C++ over mbedTLS, no Arduino dependency.
//
// Mnemonic format accepted by every function: exactly kWordCount lowercase
// BIP-39 words separated by a single ASCII space, with no leading or trailing
// whitespace. This is the canonical form entropyToMnemonic() produces and the
// exact byte string BIP-39 feeds into PBKDF2, so a mnemonic that is accepted
// always yields the standard seed.

namespace es {
namespace bip39 {

constexpr size_t kEntropyBytes = 32;  // 256 bits
constexpr size_t kChecksumBits = kEntropyBytes * 8 / 32;  // 8 bits
constexpr size_t kWordCount = 24;  // (256 + 8) / 11
constexpr size_t kMaxMnemonicLength = 240;  // 24 words * 8 chars + 23 spaces + NUL = 216, rounded up
constexpr size_t kSeedBytes = 64;  // 512 bits
constexpr uint32_t kPbkdf2Iterations = 2048;
constexpr size_t kMaxPassphraseLength = 128;  // bytes, excluding NUL

// Encodes entropy as a 24-word mnemonic in mnemonic_out (NUL-terminated).
// out_size must be at least kMaxMnemonicLength. On failure mnemonic_out is
// zeroed (when non-null) and false is returned.
bool entropyToMnemonic(const uint8_t entropy[kEntropyBytes], char* mnemonic_out, size_t out_size);

// True if and only if mnemonic has the canonical format above, every word is in
// the wordlist and the 8-bit checksum matches.
bool validateMnemonic(const char* mnemonic);

// Recovers the 32 bytes of entropy from a valid mnemonic. On failure
// entropy_out is zeroed and false is returned.
bool mnemonicToEntropy(const char* mnemonic, uint8_t entropy_out[kEntropyBytes]);

// seed = PBKDF2-HMAC-SHA512(password = mnemonic,
//                           salt = "mnemonic" || passphrase,
//                           iterations = 2048, length = 64 bytes).
// passphrase may be null (treated as ""). BIP-39 requires both strings to be
// NFKD-normalized UTF-8; there is no Unicode normalizer on the device, so only
// printable ASCII passphrases (for which NFKD is the identity) are accepted.
// The mnemonic must also pass validateMnemonic(): BIP-39 itself would derive a
// seed from any string, but on a wallet a typo must not silently produce a
// different, empty wallet. On failure seed_out is zeroed and false is returned.
bool mnemonicToSeed(const char* mnemonic, const char* passphrase, uint8_t seed_out[kSeedBytes]);

}  // namespace bip39
}  // namespace es

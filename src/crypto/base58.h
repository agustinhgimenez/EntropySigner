#pragma once

#include <stddef.h>
#include <stdint.h>

// Base58 and Base58Check encoding (Bitcoin alphabet
// 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz).
// Pure C++, no Arduino dependency. Only public data (hashes, addresses) is
// encoded here, so the big-number division is not constant time.

namespace es {
namespace crypto {

// Largest input accepted by encodeBase58(); bounds the stack scratch buffer.
constexpr size_t kMaxBase58InputBytes = 128;
constexpr size_t kBase58ChecksumBytes = 4;
// Largest payload accepted by encodeBase58Check() (version + payload + checksum
// must fit kMaxBase58InputBytes).
constexpr size_t kMaxBase58CheckPayloadBytes = kMaxBase58InputBytes - 1 - kBase58ChecksumBytes;

// Encodes len bytes as a NUL-terminated Base58 string. Each leading zero byte
// becomes a leading '1'. Fails if out is too small (out_max counts the NUL) or
// len > kMaxBase58InputBytes; on failure out is zeroed (when non-null).
bool encodeBase58(const uint8_t* data, size_t len, char* out, size_t out_max);

// Base58(version || payload || checksum), checksum = first 4 bytes of
// SHA256(SHA256(version || payload)). For P2PKH addresses payload is the
// 20-byte HASH160 of the public key. Same failure contract as encodeBase58().
bool encodeBase58Check(uint8_t version, const uint8_t* payload, size_t payload_len, char* out, size_t out_max);

}  // namespace crypto
}  // namespace es

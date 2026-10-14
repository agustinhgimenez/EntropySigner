#include "ethereum/ethereum.h"

#include <string.h>

#include "crypto/keccak256.h"
#include "security/secure_mem.h"

namespace es {
namespace ethereum {

namespace {

constexpr size_t kHexDigits = 2 * kAddressBytes;
constexpr size_t kPrefixLength = 2;  // "0x"
constexpr char kHexLower[] = "0123456789abcdef";

static_assert(kPrefixLength + kHexDigits + 1 == kAddressLength, "0x + 40 hex + NUL");

}  // namespace

bool toChecksumAddress(const uint8_t address[kAddressBytes], char address_out[kAddressLength]) {
    if (address_out == nullptr) {
        return false;
    }
    if (address == nullptr) {
        memset(address_out, 0, kAddressLength);
        return false;
    }

    char hex[kHexDigits];
    for (size_t i = 0; i < kAddressBytes; ++i) {
        hex[2 * i] = kHexLower[address[i] >> 4];
        hex[2 * i + 1] = kHexLower[address[i] & 0x0F];
    }
    uint8_t hash[crypto::kKeccak256DigestSize];
    if (!crypto::keccak256(reinterpret_cast<const uint8_t*>(hex), sizeof(hex), hash)) {
        memset(address_out, 0, kAddressLength);
        return false;
    }

    address_out[0] = '0';
    address_out[1] = 'x';
    for (size_t i = 0; i < kHexDigits; ++i) {
        // Nibble i of the hash: high nibble for even i, low nibble for odd i.
        const uint8_t nibble = (i % 2 == 0) ? (hash[i / 2] >> 4) : (hash[i / 2] & 0x0F);
        char c = hex[i];
        if (c >= 'a' && c <= 'f' && nibble >= 8) {
            c = static_cast<char>(c - 'a' + 'A');
        }
        address_out[kPrefixLength + i] = c;
    }
    address_out[kPrefixLength + kHexDigits] = '\0';
    return true;
}

bool pubkeyToEthereumAddress(const uint8_t compressed_pub[bip32::kPublicKeyBytes], char address_out[kAddressLength]) {
    if (address_out == nullptr) {
        return false;
    }
    uint8_t uncompressed[bip32::kUncompressedPublicKeyBytes];
    uint8_t hash[crypto::kKeccak256DigestSize];
    // Hash X || Y, skipping the 04 prefix; the address is the last 20 bytes.
    const bool ok = compressed_pub != nullptr && bip32::decompressPublicKey(compressed_pub, uncompressed) &&
                    crypto::keccak256(uncompressed + 1, sizeof(uncompressed) - 1, hash) &&
                    toChecksumAddress(hash + sizeof(hash) - kAddressBytes, address_out);
    if (!ok) {
        memset(address_out, 0, kAddressLength);
    }
    security::secureMemzero(uncompressed, sizeof(uncompressed));
    security::secureMemzero(hash, sizeof(hash));
    return ok;
}

bool deriveEthereumAddress(const bip32::ExtendedPrivateKey& master, char address_out[kAddressLength]) {
    if (address_out == nullptr) {
        return false;
    }
    bip32::ExtendedPrivateKey priv;
    uint8_t pub[bip32::kPublicKeyBytes];
    bool ok = bip32::derivePath(&master, kBip44Path, &priv) && bip32::privateToPublicKey(priv.key, pub);
    bip32::wipe(&priv);  // only the public key is needed from here on
    ok = ok && pubkeyToEthereumAddress(pub, address_out);
    if (!ok) {
        memset(address_out, 0, kAddressLength);
    }
    security::secureMemzero(pub, sizeof(pub));
    return ok;
}

}  // namespace ethereum
}  // namespace es

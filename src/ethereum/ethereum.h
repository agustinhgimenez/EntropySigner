#pragma once

#include <stddef.h>
#include <stdint.h>

#include "bip32/bip32.h"

// Ethereum BIP-44 account 0, first address, with the EIP-55 mixed-case
// checksum. Pure C++, no Arduino dependency.
//
// Every function returns false on invalid arguments or failure and then zeroes
// its output (when non-null).

namespace es {
namespace ethereum {

constexpr char kBip44Path[] = "m/44'/60'/0'/0/0";
constexpr size_t kAddressBytes = 20;
constexpr size_t kAddressLength = 43;  // "0x" + 40 hex + NUL

// EIP-55: "0x" + the 40 hex digits of address, where each letter is uppercase
// iff the matching nibble of Keccak-256(lowercase hex) is >= 8.
bool toChecksumAddress(const uint8_t address[kAddressBytes], char address_out[kAddressLength]);

// Address = last 20 bytes of Keccak-256(X || Y) of the uncompressed public key
// (without the 04 prefix), rendered with toChecksumAddress().
bool pubkeyToEthereumAddress(const uint8_t compressed_pub[bip32::kPublicKeyBytes], char address_out[kAddressLength]);

// Derives kBip44Path and writes its EIP-55 address. The derived private key
// is wiped as soon as its public key has been computed.
bool deriveEthereumAddress(const bip32::ExtendedPrivateKey& master, char address_out[kAddressLength]);

}  // namespace ethereum
}  // namespace es

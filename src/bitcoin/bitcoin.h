#pragma once

#include <stddef.h>
#include <stdint.h>

#include "bip32/bip32.h"

// Bitcoin BIP-44 account 0, external chain, first address, as a legacy
// mainnet P2PKH address (Base58Check, starts with '1').
// Pure C++, no Arduino dependency.
//
// Every function returns false on invalid arguments or failure and then zeroes
// its outputs (when non-null).

namespace es {
namespace bitcoin {

constexpr char kBip44Path[] = "m/44'/0'/0'/0/0";
// Output buffer size for an address, NUL included. P2PKH addresses are
// 26-34 characters (25 bytes in Base58).
constexpr size_t kMaxAddressLength = 40;
constexpr uint8_t kP2pkhMainnetVersion = 0x00;

// Derives kBip44Path from a master key. out_priv receives the private node and
// out_pub its public counterpart; the caller must bip32::wipe(out_priv).
bool deriveBitcoinKey(const bip32::ExtendedPrivateKey& master, bip32::ExtendedPrivateKey* out_priv,
                      bip32::ExtendedPublicKey* out_pub);

// P2PKH address: Base58Check(0x00 || HASH160(compressed pubkey)). out_size
// counts the NUL and must be large enough for the address (kMaxAddressLength
// always is).
bool pubkeyToLegacyAddress(const uint8_t pubkey[bip32::kPublicKeyBytes], char* address_out, size_t out_size);

// Derives kBip44Path and writes its P2PKH address. The derived private key is
// wiped as soon as its public key has been computed.
bool deriveBitcoinAddress(const bip32::ExtendedPrivateKey& master, char* address_out, size_t out_size);

}  // namespace bitcoin
}  // namespace es

#include "bitcoin/bitcoin.h"

#include <string.h>

#include "crypto/base58.h"
#include "crypto/ripemd160.h"
#include "security/secure_mem.h"

namespace es {
namespace bitcoin {

bool deriveBitcoinKey(const bip32::ExtendedPrivateKey& master, bip32::ExtendedPrivateKey* out_priv,
                      bip32::ExtendedPublicKey* out_pub) {
    if (out_priv == nullptr || out_pub == nullptr) {
        bip32::wipe(out_priv);
        bip32::wipe(out_pub);
        return false;
    }
    const bool ok = bip32::derivePath(&master, kBip44Path, out_priv) && bip32::toPublic(out_priv, out_pub);
    if (!ok) {
        bip32::wipe(out_priv);
        bip32::wipe(out_pub);
    }
    return ok;
}

bool pubkeyToLegacyAddress(const uint8_t pubkey[bip32::kPublicKeyBytes], char* address_out, size_t out_size) {
    if (address_out == nullptr || out_size == 0) {
        return false;
    }
    uint8_t id[crypto::kRipemd160DigestSize];
    const bool ok = pubkey != nullptr && (pubkey[0] == 0x02 || pubkey[0] == 0x03) &&
                    crypto::hash160(pubkey, bip32::kPublicKeyBytes, id) &&
                    crypto::encodeBase58Check(kP2pkhMainnetVersion, id, sizeof(id), address_out, out_size);
    if (!ok) {
        memset(address_out, 0, out_size);
    }
    security::secureMemzero(id, sizeof(id));
    return ok;
}

bool deriveBitcoinAddress(const bip32::ExtendedPrivateKey& master, char* address_out, size_t out_size) {
    if (address_out == nullptr || out_size == 0) {
        return false;
    }
    bip32::ExtendedPrivateKey priv;
    bip32::ExtendedPublicKey pub;
    bool ok = deriveBitcoinKey(master, &priv, &pub);
    bip32::wipe(&priv);  // only the public key is needed from here on
    ok = ok && pubkeyToLegacyAddress(pub.key, address_out, out_size);
    if (!ok) {
        memset(address_out, 0, out_size);
    }
    bip32::wipe(&pub);
    return ok;
}

}  // namespace bitcoin
}  // namespace es

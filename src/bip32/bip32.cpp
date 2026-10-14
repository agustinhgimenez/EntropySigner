#include "bip32/bip32.h"

#include <string.h>

#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>
#include <mbedtls/hmac_drbg.h>
#include <mbedtls/md.h>

#include "crypto/ripemd160.h"
#include "security/secure_mem.h"

namespace es {
namespace bip32 {

namespace {

constexpr size_t kHmacBytes = 64;  // HMAC-SHA512 output: I_L || I_R
constexpr size_t kIndexBytes = 4;
constexpr size_t kCkdDataBytes = kPublicKeyBytes + kIndexBytes;  // serP(K) || ser32(i), or 0x00 || ser256(k) || ser32(i)
constexpr size_t kUncompressedBytes = kUncompressedPublicKeyBytes;

static_assert(1 + 2 * kPrivateKeyBytes == kUncompressedBytes, "uncompressed key is 04 || X || Y");

static_assert(kPrivateKeyBytes + kChainCodeBytes == kHmacBytes, "I splits into key and chain code");
static_assert(1 + kPrivateKeyBytes == kPublicKeyBytes, "hardened data has the same length as normal data");

// HMAC key for the master node, without the NUL terminator.
constexpr char kMasterHmacKey[] = "Bitcoin seed";
constexpr size_t kMasterHmacKeyLength = sizeof(kMasterHmacKey) - 1;

// Owning wrappers so every exit path frees (and thereby zeroizes) mbedTLS state.
struct Mpi {
    mbedtls_mpi v;
    Mpi() { mbedtls_mpi_init(&v); }
    ~Mpi() { mbedtls_mpi_free(&v); }
    Mpi(const Mpi&) = delete;
    Mpi& operator=(const Mpi&) = delete;
};

struct Point {
    mbedtls_ecp_point v;
    Point() { mbedtls_ecp_point_init(&v); }
    ~Point() { mbedtls_ecp_point_free(&v); }
    Point(const Point&) = delete;
    Point& operator=(const Point&) = delete;
};

class Secp256k1 {
public:
    Secp256k1() {
        mbedtls_ecp_group_init(&grp_);
        ok_ = mbedtls_ecp_group_load(&grp_, MBEDTLS_ECP_DP_SECP256K1) == 0;
    }
    ~Secp256k1() { mbedtls_ecp_group_free(&grp_); }
    Secp256k1(const Secp256k1&) = delete;
    Secp256k1& operator=(const Secp256k1&) = delete;

    bool ok() const { return ok_; }
    mbedtls_ecp_group* grp() { return &grp_; }

private:
    mbedtls_ecp_group grp_;
    bool ok_;
};

inline void writeBe32(uint32_t value, uint8_t out[kIndexBytes]) {
    out[0] = static_cast<uint8_t>(value >> 24);
    out[1] = static_cast<uint8_t>(value >> 16);
    out[2] = static_cast<uint8_t>(value >> 8);
    out[3] = static_cast<uint8_t>(value);
}

bool hmacSha512(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len, uint8_t out[kHmacBytes]) {
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    // mbedtls_md_hmac() frees (and zeroizes) its internal context on return.
    return info != nullptr && mbedtls_md_hmac(info, key, key_len, data, data_len, out) == 0;
}

// True if k (big-endian, 32 bytes) is a valid private key: 0 < k < n.
bool isValidPrivateKey(Secp256k1& curve, const uint8_t k[kPrivateKeyBytes]) {
    Mpi d;
    return mbedtls_mpi_read_binary(&d.v, k, kPrivateKeyBytes) == 0 &&
           mbedtls_ecp_check_privkey(curve.grp(), &d.v) == 0;
}

// point(k), serialized compressed.
bool computePublicKey(Secp256k1& curve, const uint8_t priv[kPrivateKeyBytes], uint8_t pub_out[kPublicKeyBytes]) {
    Mpi d;
    Point q;
    if (mbedtls_mpi_read_binary(&d.v, priv, kPrivateKeyBytes) != 0 ||
        mbedtls_ecp_check_privkey(curve.grp(), &d.v) != 0) {
        return false;
    }

    // mbedtls_ecp_mul() randomizes the projective coordinates as a side-channel
    // countermeasure; mbedTLS 3.x requires an RNG for it. A deterministic
    // HMAC-DRBG seeded from the scalar mirrors mbedTLS 2.x's internal fallback
    // and keeps this module free of a hardware RNG dependency.
    mbedtls_hmac_drbg_context drbg;
    mbedtls_hmac_drbg_init(&drbg);
    const mbedtls_md_info_t* sha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    size_t written = 0;
    const bool ok = sha256 != nullptr && mbedtls_hmac_drbg_seed_buf(&drbg, sha256, priv, kPrivateKeyBytes) == 0 &&
                    mbedtls_ecp_mul(curve.grp(), &q.v, &d.v, &curve.grp()->G, mbedtls_hmac_drbg_random, &drbg) == 0 &&
                    mbedtls_ecp_point_write_binary(curve.grp(), &q.v, MBEDTLS_ECP_PF_COMPRESSED, &written, pub_out,
                                                   kPublicKeyBytes) == 0 &&
                    written == kPublicKeyBytes;
    mbedtls_hmac_drbg_free(&drbg);  // zeroizes the DRBG state
    return ok;
}

// Parses a compressed public key. mbedTLS only reads the uncompressed form, so
// Y is recovered as sqrt(X^3 + 7) mod p, which for secp256k1 (A = 0,
// p = 3 mod 4) is (X^3 + 7)^((p + 1) / 4) mod p, then its parity is fixed.
bool parsePublicKey(Secp256k1& curve, const uint8_t pub[kPublicKeyBytes], mbedtls_ecp_point* q) {
    if (pub[0] != 0x02 && pub[0] != 0x03) {
        return false;
    }
    mbedtls_ecp_group* grp = curve.grp();
    Mpi x, y, rhs, exp, check;
    if (mbedtls_mpi_read_binary(&x.v, pub + 1, kPrivateKeyBytes) != 0 || mbedtls_mpi_cmp_mpi(&x.v, &grp->P) >= 0) {
        return false;
    }
    // rhs = X^3 + B mod p; exp = (p + 1) / 4
    if (mbedtls_mpi_mul_mpi(&rhs.v, &x.v, &x.v) != 0 || mbedtls_mpi_mod_mpi(&rhs.v, &rhs.v, &grp->P) != 0 ||
        mbedtls_mpi_mul_mpi(&rhs.v, &rhs.v, &x.v) != 0 || mbedtls_mpi_add_mpi(&rhs.v, &rhs.v, &grp->B) != 0 ||
        mbedtls_mpi_mod_mpi(&rhs.v, &rhs.v, &grp->P) != 0 || mbedtls_mpi_add_int(&exp.v, &grp->P, 1) != 0 ||
        mbedtls_mpi_shift_r(&exp.v, 2) != 0 || mbedtls_mpi_exp_mod(&y.v, &rhs.v, &exp.v, &grp->P, nullptr) != 0) {
        return false;
    }
    // X is not on the curve if rhs has no square root.
    if (mbedtls_mpi_mul_mpi(&check.v, &y.v, &y.v) != 0 || mbedtls_mpi_mod_mpi(&check.v, &check.v, &grp->P) != 0 ||
        mbedtls_mpi_cmp_mpi(&check.v, &rhs.v) != 0) {
        return false;
    }
    if (static_cast<uint8_t>(mbedtls_mpi_get_bit(&y.v, 0)) != (pub[0] & 1) &&
        mbedtls_mpi_sub_mpi(&y.v, &grp->P, &y.v) != 0) {
        return false;
    }

    uint8_t uncompressed[kUncompressedBytes];
    uncompressed[0] = 0x04;
    memcpy(uncompressed + 1, pub + 1, kPrivateKeyBytes);
    return mbedtls_mpi_write_binary(&y.v, uncompressed + 1 + kPrivateKeyBytes, kPrivateKeyBytes) == 0 &&
           mbedtls_ecp_point_read_binary(grp, q, uncompressed, sizeof(uncompressed)) == 0 &&
           mbedtls_ecp_check_pubkey(grp, q) == 0;
}

bool computeFingerprint(const uint8_t pub[kPublicKeyBytes], uint32_t* out) {
    uint8_t id[crypto::kRipemd160DigestSize];
    if (!crypto::hash160(pub, kPublicKeyBytes, id)) {
        return false;
    }
    *out = (static_cast<uint32_t>(id[0]) << 24) | (static_cast<uint32_t>(id[1]) << 16) |
           (static_cast<uint32_t>(id[2]) << 8) | static_cast<uint32_t>(id[3]);
    return true;
}

// CKDpriv on an already loaded curve (derivePath reuses one across levels).
// Writes the child into a local and copies it out only on success.
bool ckdPriv(Secp256k1& curve, const ExtendedPrivateKey& parent, uint32_t index, ExtendedPrivateKey* out_child) {
    if (parent.depth == kMaxDepth) {
        return false;
    }
    uint8_t parent_pub[kPublicKeyBytes];
    uint8_t data[kCkdDataBytes];
    uint8_t i[kHmacBytes];
    ExtendedPrivateKey child;
    memset(&child, 0, sizeof(child));
    bool ok = computePublicKey(curve, parent.key, parent_pub);
    if (ok) {
        if (index & kHardenedFlag) {
            data[0] = 0x00;
            memcpy(data + 1, parent.key, kPrivateKeyBytes);
        } else {
            memcpy(data, parent_pub, kPublicKeyBytes);
        }
        writeBe32(index, data + kPublicKeyBytes);
        ok = hmacSha512(parent.chain_code, kChainCodeBytes, data, sizeof(data), i);
    }
    if (ok) {
        // k_i = parse256(I_L) + k_par (mod n), rejecting I_L >= n and k_i = 0.
        Mpi il, k;
        mbedtls_ecp_group* grp = curve.grp();
        ok = mbedtls_mpi_read_binary(&il.v, i, kPrivateKeyBytes) == 0 && mbedtls_mpi_cmp_mpi(&il.v, &grp->N) < 0 &&
             mbedtls_mpi_read_binary(&k.v, parent.key, kPrivateKeyBytes) == 0 &&
             mbedtls_mpi_add_mpi(&k.v, &k.v, &il.v) == 0 && mbedtls_mpi_mod_mpi(&k.v, &k.v, &grp->N) == 0 &&
             mbedtls_mpi_cmp_int(&k.v, 0) != 0 && mbedtls_mpi_write_binary(&k.v, child.key, kPrivateKeyBytes) == 0;
    }
    if (ok) {
        memcpy(child.chain_code, i + kPrivateKeyBytes, kChainCodeBytes);
        child.depth = static_cast<uint8_t>(parent.depth + 1);
        child.child_number = index;
        ok = computeFingerprint(parent_pub, &child.parent_fingerprint);
    }
    if (ok) {
        memcpy(out_child, &child, sizeof(child));
    } else {
        wipe(out_child);
    }
    wipe(&child);
    security::secureMemzero(data, sizeof(data));
    security::secureMemzero(i, sizeof(i));
    security::secureMemzero(parent_pub, sizeof(parent_pub));
    return ok;
}

// Parses one decimal path index (< 2^31) with an optional hardened mark.
// Advances *p past it.
bool parsePathIndex(const char** p, uint32_t* index) {
    const char* s = *p;
    if (*s < '0' || *s > '9') {
        return false;
    }
    uint32_t value = 0;
    while (*s >= '0' && *s <= '9') {
        value = value * 10 + static_cast<uint32_t>(*s - '0');
        if (value >= kHardenedFlag) {
            return false;
        }
        ++s;
    }
    if (*s == '\'' || *s == 'h' || *s == 'H') {
        value |= kHardenedFlag;
        ++s;
    }
    *index = value;
    *p = s;
    return true;
}

}  // namespace

bool createMasterKey(const uint8_t* seed, size_t seed_len, ExtendedPrivateKey* out_master) {
    if (out_master == nullptr) {
        return false;
    }
    wipe(out_master);
    if (seed == nullptr || seed_len < kMinSeedBytes || seed_len > kMaxSeedBytes) {
        return false;
    }
    Secp256k1 curve;
    uint8_t i[kHmacBytes];
    const bool ok = curve.ok() &&
                    hmacSha512(reinterpret_cast<const uint8_t*>(kMasterHmacKey), kMasterHmacKeyLength, seed,
                               seed_len, i) &&
                    isValidPrivateKey(curve, i);
    if (ok) {
        memcpy(out_master->key, i, kPrivateKeyBytes);
        memcpy(out_master->chain_code, i + kPrivateKeyBytes, kChainCodeBytes);
    }
    security::secureMemzero(i, sizeof(i));
    return ok;
}

bool derivePrivateChild(const ExtendedPrivateKey* parent, uint32_t index, ExtendedPrivateKey* out_child) {
    if (out_child == nullptr) {
        return false;
    }
    Secp256k1 curve;
    if (parent == nullptr || !curve.ok()) {
        wipe(out_child);
        return false;
    }
    return ckdPriv(curve, *parent, index, out_child);
}

bool derivePublicChild(const ExtendedPublicKey* parent, uint32_t index, ExtendedPublicKey* out_child) {
    if (out_child == nullptr) {
        return false;
    }
    Secp256k1 curve;
    ExtendedPublicKey child;
    memset(&child, 0, sizeof(child));
    uint8_t data[kCkdDataBytes];
    uint8_t i[kHmacBytes];
    bool ok = parent != nullptr && curve.ok() && (index & kHardenedFlag) == 0 && parent->depth < kMaxDepth;
    if (ok) {
        memcpy(data, parent->key, kPublicKeyBytes);
        writeBe32(index, data + kPublicKeyBytes);
        ok = hmacSha512(parent->chain_code, kChainCodeBytes, data, sizeof(data), i);
    }
    if (ok) {
        // K_i = point(parse256(I_L)) + K_par, rejecting I_L >= n and the point
        // at infinity. Only public values are involved, so the non-constant-time
        // mbedtls_ecp_muladd() is acceptable here.
        mbedtls_ecp_group* grp = curve.grp();
        Mpi il, one;
        Point k_par, k_child;
        size_t written = 0;
        ok = mbedtls_mpi_read_binary(&il.v, i, kPrivateKeyBytes) == 0 && mbedtls_mpi_cmp_mpi(&il.v, &grp->N) < 0 &&
             mbedtls_mpi_lset(&one.v, 1) == 0 && parsePublicKey(curve, parent->key, &k_par.v) &&
             mbedtls_ecp_muladd(grp, &k_child.v, &il.v, &grp->G, &one.v, &k_par.v) == 0 &&
             mbedtls_ecp_is_zero(&k_child.v) == 0 &&
             mbedtls_ecp_point_write_binary(grp, &k_child.v, MBEDTLS_ECP_PF_COMPRESSED, &written, child.key,
                                            kPublicKeyBytes) == 0 &&
             written == kPublicKeyBytes;
    }
    if (ok) {
        memcpy(child.chain_code, i + kPrivateKeyBytes, kChainCodeBytes);
        child.depth = static_cast<uint8_t>(parent->depth + 1);
        child.child_number = index;
        ok = computeFingerprint(parent->key, &child.parent_fingerprint);
    }
    if (ok) {
        memcpy(out_child, &child, sizeof(child));
    } else {
        memset(out_child, 0, sizeof(*out_child));
    }
    security::secureMemzero(data, sizeof(data));
    security::secureMemzero(i, sizeof(i));  // I_R is the child's chain code
    security::secureMemzero(&child, sizeof(child));
    return ok;
}

bool toPublic(const ExtendedPrivateKey* priv, ExtendedPublicKey* out_pub) {
    if (out_pub == nullptr) {
        return false;
    }
    ExtendedPublicKey pub;
    memset(&pub, 0, sizeof(pub));
    const bool ok = priv != nullptr && privateToPublicKey(priv->key, pub.key);
    if (ok) {
        memcpy(pub.chain_code, priv->chain_code, kChainCodeBytes);
        pub.depth = priv->depth;
        pub.parent_fingerprint = priv->parent_fingerprint;
        pub.child_number = priv->child_number;
    }
    memcpy(out_pub, &pub, sizeof(pub));  // all zeros on failure
    security::secureMemzero(&pub, sizeof(pub));
    return ok;
}

bool privateToPublicKey(const uint8_t priv[kPrivateKeyBytes], uint8_t pub_out[kPublicKeyBytes]) {
    if (pub_out == nullptr) {
        return false;
    }
    Secp256k1 curve;
    uint8_t pub[kPublicKeyBytes];
    const bool ok = priv != nullptr && curve.ok() && computePublicKey(curve, priv, pub);
    if (ok) {
        memcpy(pub_out, pub, kPublicKeyBytes);
    } else {
        security::secureMemzero(pub_out, kPublicKeyBytes);
    }
    security::secureMemzero(pub, sizeof(pub));
    return ok;
}

bool decompressPublicKey(const uint8_t pub[kPublicKeyBytes], uint8_t pub_out[kUncompressedPublicKeyBytes]) {
    if (pub_out == nullptr) {
        return false;
    }
    Secp256k1 curve;
    Point q;
    uint8_t buf[kUncompressedBytes];
    size_t written = 0;
    const bool ok = pub != nullptr && curve.ok() && parsePublicKey(curve, pub, &q.v) &&
                    mbedtls_ecp_point_write_binary(curve.grp(), &q.v, MBEDTLS_ECP_PF_UNCOMPRESSED, &written, buf,
                                                   sizeof(buf)) == 0 &&
                    written == kUncompressedBytes;
    if (ok) {
        memcpy(pub_out, buf, kUncompressedBytes);
    } else {
        memset(pub_out, 0, kUncompressedBytes);
    }
    return ok;
}

bool fingerprint(const uint8_t pub[kPublicKeyBytes], uint32_t* out_fingerprint) {
    if (out_fingerprint == nullptr) {
        return false;
    }
    *out_fingerprint = 0;
    return pub != nullptr && computeFingerprint(pub, out_fingerprint);
}

bool derivePath(const ExtendedPrivateKey* root, const char* path, ExtendedPrivateKey* out_key) {
    if (out_key == nullptr) {
        return false;
    }
    Secp256k1 curve;
    if (root == nullptr || path == nullptr || path[0] != 'm' || root->depth != 0 || !curve.ok()) {
        wipe(out_key);
        return false;
    }

    ExtendedPrivateKey current;
    memcpy(&current, root, sizeof(current));
    const char* p = path + 1;
    bool ok = true;
    while (ok && *p != '\0') {
        uint32_t index = 0;
        ok = *p++ == '/' && parsePathIndex(&p, &index) && ckdPriv(curve, current, index, &current);
    }
    if (ok) {
        memcpy(out_key, &current, sizeof(current));
    } else {
        wipe(out_key);
    }
    wipe(&current);
    return ok;
}

void wipe(ExtendedPrivateKey* key) {
    security::secureMemzero(key, sizeof(*key));
}

void wipe(ExtendedPublicKey* key) {
    security::secureMemzero(key, sizeof(*key));
}

}  // namespace bip32
}  // namespace es

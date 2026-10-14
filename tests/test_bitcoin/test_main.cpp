// Bitcoin unit tests: Base58 against Bitcoin Core's base58_encode_decode.json
// vectors, Base58Check / P2PKH against well-known addresses, and the BIP-44
// derivation m/44'/0'/0'/0/0 from the BIP-39 "abandon ... about" seed.

#include <Arduino.h>
#include <stdio.h>
#include <string.h>
#include <unity.h>

#include "bip32/bip32.h"
#include "bitcoin/bitcoin.h"
#include "crypto/base58.h"

using namespace es;

void setUp() {}
void tearDown() {}

namespace {

struct Base58Vector {
    const char* hex;
    const char* base58;
};

// https://github.com/bitcoin/bitcoin/blob/master/src/test/data/base58_encode_decode.json
const Base58Vector kBase58Vectors[] = {
    {"", ""},
    {"61", "2g"},
    {"626262", "a3gV"},
    {"636363", "aPEr"},
    {"73696d706c792061206c6f6e6720737472696e67", "2cFupjhnEsSn59qHXstmK2ffpLv2"},
    {"00eb15231dfceb60925886b67d065299925915aeb172c06647", "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L"},
    {"516b6fcd0f", "ABnLTmg"},
    {"bf4f89001e670274dd", "3SEo3LWLoPntC"},
    {"572e4794", "3EFU7m"},
    {"ecac89cad93923c02321", "EJDM8drfXA6uyA"},
    {"10c8511e", "Rt5zm"},
    {"00000000000000000000", "1111111111"},
};

struct AddressVector {
    const char* pubkey_hex;
    const char* address;
};

// BIP-32 test vector 1 master key, and the generator G (private key 1).
const AddressVector kAddressVectors[] = {
    {"0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2", "15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma"},
    {"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"},
};

// BIP-39 seed of "abandon abandon ... abandon about" with an empty passphrase;
// m/44'/0'/0'/0/0 is the well-known address 1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA.
const char kAbandonSeedHex[] =
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
    "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
const char kAbandonPrivateKeyHex[] = "e284129cc0922579a535bbf4d1a3b25773090d28c909bc0fed73b5e0222cc372";
const char kAbandonPublicKeyHex[] = "03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e";
const char kAbandonAddress[] = "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA";

size_t hexToBytes(const char* hex, uint8_t* out, size_t max_len) {
    const size_t len = strlen(hex) / 2;
    TEST_ASSERT_TRUE(len <= max_len);
    for (size_t i = 0; i < len; ++i) {
        unsigned int byte_val = 0;
        sscanf(hex + 2 * i, "%02x", &byte_val);
        out[i] = static_cast<uint8_t>(byte_val);
    }
    return len;
}

void masterFromHex(const char* seed_hex, bip32::ExtendedPrivateKey* master) {
    uint8_t seed[bip32::kMaxSeedBytes];
    const size_t seed_len = hexToBytes(seed_hex, seed, sizeof(seed));
    TEST_ASSERT_TRUE(bip32::createMasterKey(seed, seed_len, master));
}

}  // namespace

void test_base58_vectors() {
    for (const Base58Vector& v : kBase58Vectors) {
        uint8_t data[64];
        const size_t len = hexToBytes(v.hex, data, sizeof(data));
        char out[96];
        TEST_ASSERT_TRUE_MESSAGE(crypto::encodeBase58(data, len, out, sizeof(out)), v.hex);
        TEST_ASSERT_EQUAL_STRING_MESSAGE(v.base58, out, v.hex);
    }
}

void test_base58_buffer_too_small() {
    const uint8_t data[] = {0x62, 0x62, 0x62};  // "a3gV"
    char out[5];
    TEST_ASSERT_TRUE(crypto::encodeBase58(data, sizeof(data), out, 5));  // exact fit with NUL
    TEST_ASSERT_EQUAL_STRING("a3gV", out);

    memset(out, 'x', sizeof(out));
    TEST_ASSERT_FALSE(crypto::encodeBase58(data, sizeof(data), out, 4));
    TEST_ASSERT_EACH_EQUAL_CHAR(0, out, 4);

    uint8_t big[crypto::kMaxBase58InputBytes + 1] = {0};
    char big_out[256];
    TEST_ASSERT_FALSE(crypto::encodeBase58(big, sizeof(big), big_out, sizeof(big_out)));
    TEST_ASSERT_FALSE(crypto::encodeBase58(nullptr, 1, big_out, sizeof(big_out)));
}

void test_base58check_vectors() {
    char out[bitcoin::kMaxAddressLength];
    uint8_t payload[20] = {0};

    // All-zero HASH160: leading 0x00 version and zero payload all become '1'.
    TEST_ASSERT_TRUE(crypto::encodeBase58Check(0x00, payload, sizeof(payload), out, sizeof(out)));
    TEST_ASSERT_EQUAL_STRING("1111111111111111111114oLvT2", out);
    TEST_ASSERT_TRUE(crypto::encodeBase58Check(0x05, payload, sizeof(payload), out, sizeof(out)));
    TEST_ASSERT_EQUAL_STRING("31h1vYVSYuKP6AhS86fbRdMw9XHieotbST", out);

    // Bitcoin wiki "Technical background of version 1 Bitcoin addresses".
    hexToBytes("010966776006953d5567439e5e39f86a0d273bee", payload, sizeof(payload));
    TEST_ASSERT_TRUE(crypto::encodeBase58Check(0x00, payload, sizeof(payload), out, sizeof(out)));
    TEST_ASSERT_EQUAL_STRING("16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM", out);

    memset(out, 'x', sizeof(out));
    TEST_ASSERT_FALSE(crypto::encodeBase58Check(0x00, payload, sizeof(payload), out, 10));
    TEST_ASSERT_EACH_EQUAL_CHAR(0, out, 10);
}

void test_pubkey_to_legacy_address() {
    for (const AddressVector& v : kAddressVectors) {
        uint8_t pub[bip32::kPublicKeyBytes];
        hexToBytes(v.pubkey_hex, pub, sizeof(pub));
        char address[bitcoin::kMaxAddressLength];
        TEST_ASSERT_TRUE(bitcoin::pubkeyToLegacyAddress(pub, address, sizeof(address)));
        TEST_ASSERT_EQUAL_STRING(v.address, address);
    }

    uint8_t bad[bip32::kPublicKeyBytes];
    hexToBytes(kAddressVectors[0].pubkey_hex, bad, sizeof(bad));
    bad[0] = 0x04;
    char address[bitcoin::kMaxAddressLength];
    memset(address, 'x', sizeof(address));
    TEST_ASSERT_FALSE(bitcoin::pubkeyToLegacyAddress(bad, address, sizeof(address)));
    TEST_ASSERT_EACH_EQUAL_CHAR(0, address, sizeof(address));
}

void test_derive_bitcoin_key() {
    bip32::ExtendedPrivateKey master;
    masterFromHex(kAbandonSeedHex, &master);

    bip32::ExtendedPrivateKey priv;
    bip32::ExtendedPublicKey pub;
    TEST_ASSERT_TRUE(bitcoin::deriveBitcoinKey(master, &priv, &pub));

    uint8_t expected[bip32::kPublicKeyBytes];
    hexToBytes(kAbandonPrivateKeyHex, expected, bip32::kPrivateKeyBytes);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, priv.key, bip32::kPrivateKeyBytes);
    hexToBytes(kAbandonPublicKeyHex, expected, bip32::kPublicKeyBytes);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, pub.key, bip32::kPublicKeyBytes);
    TEST_ASSERT_EQUAL_UINT8(5, pub.depth);
    TEST_ASSERT_EQUAL_HEX32(0, pub.child_number);

    bip32::wipe(&master);
    bip32::wipe(&priv);
    bip32::wipe(&pub);
}

void test_derive_bitcoin_address() {
    bip32::ExtendedPrivateKey master;
    masterFromHex(kAbandonSeedHex, &master);

    char address[bitcoin::kMaxAddressLength];
    TEST_ASSERT_TRUE(bitcoin::deriveBitcoinAddress(master, address, sizeof(address)));
    TEST_ASSERT_EQUAL_CHAR('1', address[0]);
    TEST_ASSERT_EQUAL_STRING(kAbandonAddress, address);

    // Only a master key (depth 0) is accepted.
    master.depth = 1;
    memset(address, 'x', sizeof(address));
    TEST_ASSERT_FALSE(bitcoin::deriveBitcoinAddress(master, address, sizeof(address)));
    TEST_ASSERT_EACH_EQUAL_CHAR(0, address, sizeof(address));

    bip32::wipe(&master);
}

void setup() {
    delay(2000);
    UNITY_BEGIN();
    RUN_TEST(test_base58_vectors);
    RUN_TEST(test_base58_buffer_too_small);
    RUN_TEST(test_base58check_vectors);
    RUN_TEST(test_pubkey_to_legacy_address);
    RUN_TEST(test_derive_bitcoin_key);
    RUN_TEST(test_derive_bitcoin_address);
    UNITY_END();
}

void loop() {}

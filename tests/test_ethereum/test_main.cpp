// Ethereum unit tests: Keccak-256 (original padding, not SHA3-256), the EIP-55
// checksum vectors from https://eips.ethereum.org/EIPS/eip-55, public key to
// address, and the BIP-44 derivation m/44'/60'/0'/0/0 from the BIP-39
// "abandon ... about" seed.

#include <Arduino.h>
#include <stdio.h>
#include <string.h>
#include <unity.h>

#include "bip32/bip32.h"
#include "crypto/keccak256.h"
#include "ethereum/ethereum.h"

using namespace es;

void setUp() {}
void tearDown() {}

namespace {

void hexToBytes(const char* hex, uint8_t* out, size_t len) {
    TEST_ASSERT_EQUAL_size_t(2 * len, strlen(hex));
    for (size_t i = 0; i < len; ++i) {
        unsigned int byte_val = 0;
        sscanf(hex + 2 * i, "%02x", &byte_val);
        out[i] = static_cast<uint8_t>(byte_val);
    }
}

void assertKeccak(const uint8_t* data, size_t len, const char* expected_hex) {
    uint8_t expected[crypto::kKeccak256DigestSize];
    hexToBytes(expected_hex, expected, sizeof(expected));
    uint8_t digest[crypto::kKeccak256DigestSize];
    TEST_ASSERT_TRUE(crypto::keccak256(data, len, digest));
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(expected, digest, sizeof(digest), expected_hex);
}

void assertKeccakRepeated(char c, size_t len, const char* expected_hex) {
    uint8_t data[272];
    TEST_ASSERT_TRUE(len <= sizeof(data));
    memset(data, c, len);
    assertKeccak(data, len, expected_hex);
}

// EIP-55 vectors: all caps, all lower and mixed case.
const char* const kEip55Vectors[] = {
    "0x52908400098527886E0F7030069857D2E4169EE7", "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
    "0xde709f2102306220921060314715629080e2fb77", "0x27b1fdb04752bbc536007a920d24acb045561c26",
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
};

// BIP-39 seed of "abandon abandon ... abandon about" with an empty passphrase;
// m/44'/60'/0'/0/0 is the well-known address
// 0x9858EfFD232B4033E47d90003D41EC34EcaEda94 (MetaMask, Trezor, Ledger).
const char kAbandonSeedHex[] =
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
    "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
const char kAbandonPublicKeyHex[] = "0237b0bb7a8288d38ed49a524b5dc98cff3eb5ca824c9f9dc0dfdb3d9cd600f299";
const char kAbandonAddress[] = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";

}  // namespace

void test_keccak256_official_vectors() {
    assertKeccak(nullptr, 0, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    assertKeccak(reinterpret_cast<const uint8_t*>("abc"), 3,
                 "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
    const char fox[] = "The quick brown fox jumps over the lazy dog";
    assertKeccak(reinterpret_cast<const uint8_t*>(fox), strlen(fox),
                 "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15");
}

// Rate boundary (136 bytes): one padding byte (0x81), a full block followed by
// a padding-only block, and multi-block inputs. Expected digests were computed
// with an independent Python implementation.
void test_keccak256_block_boundaries() {
    assertKeccakRepeated('a', 135, "34367dc248bbd832f4e3e69dfaac2f92638bd0bbd18f2912ba4ef454919cf446");
    assertKeccakRepeated('a', 136, "a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e");
    assertKeccakRepeated('a', 200, "96ea54061def936c4be90b518992fdc6f12f535068a256229aca54267b4d084d");
}

void test_keccak256_invalid_arguments() {
    uint8_t digest[crypto::kKeccak256DigestSize];
    memset(digest, 0xAA, sizeof(digest));
    TEST_ASSERT_FALSE(crypto::keccak256(nullptr, 1, digest));
    TEST_ASSERT_EACH_EQUAL_UINT8(0, digest, sizeof(digest));
    TEST_ASSERT_FALSE(crypto::keccak256(reinterpret_cast<const uint8_t*>("abc"), 3, nullptr));
}

void test_eip55_vectors() {
    for (const char* vector : kEip55Vectors) {
        uint8_t raw[ethereum::kAddressBytes];
        for (size_t i = 0; i < sizeof(raw); ++i) {
            unsigned int byte_val = 0;
            sscanf(vector + 2 + 2 * i, "%02x", &byte_val);  // %x accepts either case
            raw[i] = static_cast<uint8_t>(byte_val);
        }
        char address[ethereum::kAddressLength];
        TEST_ASSERT_TRUE(ethereum::toChecksumAddress(raw, address));
        TEST_ASSERT_EQUAL_STRING(vector, address);
    }
}

void test_pubkey_to_ethereum_address() {
    char address[ethereum::kAddressLength];
    uint8_t pub[bip32::kPublicKeyBytes];

    // Generator G (private key 1).
    hexToBytes("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", pub, sizeof(pub));
    TEST_ASSERT_TRUE(ethereum::pubkeyToEthereumAddress(pub, address));
    TEST_ASSERT_EQUAL_STRING("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf", address);

    hexToBytes(kAbandonPublicKeyHex, pub, sizeof(pub));
    TEST_ASSERT_TRUE(ethereum::pubkeyToEthereumAddress(pub, address));
    TEST_ASSERT_EQUAL_STRING(kAbandonAddress, address);

    // X = 5 is not on secp256k1.
    memset(pub, 0, sizeof(pub));
    pub[0] = 0x02;
    pub[sizeof(pub) - 1] = 0x05;
    memset(address, 'x', sizeof(address));
    TEST_ASSERT_FALSE(ethereum::pubkeyToEthereumAddress(pub, address));
    TEST_ASSERT_EACH_EQUAL_CHAR(0, address, sizeof(address));
}

void test_decompress_public_key() {
    uint8_t pub[bip32::kPublicKeyBytes];
    hexToBytes("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", pub, sizeof(pub));
    uint8_t expected[bip32::kUncompressedPublicKeyBytes];
    hexToBytes(
        "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        expected, sizeof(expected));
    uint8_t out[bip32::kUncompressedPublicKeyBytes];
    TEST_ASSERT_TRUE(bip32::decompressPublicKey(pub, out));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, out, sizeof(out));
}

void test_derive_ethereum_address() {
    uint8_t seed[bip32::kMaxSeedBytes];
    hexToBytes(kAbandonSeedHex, seed, sizeof(seed));
    bip32::ExtendedPrivateKey master;
    TEST_ASSERT_TRUE(bip32::createMasterKey(seed, sizeof(seed), &master));

    char address[ethereum::kAddressLength];
    TEST_ASSERT_TRUE(ethereum::deriveEthereumAddress(master, address));
    TEST_ASSERT_EQUAL_STRING(kAbandonAddress, address);
    TEST_ASSERT_EQUAL_size_t(ethereum::kAddressLength - 1, strlen(address));

    // Only a master key (depth 0) is accepted.
    master.depth = 1;
    memset(address, 'x', sizeof(address));
    TEST_ASSERT_FALSE(ethereum::deriveEthereumAddress(master, address));
    TEST_ASSERT_EACH_EQUAL_CHAR(0, address, sizeof(address));

    bip32::wipe(&master);
}

void setup() {
    delay(2000);
    UNITY_BEGIN();
    RUN_TEST(test_keccak256_official_vectors);
    RUN_TEST(test_keccak256_block_boundaries);
    RUN_TEST(test_keccak256_invalid_arguments);
    RUN_TEST(test_eip55_vectors);
    RUN_TEST(test_pubkey_to_ethereum_address);
    RUN_TEST(test_decompress_public_key);
    RUN_TEST(test_derive_ethereum_address);
    UNITY_END();
}

void loop() {}

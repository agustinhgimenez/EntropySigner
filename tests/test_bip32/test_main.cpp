// BIP-32 unit tests: master key, CKDpriv, CKDpub and path derivation against
// the official test vectors 1 and 2
// (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors,
// xprv/xpub decoded into key, chain code, depth, parent fingerprint and child
// number), plus a BIP-44 derivation from a BIP-39 seed.

#include <Arduino.h>
#include <stdio.h>
#include <string.h>
#include <unity.h>

#include "bip32/bip32.h"

using namespace es::bip32;

void setUp() {}
void tearDown() {}

namespace {

struct Node {
    uint8_t depth;
    uint32_t parent_fingerprint;
    uint32_t child_number;
    const char* private_key_hex;
    const char* chain_code_hex;
    const char* public_key_hex;
};

constexpr size_t kChainLength = 6;  // master + 5 derivations

// Test vector 1: chain m / 0H / 1 / 2H / 2 / 1000000000.
const char kSeed1Hex[] = "000102030405060708090a0b0c0d0e0f";
const Node kChain1[kChainLength] = {
    {0, 0x00000000u, 0x00000000u,
     "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
     "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
     "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"},
    {1, 0x3442193eu, 0x80000000u,
     "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
     "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
     "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"},
    {2, 0x5c1bd648u, 0x00000001u,
     "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
     "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19",
     "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"},
    {3, 0xbef5a2f9u, 0x80000002u,
     "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
     "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f",
     "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2"},
    {4, 0xee7ab90cu, 0x00000002u,
     "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
     "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd",
     "02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29"},
    {5, 0xd880d7d8u, 0x3b9aca00u,
     "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
     "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e",
     "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011"},
};

// Test vector 2: chain m / 0 / 2147483647H / 1 / 2147483646H / 2.
const char kSeed2Hex[] =
    "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2"
    "9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";
const Node kChain2[kChainLength] = {
    {0, 0x00000000u, 0x00000000u,
     "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
     "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
     "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7"},
    {1, 0xbd16bee5u, 0x00000000u,
     "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e",
     "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c",
     "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea"},
    {2, 0x5a61ff8eu, 0xffffffffu,
     "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93",
     "be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9",
     "03c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b"},
    {3, 0xd8ab4937u, 0x00000001u,
     "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7",
     "f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb",
     "03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9"},
    {4, 0x78412e3au, 0xfffffffeu,
     "f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d",
     "637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29",
     "02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0"},
    {5, 0x31a507b8u, 0x00000002u,
     "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23",
     "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271",
     "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c"},
};

// BIP-39 seed of "abandon abandon ... abandon about" with an empty passphrase.
// m/44'/0'/0'/0/0 is the key of the well-known address
// 1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA; m/44'/60'/0'/0/0 was cross-checked
// with an independent Python implementation.
const char kAbandonSeedHex[] =
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
    "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
const Node kBip44Bitcoin = {
    5, 0x1962ab58u, 0x00000000u,
    "e284129cc0922579a535bbf4d1a3b25773090d28c909bc0fed73b5e0222cc372",
    "213909708058e0ec4a99c19d8e041c014ae6c7dc21d2a1fac86772df7ca357a6",
    "03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e"};
const Node kBip44Ethereum = {
    5, 0xe4389614u, 0x00000000u,
    "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727",
    "736094f4f24b67e838a4b3d23d31d229ca03e00c9bb99ce95da6d86e8b3847b5",
    "0237b0bb7a8288d38ed49a524b5dc98cff3eb5ca824c9f9dc0dfdb3d9cd600f299"};

void hexToBytes(const char* hex, uint8_t* out, size_t len) {
    TEST_ASSERT_EQUAL_size_t(2 * len, strlen(hex));
    for (size_t i = 0; i < len; ++i) {
        unsigned int byte_val = 0;
        sscanf(hex + 2 * i, "%02x", &byte_val);
        out[i] = static_cast<uint8_t>(byte_val);
    }
}

void assertPrivateNode(const Node& expected, const ExtendedPrivateKey& key) {
    uint8_t buf[kChainCodeBytes];
    hexToBytes(expected.private_key_hex, buf, kPrivateKeyBytes);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(buf, key.key, kPrivateKeyBytes);
    hexToBytes(expected.chain_code_hex, buf, kChainCodeBytes);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(buf, key.chain_code, kChainCodeBytes);
    TEST_ASSERT_EQUAL_UINT8(expected.depth, key.depth);
    TEST_ASSERT_EQUAL_HEX32(expected.parent_fingerprint, key.parent_fingerprint);
    TEST_ASSERT_EQUAL_HEX32(expected.child_number, key.child_number);
}

void assertPublicNode(const Node& expected, const ExtendedPublicKey& key) {
    uint8_t pub[kPublicKeyBytes];
    hexToBytes(expected.public_key_hex, pub, kPublicKeyBytes);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(pub, key.key, kPublicKeyBytes);
    uint8_t chain[kChainCodeBytes];
    hexToBytes(expected.chain_code_hex, chain, kChainCodeBytes);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(chain, key.chain_code, kChainCodeBytes);
    TEST_ASSERT_EQUAL_UINT8(expected.depth, key.depth);
    TEST_ASSERT_EQUAL_HEX32(expected.parent_fingerprint, key.parent_fingerprint);
    TEST_ASSERT_EQUAL_HEX32(expected.child_number, key.child_number);
}

void masterFromHex(const char* seed_hex, ExtendedPrivateKey* master) {
    uint8_t seed[kMaxSeedBytes];
    const size_t seed_len = strlen(seed_hex) / 2;
    hexToBytes(seed_hex, seed, seed_len);
    TEST_ASSERT_TRUE(createMasterKey(seed, seed_len, master));
}

// Walks a vector's chain with CKDpriv, checking every private and public node.
void checkPrivateChain(const char* seed_hex, const Node chain[kChainLength]) {
    ExtendedPrivateKey key;
    masterFromHex(seed_hex, &key);
    for (size_t i = 0; i < kChainLength; ++i) {
        if (i > 0) {
            TEST_ASSERT_TRUE(derivePrivateChild(&key, chain[i].child_number, &key));  // in place
        }
        assertPrivateNode(chain[i], key);
        ExtendedPublicKey pub;
        TEST_ASSERT_TRUE(toPublic(&key, &pub));
        assertPublicNode(chain[i], pub);
    }
    wipe(&key);
}

// For every non-hardened step, CKDpub on the parent's public key must match
// N(CKDpriv(parent)) from the vector.
void checkPublicDerivation(const Node chain[kChainLength]) {
    size_t checked = 0;
    for (size_t i = 1; i < kChainLength; ++i) {
        if (chain[i].child_number & kHardenedFlag) {
            continue;
        }
        ExtendedPublicKey parent;
        memset(&parent, 0, sizeof(parent));
        hexToBytes(chain[i - 1].public_key_hex, parent.key, kPublicKeyBytes);
        hexToBytes(chain[i - 1].chain_code_hex, parent.chain_code, kChainCodeBytes);
        parent.depth = chain[i - 1].depth;

        ExtendedPublicKey child;
        TEST_ASSERT_TRUE(derivePublicChild(&parent, chain[i].child_number, &child));
        assertPublicNode(chain[i], child);
        ++checked;
    }
    TEST_ASSERT_GREATER_THAN_size_t(0, checked);
}

}  // namespace

void test_vector1_private_chain() {
    checkPrivateChain(kSeed1Hex, kChain1);
}

void test_vector2_private_chain() {
    checkPrivateChain(kSeed2Hex, kChain2);
}

void test_vector1_public_derivation() {
    checkPublicDerivation(kChain1);
}

void test_vector2_public_derivation() {
    checkPublicDerivation(kChain2);
}

void test_derive_path_vectors() {
    ExtendedPrivateKey master;
    ExtendedPrivateKey key;

    masterFromHex(kSeed1Hex, &master);
    TEST_ASSERT_TRUE(derivePath(&master, "m", &key));
    assertPrivateNode(kChain1[0], key);
    TEST_ASSERT_TRUE(derivePath(&master, "m/0'/1/2'/2/1000000000", &key));
    assertPrivateNode(kChain1[5], key);
    TEST_ASSERT_TRUE(derivePath(&master, "m/0h/1/2H/2", &key));  // alternative hardened marks
    assertPrivateNode(kChain1[4], key);

    masterFromHex(kSeed2Hex, &master);
    TEST_ASSERT_TRUE(derivePath(&master, "m/0/2147483647'/1/2147483646'/2", &key));
    assertPrivateNode(kChain2[5], key);

    masterFromHex(kAbandonSeedHex, &master);
    TEST_ASSERT_TRUE(derivePath(&master, "m/44'/0'/0'/0/0", &key));
    assertPrivateNode(kBip44Bitcoin, key);
    TEST_ASSERT_TRUE(derivePath(&master, "m/44'/60'/0'/0/0", &key));
    assertPrivateNode(kBip44Ethereum, key);

    wipe(&master);
    wipe(&key);
}

void test_fingerprint() {
    uint8_t pub[kPublicKeyBytes];
    hexToBytes(kChain1[0].public_key_hex, pub, kPublicKeyBytes);
    uint32_t fp = 0;
    TEST_ASSERT_TRUE(fingerprint(pub, &fp));
    TEST_ASSERT_EQUAL_HEX32(kChain1[1].parent_fingerprint, fp);
}

void test_hardened_public_derivation_fails() {
    ExtendedPublicKey parent;
    memset(&parent, 0, sizeof(parent));
    hexToBytes(kChain1[0].public_key_hex, parent.key, kPublicKeyBytes);
    hexToBytes(kChain1[0].chain_code_hex, parent.chain_code, kChainCodeBytes);

    ExtendedPublicKey child;
    memset(&child, 0xAA, sizeof(child));
    TEST_ASSERT_FALSE(derivePublicChild(&parent, kHardenedFlag, &child));
    TEST_ASSERT_EACH_EQUAL_UINT8(0, reinterpret_cast<uint8_t*>(&child), sizeof(child));
}

void test_invalid_public_key_rejected() {
    ExtendedPublicKey parent;
    memset(&parent, 0, sizeof(parent));
    ExtendedPublicKey child;

    // Bad prefix (uncompressed marker).
    hexToBytes(kChain1[0].public_key_hex, parent.key, kPublicKeyBytes);
    parent.key[0] = 0x04;
    TEST_ASSERT_FALSE(derivePublicChild(&parent, 0, &child));

    // X = 5 is not on secp256k1 (5^3 + 7 = 132 is not a square mod p).
    memset(parent.key, 0, kPublicKeyBytes);
    parent.key[0] = 0x02;
    parent.key[kPublicKeyBytes - 1] = 0x05;
    TEST_ASSERT_FALSE(derivePublicChild(&parent, 0, &child));
}

void test_invalid_inputs_zero_outputs() {
    uint8_t seed[kMaxSeedBytes + 1] = {0};
    ExtendedPrivateKey key;

    memset(&key, 0xAA, sizeof(key));
    TEST_ASSERT_FALSE(createMasterKey(seed, kMinSeedBytes - 1, &key));
    TEST_ASSERT_EACH_EQUAL_UINT8(0, reinterpret_cast<uint8_t*>(&key), sizeof(key));

    memset(&key, 0xAA, sizeof(key));
    TEST_ASSERT_FALSE(createMasterKey(seed, kMaxSeedBytes + 1, &key));
    TEST_ASSERT_EACH_EQUAL_UINT8(0, reinterpret_cast<uint8_t*>(&key), sizeof(key));

    memset(&key, 0xAA, sizeof(key));
    TEST_ASSERT_FALSE(createMasterKey(nullptr, kMinSeedBytes, &key));
    TEST_ASSERT_EACH_EQUAL_UINT8(0, reinterpret_cast<uint8_t*>(&key), sizeof(key));

    // Private key 0 and n are outside [1, n).
    uint8_t pub[kPublicKeyBytes];
    const uint8_t zero_key[kPrivateKeyBytes] = {0};
    memset(pub, 0xAA, sizeof(pub));
    TEST_ASSERT_FALSE(privateToPublicKey(zero_key, pub));
    TEST_ASSERT_EACH_EQUAL_UINT8(0, pub, sizeof(pub));
    uint8_t order[kPrivateKeyBytes];
    hexToBytes("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", order, sizeof(order));
    TEST_ASSERT_FALSE(privateToPublicKey(order, pub));

    // A child of a key with private key 0 cannot be derived.
    ExtendedPrivateKey bad;
    memset(&bad, 0, sizeof(bad));
    memset(&key, 0xAA, sizeof(key));
    TEST_ASSERT_FALSE(derivePrivateChild(&bad, 0, &key));
    TEST_ASSERT_EACH_EQUAL_UINT8(0, reinterpret_cast<uint8_t*>(&key), sizeof(key));

    // Depth overflow.
    ExtendedPrivateKey master;
    masterFromHex(kSeed1Hex, &master);
    master.depth = kMaxDepth;
    TEST_ASSERT_FALSE(derivePrivateChild(&master, 0, &key));
    wipe(&master);
}

void test_derive_path_rejects_malformed() {
    ExtendedPrivateKey master;
    masterFromHex(kSeed1Hex, &master);
    ExtendedPrivateKey key;

    const char* bad_paths[] = {
        "",              // empty
        "M/0",           // uppercase root
        "0/1",           // no root
        "m/",            // trailing slash
        "m//0",          // empty component
        "m/0/",          // trailing slash after a component
        "m/a",           // not a number
        "m/-1",          // sign
        "m/0''",         // double hardened mark
        "m/2147483648",  // index >= 2^31 written without the mark
        "m/4294967296",  // overflow
        "m 0",           // missing slash
        "m/0 ",          // trailing space
    };
    for (const char* path : bad_paths) {
        memset(&key, 0xAA, sizeof(key));
        TEST_ASSERT_FALSE_MESSAGE(derivePath(&master, path, &key), path);
        TEST_ASSERT_EACH_EQUAL_UINT8_MESSAGE(0, reinterpret_cast<uint8_t*>(&key), sizeof(key), path);
    }

    // Root must be a master key.
    ExtendedPrivateKey child;
    TEST_ASSERT_TRUE(derivePrivateChild(&master, 0, &child));
    TEST_ASSERT_FALSE(derivePath(&child, "m/0", &key));
    TEST_ASSERT_FALSE(derivePath(&master, nullptr, &key));

    wipe(&master);
    wipe(&child);
}

void test_wipe() {
    ExtendedPrivateKey key;
    memset(&key, 0xAA, sizeof(key));
    wipe(&key);
    TEST_ASSERT_EACH_EQUAL_UINT8(0, reinterpret_cast<uint8_t*>(&key), sizeof(key));
}

void setup() {
    delay(2000);
    UNITY_BEGIN();
    RUN_TEST(test_vector1_private_chain);
    RUN_TEST(test_vector2_private_chain);
    RUN_TEST(test_vector1_public_derivation);
    RUN_TEST(test_vector2_public_derivation);
    RUN_TEST(test_derive_path_vectors);
    RUN_TEST(test_fingerprint);
    RUN_TEST(test_hardened_public_derivation_fails);
    RUN_TEST(test_invalid_public_key_rejected);
    RUN_TEST(test_invalid_inputs_zero_outputs);
    RUN_TEST(test_derive_path_rejects_malformed);
    RUN_TEST(test_wipe);
    UNITY_END();
}

void loop() {}

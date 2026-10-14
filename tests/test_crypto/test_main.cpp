// Cryptographic unit tests: SHA-256 (NIST test vectors), secureMemzero, entropy pool.

#include <Arduino.h>
#include <string.h>
#include <unity.h>

#include "crypto/sha256.h"
#include "entropy/entropy_pool.h"
#include "security/secure_mem.h"

void setUp() {}
void tearDown() {}

// Helper to convert hex string to byte array
static void hexToBytes(const char* hex, uint8_t* out, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        unsigned int byteVal;
        sscanf(hex + 2 * i, "%02x", &byteVal);
        out[i] = static_cast<uint8_t>(byteVal);
    }
}

void test_secure_memzero() {
    uint8_t buffer[64];
    memset(buffer, 0xAA, sizeof(buffer));
    es::security::secureMemzero(buffer, sizeof(buffer));

    for (size_t i = 0; i < sizeof(buffer); ++i) {
        TEST_ASSERT_EQUAL_UINT8(0, buffer[i]);
    }

    // Null pointer should not crash
    es::security::secureMemzero(nullptr, 16);
}

void test_sha256_nist_empty_string() {
    // NIST: SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    const char* expected_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    uint8_t expected[32];
    hexToBytes(expected_hex, expected, 32);

    uint8_t digest[32];
    TEST_ASSERT_TRUE(es::crypto::sha256(reinterpret_cast<const uint8_t*>(""), 0, digest));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, digest, 32);
}

void test_sha256_nist_abc() {
    // NIST: SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    const char* input = "abc";
    const char* expected_hex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    uint8_t expected[32];
    hexToBytes(expected_hex, expected, 32);

    uint8_t digest[32];
    TEST_ASSERT_TRUE(es::crypto::sha256(reinterpret_cast<const uint8_t*>(input), strlen(input), digest));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, digest, 32);
}

void test_sha256_nist_multi_block() {
    // NIST: SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") =
    //       248d6a61d20638b8e5c026930c3e6039a33ce45964ff21a7f7b70bc00f80a647
    const char* input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const char* expected_hex = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff21a7f7b70bc00f80a647";
    uint8_t expected[32];
    hexToBytes(expected_hex, expected, 32);

    uint8_t digest[32];
    TEST_ASSERT_TRUE(es::crypto::sha256(reinterpret_cast<const uint8_t*>(input), strlen(input), digest));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, digest, 32);
}

void test_sha256_incremental_streaming() {
    // Incremental hash of "abc" using 3 single-byte updates
    const char* expected_hex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    uint8_t expected[32];
    hexToBytes(expected_hex, expected, 32);

    es::crypto::SHA256 hasher;
    TEST_ASSERT_TRUE(hasher.init());
    TEST_ASSERT_TRUE(hasher.update(reinterpret_cast<const uint8_t*>("a"), 1));
    TEST_ASSERT_TRUE(hasher.update(reinterpret_cast<const uint8_t*>("b"), 1));
    TEST_ASSERT_TRUE(hasher.update(reinterpret_cast<const uint8_t*>("c"), 1));

    uint8_t digest[32];
    TEST_ASSERT_TRUE(hasher.finish(digest));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, digest, 32);
}

void test_entropy_pool_generation() {
    uint8_t entropy1[32] = {0};
    uint8_t entropy2[32] = {0};

    // Generate without LDR (pure HW RNG conditioning)
    TEST_ASSERT_TRUE(es::entropy::generateEntropy256(entropy1, false));

    // Generate with LDR
    TEST_ASSERT_TRUE(es::entropy::generateEntropy256(entropy2, true));

    // Both outputs must be non-zero and non-identical
    uint8_t zeroes[32] = {0};
    TEST_ASSERT_NOT_EQUAL(0, memcmp(entropy1, zeroes, 32));
    TEST_ASSERT_NOT_EQUAL(0, memcmp(entropy2, zeroes, 32));
    TEST_ASSERT_NOT_EQUAL(0, memcmp(entropy1, entropy2, 32));
}

void setup() {
    delay(2000);
    UNITY_BEGIN();
    RUN_TEST(test_secure_memzero);
    RUN_TEST(test_sha256_nist_empty_string);
    RUN_TEST(test_sha256_nist_abc);
    RUN_TEST(test_sha256_nist_multi_block);
    RUN_TEST(test_sha256_incremental_streaming);
    RUN_TEST(test_entropy_pool_generation);
    UNITY_END();
}

void loop() {}

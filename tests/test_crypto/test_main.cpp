// Cryptographic unit tests: SHA-256 (NIST test vectors), RIPEMD-160 / HASH160
// (official RIPEMD-160 test vectors), secureMemzero, entropy pool.

#include <Arduino.h>
#include <string.h>
#include <unity.h>

#include "crypto/ripemd160.h"
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

void test_ripemd160_official_vectors() {
    // Bosselaers' RIPEMD-160 page: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
    struct Vector {
        const char* message;
        const char* digest_hex;
    };
    const Vector vectors[] = {
        {"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"},
        {"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"},
        {"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"},
        {"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"},
        {"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "12a053384a9c0c88e405a06c27dcf49ada62eb2b"},
        {"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
         "9b752e45573d4b39f4dbd3323cab82bf63326bfb"},
    };
    for (const Vector& v : vectors) {
        uint8_t expected[es::crypto::kRipemd160DigestSize];
        hexToBytes(v.digest_hex, expected, sizeof(expected));
        uint8_t digest[es::crypto::kRipemd160DigestSize];
        TEST_ASSERT_TRUE(
            es::crypto::ripemd160(reinterpret_cast<const uint8_t*>(v.message), strlen(v.message), digest));
        TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(expected, digest, sizeof(digest), v.message);
    }
}

void test_ripemd160_padding_boundaries() {
    // n repetitions of 'a' around the 55/56 and 64-byte padding edges, plus a
    // multi-block input. Expected digests from Python's hashlib (OpenSSL).
    struct Vector {
        size_t length;
        const char* digest_hex;
    };
    const Vector vectors[] = {
        {55, "0d8a8c9063a48576a7c97e9f95253a6e53ff6765"},
        {56, "e72334b46c83cc70bef979e15453706c95b888be"},
        {63, "e640041293fe663b9bf3f8c21ffecac03819e6b2"},
        {64, "9dfb7d374ad924f3f88de96291c33e9abed53e32"},
        {1000, "aa69deee9a8922e92f8105e007f76110f381e9cf"},
    };
    static uint8_t buffer[1000];
    memset(buffer, 'a', sizeof(buffer));
    for (const Vector& v : vectors) {
        uint8_t expected[es::crypto::kRipemd160DigestSize];
        hexToBytes(v.digest_hex, expected, sizeof(expected));
        uint8_t digest[es::crypto::kRipemd160DigestSize];
        TEST_ASSERT_TRUE(es::crypto::ripemd160(buffer, v.length, digest));
        TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, digest, sizeof(digest));
    }
}

void test_hash160() {
    uint8_t expected[es::crypto::kRipemd160DigestSize];
    uint8_t digest[es::crypto::kRipemd160DigestSize];

    // HASH160("") = RIPEMD160(SHA256(""))
    hexToBytes("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb", expected, sizeof(expected));
    TEST_ASSERT_TRUE(es::crypto::hash160(reinterpret_cast<const uint8_t*>(""), 0, digest));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, digest, sizeof(digest));

    // BIP-32 test vector 1, master public key -> identifier 3442193e...
    uint8_t pub[33];
    hexToBytes("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2", pub, sizeof(pub));
    hexToBytes("3442193e1bb70916e914552172cd4e2dbc9df811", expected, sizeof(expected));
    TEST_ASSERT_TRUE(es::crypto::hash160(pub, sizeof(pub), digest));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, digest, sizeof(digest));
}

void test_ripemd160_invalid_arguments() {
    uint8_t digest[es::crypto::kRipemd160DigestSize];
    memset(digest, 0xAA, sizeof(digest));
    TEST_ASSERT_FALSE(es::crypto::ripemd160(nullptr, 1, digest));
    TEST_ASSERT_EACH_EQUAL_UINT8(0, digest, sizeof(digest));

    memset(digest, 0xAA, sizeof(digest));
    TEST_ASSERT_FALSE(es::crypto::hash160(nullptr, 1, digest));
    TEST_ASSERT_EACH_EQUAL_UINT8(0, digest, sizeof(digest));

    TEST_ASSERT_FALSE(es::crypto::ripemd160(reinterpret_cast<const uint8_t*>("abc"), 3, nullptr));
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
    RUN_TEST(test_ripemd160_official_vectors);
    RUN_TEST(test_ripemd160_padding_boundaries);
    RUN_TEST(test_hash160);
    RUN_TEST(test_ripemd160_invalid_arguments);
    RUN_TEST(test_entropy_pool_generation);
    UNITY_END();
}

void loop() {}

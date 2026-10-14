// BIP-39 unit tests: official wordlist, entropy <-> mnemonic, validation and
// PBKDF2-HMAC-SHA512 seed, against the Trezor reference vectors
// (https://github.com/trezor/python-mnemonic/blob/master/vectors.json, every
// 256-bit entry, passphrase "TREZOR").

#include <Arduino.h>
#include <stdio.h>
#include <string.h>
#include <unity.h>

#include "bip39/bip39.h"
#include "bip39/bip39_wordlist.h"
#include "crypto/sha256.h"

using namespace es::bip39;

void setUp() {}
void tearDown() {}

namespace {

struct Bip39Vector {
    const char* entropy_hex;
    const char* mnemonic;
    const char* seed_hex;  // passphrase "TREZOR"
};

const Bip39Vector kVectors[] = {
    {"0000000000000000000000000000000000000000000000000000000000000000",
     "abandon abandon abandon abandon abandon abandon "
     "abandon abandon abandon abandon abandon abandon "
     "abandon abandon abandon abandon abandon abandon "
     "abandon abandon abandon abandon abandon art",
     "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd30971"
     "70af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"},
    {"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
     "legal winner thank year wave sausage "
     "worth useful legal winner thank year "
     "wave sausage worth useful legal winner "
     "thank year wave sausage worth title",
     "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a40"
     "21b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87"},
    {"8080808080808080808080808080808080808080808080808080808080808080",
     "letter advice cage absurd amount doctor "
     "acoustic avoid letter advice cage absurd "
     "amount doctor acoustic avoid letter advice "
     "cage absurd amount doctor acoustic bless",
     "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09"
     "e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f"},
    {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
     "zoo zoo zoo zoo zoo zoo "
     "zoo zoo zoo zoo zoo zoo "
     "zoo zoo zoo zoo zoo zoo "
     "zoo zoo zoo zoo zoo vote",
     "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e16"
     "13912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad"},
    {"68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
     "hamster diagram private dutch cause delay "
     "private meat slide toddler razor book "
     "happy fancy gospel tennis maple dilemma "
     "loan word shrug inflict delay length",
     "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d2"
     "0b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440"},
    {"9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
     "panda eyebrow bullet gorilla call smoke "
     "muffin taste mesh discover soft ostrich "
     "alcohol speed nation flash devote level "
     "hobby quick inner drive ghost inside",
     "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6"
     "fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d"},
    {"066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
     "all hour make first leader extend "
     "hole alien behind guard gospel lava "
     "path output census museum junior mass "
     "reopen famous sing advance salt reform",
     "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6"
     "df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d"},
    {"f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
     "void come effort suffer camp survey "
     "warrior heavy shoot primary clutch crush "
     "open amazing screen patrol group space "
     "point ten exist slush involve unfold",
     "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0"
     "e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998"},
};

constexpr size_t kVectorCount = sizeof(kVectors) / sizeof(kVectors[0]);
constexpr char kTrezorPassphrase[] = "TREZOR";

// Valid mnemonic used by the negative tests (vector 0).
constexpr char kAbandonArt[] =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

void hexToBytes(const char* hex, uint8_t* out, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        unsigned int byte_val;
        sscanf(hex + 2 * i, "%02x", &byte_val);
        out[i] = static_cast<uint8_t>(byte_val);
    }
}

}  // namespace

void test_wordlist_bounds() {
    TEST_ASSERT_EQUAL_STRING("abandon", getWord(0));
    TEST_ASSERT_EQUAL_STRING("zoo", getWord(kWordlistSize - 1));
    TEST_ASSERT_NULL(getWord(kWordlistSize));
}

void test_wordlist_matches_official_file() {
    // SHA-256 of bip-0039/english.txt: every word followed by '\n'.
    uint8_t expected[32];
    hexToBytes("2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda", expected, 32);

    es::crypto::SHA256 hasher;
    TEST_ASSERT_TRUE(hasher.init());
    for (size_t i = 0; i < kWordlistSize; ++i) {
        const char* word = getWord(i);
        TEST_ASSERT_TRUE(hasher.update(reinterpret_cast<const uint8_t*>(word), strlen(word)));
        TEST_ASSERT_TRUE(hasher.update(reinterpret_cast<const uint8_t*>("\n"), 1));
    }
    uint8_t digest[32];
    TEST_ASSERT_TRUE(hasher.finish(digest));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, digest, 32);
}

void test_wordlist_find_roundtrip() {
    for (size_t i = 0; i < kWordlistSize; ++i) {
        TEST_ASSERT_EQUAL_INT(static_cast<int>(i), findWordIndex(getWord(i)));
    }
    TEST_ASSERT_EQUAL_INT(-1, findWordIndex("bitcoin"));
    TEST_ASSERT_EQUAL_INT(-1, findWordIndex("Abandon"));
    TEST_ASSERT_EQUAL_INT(-1, findWordIndex("aban"));
    TEST_ASSERT_EQUAL_INT(-1, findWordIndex(""));
    TEST_ASSERT_EQUAL_INT(-1, findWordIndex("zzz"));
    TEST_ASSERT_EQUAL_INT(-1, findWordIndex(nullptr));
}

void test_entropy_to_mnemonic_vectors() {
    for (size_t i = 0; i < kVectorCount; ++i) {
        uint8_t entropy[kEntropyBytes];
        hexToBytes(kVectors[i].entropy_hex, entropy, kEntropyBytes);

        char mnemonic[kMaxMnemonicLength];
        TEST_ASSERT_TRUE(entropyToMnemonic(entropy, mnemonic, sizeof(mnemonic)));
        TEST_ASSERT_EQUAL_STRING(kVectors[i].mnemonic, mnemonic);
    }
}

void test_mnemonic_to_entropy_vectors() {
    for (size_t i = 0; i < kVectorCount; ++i) {
        uint8_t expected[kEntropyBytes];
        hexToBytes(kVectors[i].entropy_hex, expected, kEntropyBytes);

        uint8_t entropy[kEntropyBytes];
        TEST_ASSERT_TRUE(validateMnemonic(kVectors[i].mnemonic));
        TEST_ASSERT_TRUE(mnemonicToEntropy(kVectors[i].mnemonic, entropy));
        TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, entropy, kEntropyBytes);
    }
}

void test_mnemonic_to_seed_vectors() {
    for (size_t i = 0; i < kVectorCount; ++i) {
        uint8_t expected[kSeedBytes];
        hexToBytes(kVectors[i].seed_hex, expected, kSeedBytes);

        uint8_t seed[kSeedBytes];
        TEST_ASSERT_TRUE(mnemonicToSeed(kVectors[i].mnemonic, kTrezorPassphrase, seed));
        TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, seed, kSeedBytes);
    }
}

void test_mnemonic_to_seed_empty_passphrase() {
    // A null passphrase means "" (salt = "mnemonic") and differs from "TREZOR".
    uint8_t seed_null[kSeedBytes];
    uint8_t seed_empty[kSeedBytes];
    uint8_t seed_trezor[kSeedBytes];
    TEST_ASSERT_TRUE(mnemonicToSeed(kAbandonArt, nullptr, seed_null));
    TEST_ASSERT_TRUE(mnemonicToSeed(kAbandonArt, "", seed_empty));
    TEST_ASSERT_TRUE(mnemonicToSeed(kAbandonArt, kTrezorPassphrase, seed_trezor));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(seed_null, seed_empty, kSeedBytes);
    TEST_ASSERT_NOT_EQUAL(0, memcmp(seed_empty, seed_trezor, kSeedBytes));
}

void test_validate_rejects_malformed() {
    TEST_ASSERT_TRUE(validateMnemonic(kAbandonArt));

    // Bad checksum: last word "abandon" instead of "art".
    TEST_ASSERT_FALSE(validateMnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"));
    // 23 words.
    TEST_ASSERT_FALSE(validateMnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"));
    // 25 words.
    TEST_ASSERT_FALSE(validateMnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art art"));
    // Unknown word.
    TEST_ASSERT_FALSE(validateMnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon bitcoin"));
    // Uppercase.
    TEST_ASSERT_FALSE(validateMnemonic(
        "Abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"));
    // Double space, leading space, trailing space, trailing newline.
    TEST_ASSERT_FALSE(validateMnemonic(
        "abandon  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"));
    TEST_ASSERT_FALSE(validateMnemonic(
        " abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"));
    TEST_ASSERT_FALSE(validateMnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art "));
    TEST_ASSERT_FALSE(validateMnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art\n"));
    TEST_ASSERT_FALSE(validateMnemonic(""));
    TEST_ASSERT_FALSE(validateMnemonic(nullptr));
}

void test_failures_zero_outputs() {
    uint8_t entropy[kEntropyBytes];
    memset(entropy, 0xAA, sizeof(entropy));
    TEST_ASSERT_FALSE(mnemonicToEntropy("abandon", entropy));
    TEST_ASSERT_EACH_EQUAL_UINT8(0, entropy, kEntropyBytes);

    uint8_t seed[kSeedBytes];
    memset(seed, 0xAA, sizeof(seed));
    TEST_ASSERT_FALSE(mnemonicToSeed("abandon", "", seed));
    TEST_ASSERT_EACH_EQUAL_UINT8(0, seed, kSeedBytes);

    // Non-ASCII passphrase (would need NFKD normalization) is rejected.
    memset(seed, 0xAA, sizeof(seed));
    TEST_ASSERT_FALSE(mnemonicToSeed(kAbandonArt, "contrase\xc3\xb1" "a", seed));
    TEST_ASSERT_EACH_EQUAL_UINT8(0, seed, kSeedBytes);

    // Output buffer too small.
    const uint8_t zero_entropy[kEntropyBytes] = {0};
    char small[kMaxMnemonicLength - 1];
    memset(small, 'x', sizeof(small));
    TEST_ASSERT_FALSE(entropyToMnemonic(zero_entropy, small, sizeof(small)));
    TEST_ASSERT_EACH_EQUAL_UINT8(0, reinterpret_cast<uint8_t*>(small), sizeof(small));
}

void test_single_bit_flip_changes_mnemonic() {
    uint8_t entropy[kEntropyBytes] = {0};
    char base[kMaxMnemonicLength];
    char flipped[kMaxMnemonicLength];
    TEST_ASSERT_TRUE(entropyToMnemonic(entropy, base, sizeof(base)));
    entropy[kEntropyBytes - 1] ^= 0x01;
    TEST_ASSERT_TRUE(entropyToMnemonic(entropy, flipped, sizeof(flipped)));
    TEST_ASSERT_NOT_EQUAL(0, strcmp(base, flipped));
    TEST_ASSERT_TRUE(validateMnemonic(flipped));
}

void setup() {
    delay(2000);
    UNITY_BEGIN();
    RUN_TEST(test_wordlist_bounds);
    RUN_TEST(test_wordlist_matches_official_file);
    RUN_TEST(test_wordlist_find_roundtrip);
    RUN_TEST(test_entropy_to_mnemonic_vectors);
    RUN_TEST(test_mnemonic_to_entropy_vectors);
    RUN_TEST(test_mnemonic_to_seed_vectors);
    RUN_TEST(test_mnemonic_to_seed_empty_passphrase);
    RUN_TEST(test_validate_rejects_malformed);
    RUN_TEST(test_failures_zero_outputs);
    RUN_TEST(test_single_bit_flip_changes_mnemonic);
    UNITY_END();
}

void loop() {}

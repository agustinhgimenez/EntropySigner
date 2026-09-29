// On-device tests for the Paso 1 foundation: board pin map, build mode, chip.

#include <Arduino.h>
#include <unity.h>

#include "config/board_config.h"
#include "config/build_config.h"
#include "config/pin_rules.h"

void setUp() {}
void tearDown() {}

void test_pin_rules_reject_reserved_pins() {
    TEST_ASSERT_FALSE(es::pins::isSafeGpio(0));   // strapping
    TEST_ASSERT_FALSE(es::pins::isSafeGpio(46));  // strapping
    TEST_ASSERT_FALSE(es::pins::isSafeGpio(19));  // USB D-
    TEST_ASSERT_FALSE(es::pins::isSafeGpio(20));  // USB D+
    TEST_ASSERT_FALSE(es::pins::isSafeGpio(22));  // does not exist
    TEST_ASSERT_FALSE(es::pins::isSafeGpio(30));  // flash / PSRAM
    TEST_ASSERT_TRUE(es::pins::isSafeGpio(1));
    TEST_ASSERT_TRUE(es::pins::isSafeGpio(12));
}

void test_board_pins_are_safe_and_unique() {
    for (int i = 0; i < es::board::kUsedPinCount; ++i) {
        TEST_ASSERT_TRUE_MESSAGE(es::pins::isSafeGpio(es::board::kUsedPins[i]), "unsafe GPIO in board map");
        for (int j = i + 1; j < es::board::kUsedPinCount; ++j) {
            TEST_ASSERT_NOT_EQUAL_MESSAGE(es::board::kUsedPins[i], es::board::kUsedPins[j], "GPIO used twice");
        }
    }
}

void test_ldr_is_on_adc1() {
    TEST_ASSERT_TRUE(es::pins::isAdc1(es::board::kLdrPin));
}

void test_build_identity() {
    TEST_ASSERT_EQUAL_STRING("EntropySigner", es::kProductName);
#if defined(ES_MODE_DEMO)
    TEST_ASSERT_TRUE(es::kDemoMode);
    TEST_ASSERT_EQUAL_STRING("DEMO", es::kModeName);
#else
    TEST_ASSERT_FALSE(es::kDemoMode);
    TEST_ASSERT_EQUAL_STRING("PRODUCTION", es::kModeName);
#endif
}

void test_chip_is_esp32s3() {
    TEST_ASSERT_EQUAL_STRING("ESP32-S3", ESP.getChipModel());
}

void setup() {
    delay(2000);  // allow the serial monitor to attach
    UNITY_BEGIN();
    RUN_TEST(test_pin_rules_reject_reserved_pins);
    RUN_TEST(test_board_pins_are_safe_and_unique);
    RUN_TEST(test_ldr_is_on_adc1);
    RUN_TEST(test_build_identity);
    RUN_TEST(test_chip_is_esp32s3);
    UNITY_END();
}

void loop() {}

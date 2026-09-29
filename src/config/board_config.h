#pragma once

#include <stdint.h>

#include "config/pin_rules.h"

// Hardware description for ESP32-S3-DevKitC-1 + ST7796S (SPI) + FT6336U (I2C)
// + LDR divider. See docs/HARDWARE.md and assets/circuit.svg.

// A write-only SPI panel cannot be detected at runtime, so its presence is a
// build option. Touch presence is detected by probing the I2C address.
#ifndef ES_HAS_DISPLAY
#define ES_HAS_DISPLAY 1
#endif

// Many IPS ST7796S modules need color inversion; flip this if colors look negative.
#ifndef ES_DISPLAY_INVERT
#define ES_DISPLAY_INVERT 0
#endif

namespace es {
namespace board {

// Display ST7796S on SPI2 (FSPI)
constexpr int kDisplaySclk = 12;
constexpr int kDisplayMosi = 11;
constexpr int kDisplayMiso = 13;
constexpr int kDisplayCs = 10;
constexpr int kDisplayDc = 9;
constexpr int kDisplayRst = 8;
constexpr int kDisplayBacklight = 7;
constexpr int kDisplayWidth = 320;
constexpr int kDisplayHeight = 480;
constexpr uint32_t kDisplaySpiWriteHz = 40000000;
constexpr uint32_t kDisplaySpiReadHz = 16000000;

// Capacitive touch FT6336U on I2C
constexpr int kTouchSda = 15;
constexpr int kTouchScl = 16;
constexpr int kTouchInt = 17;
constexpr int kTouchRst = 18;
constexpr uint8_t kTouchI2cAddr = 0x38;
constexpr uint32_t kTouchI2cHz = 400000;

// LDR voltage divider on ADC1 (ADC2 conflicts with the radio)
constexpr int kLdrPin = 1;

constexpr int kUsedPins[] = {
    kDisplaySclk, kDisplayMosi, kDisplayMiso, kDisplayCs, kDisplayDc, kDisplayRst,
    kDisplayBacklight, kTouchSda, kTouchScl, kTouchInt, kTouchRst, kLdrPin,
};
constexpr int kUsedPinCount = sizeof(kUsedPins) / sizeof(kUsedPins[0]);

static_assert(pins::isSafeGpio(kDisplaySclk), "kDisplaySclk is not a safe GPIO");
static_assert(pins::isSafeGpio(kDisplayMosi), "kDisplayMosi is not a safe GPIO");
static_assert(pins::isSafeGpio(kDisplayMiso), "kDisplayMiso is not a safe GPIO");
static_assert(pins::isSafeGpio(kDisplayCs), "kDisplayCs is not a safe GPIO");
static_assert(pins::isSafeGpio(kDisplayDc), "kDisplayDc is not a safe GPIO");
static_assert(pins::isSafeGpio(kDisplayRst), "kDisplayRst is not a safe GPIO");
static_assert(pins::isSafeGpio(kDisplayBacklight), "kDisplayBacklight is not a safe GPIO");
static_assert(pins::isSafeGpio(kTouchSda), "kTouchSda is not a safe GPIO");
static_assert(pins::isSafeGpio(kTouchScl), "kTouchScl is not a safe GPIO");
static_assert(pins::isSafeGpio(kTouchInt), "kTouchInt is not a safe GPIO");
static_assert(pins::isSafeGpio(kTouchRst), "kTouchRst is not a safe GPIO");
static_assert(pins::isSafeGpio(kLdrPin), "kLdrPin is not a safe GPIO");
static_assert(pins::isAdc1(kLdrPin), "kLdrPin must be an ADC1 channel");

}  // namespace board
}  // namespace es

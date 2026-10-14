#include "entropy/ldr_entropy.h"

#include <Arduino.h>

#include "config/board_config.h"

namespace es {
namespace entropy {

namespace {

constexpr uint8_t kAdcResolutionBits = 12;

bool g_ldr_initialized = false;

}  // namespace

void initLdr() {
    if (g_ldr_initialized) {
        return;
    }
    analogReadResolution(kAdcResolutionBits);
    analogSetPinAttenuation(board::kLdrPin, ADC_11db);  // full 0..~3.1 V range
    g_ldr_initialized = true;
}

uint16_t readLdrRaw() {
    initLdr();
    return static_cast<uint16_t>(analogRead(board::kLdrPin));
}

size_t collectLdrSamples(uint16_t* buffer, size_t max_samples, uint32_t delay_us) {
    if (buffer == nullptr) {
        return 0;
    }
    initLdr();
    for (size_t i = 0; i < max_samples; ++i) {
        buffer[i] = readLdrRaw();
        if (delay_us > 0) {
            delayMicroseconds(delay_us);
        }
    }
    return max_samples;
}

}  // namespace entropy
}  // namespace es

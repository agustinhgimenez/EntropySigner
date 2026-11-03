#include "entropy/hw_rng.h"

#include <Arduino.h>
#include <bootloader_random.h>
#include <esp_random.h>
#include <string.h>

#include "security/secure_mem.h"

namespace es {
namespace entropy {

namespace {

// ESP32 TRM v5.9 section 18.3: with the SAR ADC as the only noise source the RNG
// receives 2 bits per RC_FAST_CLK (8 MHz) cycle, so RNG_DATA_REG must be read at
// <= 500 kHz to get full entropy per 32-bit word. esp_random() only waits 16 APB
// cycles (~5 MHz) on the classic ESP32, a rate that assumes the radio's
// high-speed ADC is feeding the RNG.
constexpr uint32_t kSarAdcWordIntervalUs = 2;

}  // namespace

uint32_t getRandom32() {
    bootloader_random_enable();
    delayMicroseconds(kSarAdcWordIntervalUs);
    const uint32_t value = esp_random();
    bootloader_random_disable();
    return value;
}

void fillRandomBytes(uint8_t* out, size_t len) {
    if (out == nullptr || len == 0) {
        return;
    }
    bootloader_random_enable();
    for (size_t offset = 0; offset < len; offset += sizeof(uint32_t)) {
        delayMicroseconds(kSarAdcWordIntervalUs);
        uint32_t word = esp_random();
        const size_t n = (len - offset < sizeof(word)) ? len - offset : sizeof(word);
        memcpy(out + offset, &word, n);
        security::secureMemzero(&word, sizeof(word));
    }
    bootloader_random_disable();
}

}  // namespace entropy
}  // namespace es

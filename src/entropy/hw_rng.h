#pragma once

#include <stddef.h>
#include <stdint.h>

namespace es {
namespace entropy {

// Wrapper over the ESP32-S3 hardware RNG (esp_random / esp_fill_random).
//
// The RNG is a true RNG only while a physical noise source is mixed in: the
// radio, or the SAR ADC when enabled through bootloader_random_enable(). With
// the radio off (offline device), these functions enable the SAR ADC source for
// the duration of the call. While enabled the ADC cannot be used, so do not
// call them concurrently with LDR sampling (entropy/ldr_entropy.h).

// Returns 32 random bits.
uint32_t getRandom32();

// Fills len bytes of out with random data. No-op if out is null.
void fillRandomBytes(uint8_t* out, size_t len);

}  // namespace entropy
}  // namespace es

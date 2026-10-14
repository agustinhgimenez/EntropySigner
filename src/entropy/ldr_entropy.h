#pragma once

#include <stddef.h>
#include <stdint.h>

namespace es {
namespace entropy {

// LDR voltage divider sampled on ADC1 (board::kLdrPin). This is an additional
// physical source of variability, not the primary one: no fixed amount of
// entropy is credited to it (see docs/ARCHITECTURE.md).

// Configures the ADC for the LDR pin (12-bit, 11 dB attenuation). Idempotent;
// readLdrRaw() and collectLdrSamples() call it on first use.
void initLdr();

// Returns one raw 12-bit ADC reading (0..4095).
uint16_t readLdrRaw();

// Fills buffer with up to max_samples raw readings spaced delay_us apart.
// Returns the number of samples written (0 if buffer is null).
size_t collectLdrSamples(uint16_t* buffer, size_t max_samples, uint32_t delay_us = 200);

}  // namespace entropy
}  // namespace es

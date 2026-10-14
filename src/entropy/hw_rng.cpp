#include "entropy/hw_rng.h"

#include <bootloader_random.h>
#include <esp_random.h>

namespace es {
namespace entropy {

uint32_t getRandom32() {
    bootloader_random_enable();
    const uint32_t value = esp_random();
    bootloader_random_disable();
    return value;
}

void fillRandomBytes(uint8_t* out, size_t len) {
    if (out == nullptr || len == 0) {
        return;
    }
    bootloader_random_enable();
    esp_fill_random(out, len);
    bootloader_random_disable();
}

}  // namespace entropy
}  // namespace es

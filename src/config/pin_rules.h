#pragma once

// GPIO usage rules for the ESP32-S3 (ESP32-S3 datasheet / ESP-IDF GPIO docs).
// Pure C++ with no Arduino dependency so it can be unit-tested on the host.

namespace es {
namespace pins {

constexpr bool exists(int gpio) {
    return (gpio >= 0 && gpio <= 21) || (gpio >= 26 && gpio <= 48);
}

constexpr bool isStrapping(int gpio) {
    return gpio == 0 || gpio == 3 || gpio == 45 || gpio == 46;
}

constexpr bool isNativeUsb(int gpio) {
    return gpio == 19 || gpio == 20;
}

// SPI flash and octal PSRAM (R8 modules) share GPIO26-GPIO37.
constexpr bool isFlashOrPsram(int gpio) {
    return gpio >= 26 && gpio <= 37;
}

constexpr bool isAdc1(int gpio) {
    return gpio >= 1 && gpio <= 10;
}

constexpr bool isSafeGpio(int gpio) {
    return exists(gpio) && !isStrapping(gpio) && !isNativeUsb(gpio) && !isFlashOrPsram(gpio);
}

}  // namespace pins
}  // namespace es

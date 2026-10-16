#pragma once

// GPIO usage rules per target (ESP32-S3 / ESP32 datasheets, ESP-IDF GPIO docs).
// Pure C++ with no Arduino dependency so it can be unit-tested on the host.
// ES_BOARD_ESP32_DEVKIT selects the classic ESP32 (DOIT DevKit V1, WROOM-32).

namespace es {
namespace pins {

#if defined(ES_BOARD_ESP32_DEVKIT)

constexpr bool exists(int gpio) {
    return (gpio >= 0 && gpio <= 19) || (gpio >= 21 && gpio <= 23) || (gpio >= 25 && gpio <= 27) ||
           (gpio >= 32 && gpio <= 39);
}

constexpr bool isStrapping(int gpio) {
    return gpio == 0 || gpio == 2 || gpio == 5 || gpio == 12 || gpio == 15;
}

// UART0 (TX0/RX0) is wired to the on-board USB-UART bridge.
constexpr bool isConsoleUart(int gpio) {
    return gpio == 1 || gpio == 3;
}

// GPIO6-GPIO11 drive the internal SPI flash on WROOM-32 modules.
constexpr bool isFlashOrPsram(int gpio) {
    return gpio >= 6 && gpio <= 11;
}

constexpr bool isInputOnly(int gpio) {
    return gpio >= 34 && gpio <= 39;
}

constexpr bool isAdc1(int gpio) {
    return gpio >= 32 && gpio <= 39;
}

constexpr bool isSafeGpio(int gpio) {
    return exists(gpio) && !isStrapping(gpio) && !isConsoleUart(gpio) && !isFlashOrPsram(gpio);
}

#else

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

constexpr bool isInputOnly(int /*gpio*/) {
    return false;
}

constexpr bool isAdc1(int gpio) {
    return gpio >= 1 && gpio <= 10;
}

constexpr bool isSafeGpio(int gpio) {
    return exists(gpio) && !isStrapping(gpio) && !isNativeUsb(gpio) && !isFlashOrPsram(gpio);
}

#endif

constexpr bool isSafeOutput(int gpio) {
    return isSafeGpio(gpio) && !isInputOnly(gpio);
}

}  // namespace pins
}  // namespace es

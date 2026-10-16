#include "system/demo_console.h"

#include "config/build_config.h"

#if defined(ES_MODE_DEMO)

#include <Arduino.h>
#include <stdlib.h>
#include <string.h>

#include "entropy/hw_rng.h"
#include "entropy/ldr_entropy.h"
#include "security/secure_mem.h"

namespace es {
namespace system {

namespace {

constexpr size_t kMaxLine = 48;
constexpr long kMaxRngBytes = 1024;
constexpr long kMaxLdrSamples = 512;
constexpr long kMaxLdrDelayUs = 10000;
constexpr uint32_t kDefaultLdrDelayUs = 200;
constexpr size_t kRngChunk = 64;

char g_line[kMaxLine];
size_t g_len = 0;
bool g_overflow = false;

// Parses an integer in [lo, hi]; returns false on garbage or out of range.
bool parseArg(const char* text, long lo, long hi, long* out) {
    char* end = nullptr;
    const long v = strtol(text, &end, 10);
    if (end == text || v < lo || v > hi) {
        return false;
    }
    *out = v;
    return true;
}

void sendRng(long count) {
    static const char kHex[] = "0123456789abcdef";
    uint8_t chunk[kRngChunk];
    Serial.print("ES:RNG ");
    while (count > 0) {
        const size_t n = count > static_cast<long>(kRngChunk) ? kRngChunk : static_cast<size_t>(count);
        entropy::fillRandomBytes(chunk, n);
        for (size_t i = 0; i < n; ++i) {
            Serial.write(kHex[chunk[i] >> 4]);
            Serial.write(kHex[chunk[i] & 0x0F]);
        }
        count -= static_cast<long>(n);
    }
    security::secureMemzero(chunk, sizeof(chunk));
    Serial.print("\r\n");
}

void sendLdr(long count, long delay_us) {
    // Sampled one by one so the buffer stays small; the delay matches collectLdrSamples().
    entropy::initLdr();
    Serial.print("ES:LDR ");
    for (long i = 0; i < count; ++i) {
        Serial.print(entropy::readLdrRaw());
        if (i + 1 < count) {
            Serial.write(',');
        }
        if (delay_us > 0) {
            delayMicroseconds(static_cast<uint32_t>(delay_us));
        }
    }
    Serial.print("\r\n");
}

void handleLine(char* line) {
    if (strcmp(line, "ES:PING") == 0) {
        Serial.printf("ES:PONG %s %s %s\r\n", kFirmwareVersion, kModeName, ESP.getChipModel());
        return;
    }
    if (strncmp(line, "ES:RNG ", 7) == 0) {
        long n = 0;
        if (!parseArg(line + 7, 1, kMaxRngBytes, &n)) {
            Serial.print("ES:ERR RNG expects 1..1024\r\n");
            return;
        }
        sendRng(n);
        return;
    }
    if (strncmp(line, "ES:LDR ", 7) == 0) {
        char* args = line + 7;
        char* space = strchr(args, ' ');
        long n = 0;
        long delay_us = kDefaultLdrDelayUs;
        if (space != nullptr) {
            *space = '\0';
            if (!parseArg(space + 1, 0, kMaxLdrDelayUs, &delay_us)) {
                Serial.print("ES:ERR LDR delay expects 0..10000 us\r\n");
                return;
            }
        }
        if (!parseArg(args, 1, kMaxLdrSamples, &n)) {
            Serial.print("ES:ERR LDR expects 1..512\r\n");
            return;
        }
        sendLdr(n, delay_us);
        return;
    }
    Serial.print("ES:ERR unknown command\r\n");
}

}  // namespace

void pollDemoConsole() {
    while (Serial.available() > 0) {
        const int c = Serial.read();
        if (c == '\r') {
            continue;
        }
        if (c == '\n') {
            g_line[g_len] = '\0';
            if (g_overflow) {
                Serial.print("ES:ERR line too long\r\n");
            } else if (g_len > 0) {
                handleLine(g_line);
            }
            g_len = 0;
            g_overflow = false;
            continue;
        }
        if (g_len + 1 < kMaxLine) {
            g_line[g_len++] = static_cast<char>(c);
        } else {
            g_overflow = true;
        }
    }
}

}  // namespace system
}  // namespace es

#else

namespace es {
namespace system {

void pollDemoConsole() {}

}  // namespace system
}  // namespace es

#endif

#pragma once

#include <Arduino.h>

#include "config/build_config.h"

// Logging policy.
// ES_LOG_INFO:  non-sensitive status messages, printed in every mode.
// ES_LOG_DEBUG: diagnostics, compiled out in PRODUCTION.
// Secrets (entropy, mnemonic, seed, keys) must never be passed to these macros.

#define ES_LOG_INFO(fmt, ...) Serial.printf("[ES] " fmt "\r\n", ##__VA_ARGS__)

#if defined(ES_MODE_DEMO)
#define ES_LOG_DEBUG(fmt, ...) Serial.printf("[ES:DBG] " fmt "\r\n", ##__VA_ARGS__)
#else
#define ES_LOG_DEBUG(fmt, ...) \
    do {                       \
    } while (0)
#endif

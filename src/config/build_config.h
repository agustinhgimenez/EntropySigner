#pragma once

// Operating mode is selected at compile time (see platformio.ini) so that
// debug-only code paths do not exist in a PRODUCTION binary.
#if defined(ES_MODE_DEMO) == defined(ES_MODE_PRODUCTION)
#error "Define exactly one of ES_MODE_DEMO or ES_MODE_PRODUCTION"
#endif

namespace es {

constexpr const char* kProductName = "EntropySigner";
constexpr const char* kProductTagline = "SECURE HARDWARE WALLET";
constexpr const char* kFirmwareVersion = "0.1.0";

#if defined(ES_MODE_DEMO)
constexpr bool kDemoMode = true;
constexpr const char* kModeName = "DEMO";
#else
constexpr bool kDemoMode = false;
constexpr const char* kModeName = "PRODUCTION";
#endif

}  // namespace es

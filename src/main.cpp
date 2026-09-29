// EntropySigner - ESP32 Educational Hardware Wallet Prototype

#include <Arduino.h>

#include "config/build_config.h"
#include "security/secure_log.h"
#include "system/device_info.h"
#include "ui/display.h"

void setup() {
    Serial.begin(115200);
    delay(500);  // give the USB-UART bridge time to enumerate before the banner

    ES_LOG_INFO("==============================");
    ES_LOG_INFO("ENTROPYSIGNER v%s", es::kFirmwareVersion);
    ES_LOG_INFO("%s | ESP32 | mode: %s", es::kProductTagline, es::kModeName);
    ES_LOG_INFO("==============================");
    ES_LOG_INFO("Initializing...");

    es::system::logDeviceInfo();

    const es::ui::DisplayStatus status = es::ui::begin();
    ES_LOG_INFO("Display: %s", status.display_enabled ? "initialized" : "disabled");
    ES_LOG_INFO("Touch: %s", status.touch_detected ? "detected (FT6336U @ 0x38)" : "not detected");
    es::ui::showBootScreen(status);

    ES_LOG_INFO("BOOT OK");
}

void loop() {
    delay(1000);
}

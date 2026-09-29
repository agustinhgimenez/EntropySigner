#include "ui/display.h"

#include <Arduino.h>
#include <Wire.h>

#include "config/board_config.h"
#include "config/build_config.h"
#include "ui/lgfx_device.h"

namespace es {
namespace ui {

namespace {

LgfxDevice* g_lcd = nullptr;

bool probeTouchController() {
    pinMode(board::kTouchRst, OUTPUT);
    digitalWrite(board::kTouchRst, LOW);
    delay(10);
    digitalWrite(board::kTouchRst, HIGH);
    delay(300);  // FT6336U needs ~300 ms after reset before answering on I2C

    Wire.begin(board::kTouchSda, board::kTouchScl, board::kTouchI2cHz);
    Wire.beginTransmission(board::kTouchI2cAddr);
    const bool found = Wire.endTransmission() == 0;
    Wire.end();  // LovyanGFX drives the touch controller on its own I2C port
    return found;
}

}  // namespace

DisplayStatus begin() {
    DisplayStatus status{};
    status.touch_detected = probeTouchController();
#if ES_HAS_DISPLAY
    static LgfxDevice lcd(status.touch_detected);
    g_lcd = &lcd;
    status.display_enabled = lcd.init();
    if (status.display_enabled) {
        lcd.setRotation(0);
        lcd.setBrightness(200);
    }
#endif
    return status;
}

void showBootScreen(const DisplayStatus& status) {
    if (g_lcd == nullptr || !status.display_enabled) {
        return;
    }
    LgfxDevice& lcd = *g_lcd;

    const uint16_t background = lcd.color565(0x0B, 0x0F, 0x14);
    const uint16_t cyan = lcd.color565(0x00, 0xE5, 0xFF);
    const uint16_t green = lcd.color565(0x00, 0xFF, 0x9C);
    const uint16_t grey = lcd.color565(0x8B, 0x98, 0xA5);
    const uint16_t amber = lcd.color565(0xFF, 0xC8, 0x57);
    const int cx = lcd.width() / 2;

    lcd.fillScreen(background);
    lcd.setTextDatum(textdatum_t::middle_center);

    if (kDemoMode) {
        lcd.fillRect(0, 0, lcd.width(), 28, amber);
        lcd.setFont(&fonts::FreeSansBold9pt7b);
        lcd.setTextColor(background);
        lcd.drawString("DEMO MODE", cx, 14);
    }

    lcd.setFont(&fonts::FreeSansBold12pt7b);
    lcd.setTextColor(cyan);
    lcd.drawString("ENTROPYSIGNER", cx, 170);

    lcd.setFont(&fonts::FreeSans9pt7b);
    lcd.setTextColor(grey);
    lcd.drawString(kProductTagline, cx, 210);
    lcd.drawString("ESP32-S3", cx, 240);

    lcd.fillRect(cx - 60, 270, 120, 3, cyan);

    lcd.setFont(&fonts::FreeSansBold12pt7b);
    lcd.setTextColor(green);
    lcd.drawString("BOOT OK", cx, 310);

    lcd.setFont(&fonts::FreeSans9pt7b);
    lcd.setTextColor(grey);
    lcd.drawString(status.touch_detected ? "Touch: detected" : "Touch: not detected", cx, 350);

    char footer[40];
    snprintf(footer, sizeof(footer), "v%s  |  %s", kFirmwareVersion, kModeName);
    lcd.drawString(footer, cx, lcd.height() - 20);
}

}  // namespace ui
}  // namespace es

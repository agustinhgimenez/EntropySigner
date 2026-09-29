#pragma once

#define LGFX_USE_V1
#include <LovyanGFX.hpp>

#include "config/board_config.h"

namespace es {
namespace ui {

// LovyanGFX device for ST7796S (SPI) with optional FT6336U touch (FT5x06 family).
class LgfxDevice : public lgfx::LGFX_Device {
public:
    explicit LgfxDevice(bool with_touch) {
        {
            auto cfg = bus_.config();
            cfg.spi_host = SPI2_HOST;
            cfg.spi_mode = 0;
            cfg.freq_write = board::kDisplaySpiWriteHz;
            cfg.freq_read = board::kDisplaySpiReadHz;
            cfg.spi_3wire = false;
            cfg.use_lock = true;
            cfg.dma_channel = SPI_DMA_CH_AUTO;
            cfg.pin_sclk = board::kDisplaySclk;
            cfg.pin_mosi = board::kDisplayMosi;
            cfg.pin_miso = board::kDisplayMiso;
            cfg.pin_dc = board::kDisplayDc;
            bus_.config(cfg);
            panel_.setBus(&bus_);
        }
        {
            auto cfg = panel_.config();
            cfg.pin_cs = board::kDisplayCs;
            cfg.pin_rst = board::kDisplayRst;
            cfg.pin_busy = -1;
            cfg.panel_width = board::kDisplayWidth;
            cfg.panel_height = board::kDisplayHeight;
            cfg.offset_x = 0;
            cfg.offset_y = 0;
            cfg.offset_rotation = 0;
            cfg.readable = true;
            cfg.invert = ES_DISPLAY_INVERT != 0;
            cfg.rgb_order = false;
            cfg.dlen_16bit = false;
            cfg.bus_shared = false;
            panel_.config(cfg);
        }
        {
            auto cfg = light_.config();
            cfg.pin_bl = board::kDisplayBacklight;
            cfg.invert = false;
            cfg.freq = 44100;
            cfg.pwm_channel = 7;
            light_.config(cfg);
            panel_.setLight(&light_);
        }
        if (with_touch) {
            auto cfg = touch_.config();
            cfg.x_min = 0;
            cfg.x_max = board::kDisplayWidth - 1;
            cfg.y_min = 0;
            cfg.y_max = board::kDisplayHeight - 1;
            cfg.pin_int = board::kTouchInt;
            cfg.bus_shared = false;
            cfg.offset_rotation = 0;
            cfg.i2c_port = 1;
            cfg.i2c_addr = board::kTouchI2cAddr;
            cfg.pin_sda = board::kTouchSda;
            cfg.pin_scl = board::kTouchScl;
            cfg.freq = board::kTouchI2cHz;
            touch_.config(cfg);
            panel_.setTouch(&touch_);
        }
        setPanel(&panel_);
    }

private:
    lgfx::Bus_SPI bus_;
    lgfx::Panel_ST7796 panel_;
    lgfx::Light_PWM light_;
    lgfx::Touch_FT5x06 touch_;
};

}  // namespace ui
}  // namespace es

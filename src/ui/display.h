#pragma once

namespace es {
namespace ui {

struct DisplayStatus {
    bool display_enabled;  // panel configured and initialized (ES_HAS_DISPLAY)
    bool touch_detected;   // FT6336U answered on I2C
};

// Probes the touch controller and initializes the panel. Safe to call with no
// display or touch connected.
DisplayStatus begin();

// Draws the EntropySigner boot screen ("ENTROPYSIGNER ... BOOT OK").
void showBootScreen(const DisplayStatus& status);

}  // namespace ui
}  // namespace es

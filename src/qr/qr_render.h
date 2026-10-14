#pragma once

#include <stdint.h>

#include "ui/lgfx_device.h"

// QR rendering for PUBLIC data only (Bitcoin / Ethereum addresses).
// Never pass a mnemonic, seed or private key here: a QR on screen is meant to
// be photographed and scanned by another device.

namespace es {
namespace qr {

// Highest QR version tried. Version 6 at ECC level M holds 106 bytes, far more
// than any address needs, and keeps modules large on a 320 px wide panel.
constexpr uint8_t kMaxVersion = 6;
constexpr uint16_t kMaxTextLength = 106;

// Encodes text (byte mode, ECC level M) using the smallest version in
// [1, kMaxVersion] that fits it (34-char P2PKH and 42-char EIP-55 addresses
// both fit version 3) and draws it as a white square of side <= box_size
// centered at (center_x, center_y): black modules, integer pixels per module,
// surrounded by a 4-module quiet zone (2 if the box is too small for 4).
// Returns false, drawing nothing, if text is null, empty, too long, or the box
// cannot hold one pixel per module.
bool renderQr(ui::LgfxDevice& lcd, const char* text, int center_x, int center_y, int box_size);

}  // namespace qr
}  // namespace es

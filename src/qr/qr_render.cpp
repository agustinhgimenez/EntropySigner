#include "qr/qr_render.h"

#include <string.h>

#include <qrcode.h>

namespace es {
namespace qr {

namespace {

// Byte-mode capacity at ECC level M for versions 1..kMaxVersion (ISO/IEC 18004
// table 7). ricmoo/QRCode does not check the input length against the version
// capacity and overruns its buffers when it does not fit, so the check must
// happen here before calling it. Numeric and alphanumeric texts, which the
// library may auto-select, pack denser than byte mode, so this is a safe bound.
constexpr uint16_t kByteCapacityEccM[kMaxVersion] = {14, 26, 42, 62, 84, 106};

constexpr uint8_t kPreferredQuietZone = 4;
constexpr uint8_t kMinQuietZone = 2;

uint8_t smallestVersionFor(size_t length) {
    for (uint8_t v = 1; v <= kMaxVersion; ++v) {
        if (length <= kByteCapacityEccM[v - 1]) {
            return v;
        }
    }
    return 0;
}

}  // namespace

bool renderQr(ui::LgfxDevice& lcd, const char* text, int center_x, int center_y, int box_size) {
    if (text == nullptr || box_size <= 0) {
        return false;
    }
    const size_t length = strnlen(text, kMaxTextLength + 1);
    const uint8_t version = (length == 0) ? 0 : smallestVersionFor(length);
    if (version == 0) {
        return false;
    }

    // Sized for kMaxVersion: (6 * 4 + 17)^2 bits = 211 bytes.
    uint8_t modules[(((kMaxVersion * 4 + 17) * (kMaxVersion * 4 + 17)) + 7) / 8];
    QRCode code;
    if (qrcode_initBytes(&code, modules, version, ECC_MEDIUM,
                         reinterpret_cast<uint8_t*>(const_cast<char*>(text)),
                         static_cast<uint16_t>(length)) < 0) {
        return false;
    }

    const int size = code.size;
    int quiet = kPreferredQuietZone;
    int scale = box_size / (size + 2 * quiet);
    if (scale < 2) {
        quiet = kMinQuietZone;
        scale = box_size / (size + 2 * quiet);
    }
    if (scale < 1) {
        return false;
    }

    const int side = (size + 2 * quiet) * scale;
    const int left = center_x - side / 2;
    const int top = center_y - side / 2;
    const int origin_x = left + quiet * scale;
    const int origin_y = top + quiet * scale;
    const uint16_t white = lcd.color565(0xFF, 0xFF, 0xFF);
    const uint16_t black = lcd.color565(0x00, 0x00, 0x00);

    lcd.startWrite();
    lcd.fillRect(left, top, side, side, white);
    // One fillRect per horizontal run of dark modules instead of per module.
    for (int y = 0; y < size; ++y) {
        int x = 0;
        while (x < size) {
            if (!qrcode_getModule(&code, x, y)) {
                ++x;
                continue;
            }
            const int run_start = x;
            while (x < size && qrcode_getModule(&code, x, y)) {
                ++x;
            }
            lcd.fillRect(origin_x + run_start * scale, origin_y + y * scale, (x - run_start) * scale, scale, black);
        }
    }
    lcd.endWrite();
    return true;
}

}  // namespace qr
}  // namespace es

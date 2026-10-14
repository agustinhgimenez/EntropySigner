#include "ui/wallet_ui.h"

#include <Arduino.h>
#include <string.h>

#include "bip32/bip32.h"
#include "bip39/bip39.h"
#include "bitcoin/bitcoin.h"
#include "config/build_config.h"
#include "entropy/entropy_pool.h"
#include "entropy/ldr_entropy.h"
#include "ethereum/ethereum.h"
#include "qr/qr_render.h"
#include "security/secure_log.h"
#include "security/secure_mem.h"
#include "ui/lgfx_device.h"

namespace es {
namespace ui {

namespace {

// ---------------------------------------------------------------- timing ---

constexpr uint32_t kBootTimeoutMs = 2500;
constexpr uint32_t kTapGuardMs = 250;  // ignore taps right after a screen change
constexpr uint32_t kMnemonicTimeoutMs = 120000;  // 2-min inactivity timeout: wipes mnemonic and resets to IDLE
constexpr uint32_t kLdrSamplePeriodMs = 40;
constexpr uint32_t kLdrRedrawPeriodMs = 120;

// ---------------------------------------------------------------- layout ---

constexpr int kBannerHeight = 28;  // "DEMO MODE" strip, DEMO builds only
constexpr int kMargin = 16;

struct Button {
    int16_t x, y, w, h;
    bool contains(int32_t px, int32_t py) const { return px >= x && px < x + w && py >= y && py < y + h; }
};

constexpr Button kWideButton = {32, 412, 256, 52};
constexpr Button kLeftButton = {kMargin, 412, 136, 52};
constexpr Button kRightButton = {168, 412, 136, 52};

// IDLE sensor card
constexpr int kCardTop = 108;
constexpr int kCardHeight = 214;
constexpr int kBarX = 32;
constexpr int kBarWidth = 256;
constexpr int kBarHeight = 14;
constexpr int kValueY = 162;
constexpr int kLevelBarY = 192;
constexpr int kVariationLabelY = 234;
constexpr int kVariationBarY = 252;

constexpr uint16_t kAdcMax = 4095;
constexpr uint16_t kVariationFullScale = 512;  // max-min counts for a full bar
constexpr size_t kLdrWindow = 32;

// Address screens
constexpr int kQrCenterY = 215;
constexpr int kQrBox = 250;

// ---------------------------------------------------------------- state ---

struct Palette {
    uint16_t background;
    uint16_t cyan;
    uint16_t amber;
    uint16_t green;
    uint16_t grey;
    uint16_t surface;
};

// Everything the wallet keeps between screens. Only the mnemonic is secret;
// the addresses are public.
struct Session {
    char mnemonic[bip39::kMaxMnemonicLength];
    char btc_address[bitcoin::kMaxAddressLength];
    char eth_address[ethereum::kAddressLength];
};

LgfxDevice* g_lcd = nullptr;
Palette g_pal{};
WalletState g_state = WalletState::BOOT;
uint32_t g_state_entered_ms = 0;
bool g_touch_was_down = false;
Session g_session;
const char* g_error = "";

uint16_t g_ldr_window[kLdrWindow];
size_t g_ldr_count = 0;
size_t g_ldr_next = 0;
uint32_t g_last_ldr_sample_ms = 0;
uint32_t g_last_ldr_redraw_ms = 0;

void wipeSession() {
    security::secureMemzero(&g_session, sizeof(g_session));
}

// ------------------------------------------------------------ primitives ---

void drawFrame() {
    LgfxDevice& lcd = *g_lcd;
    lcd.fillScreen(g_pal.background);
    if (kDemoMode) {
        lcd.fillRect(0, 0, lcd.width(), kBannerHeight, g_pal.amber);
        lcd.setFont(&fonts::FreeSansBold9pt7b);
        lcd.setTextDatum(textdatum_t::middle_center);
        lcd.setTextColor(g_pal.background);
        lcd.drawString("DEMO MODE", lcd.width() / 2, kBannerHeight / 2);
    }
}

void drawTitle(const char* title, const char* subtitle, uint16_t color) {
    LgfxDevice& lcd = *g_lcd;
    const int cx = lcd.width() / 2;
    lcd.setTextDatum(textdatum_t::middle_center);
    lcd.setFont(&fonts::FreeSansBold12pt7b);
    lcd.setTextColor(color);
    lcd.drawString(title, cx, 52);
    if (subtitle != nullptr) {
        lcd.setFont(&fonts::FreeSans9pt7b);
        lcd.setTextColor(g_pal.grey);
        lcd.drawString(subtitle, cx, 80);
    }
}

void drawButton(const Button& b, const char* label, uint16_t accent) {
    LgfxDevice& lcd = *g_lcd;
    lcd.fillRoundRect(b.x, b.y, b.w, b.h, 10, g_pal.surface);
    lcd.drawRoundRect(b.x, b.y, b.w, b.h, 10, accent);
    lcd.drawRoundRect(b.x + 1, b.y + 1, b.w - 2, b.h - 2, 9, accent);
    lcd.setFont(&fonts::FreeSansBold9pt7b);
    lcd.setTextDatum(textdatum_t::middle_center);
    lcd.setTextColor(accent);
    lcd.drawString(label, b.x + b.w / 2, b.y + b.h / 2);
}

void drawBar(int y, uint32_t value, uint32_t full_scale, uint16_t color) {
    LgfxDevice& lcd = *g_lcd;
    if (value > full_scale) {
        value = full_scale;
    }
    const int filled = static_cast<int>(value * kBarWidth / full_scale);
    lcd.fillRect(kBarX, y, filled, kBarHeight, color);
    lcd.fillRect(kBarX + filled, y, kBarWidth - filled, kBarHeight, g_pal.background);
    lcd.drawRect(kBarX - 1, y - 1, kBarWidth + 2, kBarHeight + 2, g_pal.grey);
}

// Returns true once per finger-down (press edge), with its coordinates.
bool pollTap(int32_t* x, int32_t* y) {
    int32_t tx = 0;
    int32_t ty = 0;
    const bool down = g_lcd->getTouch(&tx, &ty) > 0;
    const bool pressed = down && !g_touch_was_down;
    g_touch_was_down = down;
    if (!pressed || millis() - g_state_entered_ms < kTapGuardMs) {
        return false;
    }
    *x = tx;
    *y = ty;
    return true;
}

// --------------------------------------------------------------- screens ---

void drawIdle() {
    LgfxDevice& lcd = *g_lcd;
    drawFrame();
    drawTitle("ENTROPYSIGNER", "Wallet offline BIP-39 / BIP-44", g_pal.cyan);

    lcd.fillRoundRect(kMargin, kCardTop, lcd.width() - 2 * kMargin, kCardHeight, 12, g_pal.surface);
    lcd.setTextDatum(textdatum_t::middle_left);
    lcd.setFont(&fonts::FreeSans9pt7b);
    lcd.setTextColor(g_pal.grey);
    lcd.drawString("SENSOR LDR  -  ADC1_CH0", kBarX, kCardTop + 22);
    lcd.drawString("VARIACION AMBIENTAL", kBarX, kVariationLabelY);
    lcd.drawString("Pasa la mano sobre el sensor", kBarX, kCardTop + kCardHeight - 22);

    lcd.setTextDatum(textdatum_t::middle_center);
    lcd.drawString("Fuente principal: RNG de hardware", lcd.width() / 2, 348);
    lcd.drawString("LDR: fuente adicional + SHA-256", lcd.width() / 2, 372);

    drawButton(kWideButton, "GENERAR WALLET", g_pal.green);

    g_ldr_count = 0;
    g_ldr_next = 0;
    g_last_ldr_redraw_ms = 0;
}

void refreshIdleSensor() {
    LgfxDevice& lcd = *g_lcd;
    const uint32_t now = millis();

    if (now - g_last_ldr_sample_ms >= kLdrSamplePeriodMs) {
        g_last_ldr_sample_ms = now;
        g_ldr_window[g_ldr_next] = entropy::readLdrRaw();
        g_ldr_next = (g_ldr_next + 1) % kLdrWindow;
        if (g_ldr_count < kLdrWindow) {
            ++g_ldr_count;
        }
    }
    if (g_ldr_count == 0 || now - g_last_ldr_redraw_ms < kLdrRedrawPeriodMs) {
        return;
    }
    g_last_ldr_redraw_ms = now;

    const uint16_t latest = g_ldr_window[(g_ldr_next + kLdrWindow - 1) % kLdrWindow];
    uint16_t lo = kAdcMax;
    uint16_t hi = 0;
    for (size_t i = 0; i < g_ldr_count; ++i) {
        lo = min(lo, g_ldr_window[i]);
        hi = max(hi, g_ldr_window[i]);
    }
    const uint16_t variation = hi - lo;

    char text[24];
    lcd.startWrite();
    lcd.fillRect(kBarX, kValueY - 16, kBarWidth, 32, g_pal.surface);
    lcd.setTextDatum(textdatum_t::middle_left);
    lcd.setFont(&fonts::FreeSansBold12pt7b);
    lcd.setTextColor(g_pal.cyan);
    snprintf(text, sizeof(text), "%u", latest);
    lcd.drawString(text, kBarX, kValueY);
    lcd.setFont(&fonts::FreeSans9pt7b);
    lcd.setTextColor(g_pal.grey);
    lcd.drawString("/ 4095", kBarX + 70, kValueY);
    drawBar(kLevelBarY, latest, kAdcMax, g_pal.cyan);

    lcd.fillRect(kBarX + 190, kVariationLabelY - 10, kBarWidth - 190, 20, g_pal.surface);
    lcd.setTextDatum(textdatum_t::middle_right);
    lcd.setTextColor(g_pal.green);
    snprintf(text, sizeof(text), "%u", variation);
    lcd.drawString(text, kBarX + kBarWidth, kVariationLabelY);
    drawBar(kVariationBarY, variation, kVariationFullScale, g_pal.green);
    lcd.endWrite();
}

void drawGeneratingStep(int index, const char* label, const char* status, uint16_t status_color) {
    LgfxDevice& lcd = *g_lcd;
    const int y = 130 + index * 40;
    lcd.fillRect(kMargin, y - 14, lcd.width() - 2 * kMargin, 28, g_pal.background);
    lcd.setFont(&fonts::FreeSans9pt7b);
    lcd.setTextDatum(textdatum_t::middle_left);
    lcd.setTextColor(g_pal.grey);
    lcd.drawString(label, kMargin + 8, y);
    lcd.setFont(&fonts::FreeSansBold9pt7b);
    lcd.setTextDatum(textdatum_t::middle_right);
    lcd.setTextColor(status_color);
    lcd.drawString(status, lcd.width() - kMargin - 8, y);
}

void drawGenerating() {
    drawFrame();
    drawTitle("GENERANDO WALLET", "No apagues el dispositivo", g_pal.cyan);
}

// Runs the whole derivation pipeline. Every secret intermediate lives on this
// stack frame and is wiped before returning; only the mnemonic and the two
// public addresses survive in g_session.
bool generateWallet() {
    static const char* const kSteps[] = {
        "Entropia 256 bits (RNG+LDR)", "BIP-39: 24 palabras",       "PBKDF2-HMAC-SHA512 seed",
        "BIP-32 master key",           "BTC  m/44'/0'/0'/0/0",       "ETH  m/44'/60'/0'/0/0",
    };
    constexpr int kStepCount = sizeof(kSteps) / sizeof(kSteps[0]);
    for (int i = 0; i < kStepCount; ++i) {
        drawGeneratingStep(i, kSteps[i], "...", g_pal.grey);
    }

    uint8_t entropy[entropy::kEntropySize];
    uint8_t seed[bip39::kSeedBytes];
    bip32::ExtendedPrivateKey master;
    int step = 0;
    bool ok = false;

    wipeSession();
    do {
        if (!entropy::generateEntropy256(entropy, true)) break;
        drawGeneratingStep(step, kSteps[step], "OK", g_pal.green);
        ++step;

        if (!bip39::entropyToMnemonic(entropy, g_session.mnemonic, sizeof(g_session.mnemonic))) break;
        security::secureMemzero(entropy, sizeof(entropy));
        drawGeneratingStep(step, kSteps[step], "OK", g_pal.green);
        ++step;

        if (!bip39::mnemonicToSeed(g_session.mnemonic, nullptr, seed)) break;
        drawGeneratingStep(step, kSteps[step], "OK", g_pal.green);
        ++step;

        const bool master_ok = bip32::createMasterKey(seed, sizeof(seed), &master);
        security::secureMemzero(seed, sizeof(seed));
        if (!master_ok) break;
        drawGeneratingStep(step, kSteps[step], "OK", g_pal.green);
        ++step;

        if (!bitcoin::deriveBitcoinAddress(master, g_session.btc_address, sizeof(g_session.btc_address))) break;
        drawGeneratingStep(step, kSteps[step], "OK", g_pal.green);
        ++step;

        if (!ethereum::deriveEthereumAddress(master, g_session.eth_address)) break;
        drawGeneratingStep(step, kSteps[step], "OK", g_pal.green);
        ok = true;
    } while (false);

    security::secureMemzero(entropy, sizeof(entropy));
    security::secureMemzero(seed, sizeof(seed));
    bip32::wipe(&master);
    if (!ok) {
        drawGeneratingStep(step, kSteps[step], "FALLO", g_pal.amber);
        wipeSession();
        g_error = kSteps[step];
    }
    return ok;
}

void drawBackupWarning() {
    LgfxDevice& lcd = *g_lcd;
    drawFrame();
    drawTitle("ATENCION", "Backup de la frase de recuperacion", g_pal.amber);

    static const char* const kLines[] = {
        "Vas a ver las 24 palabras que",
        "controlan esta wallet.",
        "",
        "- Que nadie mire la pantalla.",
        "- No saques fotos ni capturas.",
        "- Anotalas en papel, en orden.",
        "- No se guardan en el equipo:",
        "  si las perdes, perdes los fondos.",
    };
    lcd.fillRoundRect(kMargin, 108, lcd.width() - 2 * kMargin, 270, 12, g_pal.surface);
    lcd.setFont(&fonts::FreeSans9pt7b);
    lcd.setTextDatum(textdatum_t::middle_left);
    int y = 136;
    for (const char* line : kLines) {
        lcd.setTextColor(line[0] == '-' ? g_pal.amber : g_pal.grey);
        lcd.drawString(line, kMargin + 14, y);
        y += 30;
    }

    drawButton(kLeftButton, "CANCELAR", g_pal.grey);
    drawButton(kRightButton, "MOSTRAR", g_pal.amber);
}

void drawMnemonic() {
    LgfxDevice& lcd = *g_lcd;
    drawFrame();
    drawTitle("FRASE DE RECUPERACION", "Anota las 24 palabras en orden", g_pal.amber);

    constexpr int kRows = static_cast<int>(bip39::kWordCount) / 2;
    constexpr int kTop = 108;
    constexpr int kRowHeight = 24;
    constexpr int kColumnX[2] = {28, 172};

    char word[12];
    const char* p = g_session.mnemonic;
    lcd.setTextDatum(textdatum_t::middle_left);
    for (int i = 0; i < static_cast<int>(bip39::kWordCount); ++i) {
        size_t len = 0;
        while (*p != '\0' && *p != ' ' && len + 1 < sizeof(word)) {
            word[len++] = *p++;
        }
        word[len] = '\0';
        if (*p == ' ') {
            ++p;
        }

        const int x = kColumnX[i / kRows];
        const int y = kTop + (i % kRows) * kRowHeight;
        char index[4];
        snprintf(index, sizeof(index), "%02d", i + 1);
        lcd.setFont(&fonts::FreeMono9pt7b);
        lcd.setTextColor(g_pal.grey);
        lcd.drawString(index, x, y);
        lcd.setFont(&fonts::FreeMonoBold9pt7b);
        lcd.setTextColor(g_pal.cyan);
        lcd.drawString(word, x + 30, y);
    }
    security::secureMemzero(word, sizeof(word));

    drawButton(kWideButton, "YA LAS ANOTE", g_pal.green);
}

void drawAddress(const char* title, const char* path, const char* address, uint16_t accent) {
    LgfxDevice& lcd = *g_lcd;
    drawFrame();
    drawTitle(title, path, accent);

    if (!qr::renderQr(lcd, address, lcd.width() / 2, kQrCenterY, kQrBox)) {
        lcd.setFont(&fonts::FreeSans9pt7b);
        lcd.setTextDatum(textdatum_t::middle_center);
        lcd.setTextColor(g_pal.amber);
        lcd.drawString("QR no disponible", lcd.width() / 2, kQrCenterY);
    }

    // Two centered lines: up to 21 FreeMono characters (11 px) fit per line.
    char line[24];
    const size_t len = strlen(address);
    const size_t half = (len + 1) / 2;
    lcd.setFont(&fonts::FreeMono9pt7b);
    lcd.setTextDatum(textdatum_t::middle_center);
    lcd.setTextColor(g_pal.cyan);
    snprintf(line, sizeof(line), "%.*s", static_cast<int>(half), address);
    lcd.drawString(line, lcd.width() / 2, 360);
    snprintf(line, sizeof(line), "%s", address + half);
    lcd.drawString(line, lcd.width() / 2, 382);
}

void drawBtc() {
    drawAddress("BITCOIN", bitcoin::kBip44Path, g_session.btc_address, g_pal.amber);
    drawButton(kLeftButton, "TERMINAR", g_pal.grey);
    drawButton(kRightButton, "ETHEREUM >", g_pal.cyan);
}

void drawEth() {
    drawAddress("ETHEREUM", ethereum::kBip44Path, g_session.eth_address, g_pal.cyan);
    drawButton(kLeftButton, "< BITCOIN", g_pal.amber);
    drawButton(kRightButton, "TERMINAR", g_pal.grey);
}

void drawError() {
    LgfxDevice& lcd = *g_lcd;
    drawFrame();
    drawTitle("ERROR", "No se pudo generar la wallet", g_pal.amber);
    lcd.setFont(&fonts::FreeSans9pt7b);
    lcd.setTextDatum(textdatum_t::middle_center);
    lcd.setTextColor(g_pal.grey);
    lcd.drawString("Fallo en el paso:", lcd.width() / 2, 200);
    lcd.setTextColor(g_pal.amber);
    lcd.drawString(g_error, lcd.width() / 2, 228);
    lcd.setTextColor(g_pal.grey);
    lcd.drawString("Ningun secreto quedo en memoria.", lcd.width() / 2, 280);
    drawButton(kWideButton, "VOLVER", g_pal.cyan);
}

// ------------------------------------------------------------ transitions ---

const char* stateName(WalletState s) {
    switch (s) {
        case WalletState::BOOT: return "BOOT";
        case WalletState::IDLE: return "IDLE";
        case WalletState::GENERATING: return "GENERATING";
        case WalletState::BACKUP_WARNING: return "BACKUP_WARNING";
        case WalletState::SHOW_MNEMONIC: return "SHOW_MNEMONIC";
        case WalletState::SHOW_BTC: return "SHOW_BTC";
        case WalletState::SHOW_ETH: return "SHOW_ETH";
        case WalletState::ERROR: return "ERROR";
    }
    return "?";
}

void enterState(WalletState next) {
    // The mnemonic is only needed for the backup screens.
    if (g_state == WalletState::SHOW_MNEMONIC && next != WalletState::SHOW_MNEMONIC) {
        security::secureMemzero(g_session.mnemonic, sizeof(g_session.mnemonic));
    }
    if (next == WalletState::IDLE) {
        wipeSession();
    }

    g_state = next;
    ES_LOG_INFO("UI state: %s", stateName(next));
    switch (next) {
        case WalletState::BOOT: break;  // drawn by beginWallet()
        case WalletState::IDLE: drawIdle(); break;
        case WalletState::GENERATING: drawGenerating(); break;
        case WalletState::BACKUP_WARNING: drawBackupWarning(); break;
        case WalletState::SHOW_MNEMONIC: drawMnemonic(); break;
        case WalletState::SHOW_BTC: drawBtc(); break;
        case WalletState::SHOW_ETH: drawEth(); break;
        case WalletState::ERROR: drawError(); break;
    }
    // Taken after drawing so slow screens (QR) do not eat the tap guard.
    g_state_entered_ms = millis();
}

}  // namespace

void beginWallet(const DisplayStatus& status) {
    g_lcd = device();
    if (g_lcd == nullptr || !status.display_enabled) {
        g_lcd = nullptr;
        ES_LOG_INFO("Wallet UI disabled: no display");
        return;
    }
    LgfxDevice& lcd = *g_lcd;
    g_pal.background = lcd.color565(0x0B, 0x0F, 0x14);
    g_pal.cyan = lcd.color565(0x00, 0xE5, 0xFF);
    g_pal.amber = lcd.color565(0xFF, 0xC8, 0x57);
    g_pal.green = lcd.color565(0x00, 0xFF, 0x9C);
    g_pal.grey = lcd.color565(0x8B, 0x98, 0xA5);
    g_pal.surface = lcd.color565(0x16, 0x1F, 0x28);
    if (!status.touch_detected) {
        ES_LOG_INFO("Wallet UI: no touch, the flow stops at IDLE");
    }

    wipeSession();
    g_state = WalletState::BOOT;
    showBootScreen(status);
    g_state_entered_ms = millis();
}

void updateWallet() {
    if (g_lcd == nullptr) {
        return;
    }
    int32_t x = 0;
    int32_t y = 0;
    const bool tap = pollTap(&x, &y);

    switch (g_state) {
        case WalletState::BOOT:
            if (tap || millis() - g_state_entered_ms >= kBootTimeoutMs) {
                enterState(WalletState::IDLE);
            }
            break;

        case WalletState::IDLE:
            refreshIdleSensor();
            if (tap && kWideButton.contains(x, y)) {
                enterState(WalletState::GENERATING);
            }
            break;

        case WalletState::GENERATING:
            // Blocking (PBKDF2 dominates); the screen shows per-step progress.
            if (generateWallet()) {
#if defined(ES_MODE_DEMO)
                ES_LOG_INFO("Wallet generated. BTC %s | ETH %s", g_session.btc_address, g_session.eth_address);
#else
                ES_LOG_INFO("Wallet generated successfully.");
#endif
                enterState(WalletState::BACKUP_WARNING);
            } else {
                ES_LOG_INFO("Wallet generation failed at: %s", g_error);
                enterState(WalletState::ERROR);
            }
            g_touch_was_down = true;  // drop any touch made while blocked
            break;

        case WalletState::BACKUP_WARNING:
            if (millis() - g_state_entered_ms >= kMnemonicTimeoutMs) {
                ES_LOG_INFO("Backup warning screen timed out, wiping session");
                enterState(WalletState::IDLE);
            } else if (tap && kLeftButton.contains(x, y)) {
                enterState(WalletState::IDLE);
            } else if (tap && kRightButton.contains(x, y)) {
                enterState(WalletState::SHOW_MNEMONIC);
            }
            break;

        case WalletState::SHOW_MNEMONIC:
            if (millis() - g_state_entered_ms >= kMnemonicTimeoutMs) {
                ES_LOG_INFO("Mnemonic screen timed out, wiping session");
                enterState(WalletState::IDLE);
            } else if (tap && kWideButton.contains(x, y)) {
                enterState(WalletState::SHOW_BTC);
            }
            break;

        case WalletState::SHOW_BTC:
            if (tap && kLeftButton.contains(x, y)) {
                enterState(WalletState::IDLE);
            } else if (tap && kRightButton.contains(x, y)) {
                enterState(WalletState::SHOW_ETH);
            }
            break;

        case WalletState::SHOW_ETH:
            if (tap && kLeftButton.contains(x, y)) {
                enterState(WalletState::SHOW_BTC);
            } else if (tap && kRightButton.contains(x, y)) {
                enterState(WalletState::IDLE);
            }
            break;

        case WalletState::ERROR:
            if (tap && kWideButton.contains(x, y)) {
                enterState(WalletState::IDLE);
            }
            break;
    }
}

WalletState currentWalletState() {
    return g_state;
}

}  // namespace ui
}  // namespace es

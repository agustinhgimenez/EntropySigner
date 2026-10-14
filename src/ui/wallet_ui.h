#pragma once

#include <stdint.h>

#include "ui/display.h"

// Interactive wallet flow on the ST7796S + FT6336U touch panel.
//
//   BOOT ──tap / 2.5 s──▶ IDLE ──[GENERAR WALLET]──▶ GENERATING ──▶ BACKUP_WARNING
//                          ▲                              │ error      │ [MOSTRAR]
//                          │                              ▼            ▼
//                          ├──────[VOLVER]─────────── ERROR      SHOW_MNEMONIC
//                          │                                           │ [YA LAS ANOTE]
//                          │                                           ▼
//                          └──[CANCELAR] / [TERMINAR]──── SHOW_BTC ◀──▶ SHOW_ETH
//
// Secret handling: the seed, master key and derived private keys only live on
// the stack of the generation step and are wiped before it returns. The
// mnemonic is kept in RAM only until the user confirms the backup and is wiped
// on leaving SHOW_MNEMONIC (or on cancel). Nothing is persisted: leaving the
// address screens discards the wallet.

namespace es {
namespace ui {

enum class WalletState : uint8_t {
    BOOT,
    IDLE,
    GENERATING,
    BACKUP_WARNING,
    SHOW_MNEMONIC,
    SHOW_BTC,
    SHOW_ETH,
    ERROR,
};

// Starts the state machine in BOOT, drawing the boot screen. Call after
// ui::begin(). Without an initialized display every later call is a no-op.
void beginWallet(const DisplayStatus& status);

// Polls touch, advances the state machine and refreshes the screen. Call from
// loop() as often as possible; it never blocks except during GENERATING.
void updateWallet();

WalletState currentWalletState();

}  // namespace ui
}  // namespace es

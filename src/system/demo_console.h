#pragma once

namespace es {
namespace system {

// Line-based USB serial protocol that lets the web lab (simulator/) pull raw
// entropy from the real device. DEMO builds only: in PRODUCTION this is a no-op
// and the command parser is not compiled in.
//
//   ES:PING              -> ES:PONG <version> <mode> <chip model>
//   ES:RNG <n>           -> ES:RNG <2n hex chars>       n = 1..1024 bytes of HW RNG
//   anything else        -> ES:ERR <reason>
//
// The bytes sent are fresh reads, never the ones the device uses for its own
// wallets, and the device never sends mnemonics, seeds or keys over USB.
void pollDemoConsole();

}  // namespace system
}  // namespace es

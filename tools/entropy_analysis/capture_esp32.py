#!/usr/bin/env python3
"""EntropySigner - capture raw entropy from the ESP32 over USB.

Talks to the DEMO-only console of src/system/demo_console.cpp:
    ES:PING            -> ES:PONG <version> <mode> <chip>
    ES:RNG <n>         -> ES:RNG <hex>          (n <= 1024 bytes, same path as wallet generation)
    ES:LDR <n> [us]    -> ES:LDR v1,v2,...      (n <= 512 ADC readings of GPIO34)

Outputs feed analyze_entropy.py (SP 800-90B) and nist_sp800_22.py (SP 800-22):
    python tools/entropy_analysis/capture_esp32.py --port COM4 --rng 1000000 --out rng.bin
    python tools/entropy_analysis/capture_esp32.py --port COM4 --ldr 100000 --out ldr.txt

Requires pyserial.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

try:
    import serial  # type: ignore
except ImportError:
    sys.exit("Error: requiere pyserial (pip install pyserial).")

RNG_CHUNK = 1024
LDR_CHUNK = 512


class Esp32:
    def __init__(self, port: str, baud: int = 115200) -> None:
        self.link = serial.Serial(port, baud, timeout=2)
        time.sleep(2.5)  # opening the port resets the board
        self.link.reset_input_buffer()

    def request(self, command: str, prefix: str) -> str:
        self.link.write((command + "\n").encode())
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            line = self.link.readline().decode("ascii", errors="replace").strip()
            if line.startswith("ES:ERR"):
                raise RuntimeError(f"{command}: {line}")
            if line.startswith(prefix + " "):
                return line[len(prefix) + 1:]
        raise TimeoutError(f"sin respuesta a {command} (¿firmware DEMO cargado?)")

    def close(self) -> None:
        self.link.close()


def progress(done: int, total: int, start: float) -> None:
    rate = done / max(time.monotonic() - start, 1e-6)
    eta = (total - done) / rate if rate else 0
    print(f"\r  {done:,}/{total:,}  ({rate:,.0f}/s, faltan {eta:,.0f} s)   ", end="", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser(description="Captura entropia cruda de la ESP32 por USB.")
    ap.add_argument("--port", required=True, help="puerto serie, p.ej. COM4 o /dev/ttyUSB0")
    what = ap.add_mutually_exclusive_group(required=True)
    what.add_argument("--rng", type=int, metavar="BYTES", help="bytes del RNG de hardware")
    what.add_argument("--ldr", type=int, metavar="N", help="lecturas del ADC en GPIO34")
    ap.add_argument("--delay-us", type=int, default=200, help="espera entre lecturas del LDR (como el firmware)")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    dev = Esp32(args.port)
    try:
        print("Placa:", dev.request("ES:PING", "ES:PONG"))
        start = time.monotonic()
        if args.rng:
            data = bytearray()
            while len(data) < args.rng:
                n = min(RNG_CHUNK, args.rng - len(data))
                data += bytes.fromhex(dev.request(f"ES:RNG {n}", "ES:RNG"))
                progress(len(data), args.rng, start)
            args.out.write_bytes(bytes(data))
        else:
            samples: list[int] = []
            while len(samples) < args.ldr:
                n = min(LDR_CHUNK, args.ldr - len(samples))
                samples += [int(v) for v in dev.request(f"ES:LDR {n} {args.delay_us}", "ES:LDR").split(",")]
                progress(len(samples), args.ldr, start)
            args.out.write_text("\n".join(map(str, samples)) + "\n", encoding="ascii")
        print(f"\n  guardado en {args.out}")
    finally:
        dev.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

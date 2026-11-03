#!/usr/bin/env python3
"""Generates the data and figures of docs/estudio (study guide and slides).

Runs the NIST SP 800-22 subset on reference generators, and on the real ESP32
capture when docs/estudio/data/esp32_rng.bin exists (capture_esp32.py).

    python docs/estudio/generar_figuras.py
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools" / "entropy_analysis"))
import nist_sp800_22 as nist  # noqa: E402

IMG = HERE / "img"
DATA = HERE / "data"
N_BYTES = 1_000_000
SEQ_BITS = 100_000

BG, FG, CYAN, GREEN, AMBER, RED, GREY = "#0b1220", "#e6edf3", "#00e5ff", "#00ff9c", "#ffc857", "#ff5370", "#8b98a9"


def lcg_low_bytes(n: int) -> bytes:
    """Classic weak PRNG: low byte of an LCG mod 2^32 (low bits have short periods)."""
    x, out = 12345, bytearray(n)
    for i in range(n):
        x = (1103515245 * x + 12345) & 0xFFFFFFFF
        out[i] = x & 0xFF
    return bytes(out)


def biased(n: int) -> bytes:
    rng = np.random.default_rng(7)
    return np.packbits((rng.random(8 * n) < 0.52).astype(np.uint8)).tobytes()


def sha256_counter(n: int) -> bytes:
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hashlib.sha256(i.to_bytes(8, "big")).digest()
        i += 1
    return bytes(out[:n])


def generators() -> list[tuple[str, str, bytes]]:
    gens = [
        ("os.urandom", "CSPRNG del sistema operativo (sembrado con ruido fisico)", os.urandom(N_BYTES)),
        ("Mersenne Twister", "PRNG determinista (random de Python, semilla 2026)", random.Random(2026).randbytes(N_BYTES)),
        ("SHA-256(contador)", "Determinista y 100% predecible", sha256_counter(N_BYTES)),
        ("LCG byte bajo", "PRNG debil tipo rand() de C", lcg_low_bytes(N_BYTES)),
        ("Sesgado 52% unos", "Fuente fisica mal calibrada", biased(N_BYTES)),
    ]
    real = DATA / "esp32_rng.bin"
    if real.exists():
        gens.insert(0, ("ESP32 RNG (real)", "esp_random() con SAR ADC, capturado por USB", real.read_bytes()))
    return gens


def run_nist() -> list[dict]:
    rows = []
    for name, desc, data in generators():
        bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
        rep = nist.run_suite(bits, SEQ_BITS)
        passed = sum(r["proportion_ok"] and r["uniformity_ok"] for r in rep["results"])
        rows.append({"name": name, "description": desc, "bytes": len(data), "passed": passed,
                     "total": len(rep["results"]), "report": rep})
        print(f"{name:<22} {passed}/{len(rep['results'])} pruebas")
    (DATA / "nist_resultados.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    return rows


def style(ax):
    ax.set_facecolor(BG)
    for s in ax.spines.values():
        s.set_color(GREY)
    ax.tick_params(colors=FG)
    ax.xaxis.label.set_color(FG)
    ax.yaxis.label.set_color(FG)
    ax.title.set_color(FG)


def fig_bitmaps(gens):
    picks = [g for g in gens if g[0] in ("os.urandom", "Mersenne Twister", "LCG byte bajo", "Sesgado 52% unos")]
    if gens[0][0].startswith("ESP32"):
        picks.insert(0, gens[0])
    fig, axes = plt.subplots(1, len(picks), figsize=(3.2 * len(picks), 3.6), facecolor=BG)
    for ax, (name, _, data) in zip(axes, picks):
        bits = np.unpackbits(np.frombuffer(data[:128 * 128 // 8 * 4], dtype=np.uint8))[: 256 * 256]
        ax.imshow(bits.reshape(256, 256), cmap="gray", interpolation="nearest")
        ax.set_title(name, color=FG, fontsize=11)
        ax.axis("off")
    fig.suptitle("Cada pixel es un bit (blanco = 1). Un PRNG debil deja patrones visibles", color=FG, fontsize=12)
    fig.tight_layout()
    fig.savefig(IMG / "bitmaps.png", dpi=150, facecolor=BG)
    plt.close(fig)


def fig_histograms(gens):
    picks = [g for g in gens if g[0] in ("os.urandom", "Sesgado 52% unos")]
    if gens[0][0].startswith("ESP32"):
        picks.insert(0, gens[0])
    fig, axes = plt.subplots(1, len(picks), figsize=(4.4 * len(picks), 3.2), facecolor=BG)
    for ax, (name, _, data) in zip(axes, picks):
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        style(ax)
        ax.bar(range(256), counts, width=1.0, color=CYAN)
        ax.axhline(len(data) / 256, color=AMBER, lw=1, ls="--")
        ax.set_title(f"{name}: frecuencia de cada byte", fontsize=10)
        ax.set_xlim(0, 255)
    fig.tight_layout()
    fig.savefig(IMG / "histogramas.png", dpi=150, facecolor=BG)
    plt.close(fig)


def fig_nist_table(rows):
    fig, ax = plt.subplots(figsize=(11, 0.6 + 0.48 * len(rows)), facecolor=BG)
    ax.axis("off")
    tests = [r["test"] for r in rows[0]["report"]["results"]]
    short = ["Monobit", "Bloques", "Rachas", "Racha max", "Rango", "DFT", "Serial", "ApEn", "CuSum ->", "CuSum <-"]
    cell, colors = [], []
    for r in rows:
        line, col = [], []
        for t in r["report"]["results"]:
            ok = t["proportion_ok"] and t["uniformity_ok"]
            line.append("PASA" if ok else "FALLA")
            col.append("#0f3d2e" if ok else "#4a1420")
        cell.append([r["name"]] + line + [f"{r['passed']}/{r['total']}"])
        colors.append(["#152033"] + col + ["#152033"])
    table = ax.table(cellText=cell, cellColours=colors, colLabels=["Generador"] + short[: len(tests)] + ["Total"],
                     loc="center", cellLoc="center")
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1, 1.5)
    for (i, j), c in table.get_celld().items():
        c.set_edgecolor(GREY)
        c.get_text().set_color(FG)
        if i == 0:
            c.set_facecolor("#1d2b44")
            c.get_text().set_weight("bold")
    table.auto_set_column_width([0])
    fig.tight_layout()
    fig.savefig(IMG / "nist_tabla.png", dpi=170, facecolor=BG)
    plt.close(fig)


def box(ax, x, y, w, h, text, color, fs=10):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08",
                                fc="#152033", ec=color, lw=2))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", color=FG, fontsize=fs)


def arrow(ax, x1, y1, x2, y2, color=GREY):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=14, color=color, lw=1.6))


def fig_rng_hardware():
    fig, ax = plt.subplots(figsize=(11, 4.6), facecolor=BG)
    ax.set_xlim(0, 11)
    ax.set_ylim(0, 4.6)
    ax.axis("off")
    box(ax, 0.2, 3.1, 2.6, 1.1, "SAR ADC\nruido termico\n(bootloader_random_enable)", GREEN, 9)
    box(ax, 0.2, 1.6, 2.6, 1.1, "ADC alta velocidad\n(solo con WiFi/BT)", GREY, 9)
    box(ax, 0.2, 0.1, 2.6, 1.1, "RC_FAST_CLK 8 MHz\nvs reloj APB 80 MHz\n(jitter asincronico)", AMBER, 9)
    box(ax, 3.6, 1.6, 1.0, 1.1, "XOR", CYAN, 12)
    box(ax, 5.4, 1.4, 2.3, 1.5, "Estado interno\ndel RNG\n(+2 bits de ruido\npor ciclo)", CYAN, 9)
    box(ax, 8.5, 1.6, 2.3, 1.1, "RNG_DATA_REG\n0x3FF75144\n32 bits", GREEN, 9)
    arrow(ax, 2.8, 3.65, 3.6, 2.4)
    arrow(ax, 2.8, 2.15, 3.6, 2.15)
    arrow(ax, 2.8, 0.65, 3.6, 1.9)
    arrow(ax, 4.6, 2.15, 5.4, 2.15)
    arrow(ax, 7.7, 2.15, 8.5, 2.15)
    ax.text(5.5, 4.35, "RNG de hardware del ESP32 (TRM v5.9, cap. 18)", color=FG, fontsize=13, ha="center", weight="bold")
    ax.text(9.65, 1.2, "esp_random() lee aca\n(max. 500 kHz con SAR ADC)", color=AMBER, fontsize=8.5, ha="center")
    fig.savefig(IMG / "rng_hardware.png", dpi=160, facecolor=BG, bbox_inches="tight")
    plt.close(fig)


def fig_pipeline():
    fig, ax = plt.subplots(figsize=(12, 3.4), facecolor=BG)
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 3.4)
    ax.axis("off")
    box(ax, 0.1, 1.0, 2.3, 1.4, "RNG hardware\n(ruido del SAR ADC)\n64 bytes = 512 bits", GREEN, 9)
    box(ax, 3.1, 1.0, 2.6, 1.4, "SHA-256(\"EntropySigner/\nentropy-pool/v2\" ||\nRNG)\n744 bits de entrada", CYAN, 8.5)
    box(ax, 6.4, 1.2, 1.6, 1.0, "Entropia\n256 bits", GREEN, 9)
    box(ax, 8.6, 1.2, 1.5, 1.0, "BIP-39\n24 palabras", CYAN, 9)
    box(ax, 10.6, 1.2, 1.3, 1.0, "BIP-32/44\nBTC / ETH", CYAN, 9)
    arrow(ax, 2.4, 1.7, 3.1, 1.7)
    arrow(ax, 5.7, 1.7, 6.4, 1.7)
    arrow(ax, 8.0, 1.7, 8.6, 1.7)
    arrow(ax, 10.1, 1.7, 10.6, 1.7)
    fig.savefig(IMG / "pipeline.png", dpi=160, facecolor=BG, bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    IMG.mkdir(exist_ok=True)
    DATA.mkdir(exist_ok=True)
    gens = generators()
    rows = run_nist()
    fig_bitmaps(gens)
    fig_histograms(gens)
    fig_nist_table(rows)
    fig_rng_hardware()
    fig_pipeline()
    print("figuras en", IMG)


if __name__ == "__main__":
    main()

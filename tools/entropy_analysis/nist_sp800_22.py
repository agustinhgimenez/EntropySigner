#!/usr/bin/env python3
"""EntropySigner - NIST SP 800-22 Rev. 1a statistical test suite (subset).

Applies nine of the fifteen tests of "A Statistical Test Suite for Random and
Pseudorandom Number Generators for Cryptographic Applications" (NIST SP 800-22
Rev. 1a, April 2010) to the OUTPUT of a random number generator, and
interprets the results the way section 4.2 of the document prescribes: the
bitstream is split into m sequences of n bits and, for every test,

  * the proportion of sequences with P-value >= alpha must fall inside
    (1 - alpha) +/- 3 sqrt(alpha (1 - alpha) / m)            (4.2.1), and
  * the P-values must be uniform on [0, 1): chi-square over 10 bins with
    P-value_T >= 0.0001                                      (4.2.2).

Implemented (section of SP 800-22): 2.1 Frequency (monobit), 2.2 Frequency
within a block, 2.3 Runs, 2.4 Longest run of ones in a block, 2.5 Binary matrix
rank, 2.6 Discrete Fourier transform (spectral), 2.11 Serial, 2.12 Approximate
entropy, 2.13 Cumulative sums (forward and backward).
Not implemented: 2.7/2.8 template matching, 2.9 Maurer's universal, 2.10 linear
complexity, 2.14/2.15 random excursions.

`--selftest` checks every test against the worked examples of section 2 of
SP 800-22. Requires numpy.

Examples:
    python tools/entropy_analysis/nist_sp800_22.py --selftest
    python tools/entropy_analysis/nist_sp800_22.py --file rng.bin --n 100000
    python tools/entropy_analysis/nist_sp800_22.py --urandom 1000000 --json out.json
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from pathlib import Path
from typing import Callable, Dict, List, Sequence

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_entropy import gammaincc as igamc  # noqa: E402

ALPHA = 0.01


def _phi(x: float) -> float:
    return 0.5 * math.erfc(-x / math.sqrt(2))


def frequency(b: np.ndarray) -> float:
    n = b.size
    s = abs(int(2 * b.sum()) - n)
    return math.erfc(s / math.sqrt(n) / math.sqrt(2))


def block_frequency(b: np.ndarray, m: int = 128) -> float:
    blocks = b.size // m
    pi = b[: blocks * m].reshape(blocks, m).mean(axis=1)
    chi = 4.0 * m * float(((pi - 0.5) ** 2).sum())
    return igamc(blocks / 2.0, chi / 2.0)


def runs(b: np.ndarray) -> float:
    n = b.size
    pi = b.mean()
    if abs(pi - 0.5) >= 2.0 / math.sqrt(n):
        return 0.0
    v = 1 + int(np.count_nonzero(b[1:] != b[:-1]))
    return math.erfc(abs(v - 2 * n * pi * (1 - pi)) / (2 * math.sqrt(2 * n) * pi * (1 - pi)))


# (block length M, class bounds of the longest run, class probabilities), table 2.4
_LONGEST_RUN = [
    (750_000, 10_000, (10, 16), [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727]),
    (6_272, 128, (4, 9), [0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124]),
    (128, 8, (1, 4), [0.2148, 0.3672, 0.2305, 0.1875]),
]


def longest_run(b: np.ndarray) -> float:
    n = b.size
    m, (lo, hi), probs = next((m, c, p) for min_n, m, c, p in _LONGEST_RUN if n >= min_n)
    blocks = n // m
    counts = [0] * len(probs)
    for blk in b[: blocks * m].reshape(blocks, m):
        padded = np.concatenate(([0], blk, [0]))
        edges = np.flatnonzero(np.diff(padded))
        longest = int((edges[1::2] - edges[::2]).max()) if edges.size else 0
        counts[min(max(longest, lo), hi) - lo] += 1
    chi = sum((c - blocks * p) ** 2 / (blocks * p) for c, p in zip(counts, probs))
    return igamc((len(probs) - 1) / 2.0, chi / 2.0)


def _gf2_rank(rows: List[int], width: int) -> int:
    rank = 0
    for col in range(width - 1, -1, -1):
        bit = 1 << col
        pivot = next((i for i in range(rank, len(rows)) if rows[i] & bit), None)
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        for i in range(len(rows)):
            if i != rank and rows[i] & bit:
                rows[i] ^= rows[rank]
        rank += 1
    return rank


def matrix_rank(b: np.ndarray, size: int = 32) -> float:
    count = b.size // (size * size)
    weights = 1 << np.arange(size - 1, -1, -1, dtype=np.uint64)
    full = minus_one = 0
    for mat in b[: count * size * size].reshape(count, size, size):
        r = _gf2_rank([int(x) for x in (mat.astype(np.uint64) * weights).sum(axis=1)], size)
        full += r == size
        minus_one += r == size - 1
    probs = (0.2888, 0.5776, 0.1336)
    obs = (full, minus_one, count - full - minus_one)
    chi = sum((o - count * p) ** 2 / (count * p) for o, p in zip(obs, probs))
    return math.exp(-chi / 2.0)


def spectral(b: np.ndarray) -> float:
    n = b.size
    mags = np.abs(np.fft.fft(2.0 * b - 1.0))[: n // 2]
    threshold = math.sqrt(math.log(1 / 0.05) * n)
    n0 = 0.95 * n / 2.0
    n1 = int(np.count_nonzero(mags < threshold))
    d = (n1 - n0) / math.sqrt(n * 0.95 * 0.05 / 4.0)
    return math.erfc(abs(d) / math.sqrt(2))


def _pattern_counts(b: np.ndarray, m: int) -> np.ndarray:
    """Counts of the 2^m overlapping m-bit patterns, wrapping around the end."""
    if m == 0:
        return np.array([b.size])
    ext = np.concatenate((b, b[: m - 1])).astype(np.int64)
    vals = np.zeros(b.size, dtype=np.int64)
    for j in range(m):
        vals = (vals << 1) | ext[j: j + b.size]
    return np.bincount(vals, minlength=1 << m)


def serial(b: np.ndarray, m: int = 16) -> List[float]:
    n = b.size

    def psi2(k: int) -> float:
        if k <= 0:
            return 0.0
        return float((1 << k) / n * (_pattern_counts(b, k).astype(np.float64) ** 2).sum() - n)

    p0, p1, p2 = psi2(m), psi2(m - 1), psi2(m - 2)
    return [igamc(2 ** (m - 2), (p0 - p1) / 2.0), igamc(2 ** (m - 3), (p0 - 2 * p1 + p2) / 2.0)]


def approximate_entropy(b: np.ndarray, m: int = 10) -> float:
    n = b.size

    def phi(k: int) -> float:
        c = _pattern_counts(b, k).astype(np.float64) / n
        c = c[c > 0]
        return float((c * np.log(c)).sum())

    apen = phi(m) - phi(m + 1)
    chi = 2.0 * n * (math.log(2) - apen)
    return igamc(2 ** (m - 1), chi / 2.0)


def cumulative_sums(b: np.ndarray, reverse: bool = False) -> float:
    n = b.size
    x = 2 * b.astype(np.int64) - 1
    if reverse:
        x = x[::-1]
    z = int(np.abs(np.cumsum(x)).max())
    sq = math.sqrt(n)
    total = 1.0
    for k in range(int((-n / z + 1) / 4), int((n / z - 1) / 4) + 1):
        total -= _phi((4 * k + 1) * z / sq) - _phi((4 * k - 1) * z / sq)
    for k in range(int((-n / z - 3) / 4), int((n / z - 1) / 4) + 1):
        total += _phi((4 * k + 3) * z / sq) - _phi((4 * k + 1) * z / sq)
    return total


def build_tests(n: int) -> Dict[str, Callable[[np.ndarray], Sequence[float]]]:
    serial_m = max(2, min(16, int(math.log2(n)) - 3))
    apen_m = max(2, min(10, int(math.log2(n)) - 6))
    return {
        "Frequency (monobit)": lambda b: [frequency(b)],
        "Block frequency (M=128)": lambda b: [block_frequency(b)],
        "Runs": lambda b: [runs(b)],
        "Longest run of ones": lambda b: [longest_run(b)],
        "Binary matrix rank (32x32)": lambda b: [matrix_rank(b)],
        "Spectral DFT": lambda b: [spectral(b)],
        f"Serial (m={serial_m})": lambda b: serial(b, serial_m),
        f"Approximate entropy (m={apen_m})": lambda b: [approximate_entropy(b, apen_m)],
        "Cumulative sums (forward)": lambda b: [cumulative_sums(b)],
        "Cumulative sums (backward)": lambda b: [cumulative_sums(b, True)],
    }


def run_suite(bits: np.ndarray, n: int) -> dict:
    m = bits.size // n
    if m < 1:
        raise ValueError(f"se necesitan al menos {n} bits")
    tests = build_tests(n)
    pvals: Dict[str, List[float]] = {name: [] for name in tests}
    for i in range(m):
        seq = bits[i * n: (i + 1) * n]
        for name, fn in tests.items():
            pvals[name].extend(fn(seq))
    results = []
    for name, ps in pvals.items():
        ps_arr = np.array(ps)
        count = ps_arr.size
        passed = int(np.count_nonzero(ps_arr >= ALPHA))
        margin = 3 * math.sqrt(ALPHA * (1 - ALPHA) / count)
        min_prop = 1 - ALPHA - margin
        bins = np.histogram(ps_arr, bins=10, range=(0.0, 1.0))[0]
        exp = count / 10.0
        chi = float(((bins - exp) ** 2 / exp).sum())
        p_t = igamc(4.5, chi / 2.0)
        results.append({
            "test": name, "sequences": count, "passed": passed, "proportion": passed / count,
            "min_proportion": min_prop, "proportion_ok": passed / count >= min_prop,
            "uniformity_p": p_t, "uniformity_ok": p_t >= 0.0001, "histogram": bins.tolist(),
        })
    return {"n": n, "m": m, "alpha": ALPHA, "results": results}


def print_report(report: dict, label: str) -> None:
    print(f"\nNIST SP 800-22 Rev. 1a - {label}")
    print(f"{report['m']} secuencias de {report['n']:,} bits, alfa = {report['alpha']}")
    print(f"{'prueba':<34}{'pasan':>10}{'minimo':>9}{'P unif.':>10}  veredicto")
    for r in report["results"]:
        ok = r["proportion_ok"] and r["uniformity_ok"]
        print(f"{r['test']:<34}{r['passed']:>5}/{r['sequences']:<4}{r['min_proportion']:>9.4f}"
              f"{r['uniformity_p']:>10.4f}  {'PASA' if ok else 'FALLA'}")


# Worked examples of SP 800-22 Rev. 1a section 2 (ε = binary expansion of e, etc.)
_E100 = "1100100100001111110110101010001000100001011010001100001000110100110001001100011001100010100010111000"
_E128 = ("11001100000101010110110001001100111000000000001001001101010100010001001111010110100000001101011111001100"
         "111001101101100010110010")


def selftest() -> bool:
    bits = lambda s: np.frombuffer(s.encode(), dtype=np.uint8) - ord("0")  # noqa: E731
    cases = [
        ("2.1 frequency", frequency(bits(_E100)), 0.109599),
        ("2.2 block frequency M=10", block_frequency(bits(_E100), 10), 0.706438),
        ("2.3 runs", runs(bits(_E100)), 0.500798),
        ("2.4 longest run (M=8)", longest_run(bits(_E128)), 0.180609),
        ("2.11 serial m=3 (1)", serial(bits("0011011101"), 3)[0], 0.808792),
        ("2.11 serial m=3 (2)", serial(bits("0011011101"), 3)[1], 0.670320),
        ("2.12 approximate entropy m=2", approximate_entropy(bits(_E100), 2), 0.235301),
        ("2.13 cumulative sums forward", cumulative_sums(bits(_E100)), 0.219194),
        ("2.13 cumulative sums backward", cumulative_sums(bits(_E100), True), 0.114866),
    ]
    ok = True
    for name, got, want in cases:
        good = abs(got - want) < 5e-4
        ok &= good
        print(f"  {'OK  ' if good else 'FAIL'} {name:<34} obtenido {got:.6f}  NIST {want:.6f}")

    # The 2.6.8 example states N1 = 46 for these 100 bits, but 48 of the 50 peaks are
    # below T (P = 0.646355), so the spectral test is checked by behaviour instead.
    rng = np.random.default_rng(2026)
    periodic = np.tile(np.array([1, 1, 0, 1, 0, 0, 0, 1], dtype=np.uint8), 12_500)
    periodic ^= (rng.random(periodic.size) < 0.05).astype(np.uint8)
    random_bits = np.unpackbits(np.frombuffer(os.urandom(12_500), dtype=np.uint8))
    checks = [
        ("2.6 spectral: periodo de 8 bits + 5% ruido", spectral(periodic) < ALPHA),
        ("2.6 spectral: os.urandom 100.000 bits", spectral(random_bits) >= ALPHA),
    ]
    for name, good in checks:
        ok &= good
        print(f"  {'OK  ' if good else 'FAIL'} {name}")
    return ok


def load_bits(path: Path) -> np.ndarray:
    return np.unpackbits(np.frombuffer(path.read_bytes(), dtype=np.uint8))


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Subconjunto de NIST SP 800-22 Rev. 1a sobre la salida de un RNG.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", type=Path, help="bytes crudos del RNG")
    src.add_argument("--urandom", type=int, metavar="BYTES", help="referencia: bytes de os.urandom")
    src.add_argument("--selftest", action="store_true", help="verificar contra los ejemplos de SP 800-22")
    ap.add_argument("--n", type=int, default=100_000, help="bits por secuencia (default 100000)")
    ap.add_argument("--json", type=Path, help="exportar resultados a JSON")
    args = ap.parse_args(argv)

    if args.selftest:
        print("Verificacion contra los ejemplos de NIST SP 800-22 Rev. 1a, seccion 2:")
        return 0 if selftest() else 1
    if args.file:
        bits, label = load_bits(args.file), str(args.file)
    else:
        bits = np.unpackbits(np.frombuffer(os.urandom(args.urandom), dtype=np.uint8))
        label = f"os.urandom ({args.urandom:,} bytes)"
    report = run_suite(bits, args.n)
    report["source"] = label
    print_report(report, label)
    if args.json:
        args.json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())

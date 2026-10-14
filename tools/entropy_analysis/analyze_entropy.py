#!/usr/bin/env python3
"""EntropySigner - statistical entropy analysis of the physical sources (Paso 17).

Analyzes raw samples of the LDR (12-bit ADC readings) or of the hardware RNG
and estimates how much min-entropy they carry, following NIST SP 800-90B
("Recommendation for the Entropy Sources Used for Random Bit Generation",
January 2018).

Input modes
-----------
  --file PATH        samples captured earlier (raw bytes, 16-bit words or text)
  --synthetic KIND   reproducible simulated sources for demos / testing when no
                     hardware is connected (trng, ldr, ldr-attack,
                     sha256-counter, or all)
  --serial PORT      live capture over USB-UART (needs the optional pyserial)

Metrics
-------
  * Min-entropy, SP 800-90B 6.3.1 Most Common Value and 6.3.8 Lag Prediction
    estimates (on the symbols) and 6.3.2 Collision estimate (on the bitstring,
    as the standard requires for that binary-only estimator), combined as in
    3.1.3:  H_I = min(H_original, n * H_bitstring)
  * Shannon entropy H = -sum p_i log2 p_i (plug-in and Miller-Madow).
  * Chi-square goodness-of-fit test for uniformity.
  * Autocorrelation at lags 1..10 (periodicity of ambient light, mains flicker).
  * SP 800-90B 4.4 continuous health tests (Repetition Count, Adaptive
    Proportion) against a claimed entropy.
  * Entropy at the output of the firmware's SHA-256 conditioner, using the
    vetted-conditioning-component formula of SP 800-90B 3.1.5.1.2.

Scope and honesty
-----------------
Only three of the ten non-IID estimators of SP 800-90B section 6.3 are
implemented here; the result is an educational upper bound, not a validation.
A formal assessment must run NIST's reference tool (ea_non_iid from
github.com/usnistgov/SP800-90B_EntropyAssessment) on >= 1,000,000 raw samples.
Statistical tests can disprove randomness, never prove it: the sha256-counter
source shows a zero-entropy sequence that passes every test below.

Only the Python 3.8+ standard library is required.

Examples:
    python tools/entropy_analysis/analyze_entropy.py --synthetic all
    python tools/entropy_analysis/analyze_entropy.py --synthetic ldr -n 1000000
    python tools/entropy_analysis/analyze_entropy.py --file ldr.txt --bits 12
    python tools/entropy_analysis/analyze_entropy.py --file rng.bin --format u8
    python tools/entropy_analysis/analyze_entropy.py --serial COM5 --count 200000 --save ldr.txt
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import operator
import os
import random
import re
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

Z_99 = 2.576  # two-sided 99% normal quantile, the confidence level used throughout SP 800-90B
NIST_MIN_SAMPLES = 1_000_000  # SP 800-90B 3.1.1
HEALTH_ALPHA_LOG2 = 20  # false-positive rate alpha = 2^-20 (SP 800-90B 4.4 recommends 2^-20 .. 2^-40)
MAX_LAG = 10

# Firmware conditioning (src/entropy/entropy_pool.cpp):
#   SHA-256(domain tag || HW RNG 32 B || include_ldr flag 1 B || 128 LDR samples x uint16)
FW_DOMAIN_TAG = b"EntropySigner/entropy-pool/v1"
FW_RNG_BYTES = 32
FW_LDR_SAMPLES = 128
FW_N_IN_BITS = 8 * (len(FW_DOMAIN_TAG) + FW_RNG_BYTES + 1 + 2 * FW_LDR_SAMPLES)
SHA256_BITS = 256


# ---------------------------------------------------------------------------
# Data sources
# ---------------------------------------------------------------------------


@dataclass
class Dataset:
    name: str
    description: str
    samples: List[int]
    bits: int  # bits per sample (alphabet size 2^bits)


def load_file(path: Path, fmt: str, bits: Optional[int]) -> Dataset:
    if fmt == "auto":
        fmt = "text" if path.suffix.lower() in (".txt", ".csv", ".log", ".dat") else "u8"
    raw = path.read_bytes()
    if fmt == "u8":
        samples = list(raw)
        width = 8
    elif fmt in ("u16le", "u16be"):
        if len(raw) % 2:
            raise ValueError("archivo de 16 bits con cantidad impar de bytes")
        order = "little" if fmt == "u16le" else "big"
        samples = [int.from_bytes(raw[i:i + 2], order) for i in range(0, len(raw), 2)]
        width = 16
    elif fmt == "text":
        samples = parse_text_samples(raw.decode("utf-8", errors="replace").splitlines())
        width = max(1, max(samples).bit_length()) if samples else 1
    else:
        raise ValueError(f"formato desconocido: {fmt}")
    bits = bits or width
    if samples and max(samples) >= 1 << bits:
        raise ValueError(f"hay muestras >= 2^{bits}; indique --bits correcto")
    return Dataset(path.name, f"archivo {path} (formato {fmt})", samples, bits)


_PREFIX = re.compile(r"^\s*[A-Za-z_]+\s*[:=]")


def parse_text_samples(lines: Sequence[str]) -> List[int]:
    """Integers separated by spaces, commas or semicolons; an optional 'LDR:' style
    prefix is accepted and any other line (firmware logs like '[ES] BOOT OK') is skipped."""
    samples: List[int] = []
    for line in lines:
        body = _PREFIX.sub("", line, count=1)
        if body.strip() and re.fullmatch(r"[\d\s,;]+", body):
            samples.extend(int(tok) for tok in re.split(r"[\s,;]+", body.strip()) if tok)
    return samples


def capture_serial(port: str, baud: int, count: int, timeout_s: float) -> List[int]:
    try:
        import serial  # type: ignore
    except ImportError:
        sys.exit("Error: la captura por puerto serie requiere pyserial (pip install pyserial).")
    samples: List[int] = []
    deadline = time.monotonic() + timeout_s
    with serial.Serial(port, baud, timeout=1) as link:
        print(f"Capturando {count} muestras desde {port} @ {baud} baud (Ctrl+C para cortar)...")
        try:
            while len(samples) < count and time.monotonic() < deadline:
                line = link.readline().decode("ascii", errors="replace")
                samples.extend(parse_text_samples([line]))
                if len(samples) % 10_000 < 8:
                    print(f"\r  {len(samples)} / {count}", end="", flush=True)
        except KeyboardInterrupt:
            pass
    print(f"\r  {len(samples)} muestras capturadas.")
    return samples[:count]


def synth_trng(n: int, _rng: random.Random) -> Dataset:
    data = os.urandom(n)
    return Dataset("trng", "Referencia ideal: os.urandom (CSPRNG del SO), 8 bits/muestra", list(data), 8)


def synth_ldr(n: int, rng: random.Random, attack: bool = False) -> Dataset:
    """Physical model of the LDR divider read by the 12-bit SAR ADC.

    Sample period ~210 us (200 us delay in collectLdrSamples() + conversion).
    Ambient light = slow random-walk drift + 100 Hz flicker (lamps on 50 Hz
    mains, Argentina) + Gaussian ADC/thermal noise of a few LSB.
    attack=True models a flashlight pressed against the sensor: the divider
    saturates and the ADC sticks at full scale.
    """
    ts = 210e-6
    level = 4095.0 if attack else 1800.0
    flicker = 3.0 if attack else 25.0
    noise_sigma = 0.35 if attack else 2.5
    phase = rng.uniform(0, 2 * math.pi)
    samples = []
    for i in range(n):
        if not attack:
            level = min(3800.0, max(300.0, level + rng.gauss(0, 0.05)))
        v = level + flicker * math.sin(2 * math.pi * 100.0 * i * ts + phase) + rng.gauss(0, noise_sigma)
        samples.append(min(4095, max(0, int(round(v)))))
    if attack:
        desc = "Simulacion LDR bajo ataque: linterna satura el divisor, ADC pegado en 4095"
        return Dataset("ldr-attack", desc, samples, 12)
    desc = "Simulacion LDR: ADC 12 bits, deriva lenta + parpadeo 100 Hz (red 50 Hz) + ruido ~2.5 LSB"
    return Dataset("ldr", desc, samples, 12)


def synth_sha256_counter(n: int, _rng: random.Random) -> Dataset:
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(counter.to_bytes(8, "big")).digest()
        counter += 1
    desc = "SHA-256(contador): salida 'perfecta' estadisticamente pero con ~0 bits de entropia real"
    return Dataset("sha256-counter", desc, list(out[:n]), 8)


SYNTHETIC = {
    "trng": synth_trng,
    "ldr": lambda n, r: synth_ldr(n, r, attack=False),
    "ldr-attack": lambda n, r: synth_ldr(n, r, attack=True),
    "sha256-counter": synth_sha256_counter,
}


# ---------------------------------------------------------------------------
# Statistics helpers
# ---------------------------------------------------------------------------


def to_bitstring(samples: Sequence[int], bits: int) -> List[int]:
    """Each sample expanded MSB first, as SP 800-90B does for binary-only estimators."""
    shifts = range(bits - 1, -1, -1)
    return [(s >> k) & 1 for s in samples for k in shifts]


def gammaincc(a: float, x: float) -> float:
    """Regularized upper incomplete gamma Q(a, x) (Numerical Recipes 6.2)."""
    if x <= 0:
        return 1.0
    log_pre = -x + a * math.log(x) - math.lgamma(a)
    if x < a + 1:  # series for P(a, x)
        term = total = 1.0 / a
        ap = a
        for _ in range(100_000):
            ap += 1
            term *= x / ap
            total += term
            if abs(term) < abs(total) * 1e-15:
                break
        return max(0.0, 1.0 - total * math.exp(log_pre))
    tiny = 1e-300  # continued fraction for Q(a, x), modified Lentz
    b = x + 1 - a
    c = 1 / tiny
    d = 1 / b
    h = d
    for i in range(1, 100_000):
        an = -i * (i - a)
        b += 2
        d = an * d + b
        d = tiny if abs(d) < tiny else d
        c = b + an / c
        c = tiny if abs(c) < tiny else c
        d = 1 / d
        delta = d * c
        h *= delta
        if abs(delta - 1) < 1e-15:
            break
    return min(1.0, math.exp(log_pre) * h)


def binom_critical(n: int, p: float, log2_alpha: int) -> int:
    """Smallest k with P(X <= k) >= 1 - alpha for X ~ Bin(n, p) (Excel CRITBINOM)."""
    target = 1.0 - 2.0 ** -log2_alpha
    log_p, log_q = math.log(p), math.log1p(-p) if p < 1 else -math.inf
    cdf = 0.0
    for k in range(n + 1):
        log_pmf = math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1) + k * log_p
        log_pmf += (n - k) * log_q if n - k else 0.0
        cdf += math.exp(log_pmf)
        if cdf >= target:
            return k
    return n


# ---------------------------------------------------------------------------
# Estimators and tests
# ---------------------------------------------------------------------------


@dataclass
class McvResult:
    p_hat: float
    p_upper: float
    min_entropy: float
    mode: int


def mcv_estimate(samples: Sequence[int]) -> McvResult:
    """SP 800-90B 6.3.1: p_u = min(1, p_hat + 2.576 sqrt(p_hat (1 - p_hat) / (L - 1)))."""
    counts = Counter(samples)
    mode, top = counts.most_common(1)[0]
    n = len(samples)
    p_hat = top / n
    p_u = min(1.0, p_hat + Z_99 * math.sqrt(p_hat * (1 - p_hat) / (n - 1)))
    return McvResult(p_hat, p_u, -math.log2(p_u), mode)


def _p_local(n: int, r: int) -> float:
    """Upper bound on the predictor's success probability from its longest run of
    correct predictions (r = longest run + 1), SP 800-90B 6.3.7-6.3.10:
        0.99 = (1 - p x) / ((r + 1 - r x) q) * x^-(N + 1),  q = 1 - p,
    with x the fixed point of x = 1 + q p^r x^(r + 1) (10 iterations from x = 1).
    Solved for p by bisection in the log domain (x^(N + 1) overflows otherwise)."""

    def log_rhs(p: float) -> float:
        q = 1.0 - p
        x = 1.0
        for _ in range(10):
            x = 1.0 + q * p ** r * x ** (r + 1)
        num = 1.0 - p * x
        den = (r + 1.0 - r * x) * q
        if num <= 0 or den <= 0:
            return -math.inf
        return math.log(num / den) - (n + 1) * math.log(x)

    target = math.log(0.99)
    lo, hi = 1e-12, 1.0 - 1e-12
    if log_rhs(lo) < target:
        return lo
    for _ in range(200):  # log_rhs decreases as p grows
        mid = (lo + hi) / 2
        if log_rhs(mid) > target:
            lo = mid
        else:
            hi = mid
    return hi


@dataclass
class LagResult:
    correct: int
    predictions: int
    p_global: float
    p_local: float
    longest_run: int
    min_entropy: float


def lag_prediction_estimate(samples: Sequence[int], bits: int, depth: int = 128) -> LagResult:
    """SP 800-90B 6.3.8: D = 128 predictors, predictor d guesses s_i = s_(i-d);
    the prediction used is that of the predictor with the best score so far.
    Unlike MCV it captures sequential dependence (drift, periodicity).
    Only the lags that actually match are visited, so the cost grows with the
    number of repetitions instead of N * D."""
    scoreboard = [0] * (depth + 1)
    winner = 1
    recent: Dict[int, List[int]] = {}  # value -> positions within the last D samples
    correct = 0
    longest = run = 0
    n = len(samples)
    for i in range(n):
        x = samples[i]
        if i >= 1:
            if winner <= i and samples[i - winner] == x:
                correct += 1
                run += 1
                longest = max(longest, run)
            else:
                run = 0
        positions = recent.get(x)
        if positions:
            positions[:] = [p for p in positions if i - p <= depth]
            for p in reversed(positions):  # increasing d = i - p
                d = i - p
                scoreboard[d] += 1
                if scoreboard[d] >= scoreboard[winner]:
                    winner = d
            positions.append(i)
        else:
            recent[x] = [i]
    predictions = n - 1
    p_global = correct / predictions
    p_global_u = 0.0 if correct == 0 else min(
        1.0, p_global + Z_99 * math.sqrt(p_global * (1 - p_global) / (predictions - 1)))
    p_local = _p_local(predictions, longest + 1)
    p_max = max(p_global_u, p_local, 2.0 ** -bits)
    return LagResult(correct, predictions, p_global_u, p_local, longest, -math.log2(p_max))


@dataclass
class CollisionResult:
    collisions: int
    mean: float
    stdev: float
    mean_lower: float
    p: float
    min_entropy: float  # per bit


def _collision_expectation(p: float) -> float:
    # E[t] for a binary source with max probability p (SP 800-90B 6.3.2 step 7):
    #   p q^-2 (1 + (p^-1 - q^-1)/2) F(q) - p q^-1 (p^-1 - q^-1)/2,
    # with F(1/z) = Gamma(3, z) z^-3 e^z  =>  F(q) = q + 2 q^2 + 2 q^3.
    # For a binary alphabet this simplifies to 2 + 2 p q (t is 2 or 3).
    q = 1.0 - p
    f_q = q + 2 * q * q + 2 * q ** 3
    half_diff = 0.5 * (1 / p - 1 / q)
    return p / (q * q) * (1 + half_diff) * f_q - p / q * half_diff


def collision_estimate(bits: Sequence[int]) -> CollisionResult:
    """SP 800-90B 6.3.2 (binary inputs only). For a binary alphabet every
    collision time t is 2 (s_i == s_i+1) or 3 (the third bit must repeat one)."""
    times: List[int] = []
    i, n = 0, len(bits)
    while i + 1 < n:
        if bits[i] == bits[i + 1]:
            times.append(2)
            i += 2
        elif i + 2 < n:
            times.append(3)
            i += 3
        else:
            break
    v = len(times)
    mean = sum(times) / v
    stdev = math.sqrt(sum((t - mean) ** 2 for t in times) / (v - 1))
    lower = mean - Z_99 * stdev / math.sqrt(v)
    # E[t] decreases monotonically from 2.5 (p = 0.5) to 2 (p -> 1).
    if lower >= _collision_expectation(0.5):
        p = 0.5
    else:
        lo, hi = 0.5, 1.0 - 1e-12
        for _ in range(200):
            mid = (lo + hi) / 2
            if _collision_expectation(mid) > lower:
                lo = mid
            else:
                hi = mid
        p = (lo + hi) / 2
    return CollisionResult(v, mean, stdev, lower, p, -math.log2(p))


@dataclass
class ShannonResult:
    plugin: float
    miller_madow: float
    distinct: int


def shannon_entropy(samples: Sequence[int]) -> ShannonResult:
    n = len(samples)
    counts = Counter(samples)
    h = -sum(c / n * math.log2(c / n) for c in counts.values())
    # Miller-Madow bias correction: + (K - 1) / (2 N ln 2), K = observed symbols.
    return ShannonResult(h, h + (len(counts) - 1) / (2 * n * math.log(2)), len(counts))


@dataclass
class ChiSquareResult:
    label: str
    bins: int
    statistic: float
    dof: int
    p_value: float
    applicable: bool
    note: str = ""


def chi_square_uniform(samples: Sequence[int], bins: int, label: str) -> ChiSquareResult:
    n = len(samples)
    expected = n / bins
    if expected < 5:
        return ChiSquareResult(label, bins, float("nan"), bins - 1, float("nan"), False,
                               f"esperado {expected:.2f} < 5 por celda: requiere >= {5 * bins} muestras")
    counts = Counter(samples)
    stat = sum((counts.get(k, 0) - expected) ** 2 for k in range(bins)) / expected
    return ChiSquareResult(label, bins, stat, bins - 1, gammaincc((bins - 1) / 2, stat / 2), True)


def autocorrelation(samples: Sequence[int], max_lag: int = MAX_LAG) -> List[float]:
    n = len(samples)
    mean = sum(samples) / n
    centered = [s - mean for s in samples]
    var = sum(map(operator.mul, centered, centered))
    if var == 0:
        return [float("nan")] * max_lag
    return [sum(map(operator.mul, centered, centered[k:])) / var for k in range(1, max_lag + 1)]


@dataclass
class HealthResult:
    h_claim: float
    rct_cutoff: int
    rct_failures: int
    rct_longest_run: int
    apt_window: int
    apt_cutoff: int
    apt_failures: int
    apt_max_count: int


def health_tests(samples: Sequence[int], bits: int, h_claim: float) -> HealthResult:
    """SP 800-90B 4.4.1 Repetition Count and 4.4.2 Adaptive Proportion tests."""
    h = max(h_claim, 1e-3)
    rct_cutoff = 1 + math.ceil(HEALTH_ALPHA_LOG2 / h)
    rct_failures, longest, run, prev = 0, 1, 0, None
    for s in samples:
        run = run + 1 if s == prev else 1
        prev = s
        longest = max(longest, run)
        if run == rct_cutoff:
            rct_failures += 1
    window = 1024 if bits == 1 else 512
    apt_cutoff = 1 + binom_critical(window, min(1.0, 2.0 ** -h), HEALTH_ALPHA_LOG2)
    apt_failures, apt_max = 0, 0
    for start in range(0, len(samples) - window + 1, window):
        block = samples[start:start + window]
        count = block.count(block[0])
        apt_max = max(apt_max, count)
        if count >= apt_cutoff:
            apt_failures += 1
    return HealthResult(h_claim, rct_cutoff, rct_failures, longest, window, apt_cutoff, apt_failures, apt_max)


def conditioned_entropy(h_in: float, n_in: int = FW_N_IN_BITS, n_out: int = SHA256_BITS,
                        nw: int = SHA256_BITS) -> float:
    """SP 800-90B 3.1.5.1.2 output entropy of a vetted conditioning component:
        P_high = 2^-h_in, P_low = (1 - P_high) / (2^n_in - 1), n = min(n_out, nw)
        psi    = 2^(n_in - n) P_low + P_high
        U      = 2^(n_in - n) + sqrt(2 n 2^(n_in - n) ln 2),  omega = U P_low
        h_out  = -log2(max(psi, omega))
    evaluated in a form that does not overflow for n_in in the thousands of bits."""
    h_in = min(max(h_in, 0.0), float(n_in))
    if h_in == 0:
        return 0.0
    n = min(n_out, nw)
    p_high = 2.0 ** -h_in
    scale = 1.0 / (1.0 - 2.0 ** -n_in) if n_in < 64 else 1.0  # 2^n_in / (2^n_in - 1)
    term = (1 - p_high) * 2.0 ** -n * scale  # 2^(n_in - n) * P_low
    psi = term + p_high
    omega = term + math.sqrt(2 * n * math.log(2)) * (1 - p_high) * 2.0 ** (-(n_in + n) / 2) * scale
    return min(float(n), -math.log2(max(psi, omega)))


# ---------------------------------------------------------------------------
# Analysis and report
# ---------------------------------------------------------------------------


@dataclass
class Analysis:
    name: str
    description: str
    n: int
    bits: int
    minimum: int
    maximum: int
    mean: float
    stdev: float
    mcv: McvResult
    lag: LagResult
    h_original: float
    mcv_bitstring: McvResult
    collision: CollisionResult
    h_bitstring: float
    h_initial: float
    shannon: ShannonResult
    shannon_bit: float
    chi_square: List[ChiSquareResult]
    autocorr: List[float]
    autocorr_bound: float
    health: HealthResult
    warnings: List[str] = field(default_factory=list)

    @property
    def significant_lags(self) -> List[int]:
        return [k + 1 for k, r in enumerate(self.autocorr) if not math.isnan(r) and abs(r) > self.autocorr_bound]


def analyze(ds: Dataset, h_claim: float) -> Analysis:
    s = ds.samples
    n = len(s)
    if n < 1000:
        raise ValueError(f"{ds.name}: se necesitan al menos 1000 muestras (hay {n})")
    mean = sum(s) / n
    stdev = math.sqrt(sum((x - mean) ** 2 for x in s) / (n - 1))
    bitstring = to_bitstring(s, ds.bits)
    mcv = mcv_estimate(s)
    lag = lag_prediction_estimate(s, ds.bits)
    h_original = min(mcv.min_entropy, lag.min_entropy)
    mcv_bits = mcv_estimate(bitstring) if ds.bits > 1 else mcv
    coll = collision_estimate(bitstring)
    h_bitstring = min(mcv_bits.min_entropy, coll.min_entropy)
    h_initial = min(h_original, ds.bits * h_bitstring) if ds.bits > 1 else min(h_original, h_bitstring)

    chi = []
    if ds.bits <= 16:
        chi.append(chi_square_uniform(s, 1 << ds.bits, f"alfabeto completo ({ds.bits} bits)"))
    if ds.bits > 8:
        chi.append(chi_square_uniform([x & 0xFF for x in s], 256, "byte bajo (8 LSB)"))
    if ds.bits > 1:
        chi.append(chi_square_uniform([x & 1 for x in s], 2, "bit menos significativo"))

    warnings = []
    if n < NIST_MIN_SAMPLES:
        warnings.append(f"N = {n} < {NIST_MIN_SAMPLES:,} muestras exigidas por SP 800-90B 3.1.1: "
                        "resultado orientativo.")
    an = Analysis(
        ds.name, ds.description, n, ds.bits, min(s), max(s), mean, stdev,
        mcv, lag, h_original, mcv_bits, coll, h_bitstring, h_initial,
        shannon_entropy(s), shannon_entropy(bitstring).plugin, chi,
        autocorrelation(s), Z_99 / math.sqrt(n), health_tests(s, ds.bits, h_claim), warnings,
    )
    return an


def _fmt_p(p: float) -> str:
    if math.isnan(p):
        return "n/a"
    return f"{p:.3e}" if p < 1e-3 else f"{p:.4f}"


def print_report(an: Analysis) -> None:
    line = "=" * 78
    print()
    print(line)
    print(f" FUENTE: {an.name}")
    print(f" {an.description}")
    print(line)
    for w in an.warnings:
        print(f" ! {w}")

    print("\n [1] Estadistica descriptiva")
    print(f"     N = {an.n:,} muestras de {an.bits} bits | rango [{an.minimum}, {an.maximum}] | "
          f"media {an.mean:.2f} | desvio {an.stdev:.2f} | valores distintos {an.shannon.distinct}")

    print("\n [2] Min-entropia (NIST SP 800-90B)")
    m = an.mcv
    print(f"     6.3.1 Most Common Value (simbolos): valor modal {m.mode}, p^ = {m.p_hat:.6f}, "
          f"p_u = {m.p_upper:.6f} -> {m.min_entropy:.4f} bits/muestra")
    lg = an.lag
    print(f"     6.3.8 Lag Prediction (D = 128): aciertos {lg.correct:,}/{lg.predictions:,}, "
          f"P_global' = {lg.p_global:.6f}, racha max {lg.longest_run}, P_local = {lg.p_local:.6f}")
    print(f"           -> {lg.min_entropy:.4f} bits/muestra")
    print(f"     H_original = min(MCV, Lag) = {an.h_original:.4f} bits/muestra "
          f"({an.h_original / an.bits:.4f} bits/bit)")
    c = an.collision
    print(f"     6.3.2 Collision (bitstring de {an.n * an.bits:,} bits): v = {c.collisions:,} colisiones, "
          f"media {c.mean:.4f}, desvio {c.stdev:.4f}")
    print(f"           cota inferior X' = {c.mean_lower:.4f} -> p = {c.p:.6f} -> {c.min_entropy:.4f} bits/bit")
    if an.bits > 1:
        print(f"     MCV sobre bitstring: {an.mcv_bitstring.min_entropy:.4f} bits/bit")
    print(f"     H_bitstring = min(estimadores binarios) = {an.h_bitstring:.4f} bits/bit")
    print(f"     3.1.3 H_I = min(H_original, {an.bits} x H_bitstring) = {an.h_initial:.4f} bits/muestra "
          f"({an.h_initial / an.bits:.2%} del maximo)")

    s = an.shannon
    print("\n [3] Entropia de Shannon  H = -sum p_i log2 p_i")
    print(f"     plug-in {s.plugin:.4f} bits/muestra | Miller-Madow {s.miller_madow:.4f} | "
          f"por bit {an.shannon_bit:.4f}")
    print(f"     brecha Shannon - min-entropia = {s.plugin - an.h_initial:.4f} bits/muestra "
          "(la min-entropia es la que acota un ataque por adivinanza)")

    print("\n [4] Chi-cuadrado de uniformidad (H0: distribucion uniforme)")
    for ch in an.chi_square:
        if not ch.applicable:
            print(f"     {ch.label:<28} no aplicable: {ch.note}")
            continue
        verdict = "RECHAZA H0" if ch.p_value < 0.01 else "no rechaza H0"
        print(f"     {ch.label:<28} chi2 = {ch.statistic:,.1f}  gl = {ch.dof:<5} p = {_fmt_p(ch.p_value):<10} "
              f"-> {verdict} (alfa = 0.01)")

    print(f"\n [5] Autocorrelacion (lags 1..{MAX_LAG}); banda de no correlacion +/-{an.autocorr_bound:.5f} (99%)")
    for k, r in enumerate(an.autocorr, start=1):
        flag = "" if math.isnan(r) or abs(r) <= an.autocorr_bound else "  <- significativa"
        bar = "" if math.isnan(r) else "#" * min(40, int(abs(r) * 40 + 0.5))
        r_text = "  n/a (varianza nula)" if math.isnan(r) else f"{r:+.5f}"
        print(f"     lag {k:>2}: {r_text:>10}  {bar}{flag}")

    h = an.health
    print(f"\n [6] Health tests continuos SP 800-90B 4.4 (H declarada = {h.h_claim} bits/muestra, alfa = 2^-20)")
    print(f"     Repetition Count:   corte C = {h.rct_cutoff}, racha maxima {h.rct_longest_run}, "
          f"fallas {h.rct_failures} -> {'FALLA' if h.rct_failures else 'ok'}")
    print(f"     Adaptive Proportion: W = {h.apt_window}, corte C = {h.apt_cutoff}, conteo maximo "
          f"{h.apt_max_count}, fallas {h.apt_failures} -> {'FALLA' if h.apt_failures else 'ok'}")

    print("\n [7] Diagnostico")
    for text in diagnose(an):
        print(f"     - {text}")


def diagnose(an: Analysis) -> List[str]:
    out = []
    ratio = an.h_initial / an.bits
    if ratio > 0.85:
        out.append("Consistente con entropia completa a la resolucion de estos estimadores (Collision es "
                   "conservador: aun con datos ideales reporta ~0.9 bit/bit con N = 200.000).")
    elif ratio > 0.3:
        out.append(f"Entropia parcial ({ratio:.0%} del alfabeto): fuente util solo tras acondicionamiento.")
    else:
        out.append(f"Entropia muy baja ({an.h_initial:.3f} bits/muestra): la mayoria de los bits son predecibles.")
    lags = an.significant_lags
    if an.lag.min_entropy < an.mcv.min_entropy - 0.5:
        out.append(f"El predictor Lag acierta mucho mas que el valor modal ({an.lag.min_entropy:.2f} vs "
                   f"{an.mcv.min_entropy:.2f} bits): conocer las muestras previas reduce la incertidumbre.")
    if lags:
        out.append(f"Autocorrelacion significativa en lags {lags}: las muestras NO son IID; los estimadores "
                   "IID sobrestiman la entropia y corresponde la via non-IID de SP 800-90B.")
    else:
        out.append("Sin autocorrelacion significativa en lags 1-10 (no prueba independencia, solo no la refuta).")
    rejects = [c.label for c in an.chi_square if c.applicable and c.p_value < 0.01]
    if rejects:
        out.append(f"Chi-cuadrado rechaza uniformidad en: {', '.join(rejects)}.")
    if an.health.rct_failures or an.health.apt_failures:
        out.append("Los health tests disparan: en el dispositivo esta fuente debe declararse fallada y "
                   "no usarse (deteccion de fuente atascada/manipulada).")
    return out


def print_conditioning(ldr_h: Optional[float]) -> None:
    line = "=" * 78
    print()
    print(line)
    print(" ACONDICIONAMIENTO SHA-256 DEL FIRMWARE (src/entropy/entropy_pool.cpp)")
    print(line)
    print(f"  entrada: tag ({len(FW_DOMAIN_TAG)} B) || RNG HW ({FW_RNG_BYTES} B) || flag (1 B) || "
          f"{FW_LDR_SAMPLES} muestras LDR x 2 B  ->  n_in = {FW_N_IN_BITS} bits")
    print(f"  salida:  n_out = {SHA256_BITS} bits, ancho interno nw = {SHA256_BITS} (SHA-256, FIPS 180-4)")
    print("  h_out segun SP 800-90B 3.1.5.1.2 (componente de acondicionamiento aprobado):")
    rows: List[Tuple[str, float]] = [
        ("RNG HW a entropia completa, LDR acreditado en 0 (politica)", 256.0),
        ("RNG HW con solo 128 bits efectivos, LDR en 0", 128.0),
        ("RNG HW a entropia completa + 64 bits de margen (criterio SP 800-90C)", 320.0),
    ]
    if ldr_h is not None:
        ldr_total = FW_LDR_SAMPLES * ldr_h
        rows.append((f"RNG HW completo + LDR medido ({FW_LDR_SAMPLES} x {ldr_h:.3f} = {ldr_total:.1f} bits)",
                     256.0 + ldr_total))
        rows.append(("RNG HW comprometido, solo LDR medido (optimista: sin atacante, NO acreditado)", ldr_total))
    rows.append(("RNG HW comprometido y LDR saturado por el atacante", 0.0))
    for label, h_in in rows:
        print(f"    h_in = {h_in:7.1f}  ->  h_out = {conditioned_entropy(h_in):7.2f} bits   {label}")
    print("  SHA-256 nunca produce mas entropia que la de su entrada: h_out <= min(h_in, 256).")


CONCLUSIONS = """\
 1. Metrica correcta. Para generar claves importa la MIN-entropia, no la de
    Shannon: un atacante prueba primero el valor mas probable, y -log2(p_max)
    mide exactamente ese esfuerzo. Shannon promedia y siempre es >= min-entropia,
    por eso sobrestima la seguridad (ver brecha en la seccion [3]).

 2. El LDR es solo una fuente complementaria. Su senal esta dominada por la luz
    ambiente, que es lenta, periodica (parpadeo de 100 Hz por la red de 50 Hz) y
    sobre todo CONTROLABLE desde afuera: una linterna, la oscuridad total o un
    LED modulado fuerzan la lectura (fuente 'ldr-attack': ADC pegado en 4095,
    entropia ~0). La poca variabilidad util esta en los bits bajos y proviene
    del ruido termico/cuantizacion del ADC, no de la luz. Ademas las muestras
    estan autocorrelacionadas (no IID) y no existe un modelo estocastico
    validado del sensor, que SP 800-90B 3.2.2 exige para acreditar entropia.
    Por eso el firmware le acredita 0 bits: suma defensa en profundidad pero
    la seguridad descansa en el RNG de hardware del ESP32-S3.

 3. Por que el acondicionador SHA-256 es imprescindible. Ninguna fuente fisica
    entrega bits uniformes e independientes; SHA-256 actua como extractor:
    comprime n_in = 2544 bits de entrada parcialmente impredecible en 256 bits
    casi uniformes, y combina las fuentes de modo que la salida es impredecible
    si al menos una de ellas lo es (siempre que el atacante no controle una con
    conocimiento de la otra). SP 800-90B 3.1.5.1.1 lo admite como componente de
    acondicionamiento aprobado; la tabla anterior muestra que la salida solo
    alcanza ~256 bits si la entrada aporta al menos esa cantidad (+ margen).

 4. Los tests estadisticos no prueban aleatoriedad. La fuente 'sha256-counter'
    (SHA-256 de un contador) supera chi-cuadrado, autocorrelacion y los
    estimadores, pero es totalmente predecible para quien conozca el esquema.
    Por eso SP 800-90B evalua el RUIDO CRUDO antes del acondicionamiento, y la
    salida de esp_random() (ya post-procesada por el chip) solo admite pruebas
    de cordura, no una estimacion de entropia.

 5. Alcance. Se implementan 3 de los 10 estimadores non-IID (MCV, Collision y
    Lag Prediction); H_I es una cota optimista: los omitidos (Markov,
    compresion, t-Tuple, LRS, MultiMCW, MultiMMC, LZ78Y) solo pueden bajarla. Una evaluacion formal debe correr la
    herramienta oficial de NIST (ea_non_iid / ea_restart) sobre >= 1.000.000
    de muestras crudas y 1000 reinicios.
"""


def print_comparison(analyses: Sequence[Analysis]) -> None:
    line = "=" * 78
    print()
    print(line)
    print(" COMPARACION DE FUENTES")
    print(line)
    print(f"  {'fuente':<15}{'bits':>5}{'H_MCV':>8}{'H_Lag':>8}{'H_bit':>7}{'H_I':>9}{'H_I/bit':>9}{'Shannon':>9}"
          f"{'lags sig.':>11}{'health':>9}")
    for an in analyses:
        health = "FALLA" if an.health.rct_failures or an.health.apt_failures else "ok"
        print(f"  {an.name:<15}{an.bits:>5}{an.mcv.min_entropy:>8.3f}{an.lag.min_entropy:>8.3f}{an.h_bitstring:>7.3f}{an.h_initial:>9.3f}"
              f"{an.h_initial / an.bits:>9.3f}{an.shannon.plugin:>9.3f}{len(an.significant_lags):>11}{health:>9}")


def _json_default(obj: object) -> object:
    if isinstance(obj, float) and math.isnan(obj):
        return None
    raise TypeError(type(obj).__name__)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Analisis de entropia (NIST SP 800-90B) de las fuentes de EntropySigner.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("Examples:")[1])
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", type=Path, help="archivo de muestras")
    src.add_argument("--synthetic", choices=sorted(SYNTHETIC) + ["all"], help="fuente simulada")
    src.add_argument("--serial", metavar="PORT", help="puerto serie (requiere pyserial), p.ej. COM5 o /dev/ttyUSB0")
    parser.add_argument("--format", default="auto", choices=["auto", "u8", "u16le", "u16be", "text"],
                        help="formato del archivo (auto: .txt/.csv/.log -> text, otro -> u8)")
    parser.add_argument("--bits", type=int, help="bits por muestra (12 para el ADC del LDR)")
    parser.add_argument("--lsb", type=int, metavar="K", help="analizar solo los K bits menos significativos")
    parser.add_argument("-n", "--count", type=int, default=200_000, help="muestras a generar/capturar")
    parser.add_argument("--seed", type=int, default=2026, help="semilla de las simulaciones (reproducibles)")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--timeout", type=float, default=600.0, help="limite de la captura serie en segundos")
    parser.add_argument("--save", type=Path, help="guardar la captura serie como texto")
    parser.add_argument("--h-claim", type=float, default=1.0,
                        help="entropia declarada por muestra para los health tests (default 1.0)")
    parser.add_argument("--json", type=Path, help="exportar las metricas a JSON")
    args = parser.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    datasets: List[Dataset] = []
    if args.file:
        datasets.append(load_file(args.file, args.format, args.bits))
    elif args.synthetic:
        kinds = list(SYNTHETIC) if args.synthetic == "all" else [args.synthetic]
        for kind in kinds:
            datasets.append(SYNTHETIC[kind](args.count, random.Random(args.seed)))
    else:
        samples = capture_serial(args.serial, args.baud, args.count, args.timeout)
        if args.save:
            args.save.write_text("\n".join(map(str, samples)) + "\n", encoding="ascii")
            print(f"  captura guardada en {args.save}")
        bits = args.bits or (max(samples).bit_length() if samples else 12)
        datasets.append(Dataset(f"serial:{args.serial}", f"captura en vivo desde {args.serial}", samples, bits))

    if args.lsb:
        mask = (1 << args.lsb) - 1
        datasets = [Dataset(f"{d.name}[{args.lsb} LSB]", d.description + f" - solo {args.lsb} LSB",
                            [s & mask for s in d.samples], args.lsb) for d in datasets]

    print("EntropySigner - analisis de entropia (Paso 17, NIST SP 800-90B)")
    analyses = []
    for ds in datasets:
        an = analyze(ds, args.h_claim)
        print_report(an)
        analyses.append(an)
    if len(analyses) > 1:
        print_comparison(analyses)

    ldr = next((a for a in analyses if a.name == "ldr"), None)
    ldr_h = ldr.h_initial if ldr else (analyses[0].h_initial if analyses[0].bits == 12 else None)
    print_conditioning(ldr_h)
    print()
    print("=" * 78)
    print(" CONCLUSIONES")
    print("=" * 78)
    print(CONCLUSIONS)

    if args.json:
        payload = [{**asdict(a), "significant_lags": a.significant_lags} for a in analyses]
        args.json.write_text(json.dumps(payload, indent=2, default=_json_default), encoding="utf-8")
        print(f"Metricas exportadas a {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

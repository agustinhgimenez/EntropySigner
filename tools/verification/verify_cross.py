#!/usr/bin/env python3
"""EntropySigner - cross-verification of the firmware cryptography (Paso 18).

Recomputes, with implementations that are independent from the C++ firmware,
every known-answer vector the Unity tests in tests/ assert:

    SHA-256 (NIST FIPS 180-4 examples)          tests/test_crypto
    RIPEMD-160 / HASH160 (Bosselaers vectors)   tests/test_crypto
    Keccak-256, Ethereum padding 0x01           tests/test_ethereum
    BIP-39 wordlist, checksum, PBKDF2 seed      tests/test_bip39
    BIP-32 vectors 1-2, BIP-44 BTC / ETH paths  tests/test_bip32
    Base58 / Base58Check / P2PKH                tests/test_bitcoin
    EIP-55 checksum addresses                   tests/test_ethereum

Why this proves bit-for-bit agreement
-------------------------------------
The Unity tests prove  C++(x) == expected(x)  on the host or on the ESP32.
This script proves     Python(x) == expected(x)  and, unless --no-source-check
is given, that every expected value is literally present in the matching
tests/*.cpp file (so both sides check the very same constant). Together:
C++(x) == Python(x), byte by byte.

Independence
------------
RIPEMD-160, Keccak-f[1600] and secp256k1 are implemented here from their
specifications in pure Python (the firmware uses its own C++ code and mbedTLS).
The Keccak permutation is additionally validated against hashlib.sha3_256
(same permutation, FIPS 202 padding 0x06), and RIPEMD-160 against hashlib when
OpenSSL still provides it. Optional third-party libraries (pycryptodome,
mnemonic) are used as extra oracles only if installed; nothing beyond the
Python 3.8+ standard library is required.

Usage:
    python tools/verification/verify_cross.py [-v] [--no-source-check]

Exit status is 0 if every check passed, 1 otherwise.

The elliptic-curve code below is NOT constant time and must never handle real
secrets: it only processes public test vectors.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import re
import sys
import unicodedata
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_DIR = REPO_ROOT / "tests"
WORDLIST_CPP = REPO_ROOT / "src" / "bip39" / "bip39_wordlist.cpp"


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


class Report:
    """Collects PASS / FAIL / SKIP results and checks C++ source literals."""

    def __init__(self, verbose: bool, source_check: bool) -> None:
        self.verbose = verbose
        self.source_check = source_check
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.literals_found = 0
        self._sources: Dict[str, Optional[str]] = {}

    def section(self, title: str) -> None:
        print()
        print("=" * 78)
        print(f" {title}")
        print("=" * 78)

    def _source(self, test_dir: str) -> Optional[str]:
        """Test source with adjacent C string literals merged ("ab" "cd" -> "abcd")."""
        if test_dir not in self._sources:
            path = TESTS_DIR / test_dir / "test_main.cpp"
            try:
                text = path.read_text(encoding="utf-8")
            except OSError:
                self._sources[test_dir] = None
            else:
                self._sources[test_dir] = re.sub(r'"\s*\n\s*"', "", text)
        return self._sources[test_dir]

    def check(
        self,
        name: str,
        got: object,
        expected: object,
        cpp_test: Optional[str] = None,
        literal: Optional[str] = None,
    ) -> bool:
        """Compares got against expected and, optionally, finds the literal in tests/<cpp_test>."""
        ok = got == expected
        note = ""
        if ok and cpp_test and self.source_check:
            needle = literal if literal is not None else (expected if isinstance(expected, str) else None)
            if needle:
                source = self._source(cpp_test)
                if source is None:
                    ok = False
                    note = f"no se pudo leer tests/{cpp_test}/test_main.cpp"
                elif needle not in source:
                    ok = False
                    note = f"el valor esperado no figura en tests/{cpp_test} (vectores desincronizados)"
                else:
                    self.literals_found += 1
        if ok:
            self.passed += 1
            print(f"  [PASS] {name}")
            if self.verbose:
                print(f"         = {_short(got)}")
        else:
            self.failed += 1
            print(f"  [FAIL] {name}")
            print(f"         esperado: {_short(expected)}")
            print(f"         obtenido: {_short(got)}")
            if note:
                print(f"         motivo:   {note}")
        return ok

    def check_true(self, name: str, condition: bool) -> bool:
        return self.check(name, bool(condition), True)

    def skip(self, name: str, reason: str) -> None:
        self.skipped += 1
        print(f"  [SKIP] {name}: {reason}")

    def info(self, text: str) -> None:
        print(f"         {text}")


def _short(value: object, limit: int = 140) -> str:
    text = value.hex() if isinstance(value, (bytes, bytearray)) else str(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


# ---------------------------------------------------------------------------
# RIPEMD-160 (Dobbertin, Bosselaers, Preneel 1996), pure Python
# ---------------------------------------------------------------------------

_M32 = 0xFFFFFFFF

_RMD_R_LEFT = (
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
)
_RMD_R_RIGHT = (
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
)
_RMD_S_LEFT = (
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
)
_RMD_S_RIGHT = (
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
)
_RMD_K_LEFT = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
_RMD_K_RIGHT = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)


def _rol32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _M32


def _rmd_f(j: int, x: int, y: int, z: int) -> int:
    if j == 0:
        return x ^ y ^ z
    if j == 1:
        return (x & y) | (~x & z)
    if j == 2:
        return (x | ~y) ^ z
    if j == 3:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


def ripemd160_py(data: bytes) -> bytes:
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    msg = bytes(data) + b"\x80"
    msg += b"\x00" * ((56 - len(msg)) % 64)
    msg += (8 * len(data) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
    for off in range(0, len(msg), 64):
        x = [int.from_bytes(msg[off + 4 * i: off + 4 * i + 4], "little") for i in range(16)]
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            rnd = j // 16
            t = (_rol32((al + _rmd_f(rnd, bl, cl, dl) + x[_RMD_R_LEFT[j]] + _RMD_K_LEFT[rnd]) & _M32,
                        _RMD_S_LEFT[j]) + el) & _M32
            al, el, dl, cl, bl = el, dl, _rol32(cl, 10), bl, t
            t = (_rol32((ar + _rmd_f(4 - rnd, br, cr, dr) + x[_RMD_R_RIGHT[j]] + _RMD_K_RIGHT[rnd]) & _M32,
                        _RMD_S_RIGHT[j]) + er) & _M32
            ar, er, dr, cr, br = er, dr, _rol32(cr, 10), br, t
        h = [
            (h[1] + cl + dr) & _M32,
            (h[2] + dl + er) & _M32,
            (h[3] + el + ar) & _M32,
            (h[4] + al + br) & _M32,
            (h[0] + bl + cr) & _M32,
        ]
    return b"".join(v.to_bytes(4, "little") for v in h)


def ripemd160_hashlib(data: bytes) -> Optional[bytes]:
    """RIPEMD-160 from OpenSSL through hashlib, or None (OpenSSL 3 moved it to the legacy provider)."""
    try:
        return hashlib.new("ripemd160", data).digest()
    except (ValueError, TypeError):
        return None


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash160(data: bytes) -> bytes:
    return ripemd160_py(sha256(data))


# ---------------------------------------------------------------------------
# Keccak-f[1600] sponge, pure Python (round constants and rotation offsets are
# generated from their definitions in the Keccak reference, not transcribed)
# ---------------------------------------------------------------------------

_M64 = (1 << 64) - 1


def _rc_bit(t: int) -> int:
    # LFSR x^8 + x^6 + x^5 + x^4 + 1 from the Keccak reference, section 1.2.
    r = 1
    for _ in range(t % 255):
        r <<= 1
        if r & 0x100:
            r ^= 0x171
    return r & 1


_KECCAK_RC = tuple(
    sum(_rc_bit(j + 7 * i) << ((1 << j) - 1) for j in range(7)) for i in range(24)
)


def _rho_offsets() -> Tuple[int, ...]:
    offsets = [0] * 25
    x, y = 1, 0
    for t in range(24):
        offsets[x + 5 * y] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    return tuple(offsets)


_KECCAK_RHO = _rho_offsets()


def _rol64(v: int, n: int) -> int:
    return ((v << n) | (v >> (64 - n))) & _M64 if n else v


def keccak_f1600(lanes: List[int]) -> List[int]:
    a = list(lanes)
    for rc in _KECCAK_RC:
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol64(c[(x + 1) % 5], 1) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]  # theta
        b = [0] * 25
        for x in range(5):  # rho + pi
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol64(a[x + 5 * y], _KECCAK_RHO[x + 5 * y])
        a = [b[i] ^ (~b[(i + 1) % 5 + 5 * (i // 5)] & b[(i + 2) % 5 + 5 * (i // 5)]) for i in range(25)]  # chi
        a[0] ^= rc  # iota
    return a


def keccak_sponge(data: bytes, rate: int, pad_byte: int, out_len: int) -> bytes:
    """Sponge with multi-rate padding: pad_byte 0x01 = original Keccak, 0x06 = FIPS 202 SHA-3."""
    msg = bytearray(data)
    msg.append(pad_byte)
    msg.extend(b"\x00" * ((-len(msg)) % rate))
    msg[-1] |= 0x80
    state = [0] * 25
    for off in range(0, len(msg), rate):
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(msg[off + 8 * i: off + 8 * i + 8], "little")
        state = keccak_f1600(state)
    out = b"".join(lane.to_bytes(8, "little") for lane in state[: rate // 8])
    return out[:out_len]


def keccak256(data: bytes) -> bytes:
    return keccak_sponge(data, rate=136, pad_byte=0x01, out_len=32)


def sha3_256_py(data: bytes) -> bytes:
    return keccak_sponge(data, rate=136, pad_byte=0x06, out_len=32)


# ---------------------------------------------------------------------------
# secp256k1 (SEC 2 v2, section 2.4.1) - affine arithmetic, public data only
# ---------------------------------------------------------------------------

SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
Point = Optional[Tuple[int, int]]  # None is the point at infinity


def point_add(p1: Point, p2: Point) -> Point:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and (p1[1] + p2[1]) % SECP_P == 0:
        return None
    if p1 == p2:
        lam = 3 * p1[0] * p1[0] * pow(2 * p1[1], -1, SECP_P) % SECP_P
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], -1, SECP_P) % SECP_P
    x3 = (lam * lam - p1[0] - p2[0]) % SECP_P
    return x3, (lam * (p1[0] - x3) - p1[1]) % SECP_P


def point_mul(k: int, point: Point = SECP_G) -> Point:
    result: Point = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def ser_p(point: Tuple[int, int]) -> bytes:
    return bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, "big")


def decompress(pub: bytes) -> Tuple[int, int]:
    if len(pub) != 33 or pub[0] not in (2, 3):
        raise ValueError("compressed public key expected")
    x = int.from_bytes(pub[1:], "big")
    rhs = (pow(x, 3, SECP_P) + 7) % SECP_P
    y = pow(rhs, (SECP_P + 1) // 4, SECP_P)  # p = 3 mod 4
    if y * y % SECP_P != rhs:
        raise ValueError("x is not on secp256k1")
    if (y & 1) != (pub[0] & 1):
        y = SECP_P - y
    return x, y


# ---------------------------------------------------------------------------
# BIP-32
# ---------------------------------------------------------------------------

HARDENED = 0x80000000


class Node:
    def __init__(self, key: int, chain: bytes, depth: int = 0, parent_fp: int = 0, child: int = 0) -> None:
        self.key, self.chain, self.depth, self.parent_fp, self.child = key, chain, depth, parent_fp, child

    @property
    def pub(self) -> bytes:
        return ser_p(point_mul(self.key))


def master_key(seed: bytes) -> Node:
    i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k = int.from_bytes(i[:32], "big")
    if not 0 < k < SECP_N:
        raise ValueError("invalid master key")
    return Node(k, i[32:])


def fingerprint(pub: bytes) -> int:
    return int.from_bytes(hash160(pub)[:4], "big")


def ckd_priv(parent: Node, index: int) -> Node:
    if index & HARDENED:
        data = b"\x00" + parent.key.to_bytes(32, "big") + index.to_bytes(4, "big")
    else:
        data = parent.pub + index.to_bytes(4, "big")
    i = hmac.new(parent.chain, data, hashlib.sha512).digest()
    il = int.from_bytes(i[:32], "big")
    k = (il + parent.key) % SECP_N
    if il >= SECP_N or k == 0:
        raise ValueError("invalid child, use the next index")
    return Node(k, i[32:], parent.depth + 1, fingerprint(parent.pub), index)


def ckd_pub(parent_pub: bytes, chain: bytes, index: int) -> Tuple[bytes, bytes]:
    if index & HARDENED:
        raise ValueError("hardened derivation needs the private key")
    i = hmac.new(chain, parent_pub + index.to_bytes(4, "big"), hashlib.sha512).digest()
    il = int.from_bytes(i[:32], "big")
    child = point_add(point_mul(il), decompress(parent_pub))
    if il >= SECP_N or child is None:
        raise ValueError("invalid child, use the next index")
    return ser_p(child), i[32:]


def derive_path(root: Node, path: str) -> Node:
    parts = path.split("/")
    if parts[0] != "m":
        raise ValueError("path must start with m")
    node = root
    for part in parts[1:]:
        hardened = part[-1:] in ("'", "h", "H")
        index = int(part[:-1] if hardened else part)
        node = ckd_priv(node, index | (HARDENED if hardened else 0))
    return node


# ---------------------------------------------------------------------------
# Base58Check, P2PKH, Ethereum / EIP-55
# ---------------------------------------------------------------------------

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58_ALPHABET[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


def b58decode(text: str) -> bytes:
    n = 0
    for ch in text:
        n = n * 58 + B58_ALPHABET.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(text) - len(text.lstrip("1"))) + body


def b58check(version: int, payload: bytes) -> str:
    raw = bytes([version]) + payload
    return b58encode(raw + sha256(sha256(raw))[:4])


def p2pkh_address(pub: bytes) -> str:
    return b58check(0x00, hash160(pub))


def eip55(address: bytes) -> str:
    hex_addr = address.hex()
    digest = keccak256(hex_addr.encode("ascii")).hex()
    return "0x" + "".join(c.upper() if int(digest[i], 16) >= 8 else c for i, c in enumerate(hex_addr))


def eth_address(pub: bytes) -> str:
    x, y = decompress(pub)
    return eip55(keccak256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[-20:])


# ---------------------------------------------------------------------------
# BIP-39
# ---------------------------------------------------------------------------

BIP39_ENGLISH_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"


def load_wordlist_from_firmware() -> Optional[List[str]]:
    """Extracts the kWords[] array from src/bip39/bip39_wordlist.cpp."""
    try:
        text = WORDLIST_CPP.read_text(encoding="utf-8")
    except OSError:
        return None
    match = re.search(r"kWords\[[^\]]*\]\s*=\s*\{(.*?)\};", text, re.S)
    return re.findall(r'"([a-z]+)"', match.group(1)) if match else None


def load_wordlist_from_mnemonic_pkg() -> Optional[List[str]]:
    try:
        from mnemonic import Mnemonic  # type: ignore
    except ImportError:
        return None
    return list(Mnemonic("english").wordlist)


def entropy_to_mnemonic(entropy: bytes, words: Sequence[str]) -> str:
    ent_bits = 8 * len(entropy)
    cs_bits = ent_bits // 32
    value = (int.from_bytes(entropy, "big") << cs_bits) | (sha256(entropy)[0] >> (8 - cs_bits))
    count = (ent_bits + cs_bits) // 11
    return " ".join(words[(value >> (11 * (count - 1 - i))) & 0x7FF] for i in range(count))


def mnemonic_to_entropy(mnemonic: str, words: Sequence[str]) -> Optional[bytes]:
    """Returns the entropy, or None if a word is unknown or the checksum fails."""
    index = {w: i for i, w in enumerate(words)}
    parts = mnemonic.split(" ")
    if len(parts) % 3 or any(p not in index for p in parts):
        return None
    value = 0
    for p in parts:
        value = (value << 11) | index[p]
    total_bits = 11 * len(parts)
    cs_bits = total_bits // 33
    entropy = (value >> cs_bits).to_bytes((total_bits - cs_bits) // 8, "big")
    if (value & ((1 << cs_bits) - 1)) != sha256(entropy)[0] >> (8 - cs_bits):
        return None
    return entropy


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    m = unicodedata.normalize("NFKD", mnemonic).encode("utf-8")
    s = unicodedata.normalize("NFKD", "mnemonic" + passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", m, s, 2048, 64)


# ---------------------------------------------------------------------------
# Known-answer vectors (identical to the ones asserted in tests/*/test_main.cpp)
# ---------------------------------------------------------------------------

SHA256_VECTORS = (  # FIPS 180-4 / NIST CSRC examples
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
)

RIPEMD160_VECTORS = (  # Bosselaers' RIPEMD-160 page
    (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
    (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
    (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
    (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
    (b"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "12a053384a9c0c88e405a06c27dcf49ada62eb2b"),
    (b"1234567890" * 8, "9b752e45573d4b39f4dbd3323cab82bf63326bfb"),
)
RIPEMD160_PADDING_VECTORS = (  # 'a' * n around the 55/56/64-byte padding edges
    (55, "0d8a8c9063a48576a7c97e9f95253a6e53ff6765"),
    (56, "e72334b46c83cc70bef979e15453706c95b888be"),
    (63, "e640041293fe663b9bf3f8c21ffecac03819e6b2"),
    (64, "9dfb7d374ad924f3f88de96291c33e9abed53e32"),
    (1000, "aa69deee9a8922e92f8105e007f76110f381e9cf"),
)
HASH160_VECTORS = (
    (b"", "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"),
    (bytes.fromhex("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"),
     "3442193e1bb70916e914552172cd4e2dbc9df811"),
)

KECCAK_VECTORS = (
    (b"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
    (b"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
    (b"The quick brown fox jumps over the lazy dog",
     "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"),
    (b"a" * 135, "34367dc248bbd832f4e3e69dfaac2f92638bd0bbd18f2912ba4ef454919cf446"),
    (b"a" * 136, "a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e"),
    (b"a" * 200, "96ea54061def936c4be90b518992fdc6f12f535068a256229aca54267b4d084d"),
)

BIP39_VECTORS = (  # Trezor python-mnemonic vectors.json, 256-bit entries, passphrase "TREZOR"
    ("0000000000000000000000000000000000000000000000000000000000000000",
     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
     "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd30971"
     "70af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"),
    ("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
     "legal winner thank year wave sausage worth useful legal winner thank year "
     "wave sausage worth useful legal winner thank year wave sausage worth title",
     "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a40"
     "21b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87"),
    ("8080808080808080808080808080808080808080808080808080808080808080",
     "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd "
     "amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
     "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09"
     "e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f"),
    ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
     "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
     "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
     "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e16"
     "13912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad"),
    ("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
     "hamster diagram private dutch cause delay private meat slide toddler razor book "
     "happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
     "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d2"
     "0b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440"),
    ("9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
     "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich "
     "alcohol speed nation flash devote level hobby quick inner drive ghost inside",
     "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6"
     "fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d"),
    ("066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
     "all hour make first leader extend hole alien behind guard gospel lava "
     "path output census museum junior mass reopen famous sing advance salt reform",
     "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6"
     "df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d"),
    ("f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
     "void come effort suffer camp survey warrior heavy shoot primary clutch crush "
     "open amazing screen patrol group space point ten exist slush involve unfold",
     "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0"
     "e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998"),
)

ABANDON_ABOUT = " ".join(["abandon"] * 11 + ["about"])
ABANDON_SEED = (
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
    "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
)

# BIP-32 test vectors: (depth, parent fingerprint, child number, k, c, K).
BIP32_VECTOR1_SEED = "000102030405060708090a0b0c0d0e0f"
BIP32_VECTOR1 = (
    (0, 0x00000000, 0x00000000,
     "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
     "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
     "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"),
    (1, 0x3442193E, 0x80000000,
     "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
     "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
     "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"),
    (2, 0x5C1BD648, 0x00000001,
     "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
     "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19",
     "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"),
    (3, 0xBEF5A2F9, 0x80000002,
     "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
     "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f",
     "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2"),
    (4, 0xEE7AB90C, 0x00000002,
     "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
     "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd",
     "02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29"),
    (5, 0xD880D7D8, 0x3B9ACA00,
     "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
     "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e",
     "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011"),
)
BIP32_VECTOR2_SEED = (
    "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2"
    "9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
)
BIP32_VECTOR2 = (
    (0, 0x00000000, 0x00000000,
     "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
     "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
     "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7"),
    (1, 0xBD16BEE5, 0x00000000,
     "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e",
     "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c",
     "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea"),
    (2, 0x5A61FF8E, 0xFFFFFFFF,
     "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93",
     "be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9",
     "03c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b"),
    (3, 0xD8AB4937, 0x00000001,
     "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7",
     "f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb",
     "03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9"),
    (4, 0x78412E3A, 0xFFFFFFFE,
     "f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d",
     "637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29",
     "02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0"),
    (5, 0x31A507B8, 0x00000002,
     "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23",
     "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271",
     "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c"),
)
BIP44_BTC = ("m/44'/0'/0'/0/0", 5, 0x1962AB58,
             "e284129cc0922579a535bbf4d1a3b25773090d28c909bc0fed73b5e0222cc372",
             "213909708058e0ec4a99c19d8e041c014ae6c7dc21d2a1fac86772df7ca357a6",
             "03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e",
             "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA")
BIP44_ETH = ("m/44'/60'/0'/0/0", 5, 0xE4389614,
             "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727",
             "736094f4f24b67e838a4b3d23d31d229ca03e00c9bb99ce95da6d86e8b3847b5",
             "0237b0bb7a8288d38ed49a524b5dc98cff3eb5ca824c9f9dc0dfdb3d9cd600f299",
             "0x9858EfFD232B4033E47d90003D41EC34EcaEda94")

BASE58_VECTORS = (  # Bitcoin Core src/test/data/base58_encode_decode.json
    ("", ""),
    ("61", "2g"),
    ("626262", "a3gV"),
    ("636363", "aPEr"),
    ("73696d706c792061206c6f6e6720737472696e67", "2cFupjhnEsSn59qHXstmK2ffpLv2"),
    ("00eb15231dfceb60925886b67d065299925915aeb172c06647", "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L"),
    ("516b6fcd0f", "ABnLTmg"),
    ("bf4f89001e670274dd", "3SEo3LWLoPntC"),
    ("572e4794", "3EFU7m"),
    ("ecac89cad93923c02321", "EJDM8drfXA6uyA"),
    ("10c8511e", "Rt5zm"),
    ("00000000000000000000", "1111111111"),
)
P2PKH_VECTORS = (  # BIP-32 vector 1 master key, and the generator G (private key 1)
    ("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2", "15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma"),
    ("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"),
)

EIP55_VECTORS = (  # EIP-55 specification: all caps, all lower, mixed
    "0x52908400098527886E0F7030069857D2E4169EE7", "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
    "0xde709f2102306220921060314715629080e2fb77", "0x27b1fdb04752bbc536007a920d24acb045561c26",
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
)
ETH_G_ADDRESS = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"  # address of private key 1


# ---------------------------------------------------------------------------
# Check groups
# ---------------------------------------------------------------------------


def verify_sha256(r: Report) -> None:
    r.section("SHA-256  (FIPS 180-4)  <->  src/crypto/sha256.cpp")
    for msg, expected in SHA256_VECTORS:
        r.check(f"SHA-256({_label(msg)})", sha256(msg).hex(), expected, "test_crypto")
    # Extra NIST example not present in the C++ tests: validates the Python oracle itself.
    r.check("SHA-256('a' x 1.000.000) [oraculo]", sha256(b"a" * 1_000_000).hex(),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")


def verify_ripemd160(r: Report) -> None:
    r.section("RIPEMD-160 / HASH160  <->  src/crypto/ripemd160.cpp")
    have_openssl = ripemd160_hashlib(b"") is not None
    if not have_openssl:
        r.skip("RIPEMD-160 de OpenSSL", "hashlib no lo provee (OpenSSL 3 legacy); se usa solo la implementacion propia")
    for msg, expected in RIPEMD160_VECTORS:
        r.check(f"RIPEMD-160({_label(msg)})", ripemd160_py(msg).hex(), expected, "test_crypto")
    for length, expected in RIPEMD160_PADDING_VECTORS:
        msg = b"a" * length
        r.check(f"RIPEMD-160('a' x {length}) [borde de padding]", ripemd160_py(msg).hex(), expected, "test_crypto")
        if have_openssl:
            r.check(f"  oraculo OpenSSL 'a' x {length}", ripemd160_hashlib(msg).hex(), expected)
    for msg, expected in HASH160_VECTORS:
        r.check(f"HASH160({_label(msg)})", hash160(msg).hex(), expected, "test_crypto")


def verify_keccak(r: Report) -> None:
    r.section("Keccak-256 (Ethereum, padding 0x01)  <->  src/crypto/keccak256.cpp")
    # 1. Same permutation with FIPS 202 padding must equal hashlib.sha3_256.
    for msg in (b"", b"abc", b"a" * 135, b"a" * 136, b"a" * 200, bytes(range(256)) * 3):
        r.check(f"Keccak-f[1600] con pad 0x06 == hashlib.sha3_256({_label(msg)})",
                sha3_256_py(msg).hex(), hashlib.sha3_256(msg).hexdigest())
    # 2. Ethereum Keccak-256 vectors asserted by the firmware tests.
    for msg, expected in KECCAK_VECTORS:
        r.check(f"Keccak-256({_label(msg)})", keccak256(msg).hex(), expected, "test_ethereum")
    # 3. Show that the padding byte matters: Keccak-256("") != SHA3-256("").
    r.check_true("Keccak-256('') != SHA3-256('')  (padding 0x01 vs 0x06)",
                 keccak256(b"") != hashlib.sha3_256(b"").digest())
    # 4. Optional third-party oracle.
    try:
        from Crypto.Hash import keccak as pc_keccak  # type: ignore
    except ImportError:
        r.skip("oraculo pycryptodome", "paquete no instalado (opcional)")
    else:
        for msg, expected in KECCAK_VECTORS:
            r.check(f"pycryptodome keccak256({_label(msg)})",
                    pc_keccak.new(digest_bits=256, data=msg).hexdigest(), expected)


def verify_bip39(r: Report) -> None:
    r.section("BIP-39 (wordlist, checksum 8 bits, PBKDF2-HMAC-SHA512)  <->  src/bip39/")
    words = load_wordlist_from_firmware()
    origin = "src/bip39/bip39_wordlist.cpp"
    if words is None:
        words = load_wordlist_from_mnemonic_pkg()
        origin = "paquete mnemonic"
    if words is None:
        r.skip("wordlist", "no se pudo leer el array del firmware ni importar 'mnemonic'")
    else:
        r.info(f"wordlist tomada de {origin}")
        r.check("cantidad de palabras", len(words), 2048)
        r.check_true("orden ASCII estricto (requerido por std::lower_bound)",
                     all(a < b for a, b in zip(words, words[1:])))
        r.check("SHA-256 de english.txt oficial", sha256("".join(w + "\n" for w in words).encode()).hex(),
                BIP39_ENGLISH_SHA256, "test_bip39")
        pkg_words = load_wordlist_from_mnemonic_pkg()
        if pkg_words is None:
            r.skip("oraculo python-mnemonic (Trezor)", "paquete no instalado (opcional)")
        elif origin != "paquete mnemonic":
            r.check("wordlist firmware == python-mnemonic", words, pkg_words)

    for i, (ent_hex, mnemonic, seed_hex) in enumerate(BIP39_VECTORS):
        entropy = bytes.fromhex(ent_hex)
        if words is not None:
            r.check(f"vector {i}: entropia -> 24 palabras", entropy_to_mnemonic(entropy, words), mnemonic,
                    "test_bip39")
            r.check(f"vector {i}: palabras -> entropia (checksum ok)", mnemonic_to_entropy(mnemonic, words), entropy)
        r.check(f"vector {i}: seed PBKDF2 (passphrase 'TREZOR')", mnemonic_to_seed(mnemonic, "TREZOR").hex(),
                seed_hex, "test_bip39")

    if words is not None:
        bad = BIP39_VECTORS[0][1].rsplit(" ", 1)[0] + " abandon"  # last word carries the checksum
        r.check_true("checksum invalido rechazado ('... abandon' en vez de '... art')",
                     mnemonic_to_entropy(bad, words) is None)
        cs = sha256(bytes(32))[0]
        r.info(f"checksum de 32 bytes en cero = SHA-256(...)[0] = 0x{cs:02x} -> ultimos 8 bits de 'art'")
    r.check("seed 'abandon x11 about' (passphrase vacia), usada por BIP-32/44",
            mnemonic_to_seed(ABANDON_ABOUT).hex(), ABANDON_SEED, "test_bip32")


def _check_chain(r: Report, label: str, seed_hex: str, chain: Sequence[tuple]) -> None:
    node = master_key(bytes.fromhex(seed_hex))
    for i, (depth, parent_fp, child, k_hex, c_hex, pub_hex) in enumerate(chain):
        if i > 0:
            parent = node
            node = ckd_priv(node, child)
            if not child & HARDENED:
                pub, chain_code = ckd_pub(parent.pub, parent.chain, child)
                r.check(f"{label} nodo {i}: CKDpub == N(CKDpriv)", (pub.hex(), chain_code.hex()), (pub_hex, c_hex))
        name = f"{label} nodo {i} (prof. {depth}, hijo 0x{child:08x})"
        r.check(f"{name} clave privada", node.key.to_bytes(32, "big").hex(), k_hex, "test_bip32")
        r.check(f"{name} chain code", node.chain.hex(), c_hex, "test_bip32")
        r.check(f"{name} clave publica", node.pub.hex(), pub_hex, "test_bip32")
        r.check(f"{name} fingerprint padre", node.parent_fp, parent_fp, "test_bip32",
                literal=f"0x{parent_fp:08x}u")
        r.check(f"{name} profundidad/indice", (node.depth, node.child), (depth, child))


def verify_bip32(r: Report) -> None:
    r.section("BIP-32 (HMAC-SHA512 + secp256k1)  <->  src/bip32/bip32.cpp")
    _check_chain(r, "TV1", BIP32_VECTOR1_SEED, BIP32_VECTOR1)
    _check_chain(r, "TV2", BIP32_VECTOR2_SEED, BIP32_VECTOR2)

    master = master_key(bytes.fromhex(ABANDON_SEED))
    for path, depth, parent_fp, k_hex, c_hex, pub_hex, _ in (BIP44_BTC, BIP44_ETH):
        node = derive_path(master, path)
        r.check(f"BIP-44 {path} clave privada", node.key.to_bytes(32, "big").hex(), k_hex, "test_bip32")
        r.check(f"BIP-44 {path} chain code", node.chain.hex(), c_hex, "test_bip32")
        r.check(f"BIP-44 {path} clave publica", node.pub.hex(), pub_hex, "test_bip32")
        r.check(f"BIP-44 {path} fingerprint padre", node.parent_fp, parent_fp, "test_bip32",
                literal=f"0x{parent_fp:08x}u")
        r.check(f"BIP-44 {path} profundidad", node.depth, depth)

    g = SECP_G
    r.check_true("G pertenece a secp256k1 (y^2 = x^3 + 7)", (g[1] ** 2 - g[0] ** 3 - 7) % SECP_P == 0)
    r.check("orden: n*G = infinito", point_mul(SECP_N), None)
    r.check("decompress(serP(G)) == G", decompress(ser_p(g)), g)


def verify_bitcoin(r: Report) -> None:
    r.section("Base58 / Base58Check / P2PKH  <->  src/crypto/base58.cpp, src/bitcoin/")
    for hex_in, expected in BASE58_VECTORS:
        r.check(f"Base58({hex_in or '<vacio>'})", b58encode(bytes.fromhex(hex_in)), expected,
                "test_bitcoin", literal=f'{{"{hex_in}", "{expected}"}}')
    for pub_hex, expected in P2PKH_VECTORS:
        r.check(f"P2PKH({pub_hex[:16]}...)", p2pkh_address(bytes.fromhex(pub_hex)), expected, "test_bitcoin")
    pub = BIP44_BTC[5]
    r.check(f"direccion BTC {BIP44_BTC[0]} (abandon...about)", p2pkh_address(bytes.fromhex(pub)), BIP44_BTC[6],
            "test_bitcoin")
    # Decode the address back: version 0x00 || HASH160(pub) || SHA256d(...)[0:4].
    raw = b58decode(BIP44_BTC[6])
    r.check("Base58Check decodificado: version || HASH160(pub)", raw[:21].hex(),
            "00" + hash160(bytes.fromhex(pub)).hex())
    r.check("Base58Check checksum = SHA256d(version || HASH160)[0:4]", sha256(sha256(raw[:21]))[:4].hex(),
            raw[21:].hex())


def verify_ethereum(r: Report) -> None:
    r.section("Ethereum: direccion y checksum EIP-55  <->  src/ethereum/ethereum.cpp")
    for vector in EIP55_VECTORS:
        r.check(f"EIP-55 {vector}", eip55(bytes.fromhex(vector[2:])), vector, "test_ethereum")
    g_pub = ser_p(SECP_G)
    x, y = decompress(g_pub)
    r.check("descompresion de G (04 || X || Y)", "04" + x.to_bytes(32, "big").hex() + y.to_bytes(32, "big").hex(),
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", "test_ethereum")
    r.check("direccion de la clave privada 1", eth_address(g_pub), ETH_G_ADDRESS, "test_ethereum")
    r.check(f"direccion ETH {BIP44_ETH[0]} (abandon...about)", eth_address(bytes.fromhex(BIP44_ETH[5])),
            BIP44_ETH[6], "test_ethereum")


def _label(msg: bytes) -> str:
    if len(msg) > 24 and len(set(msg)) == 1:
        return f"'{chr(msg[0])}' x {len(msg)}"
    if len(msg) > 24:
        return f"{len(msg)} bytes"
    try:
        return repr(msg.decode("ascii"))
    except UnicodeDecodeError:
        return msg.hex()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

GROUPS: Dict[str, Callable[[Report], None]] = {
    "sha256": verify_sha256,
    "ripemd160": verify_ripemd160,
    "keccak": verify_keccak,
    "bip39": verify_bip39,
    "bip32": verify_bip32,
    "bitcoin": verify_bitcoin,
    "ethereum": verify_ethereum,
}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Verificacion cruzada Python <-> firmware C++ de EntropySigner.")
    parser.add_argument("-v", "--verbose", action="store_true", help="muestra el valor calculado de cada check")
    parser.add_argument("--no-source-check", action="store_true",
                        help="no exigir que cada valor esperado figure en tests/*/test_main.cpp")
    parser.add_argument("--only", choices=sorted(GROUPS), action="append",
                        help="ejecuta solo los grupos indicados (repetible)")
    args = parser.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    print("EntropySigner - verificacion cruzada (Paso 18)")
    print(f"Python {sys.version.split()[0]} | repo: {REPO_ROOT}")
    report = Report(verbose=args.verbose, source_check=not args.no_source_check)
    for name in args.only or GROUPS:
        try:
            GROUPS[name](report)
        except Exception as exc:  # a crash in one group must not hide the others
            report.failed += 1
            print(f"  [FAIL] grupo '{name}' abortado: {type(exc).__name__}: {exc}")

    print()
    print("=" * 78)
    print(f" RESULTADO: {report.passed} PASS | {report.failed} FAIL | {report.skipped} SKIP")
    if report.source_check:
        print(f" Literales confirmados en tests/*.cpp: {report.literals_found}")
    print(" Conclusion: " + ("las implementaciones C++ y Python concuerdan bit a bit en todos los vectores."
                             if report.failed == 0 else "HAY DISCREPANCIAS - revisar los FAIL de arriba."))
    print("=" * 78)
    return 0 if report.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

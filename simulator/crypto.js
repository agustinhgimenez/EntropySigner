// EntropySigner simulator - crypto pipeline mirroring the firmware
// (src/entropy, src/bip39, src/bip32, src/bitcoin, src/ethereum).
// SHA-256, HMAC-SHA512 and PBKDF2 use WebCrypto; RIPEMD-160, Keccak-256,
// secp256k1 and Base58 are implemented here. Educational only: nothing here is
// constant-time and the browser is not a secure element.
(function () {
    "use strict";

    const subtle = window.crypto.subtle;
    const enc = new TextEncoder();

    // ------------------------------------------------------------ bytes ---

    function concat(...parts) {
        const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
        let off = 0;
        for (const p of parts) {
            out.set(p, off);
            off += p.length;
        }
        return out;
    }

    function toHex(bytes) {
        return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
    }

    function fromHex(hex) {
        const out = new Uint8Array(hex.length / 2);
        for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(2 * i, 2), 16);
        return out;
    }

    function bytesToBig(bytes) {
        return bytes.length ? BigInt("0x" + toHex(bytes)) : 0n;
    }

    function bigToBytes(n, len) {
        return fromHex(n.toString(16).padStart(2 * len, "0"));
    }

    function ser32(i) {
        return new Uint8Array([(i >>> 24) & 255, (i >>> 16) & 255, (i >>> 8) & 255, i & 255]);
    }

    // ------------------------------------------------------- WebCrypto ---

    async function sha256(data) {
        return new Uint8Array(await subtle.digest("SHA-256", data));
    }

    async function hmacSha512(key, data) {
        const k = await subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-512" }, false, ["sign"]);
        return new Uint8Array(await subtle.sign("HMAC", k, data));
    }

    async function pbkdf2Sha512(password, salt, iterations, length) {
        const k = await subtle.importKey("raw", password, "PBKDF2", false, ["deriveBits"]);
        const bits = await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-512", salt, iterations }, k, length * 8);
        return new Uint8Array(bits);
    }

    // ------------------------------------------------------- RIPEMD-160 ---

    const RMD_R = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
    ];
    const RMD_RP = [
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
    ];
    const RMD_S = [
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
    ];
    const RMD_SP = [
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
    ];
    const RMD_K = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
    const RMD_KP = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];

    function rmdF(j, x, y, z) {
        if (j < 16) return x ^ y ^ z;
        if (j < 32) return (x & y) | (~x & z);
        if (j < 48) return (x | ~y) ^ z;
        if (j < 64) return (x & z) | (y & ~z);
        return x ^ (y | ~z);
    }

    function rol(x, n) {
        return (x << n) | (x >>> (32 - n));
    }

    function ripemd160(msg) {
        const bitLen = msg.length * 8;
        const padLen = ((msg.length + 8) >> 6) * 64 + 64;
        const buf = new Uint8Array(padLen);
        buf.set(msg);
        buf[msg.length] = 0x80;
        const view = new DataView(buf.buffer);
        view.setUint32(padLen - 8, bitLen >>> 0, true);
        view.setUint32(padLen - 4, Math.floor(bitLen / 0x100000000), true);

        let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
        const X = new Array(16);
        for (let off = 0; off < padLen; off += 64) {
            for (let i = 0; i < 16; i++) X[i] = view.getUint32(off + 4 * i, true);
            let a = h0, b = h1, c = h2, d = h3, e = h4;
            let ap = h0, bp = h1, cp = h2, dp = h3, ep = h4;
            for (let j = 0; j < 80; j++) {
                const r = j >> 4;
                let t = (rol((a + rmdF(j, b, c, d) + X[RMD_R[j]] + RMD_K[r]) | 0, RMD_S[j]) + e) | 0;
                a = e; e = d; d = rol(c, 10); c = b; b = t;
                t = (rol((ap + rmdF(79 - j, bp, cp, dp) + X[RMD_RP[j]] + RMD_KP[r]) | 0, RMD_SP[j]) + ep) | 0;
                ap = ep; ep = dp; dp = rol(cp, 10); cp = bp; bp = t;
            }
            const t = (h1 + c + dp) | 0;
            h1 = (h2 + d + ep) | 0;
            h2 = (h3 + e + ap) | 0;
            h3 = (h4 + a + bp) | 0;
            h4 = (h0 + b + cp) | 0;
            h0 = t;
        }
        const out = new Uint8Array(20);
        const ov = new DataView(out.buffer);
        [h0, h1, h2, h3, h4].forEach((h, i) => ov.setUint32(4 * i, h >>> 0, true));
        return out;
    }

    // ------------------------------------------------------- Keccak-256 ---

    const MASK64 = (1n << 64n) - 1n;
    const KECCAK_RC = [
        0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
        0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
        0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
        0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
        0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
        0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
    ];
    // Rotation offsets indexed by x + 5y.
    const KECCAK_ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];

    function rot64(v, n) {
        return n === 0 ? v : ((v << BigInt(n)) | (v >> BigInt(64 - n))) & MASK64;
    }

    function keccakF(A) {
        const C = new Array(5);
        const B = new Array(25);
        for (let round = 0; round < 24; round++) {
            for (let x = 0; x < 5; x++) C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
            for (let x = 0; x < 5; x++) {
                const D = C[(x + 4) % 5] ^ rot64(C[(x + 1) % 5], 1);
                for (let y = 0; y < 25; y += 5) A[x + y] ^= D;
            }
            for (let x = 0; x < 5; x++) {
                for (let y = 0; y < 5; y++) {
                    B[y + 5 * ((2 * x + 3 * y) % 5)] = rot64(A[x + 5 * y], KECCAK_ROT[x + 5 * y]);
                }
            }
            for (let y = 0; y < 25; y += 5) {
                for (let x = 0; x < 5; x++) {
                    A[x + y] = B[x + y] ^ (~B[((x + 1) % 5) + y] & MASK64 & B[((x + 2) % 5) + y]);
                }
            }
            A[0] ^= KECCAK_RC[round];
        }
    }

    // Original Keccak padding (0x01), as used by Ethereum - not SHA3-256 (0x06).
    function keccak256(msg) {
        const rate = 136;
        const padLen = (Math.floor(msg.length / rate) + 1) * rate;
        const buf = new Uint8Array(padLen);
        buf.set(msg);
        buf[msg.length] ^= 0x01;
        buf[padLen - 1] ^= 0x80;
        const A = new Array(25).fill(0n);
        for (let off = 0; off < padLen; off += rate) {
            for (let i = 0; i < rate / 8; i++) {
                let lane = 0n;
                for (let b = 7; b >= 0; b--) lane = (lane << 8n) | BigInt(buf[off + 8 * i + b]);
                A[i] ^= lane;
            }
            keccakF(A);
        }
        const out = new Uint8Array(32);
        for (let i = 0; i < 4; i++) {
            let lane = A[i];
            for (let b = 0; b < 8; b++) {
                out[8 * i + b] = Number(lane & 0xffn);
                lane >>= 8n;
            }
        }
        return out;
    }

    // -------------------------------------------------------- secp256k1 ---

    const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
    const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
    const G = {
        x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
        y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
    };

    function mod(a, m) {
        const r = a % m;
        return r >= 0n ? r : r + m;
    }

    function inv(a, m) {
        let [r0, r1] = [mod(a, m), m];
        let [s0, s1] = [1n, 0n];
        while (r1 !== 0n) {
            const q = r0 / r1;
            [r0, r1] = [r1, r0 - q * r1];
            [s0, s1] = [s1, s0 - q * s1];
        }
        return mod(s0, m);
    }

    function pointAdd(p1, p2) {
        if (p1 === null) return p2;
        if (p2 === null) return p1;
        if (p1.x === p2.x && mod(p1.y + p2.y, P) === 0n) return null;
        const lambda =
            p1.x === p2.x
                ? mod(3n * p1.x * p1.x * inv(2n * p1.y, P), P)
                : mod((p2.y - p1.y) * inv(p2.x - p1.x, P), P);
        const x = mod(lambda * lambda - p1.x - p2.x, P);
        return { x, y: mod(lambda * (p1.x - x) - p1.y, P) };
    }

    function pointMul(k, point) {
        let result = null;
        let addend = point;
        while (k > 0n) {
            if (k & 1n) result = pointAdd(result, addend);
            addend = pointAdd(addend, addend);
            k >>= 1n;
        }
        return result;
    }

    function compressPoint(pt) {
        return concat(new Uint8Array([pt.y & 1n ? 0x03 : 0x02]), bigToBytes(pt.x, 32));
    }

    // ----------------------------------------------------------- Base58 ---

    const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    async function base58Check(version, payload) {
        const data = concat(new Uint8Array([version]), payload);
        const checksum = (await sha256(await sha256(data))).slice(0, 4);
        return base58Encode(concat(data, checksum));
    }

    function base58Encode(full) {
        let n = bytesToBig(full);
        let out = "";
        while (n > 0n) {
            out = B58[Number(n % 58n)] + out;
            n /= 58n;
        }
        for (let i = 0; i < full.length && full[i] === 0; i++) out = "1" + out;
        return out;
    }

    // ---------------------------------------------------------- entropy ---

    // Same construction as src/entropy/entropy_pool.cpp:
    // SHA-256(tag || 64 B TRNG || ldr_flag || LDR samples as uint16 LE).
    const ENTROPY_TAG = enc.encode("EntropySigner/entropy-pool/v1");
    const HW_RNG_BYTES = 64;

    function conditioningInput(rng, ldrSamples) {
        const flag = new Uint8Array([ldrSamples ? 1 : 0]);
        const ldrBytes = new Uint8Array(ldrSamples ? ldrSamples.length * 2 : 0);
        if (ldrSamples) {
            const dv = new DataView(ldrBytes.buffer);
            ldrSamples.forEach((s, i) => dv.setUint16(2 * i, s, true));
        }
        return { tag: ENTROPY_TAG, rng, flag, ldrBytes, all: concat(ENTROPY_TAG, rng, flag, ldrBytes) };
    }

    async function conditionEntropy(rng, ldrSamples) {
        return sha256(conditioningInput(rng, ldrSamples).all);
    }

    // ----------------------------------------------------------- BIP-39 ---

    async function entropyToMnemonic(entropy) {
        const words = window.BIP39_WORDLIST;
        const checksumBits = entropy.length / 4;
        const hash = await sha256(entropy);
        let bits = Array.from(entropy, (b) => b.toString(2).padStart(8, "0")).join("");
        bits += Array.from(hash, (b) => b.toString(2).padStart(8, "0")).join("").slice(0, checksumBits);
        const out = [];
        for (let i = 0; i < bits.length; i += 11) out.push(words[parseInt(bits.slice(i, i + 11), 2)]);
        return out.join(" ");
    }

    async function mnemonicToSeed(mnemonic, passphrase = "") {
        const pw = enc.encode(mnemonic.normalize("NFKD"));
        const salt = enc.encode(("mnemonic" + passphrase).normalize("NFKD"));
        return pbkdf2Sha512(pw, salt, 2048, 64);
    }

    // ----------------------------------------------------------- BIP-32 ---

    const HARDENED = 0x80000000;

    async function createMasterKey(seed) {
        const I = await hmacSha512(enc.encode("Bitcoin seed"), seed);
        const k = bytesToBig(I.slice(0, 32));
        if (k === 0n || k >= N) throw new Error("invalid master key");
        return { k, chain: I.slice(32) };
    }

    async function ckdPriv(node, index) {
        const data =
            index >= HARDENED
                ? concat(new Uint8Array([0]), bigToBytes(node.k, 32), ser32(index))
                : concat(compressPoint(pointMul(node.k, G)), ser32(index));
        const I = await hmacSha512(node.chain, data);
        const il = bytesToBig(I.slice(0, 32));
        const k = mod(il + node.k, N);
        if (il >= N || k === 0n) throw new Error("invalid child key");
        return { k, chain: I.slice(32) };
    }

    async function derivePath(master, path) {
        const parts = path.split("/");
        if (parts[0] !== "m") throw new Error("path must start with m");
        let node = master;
        for (const part of parts.slice(1)) {
            const hardened = part.endsWith("'");
            const index = parseInt(hardened ? part.slice(0, -1) : part, 10);
            node = await ckdPriv(node, hardened ? index + HARDENED : index);
        }
        return node;
    }

    // --------------------------------------------------------- addresses ---

    const BTC_PATH = "m/44'/0'/0'/0/0";
    const ETH_PATH = "m/44'/60'/0'/0/0";

    async function bitcoinAddress(master) {
        const node = await derivePath(master, BTC_PATH);
        const pub = compressPoint(pointMul(node.k, G));
        const id = ripemd160(await sha256(pub));
        return { address: await base58Check(0x00, id), publicKey: toHex(pub) };
    }

    function toChecksumAddress(addrBytes) {
        const hex = toHex(addrBytes);
        const hash = keccak256(enc.encode(hex));
        let out = "0x";
        for (let i = 0; i < 40; i++) {
            const nibble = i % 2 === 0 ? hash[i >> 1] >> 4 : hash[i >> 1] & 0x0f;
            out += nibble >= 8 ? hex[i].toUpperCase() : hex[i];
        }
        return out;
    }

    async function ethereumAddress(master) {
        const node = await derivePath(master, ETH_PATH);
        const pt = pointMul(node.k, G);
        const hash = keccak256(concat(bigToBytes(pt.x, 32), bigToBytes(pt.y, 32)));
        return { address: toChecksumAddress(hash.slice(12)), publicKey: toHex(compressPoint(pt)) };
    }

    // -------------------------------------------------------- self-test ---

    // Same vectors as tests/test_bip39, test_bitcoin and test_ethereum.
    async function selfTest() {
        const abandon = "abandon ".repeat(11) + "about";
        const results = [];
        const check = (name, got, expected) => results.push({ name, ok: got === expected, got, expected });

        check("RIPEMD-160(\"abc\")", toHex(ripemd160(enc.encode("abc"))), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
        check(
            "Keccak-256(\"\")",
            toHex(keccak256(new Uint8Array(0))),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        );
        check("BIP-39 entropia 0x00..00", await entropyToMnemonic(new Uint8Array(32)), "abandon ".repeat(23) + "art");
        const seed = await mnemonicToSeed(abandon);
        check(
            "BIP-39 seed \"abandon...about\"",
            toHex(seed),
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1" +
                "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
        );
        const master = await createMasterKey(seed);
        check("BTC " + BTC_PATH, (await bitcoinAddress(master)).address, "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA");
        check("ETH " + ETH_PATH, (await ethereumAddress(master)).address, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
        check("EIP-55 G (clave privada 1)", (() => {
            const pt = G;
            return toChecksumAddress(keccak256(concat(bigToBytes(pt.x, 32), bigToBytes(pt.y, 32))).slice(12));
        })(), "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
        return results;
    }

    window.ESCrypto = {
        BTC_PATH,
        ETH_PATH,
        HARDENED,
        HW_RNG_BYTES,
        curve: { P, N, G },
        toHex,
        fromHex,
        concat,
        bytesToBig,
        bigToBytes,
        ser32,
        sha256,
        hmacSha512,
        pbkdf2Sha512,
        ripemd160,
        keccak256,
        pointMul,
        compressPoint,
        base58Encode,
        toChecksumAddress,
        conditioningInput,
        ckdPriv,
        conditionEntropy,
        entropyToMnemonic,
        mnemonicToSeed,
        createMasterKey,
        bitcoinAddress,
        ethereumAddress,
        selfTest,
    };
})();

// EntropySigner simulator - port of src/ui/display.cpp + src/ui/wallet_ui.cpp
// to a 320x480 canvas. Layout constants, texts, colors and state transitions
// follow the firmware; keep both in sync when the UI changes.
(function () {
    "use strict";

    const WIDTH = 320;
    const HEIGHT = 480;

    // ---------------------------------------------------------- timing ---

    const BOOT_TIMEOUT_MS = 2500;
    const TAP_GUARD_MS = 250;
    const MNEMONIC_TIMEOUT_MS = 120000;
    const LDR_SAMPLE_PERIOD_MS = 40;
    const LDR_REDRAW_PERIOD_MS = 120;
    const LDR_GENERATION_SAMPLES = 128;

    // Approximate per-step time on an ESP32 @ 240 MHz (PBKDF2 dominates).
    const STEP_DELAY_MS = [80, 40, 1600, 60, 300, 300];

    // ---------------------------------------------------------- layout ---

    const BANNER_HEIGHT = 28;
    const MARGIN = 16;
    const WIDE_BUTTON = { x: 32, y: 412, w: 256, h: 52 };
    const LEFT_BUTTON = { x: MARGIN, y: 412, w: 136, h: 52 };
    const RIGHT_BUTTON = { x: 168, y: 412, w: 136, h: 52 };

    const CARD_TOP = 108;
    const CARD_HEIGHT = 214;
    const BAR_X = 32;
    const BAR_WIDTH = 256;
    const BAR_HEIGHT = 14;
    const VALUE_Y = 162;
    const LEVEL_BAR_Y = 192;
    const VARIATION_LABEL_Y = 234;
    const VARIATION_BAR_Y = 252;
    const ADC_MAX = 4095;
    const VARIATION_FULL_SCALE = 512;
    const LDR_WINDOW = 32;

    const QR_CENTER_Y = 215;
    const QR_BOX = 250;
    const QR_BYTE_CAPACITY_ECC_M = [14, 26, 42, 62, 84, 106];

    const PAL = {
        background: "#0B0F14",
        cyan: "#00E5FF",
        amber: "#FFC857",
        green: "#00FF9C",
        grey: "#8B98A5",
        surface: "#161F28",
    };

    // Approximations of the Adafruit GFX fonts bundled with LovyanGFX.
    const FONT = {
        sans9: '16px "Helvetica Neue", Helvetica, Arial, sans-serif',
        sansBold9: 'bold 16px "Helvetica Neue", Helvetica, Arial, sans-serif',
        sansBold12: 'bold 21px "Helvetica Neue", Helvetica, Arial, sans-serif',
        mono9: '18px "Courier New", Courier, monospace',
        monoBold9: 'bold 18px "Courier New", Courier, monospace',
    };

    const STEPS = [
        "Entropia 256 bits (RNG+LDR)",
        "BIP-39: 24 palabras",
        "PBKDF2-HMAC-SHA512 seed",
        "BIP-32 master key",
        "BTC  m/44'/0'/0'/0/0",
        "ETH  m/44'/60'/0'/0/0",
    ];

    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const contains = (b, x, y) => x >= b.x && x < b.x + b.w && y >= b.y && y < b.y + b.h;

    function create(canvas, hw) {
        const ES = window.ESCrypto;
        const dpr = window.devicePixelRatio || 1;
        canvas.width = WIDTH * dpr;
        canvas.height = HEIGHT * dpr;
        const lcd = canvas.getContext("2d");
        lcd.setTransform(dpr, 0, 0, dpr, 0, 0);

        let state = "BOOT";
        let stateEnteredMs = 0;
        let pendingTap = null;
        let busy = false;
        let session = { mnemonic: "", btc: "", eth: "" };
        let error = "";
        let ldr = { window: new Array(LDR_WINDOW).fill(0), count: 0, next: 0, lastSample: 0, lastRedraw: 0 };

        // ----------------------------------------------------- primitives ---

        function fillRect(x, y, w, h, color) {
            lcd.fillStyle = color;
            lcd.fillRect(x, y, w, h);
        }

        function roundRectPath(x, y, w, h, r) {
            lcd.beginPath();
            lcd.roundRect(x, y, w, h, r);
        }

        function fillRoundRect(x, y, w, h, r, color) {
            roundRectPath(x, y, w, h, r);
            lcd.fillStyle = color;
            lcd.fill();
        }

        function drawRoundRect(x, y, w, h, r, color) {
            roundRectPath(x + 0.5, y + 0.5, w - 1, h - 1, r);
            lcd.strokeStyle = color;
            lcd.lineWidth = 1;
            lcd.stroke();
        }

        function drawString(text, x, y, font, color, align = "center") {
            lcd.font = font;
            lcd.fillStyle = color;
            lcd.textAlign = align;
            lcd.textBaseline = "middle";
            lcd.fillText(text, x, y);
        }

        function drawFrame() {
            fillRect(0, 0, WIDTH, HEIGHT, PAL.background);
            if (hw.demoMode) {
                fillRect(0, 0, WIDTH, BANNER_HEIGHT, PAL.amber);
                drawString("DEMO MODE", WIDTH / 2, BANNER_HEIGHT / 2, FONT.sansBold9, PAL.background);
            }
        }

        function drawTitle(title, subtitle, color) {
            drawString(title, WIDTH / 2, 52, FONT.sansBold12, color);
            if (subtitle) drawString(subtitle, WIDTH / 2, 80, FONT.sans9, PAL.grey);
        }

        function drawButton(b, label, accent) {
            fillRoundRect(b.x, b.y, b.w, b.h, 10, PAL.surface);
            drawRoundRect(b.x, b.y, b.w, b.h, 10, accent);
            drawRoundRect(b.x + 1, b.y + 1, b.w - 2, b.h - 2, 9, accent);
            drawString(label, b.x + b.w / 2, b.y + b.h / 2, FONT.sansBold9, accent);
        }

        function drawBar(y, value, fullScale, color) {
            value = Math.min(value, fullScale);
            const filled = Math.floor((value * BAR_WIDTH) / fullScale);
            fillRect(BAR_X, y, filled, BAR_HEIGHT, color);
            fillRect(BAR_X + filled, y, BAR_WIDTH - filled, BAR_HEIGHT, PAL.background);
            lcd.strokeStyle = PAL.grey;
            lcd.lineWidth = 1;
            lcd.strokeRect(BAR_X - 1 + 0.5, y - 1 + 0.5, BAR_WIDTH + 1, BAR_HEIGHT + 1);
        }

        function pollTap(now) {
            const tap = pendingTap;
            pendingTap = null;
            if (!tap || !hw.touchDetected || now - stateEnteredMs < TAP_GUARD_MS) return null;
            return tap;
        }

        // -------------------------------------------------------- screens ---

        function showBootScreen() {
            const cx = WIDTH / 2;
            fillRect(0, 0, WIDTH, HEIGHT, PAL.background);
            if (hw.demoMode) {
                fillRect(0, 0, WIDTH, 28, PAL.amber);
                drawString("DEMO MODE", cx, 14, FONT.sansBold9, PAL.background);
            }
            drawString("ENTROPYSIGNER", cx, 170, FONT.sansBold12, PAL.cyan);
            drawString("SECURE HARDWARE WALLET", cx, 210, FONT.sans9, PAL.grey);
            drawString("ESP32-S3", cx, 240, FONT.sans9, PAL.grey);
            fillRect(cx - 60, 270, 120, 3, PAL.cyan);
            drawString("BOOT OK", cx, 310, FONT.sansBold12, PAL.green);
            drawString(hw.touchDetected ? "Touch: detected" : "Touch: not detected", cx, 350, FONT.sans9, PAL.grey);
            drawString(`v0.1.0  |  ${hw.demoMode ? "DEMO" : "PRODUCTION"}`, cx, HEIGHT - 20, FONT.sans9, PAL.grey);
        }

        function drawIdle() {
            drawFrame();
            drawTitle("ENTROPYSIGNER", "Wallet offline BIP-39 / BIP-44", PAL.cyan);
            fillRoundRect(MARGIN, CARD_TOP, WIDTH - 2 * MARGIN, CARD_HEIGHT, 12, PAL.surface);
            drawString("SENSOR LDR  -  ADC1_CH0", BAR_X, CARD_TOP + 22, FONT.sans9, PAL.grey, "left");
            drawString("VARIACION AMBIENTAL", BAR_X, VARIATION_LABEL_Y, FONT.sans9, PAL.grey, "left");
            drawString("Pasa la mano sobre el sensor", BAR_X, CARD_TOP + CARD_HEIGHT - 22, FONT.sans9, PAL.grey, "left");
            drawString("Fuente principal: RNG de hardware", WIDTH / 2, 348, FONT.sans9, PAL.grey);
            drawString("LDR: fuente adicional + SHA-256", WIDTH / 2, 372, FONT.sans9, PAL.grey);
            drawButton(WIDE_BUTTON, "GENERAR WALLET", PAL.green);
            ldr = { window: new Array(LDR_WINDOW).fill(0), count: 0, next: 0, lastSample: 0, lastRedraw: 0 };
        }

        function refreshIdleSensor(now) {
            if (now - ldr.lastSample >= LDR_SAMPLE_PERIOD_MS) {
                ldr.lastSample = now;
                ldr.window[ldr.next] = hw.readLdrRaw();
                ldr.next = (ldr.next + 1) % LDR_WINDOW;
                if (ldr.count < LDR_WINDOW) ldr.count++;
            }
            if (ldr.count === 0 || now - ldr.lastRedraw < LDR_REDRAW_PERIOD_MS) return;
            ldr.lastRedraw = now;

            const latest = ldr.window[(ldr.next + LDR_WINDOW - 1) % LDR_WINDOW];
            const samples = ldr.window.slice(0, ldr.count);
            const variation = Math.max(...samples) - Math.min(...samples);

            fillRect(BAR_X, VALUE_Y - 16, BAR_WIDTH, 32, PAL.surface);
            drawString(String(latest), BAR_X, VALUE_Y, FONT.sansBold12, PAL.cyan, "left");
            drawString("/ 4095", BAR_X + 70, VALUE_Y, FONT.sans9, PAL.grey, "left");
            drawBar(LEVEL_BAR_Y, latest, ADC_MAX, PAL.cyan);

            fillRect(BAR_X + 190, VARIATION_LABEL_Y - 10, BAR_WIDTH - 190, 20, PAL.surface);
            drawString(String(variation), BAR_X + BAR_WIDTH, VARIATION_LABEL_Y, FONT.sans9, PAL.green, "right");
            drawBar(VARIATION_BAR_Y, variation, VARIATION_FULL_SCALE, PAL.green);
        }

        function drawGeneratingStep(index, label, status, color) {
            const y = 130 + index * 40;
            fillRect(MARGIN, y - 14, WIDTH - 2 * MARGIN, 28, PAL.background);
            drawString(label, MARGIN + 8, y, FONT.sans9, PAL.grey, "left");
            drawString(status, WIDTH - MARGIN - 8, y, FONT.sansBold9, color, "right");
        }

        function drawGenerating() {
            drawFrame();
            drawTitle("GENERANDO WALLET", "No apagues el dispositivo", PAL.cyan);
        }

        async function generateWallet() {
            STEPS.forEach((s, i) => drawGeneratingStep(i, s, "...", PAL.grey));
            let step = 0;
            const ok = async () => {
                await sleep(STEP_DELAY_MS[step]);
                drawGeneratingStep(step, STEPS[step], "OK", PAL.green);
                step++;
            };
            try {
                // LDR first, then RNG, as in entropy_pool.cpp.
                const { ldr: samples, rng, origin } = await hw.getEntropySources(LDR_GENERATION_SAMPLES);
                const entropy = await ES.conditionEntropy(rng, samples);
                await ok();
                session.mnemonic = await ES.entropyToMnemonic(entropy);
                await ok();
                const seed = await ES.mnemonicToSeed(session.mnemonic);
                await ok();
                const master = await ES.createMasterKey(seed);
                await ok();
                const btc = await ES.bitcoinAddress(master);
                session.btc = btc.address;
                await ok();
                const eth = await ES.ethereumAddress(master);
                session.eth = eth.address;
                await ok();
                hw.inspect({
                    origin,
                    ldrSamples: samples,
                    rng: ES.toHex(rng),
                    entropy: ES.toHex(entropy),
                    mnemonic: session.mnemonic,
                    seed: ES.toHex(seed),
                    btcPub: btc.publicKey,
                    ethPub: eth.publicKey,
                    btc: session.btc,
                    eth: session.eth,
                });
                entropy.fill(0);
                rng.fill(0);
                seed.fill(0);
                return true;
            } catch (e) {
                hw.log(`[SIM] ${e.message}`);
                drawGeneratingStep(step, STEPS[step], "FALLO", PAL.amber);
                wipeSession();
                error = e.screenText || STEPS[step];
                return false;
            }
        }

        function drawBackupWarning() {
            drawFrame();
            drawTitle("ATENCION", "Backup de la frase de recuperacion", PAL.amber);
            const lines = [
                "Vas a ver las 24 palabras que",
                "controlan esta wallet.",
                "",
                "- Que nadie mire la pantalla.",
                "- No saques fotos ni capturas.",
                "- Anotalas en papel, en orden.",
                "- No se guardan en el equipo:",
                "  si las perdes, perdes los fondos.",
            ];
            fillRoundRect(MARGIN, 108, WIDTH - 2 * MARGIN, 270, 12, PAL.surface);
            let y = 136;
            for (const line of lines) {
                drawString(line, MARGIN + 14, y, FONT.sans9, line[0] === "-" ? PAL.amber : PAL.grey, "left");
                y += 30;
            }
            drawButton(LEFT_BUTTON, "CANCELAR", PAL.grey);
            drawButton(RIGHT_BUTTON, "MOSTRAR", PAL.amber);
        }

        function drawMnemonic() {
            drawFrame();
            drawTitle("FRASE DE RECUPERACION", "Anota las 24 palabras en orden", PAL.amber);
            const words = session.mnemonic.split(" ");
            const rows = 12;
            const columnX = [28, 172];
            words.forEach((word, i) => {
                const x = columnX[Math.floor(i / rows)];
                const y = 108 + (i % rows) * 24;
                drawString(String(i + 1).padStart(2, "0"), x, y, FONT.mono9, PAL.grey, "left");
                drawString(word, x + 30, y, FONT.monoBold9, PAL.cyan, "left");
            });
            drawButton(WIDE_BUTTON, "YA LAS ANOTE", PAL.green);
        }

        function renderQr(text, cx, cy, box) {
            const version = QR_BYTE_CAPACITY_ECC_M.findIndex((cap) => text.length <= cap) + 1;
            if (version === 0 || typeof window.qrcode !== "function") return false;
            const qr = window.qrcode(version, "M");
            qr.addData(text, "Byte");
            qr.make();
            const size = qr.getModuleCount();
            let quiet = 4;
            let scale = Math.floor(box / (size + 2 * quiet));
            if (scale < 2) {
                quiet = 2;
                scale = Math.floor(box / (size + 2 * quiet));
            }
            if (scale < 1) return false;
            const side = (size + 2 * quiet) * scale;
            const left = Math.floor(cx - side / 2);
            const top = Math.floor(cy - side / 2);
            fillRect(left, top, side, side, "#FFFFFF");
            for (let y = 0; y < size; y++) {
                for (let x = 0; x < size; x++) {
                    if (qr.isDark(y, x)) {
                        fillRect(left + (quiet + x) * scale, top + (quiet + y) * scale, scale, scale, "#000000");
                    }
                }
            }
            return true;
        }

        function drawAddress(title, path, address, accent) {
            drawFrame();
            drawTitle(title, path, accent);
            if (!renderQr(address, WIDTH / 2, QR_CENTER_Y, QR_BOX)) {
                drawString("QR no disponible", WIDTH / 2, QR_CENTER_Y, FONT.sans9, PAL.amber);
            }
            const half = Math.ceil(address.length / 2);
            drawString(address.slice(0, half), WIDTH / 2, 360, FONT.mono9, PAL.cyan);
            drawString(address.slice(half), WIDTH / 2, 382, FONT.mono9, PAL.cyan);
        }

        function drawBtc() {
            drawAddress("BITCOIN", ES.BTC_PATH, session.btc, PAL.amber);
            drawButton(LEFT_BUTTON, "TERMINAR", PAL.grey);
            drawButton(RIGHT_BUTTON, "ETHEREUM >", PAL.cyan);
        }

        function drawEth() {
            drawAddress("ETHEREUM", ES.ETH_PATH, session.eth, PAL.cyan);
            drawButton(LEFT_BUTTON, "< BITCOIN", PAL.amber);
            drawButton(RIGHT_BUTTON, "TERMINAR", PAL.grey);
        }

        function drawError() {
            drawFrame();
            drawTitle("ERROR", "No se pudo generar la wallet", PAL.amber);
            drawString("Fallo en el paso:", WIDTH / 2, 200, FONT.sans9, PAL.grey);
            drawString(error, WIDTH / 2, 228, FONT.sans9, PAL.amber);
            drawString("Ningun secreto quedo en memoria.", WIDTH / 2, 280, FONT.sans9, PAL.grey);
            drawButton(WIDE_BUTTON, "VOLVER", PAL.cyan);
        }

        // ---------------------------------------------------- transitions ---

        function wipeSession() {
            session = { mnemonic: "", btc: "", eth: "" };
            hw.inspect(null);
        }

        function enterState(next) {
            if (state === "SHOW_MNEMONIC" && next !== "SHOW_MNEMONIC") {
                session.mnemonic = "";
                hw.inspect({ mnemonicWiped: true });
            }
            if (next === "IDLE") wipeSession();
            state = next;
            hw.log(`[ES] UI state: ${next}`);
            hw.onState(next);
            ({
                IDLE: drawIdle,
                GENERATING: drawGenerating,
                BACKUP_WARNING: drawBackupWarning,
                SHOW_MNEMONIC: drawMnemonic,
                SHOW_BTC: drawBtc,
                SHOW_ETH: drawEth,
                ERROR: drawError,
            })[next]?.();
            stateEnteredMs = performance.now();
        }

        // --------------------------------------------------------- public ---

        function boot() {
            state = "BOOT";
            pendingTap = null;
            busy = false;
            hw.log("[ES] ==============================");
            hw.log("[ES] ENTROPYSIGNER v0.1.0");
            hw.log(`[ES] SECURE HARDWARE WALLET | ESP32 | mode: ${hw.demoMode ? "DEMO" : "PRODUCTION"}`);
            hw.log("[ES] ==============================");
            hw.log("[ES] Initializing...");
            hw.log("[ES] Chip: ESP32-D0WD-V3 rev 3, 2 cores @ 240 MHz");
            hw.log("[ES] Flash: 4096 KB");
            hw.log("[ES] PSRAM: 0 KB");
            hw.log("[ES] Display: initialized");
            hw.log(`[ES] Touch: ${hw.touchDetected ? "detected (FT6336U @ 0x38)" : "not detected"}`);
            if (!hw.touchDetected) hw.log("[ES] Wallet UI: no touch, the flow stops at IDLE");
            wipeSession();
            showBootScreen();
            hw.log("[ES] BOOT OK");
            hw.onState("BOOT");
            stateEnteredMs = performance.now();
        }

        function tap(x, y) {
            pendingTap = { x, y };
        }

        function loop(now) {
            if (busy) return;
            const t = pollTap(now);
            switch (state) {
                case "BOOT":
                    if (t || now - stateEnteredMs >= BOOT_TIMEOUT_MS) enterState("IDLE");
                    break;
                case "IDLE":
                    refreshIdleSensor(now);
                    if (t && contains(WIDE_BUTTON, t.x, t.y)) enterState("GENERATING");
                    break;
                case "GENERATING":
                    busy = true;
                    generateWallet().then((ok) => {
                        busy = false;
                        if (ok) {
                            hw.log(
                                hw.demoMode
                                    ? `[ES] Wallet generated. BTC ${session.btc} | ETH ${session.eth}`
                                    : "[ES] Wallet generated successfully.",
                            );
                            enterState("BACKUP_WARNING");
                        } else {
                            hw.log(`[ES] Wallet generation failed at: ${error}`);
                            enterState("ERROR");
                        }
                        pendingTap = null;
                    });
                    break;
                case "BACKUP_WARNING":
                    if (now - stateEnteredMs >= MNEMONIC_TIMEOUT_MS) {
                        hw.log("[ES] Backup warning screen timed out, wiping session");
                        enterState("IDLE");
                    } else if (t && contains(LEFT_BUTTON, t.x, t.y)) enterState("IDLE");
                    else if (t && contains(RIGHT_BUTTON, t.x, t.y)) enterState("SHOW_MNEMONIC");
                    break;
                case "SHOW_MNEMONIC":
                    if (now - stateEnteredMs >= MNEMONIC_TIMEOUT_MS) {
                        hw.log("[ES] Mnemonic screen timed out, wiping session");
                        enterState("IDLE");
                    } else if (t && contains(WIDE_BUTTON, t.x, t.y)) enterState("SHOW_BTC");
                    break;
                case "SHOW_BTC":
                    if (t && contains(LEFT_BUTTON, t.x, t.y)) enterState("IDLE");
                    else if (t && contains(RIGHT_BUTTON, t.x, t.y)) enterState("SHOW_ETH");
                    break;
                case "SHOW_ETH":
                    if (t && contains(LEFT_BUTTON, t.x, t.y)) enterState("SHOW_BTC");
                    else if (t && contains(RIGHT_BUTTON, t.x, t.y)) enterState("IDLE");
                    break;
                case "ERROR":
                    if (t && contains(WIDE_BUTTON, t.x, t.y)) enterState("IDLE");
                    break;
            }
        }

        function timeoutRemainingMs(now) {
            if (state !== "BACKUP_WARNING" && state !== "SHOW_MNEMONIC") return null;
            return Math.max(0, MNEMONIC_TIMEOUT_MS - (now - stateEnteredMs));
        }

        return { boot, tap, loop, timeoutRemainingMs, get state() { return state; }, WIDTH, HEIGHT };
    }

    window.ESFirmware = { create };
})();

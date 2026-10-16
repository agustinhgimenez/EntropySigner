// EntropySigner - connection to the real ESP32 over USB (Web Serial API, Chrome/Edge/Brave).
// Speaks the DEMO-only protocol of src/system/demo_console.cpp to pull raw HW RNG
// bytes and LDR readings. Wallets are still assembled in the browser.
(function () {
    "use strict";

    const BAUD = 115200;
    const MAX_RNG_PER_REQUEST = 1024;
    const MAX_LDR_PER_REQUEST = 512;
    const PING_ATTEMPTS = 12;
    const PING_INTERVAL_MS = 400;

    let port = null;
    let reader = null;
    let info = null;
    let rxBuffer = "";
    let pending = null;
    let queue = Promise.resolve();
    const lineListeners = [];
    const statusListeners = [];

    const supported = () => "serial" in navigator;
    const connected = () => info !== null;
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

    function emitStatus() {
        statusListeners.forEach((fn) => fn(info));
    }

    function handleLine(line) {
        lineListeners.forEach((fn) => fn(line));
        if (pending && (line.startsWith(pending.prefix) || line.startsWith("ES:ERR"))) {
            const p = pending;
            pending = null;
            clearTimeout(p.timer);
            if (line.startsWith("ES:ERR")) p.reject(new Error("ESP32: " + line.slice(7)));
            else p.resolve(line.slice(p.prefix.length).trim());
        }
    }

    async function readLoop() {
        const decoder = new TextDecoder();
        try {
            for (;;) {
                const { value, done } = await reader.read();
                if (done) break;
                rxBuffer += decoder.decode(value, { stream: true });
                let nl;
                while ((nl = rxBuffer.indexOf("\n")) >= 0) {
                    handleLine(rxBuffer.slice(0, nl).replace(/\r$/, ""));
                    rxBuffer = rxBuffer.slice(nl + 1);
                }
            }
        } catch (e) {
            // Unplugged or port closed: fall through to cleanup.
        }
        await cleanup();
    }

    async function cleanup() {
        const wasConnected = connected();
        info = null;
        if (pending) {
            clearTimeout(pending.timer);
            pending.reject(new Error("La ESP32 se desconectó."));
            pending = null;
        }
        try { reader && reader.releaseLock(); } catch (e) { /* already released */ }
        try { port && (await port.close()); } catch (e) { /* already closed */ }
        reader = null;
        port = null;
        rxBuffer = "";
        if (wasConnected) emitStatus();
    }

    // One command at a time; resolves with the payload after `prefix`.
    function request(command, prefix, timeoutMs) {
        const run = () => new Promise((resolve, reject) => {
            if (!port || !port.writable) {
                reject(new Error("La ESP32 no está conectada."));
                return;
            }
            pending = {
                prefix,
                resolve,
                reject,
                timer: setTimeout(() => {
                    pending = null;
                    reject(new Error(`La ESP32 no respondió a ${command} (¿firmware DEMO cargado?).`));
                }, timeoutMs),
            };
            const writer = port.writable.getWriter();
            writer.write(new TextEncoder().encode(command + "\n")).finally(() => writer.releaseLock());
        });
        const result = queue.then(run, run);
        queue = result.catch(() => {});
        return result;
    }

    // `chosen` is a port the user already authorized (auto-reconnect); otherwise the picker opens.
    async function connect(chosen) {
        if (!supported()) throw new Error("Este navegador no soporta Web Serial: usá Chrome, Edge o Brave.");
        if (connected()) return info;
        if (port) throw new Error("Ya hay una conexión en curso.");
        port = chosen || (await navigator.serial.requestPort());
        try {
            await port.open({ baudRate: BAUD });
        } catch (e) {
            port = null;
            throw new Error("No se pudo abrir el puerto. ¿Está abierto en otra pestaña o en el monitor de PlatformIO?");
        }
        reader = port.readable.getReader();
        readLoop();
        // Opening the port may reset the board: retry while it boots.
        for (let i = 0; i < PING_ATTEMPTS; i++) {
            try {
                const pong = await request("ES:PING", "ES:PONG", PING_INTERVAL_MS);
                const [version, mode, ...chip] = pong.split(" ");
                info = { version, mode, chip: chip.join(" ") };
                emitStatus();
                return info;
            } catch (e) {
                if (!port) break;
                await sleep(100);
            }
        }
        await cleanup();
        throw new Error("La placa no responde al protocolo DEMO. Cargá el firmware actualizado con «pio run -t upload».");
    }

    async function disconnect() {
        try { reader && (await reader.cancel()); } catch (e) { /* ignore */ }
        await cleanup();
    }

    async function getRng(bytes, onProgress) {
        const out = new Uint8Array(bytes);
        for (let off = 0; off < bytes; off += MAX_RNG_PER_REQUEST) {
            const n = Math.min(MAX_RNG_PER_REQUEST, bytes - off);
            const hex = await request(`ES:RNG ${n}`, "ES:RNG", 5000);
            if (hex.length !== 2 * n || !/^[0-9a-f]+$/.test(hex)) throw new Error("Respuesta RNG inválida de la ESP32.");
            for (let i = 0; i < n; i++) out[off + i] = parseInt(hex.substr(2 * i, 2), 16);
            onProgress && onProgress(off + n, bytes);
        }
        return out;
    }

    async function getLdr(samples, delayUs = 200, onProgress) {
        const out = new Uint16Array(samples);
        for (let off = 0; off < samples; off += MAX_LDR_PER_REQUEST) {
            const n = Math.min(MAX_LDR_PER_REQUEST, samples - off);
            const values = (await request(`ES:LDR ${n} ${delayUs}`, "ES:LDR", 8000)).split(",").map(Number);
            if (values.length !== n || values.some((v) => !Number.isInteger(v) || v < 0 || v > 4095)) {
                throw new Error("Respuesta LDR inválida de la ESP32.");
            }
            out.set(values, off);
            onProgress && onProgress(off + n, samples);
        }
        return out;
    }

    // Ports authorized once are remembered by the browser: reconnect on page load and on plug-in.
    async function autoConnect() {
        if (!supported() || connected() || port) return null;
        for (const p of await navigator.serial.getPorts()) {
            try {
                return await connect(p);
            } catch (e) {
                // Not an EntropySigner, busy in another tab, or old firmware: try the next one.
            }
        }
        return null;
    }

    if (supported()) {
        navigator.serial.addEventListener("disconnect", (e) => {
            if (e.target === port) cleanup();
        });
        navigator.serial.addEventListener("connect", () => setTimeout(autoConnect, 500));
    }

    window.ESDevice = {
        supported,
        connected,
        get info() { return info; },
        connect,
        autoConnect,
        disconnect,
        getRng,
        getLdr,
        onLine: (fn) => lineListeners.push(fn),
        onStatus: (fn) => statusListeners.push(fn),
    };
})();

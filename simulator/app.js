// EntropySigner simulator - simulated hardware around the firmware port:
// touch panel, EN button, serial monitor, inspector and the USB link to the real ESP32.
(function () {
    "use strict";

    const $ = (id) => document.getElementById(id);
    const dev = window.ESDevice;

    // The firmware's entropy comes only from the ESP32 hardware RNG, so without
    // the board there is nothing to generate a wallet from.
    async function getRngBytes() {
        if (!dev.connected()) {
            throw Object.assign(new Error("Sin ESP32 conectada por USB: no hay entropía real, no se genera la wallet."),
                { screenText: "Conecte la ESP32 por USB" });
        }
        const rng = await dev.getRng(window.ESCrypto.HW_RNG_BYTES);
        log(`[USB] ${rng.length} bytes del RNG de hardware recibidos de la ESP32`, "dev");
        return rng;
    }

    // ---------------------------------------------------------- serial ---

    const serial = $("serial");

    function log(text, cls) {
        const line = document.createElement("div");
        line.textContent = text;
        if (cls) line.className = cls;
        serial.appendChild(line);
        while (serial.childElementCount > 400) serial.firstChild.remove();
        serial.scrollTop = serial.scrollHeight;
    }

    // ------------------------------------------------------- inspector ---

    let inspectorData = null;

    // Shared with laboratorio.html (same file:// origin), which re-renders on the "storage" event.
    const LAB_KEY = "entropysigner.simulator.wallet";

    function publishToLab(d) {
        try {
            if (d) {
                localStorage.setItem(LAB_KEY, JSON.stringify({ entropy: d.entropy, rng: d.rng }));
            } else {
                localStorage.removeItem(LAB_KEY);
            }
        } catch (e) {
            // localStorage unavailable (some browsers isolate file:// pages): the URL link still works.
        }
    }

    function inspect(data) {
        if (data === null) {
            if (inspectorData) publishToLab(null);
            inspectorData = null;
        } else if (data.mnemonicWiped) {
            if (inspectorData) inspectorData.mnemonicWiped = true;
        } else {
            inspectorData = data;
            publishToLab(data);
        }
        renderInspector();
    }

    function labUrl(d) {
        return d ? `laboratorio.html#entropia=${d.entropy}&rng=${d.rng}` : "laboratorio.html";
    }

    function renderInspector() {
        const root = $("inspector");
        $("lab-link").href = labUrl(inspectorData);
        $("lab-link").title = inspectorData
            ? "Abre el paso a paso de la wallet generada en la pantalla"
            : "No hay wallet en memoria: el laboratorio va a generar una propia";
        if (!inspectorData) {
            root.innerHTML = '<p class="empty">Gener&aacute; una wallet para ver los valores intermedios. ' +
                "Al volver a IDLE (por TERMINAR, CANCELAR o a los 2 minutos en las pantallas de la frase) " +
                "la sesi&oacute;n se borra, igual que en el firmware, y el laboratorio ya no puede mostrar esa wallet.</p>";
            return;
        }
        const d = inspectorData;
        const rows = [
            ["Origen de la entropía", "RNG de hardware de la ESP32, recibido por USB", ""],
            ["RNG de hardware (64 bytes)", d.rng, "secret"],
            ["Entropía (256 bits)", d.entropy, "secret"],
            ["Frase (24 palabras)", d.mnemonicWiped ? "borrada de RAM al salir de la pantalla" : d.mnemonic,
                d.mnemonicWiped ? "wiped" : "secret"],
            ["Seed BIP-39 (512 bits)", d.seed, "secret"],
            ["Pubkey BTC", d.btcPub, ""],
            ["Dirección BTC", d.btc, ""],
            ["Pubkey ETH", d.ethPub, ""],
            ["Dirección ETH", d.eth, ""],
        ];
        const dl = document.createElement("dl");
        for (const [k, v, cls] of rows) {
            const dt = document.createElement("dt");
            dt.textContent = k;
            const dd = document.createElement("dd");
            dd.textContent = v;
            if (cls) dd.className = cls;
            dl.append(dt, dd);
        }
        const link = document.createElement("a");
        link.href = labUrl(d);
        link.target = "_blank";
        link.textContent = "Ver el paso a paso de esta wallet en el laboratorio →";
        root.replaceChildren(dl, link);
    }

    // -------------------------------------------------------- firmware ---

    const hw = {
        touchDetected: $("touch").checked,
        demoMode: $("demo").checked,
        getRngBytes,
        log: (t) => log(t),
        inspect,
        onState: (s) => ($("state").textContent = s),
    };

    const canvas = $("lcd");
    const fw = window.ESFirmware.create(canvas, hw);

    function reset() {
        hw.touchDetected = $("touch").checked;
        hw.demoMode = $("demo").checked;
        log("");
        log("ets Jul 29 2019 12:21:46", "sys");
        log("rst:0x1 (POWERON_RESET),boot:0x13 (SPI_FAST_FLASH_BOOT)", "sys");
        fw.boot();
    }

    canvas.addEventListener("pointerdown", (e) => {
        const rect = canvas.getBoundingClientRect();
        fw.tap(((e.clientX - rect.left) / rect.width) * fw.WIDTH, ((e.clientY - rect.top) / rect.height) * fw.HEIGHT);
    });
    $("btn-en").addEventListener("click", reset);
    $("touch").addEventListener("change", () => {
        log("-- cambio de hardware: reiniciando la placa --", "sys");
        reset();
    });
    $("demo").addEventListener("change", () => {
        log("-- firmware recompilado en modo " + ($("demo").checked ? "DEMO" : "PRODUCTION") + " --", "sys");
        reset();
    });

    $("selftest").addEventListener("click", async () => {
        log("-- verificación con los vectores de tests/ --", "sys");
        try {
            for (const r of await window.ESCrypto.selfTest()) {
                log(`${r.ok ? "PASS" : "FAIL"}  ${r.name}`, r.ok ? "ok" : "fail");
                if (!r.ok) log(`      esperado ${r.expected}\n      obtenido ${r.got}`, "fail");
            }
        } catch (e) {
            log("ERROR " + e.message, "fail");
        }
    });

    // ------------------------------------------------------ real ESP32 ---

    function renderDevice(info) {
        const status = $("dev-status");
        const btn = $("connect");
        if (info) {
            status.className = "dev-status real";
            status.innerHTML = `Entrop&iacute;a: <b>ESP32 REAL</b> &middot; ${info.chip} &middot; firmware ${info.version} ${info.mode}`;
            btn.textContent = "Desconectar ESP32";
        } else {
            status.className = "dev-status sim";
            status.innerHTML = dev.supported()
                ? "<b>ESP32 no conectada</b> &middot; la primera vez apret&aacute; el bot&oacute;n y eleg&iacute; el puerto COM; despu&eacute;s se reconecta sola al enchufarla"
                : "Este navegador no tiene Web Serial: us&aacute; Chrome o Edge para conectar la ESP32";
            btn.textContent = "Conectar ESP32 real (USB)";
            btn.disabled = !dev.supported();
        }
    }

    $("connect").addEventListener("click", async () => {
        const btn = $("connect");
        btn.disabled = true;
        try {
            if (dev.connected()) {
                await dev.disconnect();
            } else {
                $("dev-status").textContent = "Conectando... (si la placa se reinicia tarda unos segundos)";
                await dev.connect();
            }
        } catch (e) {
            if (e.name !== "NotFoundError") log("[USB] " + e.message, "fail"); // NotFoundError: picker cancelled
            renderDevice(null);
            if (e.name !== "NotFoundError") {
                $("dev-status").className = "dev-status err";
                $("dev-status").textContent = e.message;
            }
        } finally {
            btn.disabled = !dev.supported();
        }
    });

    dev.onStatus((info) => {
        renderDevice(info);
        if (info) log(`[USB] conectado: EntropySigner ${info.version} ${info.mode} en ${info.chip}`, "ok");
        else log("[USB] ESP32 desconectada: no se pueden generar wallets hasta reconectarla", "fail");
    });

    // Raw ES:RNG payloads are summarized by getRngBytes; boot logs and errors are shown.
    dev.onLine((line) => {
        if (/^ES:(RNG|PONG) /.test(line) || line === "") return;
        log("[ESP32] " + line, "dev");
    });

    renderDevice(null);
    dev.autoConnect();

    let lastPanel = 0;
    function frame() {
        const now = performance.now();
        fw.loop(now);
        if (now - lastPanel > 100) {
            lastPanel = now;
            const left = fw.timeoutRemainingMs(now);
            $("timeout").textContent =
                left === null ? "" : `borrado automático en ${Math.floor(left / 60000)}:${String(Math.floor(left / 1000) % 60).padStart(2, "0")}`;
        }
    }

    if (!window.crypto?.subtle) {
        log("WebCrypto no disponible: abrí el simulador con un navegador moderno.", "fail");
    }
    publishToLab(null); // power-on: RAM starts empty
    renderInspector();
    reset();
    setInterval(frame, 5); // firmware: loop() { updateWallet(); delay(5); }
})();

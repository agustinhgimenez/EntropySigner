// EntropySigner simulator - simulated hardware around the firmware port:
// LDR divider on the ADC, touch panel, EN button, serial monitor and inspector.
(function () {
    "use strict";

    const $ = (id) => document.getElementById(id);

    // ------------------------------------------------------------- LDR ---

    // GL5528 in a divider with 10 kOhm to GND, read through ADC1 at 11 dB (~0..3.1 V).
    const R_FIXED = 10000;
    const R_AT_10_LUX = 10000;
    const LDR_GAMMA = 0.7;
    const ADC_FULL_SCALE_V = 3.1;

    let shadeTarget = 0;
    let shade = 0;

    function ambientLux() {
        return Math.pow(10, (Number($("light").value) / 100) * 3); // 1 .. 1000 lux
    }

    function gaussian() {
        const u = 1 - Math.random();
        return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * Math.random());
    }

    function ldrModel() {
        shade += (shadeTarget - shade) * 0.25;
        const lux = Math.max(0.2, ambientLux() * (1 - 0.95 * shade));
        const r = R_AT_10_LUX * Math.pow(10 / lux, LDR_GAMMA);
        const volts = (3.3 * R_FIXED) / (r + R_FIXED);
        return { lux, r, volts };
    }

    const dev = window.ESDevice;
    let deviceLdr = 0;

    function simulatedLdrRaw() {
        const { volts } = ldrModel();
        const flicker = 4 * Math.sin(2 * Math.PI * 100 * (performance.now() / 1000));
        const raw = (volts / ADC_FULL_SCALE_V) * 4095 + flicker + 6 * gaussian();
        return Math.max(0, Math.min(4095, Math.round(raw)));
    }

    function readLdrRaw() {
        return dev.connected() ? deviceLdr : simulatedLdrRaw();
    }

    // Same order as entropy_pool.cpp: LDR samples first, then the HW RNG.
    async function getEntropySources(ldrCount) {
        if (!dev.connected()) {
            throw Object.assign(new Error("Sin ESP32 conectada por USB: no hay entropía real, no se genera la wallet."),
                { screenText: "Conecte la ESP32 por USB" });
        }
        const ldr = await dev.getLdr(ldrCount, 200);
        log(`[USB] ${ldrCount} lecturas reales del GPIO34 recibidas de la ESP32`, "dev");
        const rng = await dev.getRng(window.ESCrypto.HW_RNG_BYTES);
        log(`[USB] ${rng.length} bytes del RNG de hardware recibidos de la ESP32`, "dev");
        return { ldr, rng, origin: "esp32" };
    }

    const sensor = $("sensor");
    sensor.addEventListener("pointermove", (e) => {
        const rect = sensor.getBoundingClientRect();
        const dx = e.clientX - (rect.left + rect.width / 2);
        const dy = e.clientY - (rect.top + rect.height / 2);
        const dist = Math.hypot(dx, dy) / (rect.width / 2);
        shadeTarget = Math.max(0, Math.min(1, 1.15 - dist));
    });
    sensor.addEventListener("pointerleave", () => (shadeTarget = 0));

    function refreshLdrPanel() {
        if (dev.connected()) {
            $("adc").textContent = deviceLdr;
            return;
        }
        const { lux, r } = ldrModel();
        $("lux").textContent = lux < 10 ? lux.toFixed(1) : Math.round(lux);
        $("rldr").textContent = r >= 1e6 ? (r / 1e6).toFixed(2) + " M\u03a9" : (r / 1e3).toFixed(1) + " k\u03a9";
        $("adc").textContent = readLdrRaw();
        sensor.style.setProperty("--shade", (shade * 0.75).toFixed(2));
        sensor.style.setProperty("--glow", (Math.min(1, Math.log10(lux) / 3) * (1 - shade)).toFixed(2));
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
                localStorage.setItem(LAB_KEY, JSON.stringify({
                    entropy: d.entropy, rng: d.rng, ldr: Array.from(d.ldrSamples), origin: d.origin,
                }));
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
        return d
            ? `laboratorio.html#entropia=${d.entropy}&rng=${d.rng}&ldr=${Array.from(d.ldrSamples).join(",")}&origen=${d.origin}`
            : "laboratorio.html";
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
        const s = d.ldrSamples;
        const min = Math.min(...s);
        const max = Math.max(...s);
        const mean = Math.round(s.reduce((a, b) => a + b, 0) / s.length);
        const rows = [
            ["Origen de la entropía", d.origin === "esp32"
                ? "ESP32 REAL por USB (RNG de hardware + GPIO34)"
                : "SIMULADA en el navegador (la placa no participó)", d.origin === "esp32" ? "" : "secret"],
            ["Muestras LDR", `${s.length} lecturas · min ${min} · max ${max} · media ${mean}`, ""],
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
        readLdrRaw,
        getEntropySources,
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
        $("light").disabled = !!info;
        if (info) {
            status.className = "dev-status real";
            status.innerHTML = `Entrop&iacute;a: <b>ESP32 REAL</b> &middot; ${info.chip} &middot; firmware ${info.version} ${info.mode}`;
            btn.textContent = "Desconectar ESP32";
            $("ldr-mode").textContent = "· lecturas reales del ADC (sin LDR soldado el pin queda flotando y lee ruido)";
        } else {
            status.className = "dev-status sim";
            status.innerHTML = dev.supported()
                ? "<b>ESP32 no conectada</b> &middot; la primera vez apret&aacute; el bot&oacute;n y eleg&iacute; el puerto COM; despu&eacute;s se reconecta sola al enchufarla"
                : "Este navegador no tiene Web Serial: us&aacute; Chrome o Edge para conectar la ESP32";
            btn.textContent = "Conectar ESP32 real (USB)";
            btn.disabled = !dev.supported();
            $("ldr-mode").textContent = "· solo visual, no se usa sin la placa";
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

    // Raw ES:RNG/ES:LDR payloads are summarized by getEntropySources; boot logs and errors are shown.
    dev.onLine((line) => {
        if (/^ES:(RNG|LDR|PONG) /.test(line) || line === "") return;
        log("[ESP32] " + line, "dev");
    });

    let ldrPolling = false;
    setInterval(async () => {
        if (!dev.connected() || ldrPolling) return;
        ldrPolling = true;
        try {
            const v = await dev.getLdr(8, 100);
            deviceLdr = Math.round(v.reduce((a, b) => a + b, 0) / v.length);
        } catch (e) {
            // Disconnection is reported through onStatus.
        } finally {
            ldrPolling = false;
        }
    }, 150);

    renderDevice(null);
    dev.autoConnect();

    let lastPanel = 0;
    function frame() {
        const now = performance.now();
        fw.loop(now);
        if (now - lastPanel > 100) {
            lastPanel = now;
            refreshLdrPanel();
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

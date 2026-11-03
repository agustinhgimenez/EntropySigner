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
        renderDerived();
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

    // ------------------------------------------------- derived keys ---

    const DERIVED_PAGE = 10;
    let derivedKey = null;
    let derivedJob = 0;

    function el(tag, text, cls) {
        const node = document.createElement(tag);
        if (text !== undefined) node.textContent = text;
        if (cls) node.className = cls;
        return node;
    }

    async function renderDerived() {
        const root = $("derived");
        const d = inspectorData;
        if (!d) {
            derivedKey = null;
            derivedJob++;
            root.innerHTML = '<p class="empty">Gener&aacute; una wallet para ver sus direcciones derivadas.</p>';
            return;
        }
        const coin = $("d-coin").value;
        const account = Math.min(99, Math.max(0, parseInt($("d-account").value, 10) || 0));
        const change = parseInt($("d-change").value, 10);
        const key = [d.seed, coin, account, change].join("|");
        if (key === derivedKey) return;
        derivedKey = key;
        const job = ++derivedJob;
        root.replaceChildren(el("p", "Derivando claves…", "empty"));

        const ES = window.ESCrypto;
        const acct = await ES.deriveAccount(ES.fromHex(d.seed), coin, account, change);
        if (job !== derivedJob) return;

        const dl = el("dl");
        for (const [k, v, cls] of [
            ["BIP-32 root key", acct.rootXprv, "secret"],
            [`Cuenta ${acct.accountPath} xprv`, acct.accountXprv, "secret"],
            [`Cuenta ${acct.accountPath} xpub`, acct.accountXpub, ""],
            [`Cadena ${acct.chainPath} xprv`, acct.chainXprv, "secret"],
            [`Cadena ${acct.chainPath} xpub`, acct.chainXpub, ""],
        ]) {
            dl.append(el("dt", k), el("dd", v, cls));
        }

        const table = el("table");
        const head = el("tr");
        for (const h of ["Ruta", "Dirección", "Clave pública", "Clave privada"]) head.append(el("th", h));
        table.append(head);
        const more = el("button", `Mostrar ${DERIVED_PAGE} más`, "action more");
        let next = 0;

        async function addRows() {
            more.disabled = true;
            const rows = await ES.deriveRows(coin, acct, next, DERIVED_PAGE);
            if (job !== derivedJob) return;
            for (const r of rows) {
                const tr = el("tr");
                const addr = el("td");
                const link = el("a", r.address);
                link.href = EXPLORERS[coin].url(r.address);
                link.target = "_blank";
                link.rel = "noopener";
                link.title = `Ver en ${EXPLORERS[coin].name}`;
                addr.append(link);
                if (coin === "eth") {
                    const connect = el("button", "Conectar a la extensión", "action connect");
                    connect.addEventListener("click", () =>
                        connectToExtension({
                            address: r.address,
                            path: r.path,
                            label: `ES ${acct.masterFingerprint} · ${r.path.split("/").slice(-2).join("/")}`,
                        }, connect));
                    addr.append(connect);
                }
                tr.append(el("td", r.path), addr, el("td", r.publicKey), el("td", r.privateKey, "secret"));
                table.append(tr);
            }
            next += DERIVED_PAGE;
            more.disabled = false;
        }

        more.addEventListener("click", addRows);
        root.replaceChildren(dl, table, more);
        await addRows();
    }

    for (const id of ["d-coin", "d-account", "d-change"]) $(id).addEventListener("change", renderDerived);

    // ------------------------------------------- watch-only extension ---

    // extension/content.js answers on window.postMessage; only addresses and paths are sent.
    const EXT_PAGE = "entropysigner-page";
    const EXT_SOURCE = "entropysigner-ext";
    const pendingConnects = new Map();

    function connectToExtension(account, button) {
        pendingConnects.set(account.address.toLowerCase(), button);
        button.disabled = true;
        window.postMessage({ source: EXT_PAGE, type: "connect", account }, "*");
    }

    window.addEventListener("message", (e) => {
        if (e.source !== window || !e.data || e.data.source !== EXT_SOURCE) return;
        const msg = e.data;
        if (msg.type === "ready") {
            document.querySelector(".derived").classList.add("ext");
            $("ext-status").textContent = `Extensión EntropySigner Watch ${msg.version} detectada: ` +
                "elegí Ethereum y tocá «Conectar a la extensión» en las direcciones que quieras ver.";
        } else if (msg.type === "connected") {
            const button = pendingConnects.get(msg.address.toLowerCase());
            pendingConnects.delete(msg.address.toLowerCase());
            if (button) button.textContent = msg.already ? "Ya estaba conectada" : "Conectada ✓";
            log(`[EXT] ${msg.address} ${msg.already ? "ya estaba en" : "conectada a"} la extensión (solo lectura)`, "dev");
        } else if (msg.type === "error") {
            log(`[EXT] ${msg.message}`, "fail");
        }
    });
    window.postMessage({ source: EXT_PAGE, type: "ping" }, "*");

    // -------------------------------------------------------- firmware ---

    const hw = {
        touchDetected: $("touch").checked,
        demoMode: $("demo").checked,
        getRngBytes,
        log: (t) => log(t),
        inspect,
        onState: (s) => {
            $("state").textContent = s;
            updateExplorerHint();
        },
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

    const EXPLORERS = {
        btc: { name: "mempool.space", url: (a) => `https://mempool.space/address/${a}` },
        eth: { name: "Etherscan", url: (a) => `https://etherscan.io/address/${a}` },
    };

    function updateExplorerHint() {
        const hint = $("explorer-hint");
        const shown = fw.shownAddress();
        hint.hidden = !shown;
        if (!shown) return;
        hint.href = EXPLORERS[shown.coin].url(shown.address);
        hint.textContent = `Tocá el QR para ver esta dirección en ${EXPLORERS[shown.coin].name} ↗`;
    }

    function lcdPoint(e) {
        const rect = canvas.getBoundingClientRect();
        return [((e.clientX - rect.left) / rect.width) * fw.WIDTH, ((e.clientY - rect.top) / rect.height) * fw.HEIGHT];
    }

    canvas.addEventListener("pointerdown", (e) => {
        const [x, y] = lcdPoint(e);
        const hit = fw.addressAt(x, y);
        if (hit) {
            window.open(EXPLORERS[hit.coin].url(hit.address), "_blank", "noopener");
            return;
        }
        fw.tap(x, y);
    });
    canvas.addEventListener("pointermove", (e) => {
        const hit = fw.addressAt(...lcdPoint(e));
        canvas.title = hit ? `Ver esta dirección en ${EXPLORERS[hit.coin].name}` : "";
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

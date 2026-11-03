// EntropySigner - laboratorio criptografico: muestra cada paso interno del
// pipeline del firmware (entropia -> BIP-39 -> PBKDF2 -> BIP-32 -> direcciones)
// con valores reales, mas pruebas estadisticas de las fuentes de entropia.
(function () {
    "use strict";

    const C = window.ESCrypto;
    const dev = window.ESDevice;
    const WORDS = window.BIP39_WORDLIST;
    const WORD_INDEX = new Map(WORDS.map((w, i) => [w, i]));
    const enc = new TextEncoder();
    const $ = (id) => document.getElementById(id);

    const SECONDS_PER_YEAR = 3.156e7;

    let current = null;
    let imported = null;

    // ---------------------------------------------------------- helpers ---

    const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
    const short = (hex, n = 16) => (hex.length <= 2 * n + 1 ? hex : `${hex.slice(0, n)}&hellip;${hex.slice(-n)}`);
    const bitsOf = (bytes) => Array.from(bytes, (b) => b.toString(2).padStart(8, "0")).join("");
    const bytesFromBits = (bits) => Uint8Array.from({ length: bits.length / 8 }, (_, i) => parseInt(bits.slice(8 * i, 8 * i + 8), 2));
    const fmtSci = (x) => {
        const e = Math.floor(Math.log10(x));
        return `${(x / 10 ** e).toFixed(2)}&times;10<sup>${e}</sup>`;
    };

    function bitGrid(bits, cls = (b) => (b === "1" ? "one" : "")) {
        return `<div class="bitgrid">${Array.from(bits, (b, i) => `<span class="${cls(b, i)}" title="bit ${i}: ${b}"></span>`).join("")}</div>`;
    }

    function kv(rows) {
        return `<dl class="kv">${rows.map(([k, v, c = ""]) => `<dt>${k}</dt><dd class="${c}">${v}</dd>`).join("")}</dl>`;
    }

    // ------------------------------------------------------- statistics ---

    function lgamma(x) {
        const g = 7;
        const c = [0.99999999999980993, 676.5203681218851, -1259.1392167224028, 771.32342877765313,
            -176.61502916214059, 12.507343278686905, -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7];
        if (x < 0.5) return Math.log(Math.PI / Math.abs(Math.sin(Math.PI * x))) - lgamma(1 - x);
        x -= 1;
        let a = c[0];
        const t = x + g + 0.5;
        for (let i = 1; i < g + 2; i++) a += c[i] / (x + i);
        return 0.5 * Math.log(2 * Math.PI) + (x + 0.5) * Math.log(t) - t + Math.log(a);
    }

    // Regularized upper incomplete gamma Q(a, x), as gammaincc() in analyze_entropy.py.
    function gammaincc(a, x) {
        if (x <= 0) return 1;
        const logPre = -x + a * Math.log(x) - lgamma(a);
        if (x < a + 1) {
            let term = 1 / a, total = term, ap = a;
            for (let i = 0; i < 100000; i++) {
                ap += 1;
                term *= x / ap;
                total += term;
                if (Math.abs(term) < Math.abs(total) * 1e-15) break;
            }
            return Math.max(0, 1 - total * Math.exp(logPre));
        }
        const tiny = 1e-300;
        let b = x + 1 - a, c = 1 / tiny, d = 1 / b, h = d;
        for (let i = 1; i < 100000; i++) {
            const an = -i * (i - a);
            b += 2;
            d = an * d + b;
            if (Math.abs(d) < tiny) d = tiny;
            c = b + an / c;
            if (Math.abs(c) < tiny) c = tiny;
            d = 1 / d;
            const delta = d * c;
            h *= delta;
            if (Math.abs(delta - 1) < 1e-15) break;
        }
        return Math.min(1, Math.exp(logPre) * h);
    }

    function erfc(x) {
        const z = Math.abs(x);
        const t = 1 / (1 + 0.5 * z);
        const r = t * Math.exp(-z * z - 1.26551223 + t * (1.00002368 + t * (0.37409196 + t * (0.09678418 +
            t * (-0.18628806 + t * (0.27886807 + t * (-1.13520398 + t * (1.48851587 + t * (-0.82215223 + t * 0.17087277)))))))));
        return x >= 0 ? r : 2 - r;
    }

    function analyze(samples, bits) {
        const n = samples.length;
        const bins = 1 << bits;
        const counts = new Uint32Array(bins);
        let ones = 0, runs = 1, prevBit = -1, sum = 0;
        let longest = 1, run = 0, prev = -1;
        for (let i = 0; i < n; i++) {
            const s = samples[i];
            counts[s]++;
            sum += s;
            run = s === prev ? run + 1 : 1;
            if (run > longest) longest = run;
            prev = s;
            for (let k = bits - 1; k >= 0; k--) {
                const b = (s >> k) & 1;
                ones += b;
                if (prevBit !== -1 && b !== prevBit) runs++;
                prevBit = b;
            }
        }
        // SP 800-90B 6.3.1 Most Common Value
        let top = 0;
        for (const c of counts) if (c > top) top = c;
        const pHat = top / n;
        const pU = Math.min(1, pHat + 2.576 * Math.sqrt((pHat * (1 - pHat)) / (n - 1)));
        const hMin = -Math.log2(pU);
        // Shannon (plug-in)
        let shannon = 0;
        for (const c of counts) if (c) shannon -= (c / n) * Math.log2(c / n);
        // SP 800-22 2.1 monobit and 2.3 runs over the bitstring
        const nBits = n * bits;
        const sObs = Math.abs(2 * ones - nBits) / Math.sqrt(nBits);
        const pMonobit = erfc(sObs / Math.SQRT2);
        const pi = ones / nBits;
        const pRuns = Math.abs(pi - 0.5) >= 2 / Math.sqrt(nBits)
            ? 0
            : erfc(Math.abs(runs - 2 * nBits * pi * (1 - pi)) / (2 * Math.sqrt(2 * nBits) * pi * (1 - pi)));
        // Chi-square on the full alphabet, or on the low byte when there are too few samples per bin.
        let chiBins = bins, chiCounts = counts;
        if (n / bins < 5) {
            chiBins = 256;
            chiCounts = new Uint32Array(256);
            for (let i = 0; i < n; i++) chiCounts[samples[i] & 255]++;
        }
        const expected = n / chiBins;
        let chi = 0;
        for (const c of chiCounts) chi += ((c - expected) ** 2) / expected;
        const pChi = gammaincc((chiBins - 1) / 2, chi / 2);
        // Lag-1 autocorrelation
        const mean = sum / n;
        let num = 0, den = 0;
        for (let i = 0; i < n; i++) {
            const d = samples[i] - mean;
            den += d * d;
            if (i + 1 < n) num += d * (samples[i + 1] - mean);
        }
        const r1 = den ? num / den : NaN;
        // SP 800-90B 4.4.1 Repetition Count Test with H = 1 bit/sample, alpha = 2^-20
        const rctCutoff = 1 + Math.ceil(20 / 1);
        return { n, bits, hMin, shannon, pMonobit, pRuns, pChi, chiBins, r1, rBound: 2.576 / Math.sqrt(n), longest, rctCutoff };
    }

    async function sha256Counter(n) {
        const out = new Uint8Array(n);
        const ctr = new Uint8Array(8);
        const dv = new DataView(ctr.buffer);
        for (let i = 0, off = 0; off < n; i++, off += 32) {
            dv.setBigUint64(0, BigInt(i));
            out.set((await C.sha256(ctr)).slice(0, Math.min(32, n - off)), off);
        }
        return out;
    }

    // Each bit is 1 with probability 0.52: a slightly broken physical source.
    function biasedBits(n) {
        const out = new Uint8Array(n);
        const u = new Uint32Array(8);
        for (let i = 0; i < n; i++) {
            crypto.getRandomValues(u);
            let b = 0;
            for (let k = 0; k < 8; k++) if (u[k] < 0.52 * 2 ** 32) b |= 1 << k;
            out[i] = b;
        }
        return out;
    }

    function browserRng(n) {
        const out = new Uint8Array(n);
        for (let off = 0; off < n; off += 65536) crypto.getRandomValues(out.subarray(off, Math.min(n, off + 65536)));
        return out;
    }

    async function runStats() {
        const n = Number($("nsamples").value);
        const status = $("stats-status");
        const sources = [
            { name: "Referencia: CSPRNG del navegador", note: "buena, pero no es la placa", bits: 8, make: async () => browserRng(n) },
            { name: "Referencia: fuente sesgada", note: "rota a prop&oacute;sito: cada bit vale 1 con probabilidad 52%", bits: 8, make: async () => biasedBits(n) },
            { name: "SHA-256(contador)", note: "predecible a prop&oacute;sito", bits: 8, make: () => sha256Counter(n) },
        ];
        if (dev.connected()) {
            const nRng = Math.min(n, 20000);
            sources.unshift(
                { name: "RNG de la ESP32 (REAL)", note: `${nRng.toLocaleString("es-AR")} bytes por USB`, bits: 8, real: true,
                    make: () => dev.getRng(nRng, (done, total) => (status.textContent = `recibiendo bytes del RNG de la ESP32: ${done}/${total}`)) });
        }
        const rows = [];
        try {
            for (const s of sources) {
                status.textContent = `analizando ${s.name.replace(/&[a-z]+;/g, "")}...`;
                await new Promise((r) => setTimeout(r, 20));
                rows.push({ ...s, r: analyze(await s.make(), s.bits) });
            }
        } catch (e) {
            status.textContent = e.message;
            return;
        }
        const real = rows.find((s) => s.real);
        status.textContent = `${n.toLocaleString("es-AR")} muestras por fuente de referencia` +
            (real ? ` · ${real.note} de la ESP32` : "");

        const pv = (p) => `<span class="${p < 0.01 ? "bad" : "ok"}">${p < 1e-4 ? p.toExponential(1) : p.toFixed(4)}</span>`;
        const verdict = (s) => {
            const r = s.r;
            if (s.name.startsWith("SHA")) return '<span class="pill warn">pasa todo, pero 0 bits reales</span>';
            if (r.longest >= r.rctCutoff) return '<span class="pill bad">health test FALLA: fuente atascada</span>';
            if (Math.min(r.pMonobit, r.pRuns) < 0.01) return '<span class="pill bad">FALLA NIST SP 800-22: no es uniforme</span>';
            // MCV is an upper-bound estimator: even ideal data scores ~0.94-0.97 of the maximum at 50k-200k samples.
            if (r.hMin / r.bits > 0.9) return '<span class="pill ok">entrop&iacute;a completa</span>';
            return `<span class="pill warn">parcial: ${(100 * r.hMin / r.bits).toFixed(0)}% del m&aacute;ximo</span>`;
        };
        $("out-stats").innerHTML = `
            <table class="stats">
                <tr><th>Fuente</th><th>Min-entrop&iacute;a (MCV)</th><th>Shannon</th><th>Monobit p</th><th>Rachas p</th>
                    <th>&chi;&sup2; p</th><th>Autocorr. lag 1</th><th>Racha m&aacute;x.</th><th>Veredicto</th></tr>
                ${rows.map((s) => `<tr${s.real ? ' style="background:rgba(0,255,156,.06)"' : ""}>
                    <td><b>${s.name}</b><br><span class="muted">${s.note}</span></td>
                    <td class="v">${s.r.hMin.toFixed(3)} / ${s.bits} bits</td>
                    <td class="v">${s.r.shannon.toFixed(3)}</td>
                    <td class="v">${pv(s.r.pMonobit)}</td>
                    <td class="v">${pv(s.r.pRuns)}</td>
                    <td class="v">${pv(s.r.pChi)}<br><span class="muted">${s.r.chiBins} celdas</span></td>
                    <td class="v ${Math.abs(s.r.r1) > s.r.rBound ? "bad" : "ok"}">${isNaN(s.r.r1) ? "n/a" : s.r.r1.toFixed(4)}</td>
                    <td class="v ${s.r.longest >= s.r.rctCutoff ? "bad" : ""}">${s.r.longest}<br><span class="muted">corte ${s.r.rctCutoff}</span></td>
                    <td>${verdict(s)}</td></tr>`).join("")}
            </table>
            <h3>C&oacute;mo leer la tabla</h3>
            <ul style="margin-left:20px;font-size:13px;color:var(--muted)">
                <li><b>Min-entrop&iacute;a (NIST SP 800-90B &sect;6.3.1):</b> bits impredecibles por muestra en el peor caso. El RNG da ~8 de 8.
                    Con un sesgo de solo 52% ya se pierde parte de la entrop&iacute;a por byte.</li>
                <li><b>Monobit y rachas (NIST SP 800-22):</b> &iquest;hay tantos 1 como 0? &iquest;se alternan como deber&iacute;an? Un p &lt; 0,01 (rojo) rechaza que la fuente sea uniforme.</li>
                <li><b>&chi;&sup2;:</b> &iquest;todos los valores aparecen con la misma frecuencia?</li>
                <li><b>Autocorrelaci&oacute;n:</b> si una muestra predice la siguiente (en rojo si supera la banda del 99%).</li>
                <li><b>Racha m&aacute;xima (Repetition Count Test, &sect;4.4.1):</b> si el mismo valor se repite demasiadas veces seguidas, la fuente se declara rota (por ejemplo, un RNG que se qued&oacute; trabado).</li>
                <li><b>SHA-256(contador)</b> pasa todas las pruebas y sin embargo es 100% predecible: <b>las pruebas estad&iacute;sticas pueden refutar la aleatoriedad, nunca demostrarla.</b>
                    Por eso la seguridad se apoya en una fuente f&iacute;sica justificada (RNG de hardware) y no en que &laquo;los n&uacute;meros parecen aleatorios&raquo;.</li>
            </ul>
            ${rows.some((s) => s.real) ? `<div class="note">La fila verde son datos <b>reales de la placa</b>, le&iacute;dos con el mismo
                c&oacute;digo que usa el firmware para generar la wallet.</div>` : ""}
            ${rows.some((s) => s.real) ? "" : `<div class="note" style="border-color:var(--amber)"><b>La ESP32 no est&aacute; conectada:</b>
                ninguna fila de esta tabla viene de la placa. Toc&aacute; &laquo;Conectar ESP32&raquo; arriba y volv&eacute; a correr las pruebas.</div>`}
            <div class="note">Para muestras m&aacute;s grandes (&ge; 10<sup>6</sup>)
                se capturan por USB y se analizan con <code>python tools/entropy_analysis/analyze_entropy.py</code>, que agrega los estimadores
                Lag Prediction y Collision de NIST.</div>`;
    }

    // --------------------------------------------------------- sections ---

    function renderSources(rng, origin) {
        if (!rng) {
            $("out-sources").innerHTML = '<p class="note">Entrop&iacute;a fijada a mano: el RNG no se us&oacute; en esta corrida. Eleg&iacute; &laquo;Nueva: RNG simulado&raquo; o conect&aacute; la ESP32 para verlo.</p>';
            return;
        }
        const ones = bitsOf(rng).split("").filter((b) => b === "1").length;
        const real = origin === "esp32";
        $("out-sources").innerHTML = `
            <p class="pill ${real ? "ok" : "warn"}">${real
                ? "Bytes REALES: le&iacute;dos por USB del RNG de hardware de la ESP32"
                : "Bytes SIMULADOS en el navegador: la placa no particip&oacute;"}</p>
            <h3>RNG de hardware: ${C.HW_RNG_BYTES} bytes = ${8 * C.HW_RNG_BYTES} bits</h3>
            <div class="hex secret">${C.toHex(rng).match(/.{1,64}/g).join("<br>")}</div>
            ${bitGrid(bitsOf(rng))}
            <p class="muted" style="font-size:13px">${ones} unos y ${512 - ones} ceros (se esperan ~256 &plusmn; 11). Se piden 512 bits para
                sacar 256: NIST SP 800-90C pide que la entrada tenga al menos 64 bits m&aacute;s de los que se extraen.</p>`;
    }

    async function renderConditioning(input, entropy) {
        if (!input) {
            $("out-conditioning").innerHTML = kv([["Entrop&iacute;a (256 bits)", C.toHex(entropy), "secret"]]) + bitGrid(bitsOf(entropy));
            return;
        }
        const parts = [
            ["tag", input.tag.length, "#b48cff"],
            ["RNG de hardware", input.rng.length, "#00e5ff"],
        ];
        const total = input.all.length;
        $("out-conditioning").innerHTML = `
            <div class="layout">${parts.map(([n, len, col]) => `<div style="flex:${len};background:${col}" title="${n}: ${len} bytes">${n} ${len} B</div>`).join("")}</div>
            <p class="muted" style="font-size:13px">Entrada: ${total} bytes = ${8 * total} bits. El <i>tag</i> &laquo;${new TextDecoder().decode(input.tag)}&raquo; separa
                este uso de SHA-256 de cualquier otro (checksum BIP-39, Base58Check).</p>
            <div class="formula">entrop&iacute;a = SHA-256( tag || RNG )</div>
            ${kv([["Entrop&iacute;a final (256 bits)", C.toHex(entropy), "secret"]])}
            ${bitGrid(bitsOf(entropy))}
            <h3>Efecto avalancha</h3>
            <p class="muted" style="font-size:13px">Si cambia <b>un solo bit</b> de los 512 del RNG, cambia en promedio la mitad de los 256 bits de salida.
                Por eso nadie puede &laquo;ajustar&raquo; la entrada para obtener una salida elegida.</p>
            <div class="row"><button id="avalanche">Cambiar 1 bit del RNG</button><span id="avalanche-info" class="muted"></span></div>
            <div id="avalanche-grid"></div>
            <h3>Presupuesto de entrop&iacute;a</h3>
            <table>
                <tr><th>Fuente</th><th>Bits en la entrada</th><th>Bits acreditados</th><th>Motivo</th></tr>
                <tr><td>Tag de dominio</td><td class="num">${8 * input.tag.length}</td><td class="num">0</td><td>texto fijo y p&uacute;blico</td></tr>
                <tr><td>RNG de hardware</td><td class="num">512</td><td class="num ok">512</td><td>fuente f&iacute;sica documentada por Espressif</td></tr>
                <tr><td><b>Salida SHA-256</b></td><td class="num">${8 * total}</td><td class="num ok"><b>256</b></td><td>512 &ge; 256 + 64 de margen (SP 800-90C)</td></tr>
            </table>`;
        $("avalanche").onclick = async () => {
            const rng = Uint8Array.from(current.rng);
            const i = Math.floor(Math.random() * rng.length);
            const bit = Math.floor(Math.random() * 8);
            rng[i] ^= 1 << bit;
            const other = await C.sha256(C.conditioningInput(rng).all);
            const a = bitsOf(entropy), b = bitsOf(other);
            const flips = [...a].filter((x, k) => x !== b[k]).length;
            $("avalanche-info").innerHTML = `byte #${i}: ${current.rng[i]} &rarr; ${rng[i]} (bit ${bit}) &middot; cambiaron <b class="bad">${flips}</b> de 256 bits (${(flips / 2.56).toFixed(1)}%)`;
            $("avalanche-grid").innerHTML = `<div class="hex">${C.toHex(other)}</div>` + bitGrid(a, (x, k) => (x !== b[k] ? "flip" : "same"));
        };
    }

    async function renderBip39(entropy) {
        const hash = await C.sha256(entropy);
        const csBits = bitsOf(hash.slice(0, 1));
        const all = bitsOf(entropy) + csBits;
        const words = [];
        let rows = "";
        for (let i = 0; i < 24; i++) {
            const chunk = all.slice(11 * i, 11 * i + 11);
            const idx = parseInt(chunk, 2);
            words.push(WORDS[idx]);
            const bitsHtml = Array.from(chunk, (b, k) => `<span class="${11 * i + k >= 256 ? "c" : "e"}">${b}</span>`).join("");
            rows += `<tr><td class="num">${i + 1}</td><td class="bits">${bitsHtml}</td><td class="num">${idx}</td><td class="word">${WORDS[idx]}</td>
                ${i === 23 ? '<td class="muted">3 bits de entrop&iacute;a + 8 de checksum</td>' : "<td></td>"}</tr>`;
        }
        $("out-bip39").innerHTML = `
            ${kv([
                ["SHA-256(entrop&iacute;a)", `<span class="c" style="color:var(--amber);font-weight:700">${C.toHex(hash).slice(0, 2)}</span>${C.toHex(hash).slice(2)}`],
                ["Checksum (8 bits)", `<span style="color:var(--amber)">${csBits}</span> = 0x${C.toHex(hash).slice(0, 2)}`],
            ])}
            <h3>264 bits en grupos de 11 &rarr; &iacute;ndice en la lista &rarr; palabra</h3>
            <p class="muted" style="font-size:13px"><span style="color:var(--cyan)">celeste</span> = bits de entrop&iacute;a,
                <span style="color:var(--amber)">&aacute;mbar</span> = bits de checksum.</p>
            <table><tr><th>#</th><th>11 bits</th><th>&Iacute;ndice</th><th>Palabra</th><th></th></tr>${rows}</table>`;
        return words.join(" ");
    }

    async function renderLastWords(entropy) {
        const base = entropy.slice();
        const actual = entropy[31] & 7;
        const cands = [];
        for (let x = 0; x < 8; x++) {
            base[31] = (entropy[31] & 0xf8) | x;
            const cs = (await C.sha256(base))[0];
            const idx = (x << 8) | cs;
            cands.push({ x, cs, idx, word: WORDS[idx] });
        }
        const prefix = (await renderMnemonicPrefix(entropy)).join(" ");
        $("out-last").innerHTML = `
            <p class="muted" style="font-size:13px">Primeras 23 palabras fijas: <span class="mono">${prefix}</span></p>
            <div class="words-grid">${cands.map((c) => `
                <div class="candidate ${c.x === actual ? "current" : ""}">
                    <b>${c.word}</b>
                    <span style="color:var(--cyan)">${c.x.toString(2).padStart(3, "0")}</span><span style="color:var(--amber)">${c.cs.toString(2).padStart(8, "0")}</span>
                    <br><span class="muted">&iacute;ndice ${c.idx}${c.x === actual ? " &middot; la elegida" : ""}</span>
                </div>`).join("")}</div>
            <p class="muted" style="font-size:13px;margin-top:10px">Cualquiera de estas 8 forma una frase v&aacute;lida, pero cada una es una wallet distinta.
                Si alguien eligiera la palabra 24 al azar entre las 2048, acertar&iacute;a una v&aacute;lida con probabilidad 8/2048 = 1/256.</p>`;
    }

    async function renderMnemonicPrefix(entropy) {
        const all = bitsOf(entropy);
        return Array.from({ length: 23 }, (_, i) => WORDS[parseInt(all.slice(11 * i, 11 * i + 11), 2)]);
    }

    async function validate() {
        const words = $("validate-input").value.trim().toLowerCase().split(/\s+/).filter(Boolean);
        const out = $("out-validate");
        if (![12, 15, 18, 21, 24].includes(words.length)) {
            out.innerHTML = `<p class="bad">Hay ${words.length} palabras: BIP-39 admite 12, 15, 18, 21 o 24.</p>`;
            return;
        }
        const unknown = words.map((w, i) => [w, i]).filter(([w]) => !WORD_INDEX.has(w));
        if (unknown.length) {
            out.innerHTML = `<p class="bad">No est&aacute;n en la lista BIP-39: ${unknown.map(([w, i]) => `#${i + 1} &laquo;${esc(w)}&raquo;`).join(", ")}</p>`;
            return;
        }
        const bits = words.map((w) => WORD_INDEX.get(w).toString(2).padStart(11, "0")).join("");
        const ent = (bits.length * 32) / 33;
        const csLen = ent / 32;
        const entropy = bytesFromBits(bits.slice(0, ent));
        const given = bits.slice(ent);
        const expected = bitsOf(await C.sha256(entropy)).slice(0, csLen);
        const ok = given === expected;
        out.innerHTML = `
            ${kv([
                ["Entrop&iacute;a recuperada", `${ent} bits: ${C.toHex(entropy)}`],
                ["Checksum en la frase", `<span style="color:var(--amber)">${given}</span>`],
                ["SHA-256(entrop&iacute;a), primeros " + csLen, `<span style="color:var(--amber)">${expected}</span>`],
            ])}
            <p class="${ok ? "ok" : "bad"}" style="margin-top:8px;font-weight:600">${ok
                ? "&#10003; Checksum correcto: la frase es v&aacute;lida."
                : "&#10007; Checksum incorrecto: hay un error en alguna palabra (o en el orden)."}</p>`;
    }

    function corrupt() {
        const words = $("validate-input").value.trim().split(/\s+/).filter(Boolean);
        if (!words.length) return;
        const i = Math.floor(Math.random() * words.length);
        let w;
        do w = WORDS[Math.floor(Math.random() * WORDS.length)]; while (w === words[i]);
        words[i] = w;
        $("validate-input").value = words.join(" ");
        validate().then(() => {
            $("out-validate").insertAdjacentHTML("afterbegin", `<p class="muted">Se reemplaz&oacute; la palabra #${i + 1} por &laquo;${w}&raquo;. (1 de cada 256 veces el cambio pasa el checksum por azar.)</p>`);
        });
    }

    async function renderSeed(mnemonic, passphrase) {
        const t0 = performance.now();
        const seed = await C.mnemonicToSeed(mnemonic, passphrase);
        const ms = performance.now() - t0;
        const alt = await C.mnemonicToSeed(mnemonic, passphrase ? "" : "TREZOR");
        $("out-seed").innerHTML = kv([
            ["password", `NFKD(frase) = ${enc.encode(mnemonic.normalize("NFKD")).length} bytes`],
            ["salt", `&laquo;mnemonic${esc(passphrase)}&raquo;`],
            ["iteraciones", "2048 &times; HMAC-SHA512"],
            ["seed (512 bits)", C.toHex(seed), "secret"],
            ["tiempo en este navegador", `${ms.toFixed(1)} ms (en el ESP32 ~1,5 s)`],
            [passphrase ? "misma frase SIN passphrase" : "misma frase con passphrase &laquo;TREZOR&raquo;", short(C.toHex(alt), 32), "muted"],
        ]);
        return seed;
    }

    async function renderMaster(seed) {
        const I = await C.hmacSha512(enc.encode("Bitcoin seed"), seed);
        const k = C.bytesToBig(I.slice(0, 32));
        const valid = k > 0n && k < C.curve.N;
        $("out-master").innerHTML = kv([
            ["I = HMAC-SHA512 (64 bytes)", `<span class="secret">${C.toHex(I.slice(0, 32))}</span><span class="pub">${C.toHex(I.slice(32))}</span>`],
            ["k_master = I[0..31]", C.toHex(I.slice(0, 32)), "secret"],
            ["c_master = I[32..63]", C.toHex(I.slice(32)), "pub"],
            ["0 &lt; k &lt; n", valid ? '<span class="ok">&#10003; v&aacute;lida</span> (probabilidad de fallar &lt; 2<sup>-127</sup>)' : '<span class="bad">inv&aacute;lida</span>'],
        ]);
        return { k, chain: I.slice(32) };
    }

    async function traceDerivation(master, path) {
        const steps = [];
        let node = master;
        let label = "m";
        for (const part of path.split("/").slice(1)) {
            const hardened = part.endsWith("'");
            const index = parseInt(part, 10) + (hardened ? C.HARDENED : 0);
            const data = hardened
                ? C.concat(new Uint8Array([0]), C.bigToBytes(node.k, 32), C.ser32(index))
                : C.concat(C.compressPoint(C.pointMul(node.k, C.curve.G)), C.ser32(index));
            const I = await C.hmacSha512(node.chain, data);
            const il = C.bytesToBig(I.slice(0, 32));
            const k = (il + node.k) % C.curve.N;
            label += "/" + part;
            steps.push({ label, part, index, hardened, il, k, chain: I.slice(32) });
            node = { k, chain: I.slice(32) };
        }
        return { steps, node };
    }

    function derivationTable(title, trace) {
        return `<h3>${title}</h3><table>
            <tr><th>Nivel</th><th>&Iacute;ndice i</th><th>Tipo</th><th>Datos del HMAC</th><th>k hijo</th><th>chain code</th></tr>
            ${trace.steps.map((s) => `<tr>
                <td class="mono">${s.label}</td>
                <td class="mono">0x${s.index.toString(16).padStart(8, "0")}</td>
                <td>${s.hardened ? '<span class="pill warn">endurecida</span>' : '<span class="pill ok">normal</span>'}</td>
                <td class="mono muted">${s.hardened ? "0x00 || k_padre || i" : "K_padre (33 B) || i"}</td>
                <td class="mono secret">${short(s.k.toString(16).padStart(64, "0"), 8)}</td>
                <td class="mono pub">${short(C.toHex(s.chain), 8)}</td></tr>`).join("")}
        </table>`;
    }

    function renderPub(k) {
        const { P, G } = C.curve;
        const pt = C.pointMul(k, G);
        const onCurve = (pt.y * pt.y - pt.x * pt.x * pt.x - 7n) % P === 0n;
        const hx = (v) => v.toString(16).padStart(64, "0");
        $("out-pub").innerHTML = kv([
            ["k (privada BTC m/44'/0'/0'/0/0)", hx(k), "secret"],
            ["K.x", hx(pt.x), "pub"],
            ["K.y", `${hx(pt.y)} <span class="muted">(${pt.y & 1n ? "impar &rarr; prefijo 03" : "par &rarr; prefijo 02"})</span>`, "pub"],
            ["K comprimida (33 bytes)", C.toHex(C.compressPoint(pt)), "pub"],
            ["&iquest;y&sup2; &equiv; x&sup3; + 7 (mod p)?", onCurve ? '<span class="ok">&#10003; el punto est&aacute; en la curva</span>' : '<span class="bad">&#10007; no est&aacute;</span>'],
            ["Revertir K &rarr; k", "mejor ataque conocido (rho de Pollard): ~2<sup>128</sup> operaciones"],
        ]);
        return pt;
    }

    async function renderBtc(pt, expected) {
        const pub = C.compressPoint(pt);
        const sha = await C.sha256(pub);
        const h160 = C.ripemd160(sha);
        const versioned = C.concat(new Uint8Array([0]), h160);
        const checksum = (await C.sha256(await C.sha256(versioned))).slice(0, 4);
        const full = C.concat(versioned, checksum);
        const address = C.base58Encode(full);
        const stage = (op, label, val) => `<div class="stage"><div><div class="op">${op}</div><div class="muted">${label}</div></div><div class="hex">${val}</div></div>`;
        $("out-btc").innerHTML = `<div class="pipeline">
            ${stage("K comprimida", "33 bytes", C.toHex(pub))}
            ${stage("SHA-256(K)", "32 bytes", C.toHex(sha))}
            ${stage("RIPEMD-160(...)", "HASH160, 20 bytes", C.toHex(h160))}
            ${stage("0x00 || HASH160", "versi&oacute;n mainnet", `<span style="color:var(--violet)">00</span>${C.toHex(h160)}`)}
            ${stage("SHA-256(SHA-256(...))[0..3]", "checksum, 4 bytes", `<span style="color:var(--amber)">${C.toHex(checksum)}</span>`)}
            ${stage("Base58(25 bytes)", "direcci&oacute;n final", `<span class="big">${address}</span>`)}
        </div>
        <p style="margin-top:8px;font-size:13px" class="${address === expected ? "ok" : "bad"}">${address === expected
            ? "&#10003; Coincide con la direcci&oacute;n que calcula el pipeline del firmware (<code>bitcoinAddress()</code>)."
            : "&#10007; No coincide con el pipeline del firmware."}</p>`;
    }

    function renderEth(pt, expected) {
        const xy = C.concat(C.bigToBytes(pt.x, 32), C.bigToBytes(pt.y, 32));
        const hash = C.keccak256(xy);
        const lower = C.toHex(hash.slice(12));
        const csHash = C.keccak256(enc.encode(lower));
        const address = C.toChecksumAddress(hash.slice(12));
        const chars = Array.from(lower, (ch, i) => {
            const nib = i % 2 === 0 ? csHash[i >> 1] >> 4 : csHash[i >> 1] & 15;
            const up = /[a-f]/.test(ch) && nib >= 8;
            return `<span class="${up ? "up" : ""}">${up ? ch.toUpperCase() : ch}<small>${nib.toString(16)}</small></span>`;
        }).join("");
        $("out-eth").innerHTML = kv([
            ["K sin comprimir X || Y", short(C.toHex(xy), 24), "pub"],
            ["Keccak-256(X || Y)", `<span class="muted">${C.toHex(hash).slice(0, 24)}</span>${C.toHex(hash).slice(24)}`],
            ["&uacute;ltimos 20 bytes", "0x" + lower],
            ["Keccak-256(&laquo;" + lower.slice(0, 6) + "&hellip;&raquo;)", C.toHex(csHash).slice(0, 40)],
        ]) + `<h3>EIP-55: may&uacute;scula si el nibble del hash (abajo) es &ge; 8</h3>
            <div class="eip55"><span>0<small>&nbsp;</small></span><span>x<small>&nbsp;</small></span>${chars}</div>
            <p class="big" style="margin-top:10px;font-size:20px">${address}</p>
            <p style="font-size:13px" class="${address === expected ? "ok" : "bad"}">${address === expected
                ? "&#10003; Coincide con la direcci&oacute;n que calcula el pipeline del firmware (<code>ethereumAddress()</code>)."
                : "&#10007; No coincide con el pipeline del firmware."}</p>`;
    }

    function renderSecurity() {
        const space = 2 ** 256;
        const years = space / 2 / 1e12 / SECONDS_PER_YEAR;
        const milkSad = 2 ** 32 / 1e9;
        $("out-security").innerHTML = `
            <div class="cards">
                <div class="card"><div class="t">Espacio de frases</div><div class="big">2<sup>256</sup></div>
                    &asymp; ${fmtSci(space)} combinaciones. Probando un bill&oacute;n (10<sup>12</sup>) por segundo, encontrar una
                    llevar&iacute;a en promedio ${fmtSci(years)} a&ntilde;os. El universo tiene 1,4&times;10<sup>10</sup>.</div>
                <div class="card"><div class="t">Por qu&eacute; importa el RNG</div><div class="big" style="color:var(--red)">2<sup>32</sup></div>
                    Caso real &laquo;Milk Sad&raquo; (2023): una wallet usaba un generador con semilla de 32 bits. Con 10<sup>9</sup> intentos/s se recorren
                    todas en ${milkSad.toFixed(1)} s. La matem&aacute;tica de BIP-39 era correcta; fall&oacute; la entrop&iacute;a.</div>
                <div class="card"><div class="t">Checksum BIP-39</div><div class="big">255/256</div>
                    de los errores al copiar una palabra se detectan (paso 6). No protege contra robo: es contra errores humanos.</div>
                <div class="card"><div class="t">PBKDF2</div><div class="big">&times;2048</div>
                    iteraciones de HMAC-SHA512 por cada intento de un atacante que pruebe frases o passphrases.</div>
                <div class="card"><div class="t">secp256k1</div><div class="big">~2<sup>128</sup></div>
                    operaciones para sacar la clave privada desde la p&uacute;blica (logaritmo discreto, rho de Pollard).</div>
                <div class="card"><div class="t">Derivaci&oacute;n endurecida</div><div class="big">44' 0' 0'</div>
                    los niveles con ap&oacute;strofo usan la clave privada del padre: filtrar una clave hija no compromete la cuenta.</div>
            </div>
            <h3>Medidas del firmware</h3>
            <ul style="margin-left:20px;font-size:14px">
                <li>La &uacute;nica fuente es el <b>RNG de hardware</b>, le&iacute;do con <code>bootloader_random_enable()</code> activo: as&iacute; Espressif garantiza ruido f&iacute;sico real aun sin WiFi ni Bluetooth.</li>
                <li>Se piden <b>512 bits</b> y se comprimen con <b>SHA-256 con separaci&oacute;n de dominio</b> a 256: el margen de 256 bits absorbe cualquier sesgo residual (SP 800-90C).</li>
                <li>Entrop&iacute;a, seed y claves privadas se <b>borran de la RAM</b> apenas se usan (<code>secureMemzero</code>); la frase, al salir de su pantalla o a los 2 minutos.</li>
                <li><b>Sin conexi&oacute;n</b> (air-gapped): en modo PRODUCTION no hay WiFi, Bluetooth ni secretos por el puerto serie; las direcciones salen solo por pantalla y QR.</li>
                <li>Cada primitiva se valida contra los <b>vectores oficiales</b> (BIP-39, BIP-32, EIP-55, NIST) en <code>tests/</code>, y este laboratorio los repite en el navegador.</li>
            </ul>
            <h3>L&iacute;mites (prototipo educativo)</h3>
            <ul style="margin-left:20px;font-size:14px;color:var(--muted)">
                <li>Sin elemento seguro: la multiplicaci&oacute;n escalar no es de tiempo constante y un atacante con acceso f&iacute;sico podr&iacute;a usar canales laterales (<code>docs/SECURITY.md</code> &sect;2.1).</li>
                <li>Las pruebas estad&iacute;sticas no prueban aleatoriedad (paso 3); una validaci&oacute;n formal requiere la herramienta oficial de NIST sobre &ge; 10<sup>6</sup> muestras crudas.</li>
            </ul>`;
    }

    function renderOrigin(source, ref, passphrase) {
        const fromSimulator = source === "imported" || (imported && source === "manual" && $("manual").value === C.toHex(imported.entropy));
        const texts = {
            esp32: "Wallet <u>nueva</u> generada en esta p&aacute;gina con bytes <b>reales</b> del RNG de hardware de la ESP32 conectada por USB.",
            new: "Wallet <u>nueva</u> generada por el laboratorio con RNG simulado en el navegador. <b>No</b> es la del simulador de pantalla.",
            zero: "Vector de prueba oficial (entrop&iacute;a 0x00&hellip;00): sirve para comparar con implementaciones de referencia.",
            manual: "Entrop&iacute;a ingresada a mano.",
        };
        const el = $("origin");
        el.className = "origin " + (fromSimulator || source === "esp32" ? "imported" : "local");
        el.innerHTML = (fromSimulator
            ? "&#10003; Mostrando <u>la misma wallet</u> que gener&oacute; el simulador de pantalla" +
              (source === "imported" ? ", reproducida desde los mismos bytes del RNG que mand&oacute; la <b>ESP32 real</b> por USB."
                  : " (solo se recibi&oacute; la entrop&iacute;a).")
            : texts[source]) +
            `<br>BTC <b>${ref.btc}</b> &middot; ETH <b>${ref.eth}</b>` +
            (passphrase ? '<br><span class="muted">Con passphrase: las direcciones no coinciden con las del simulador, que no usa passphrase.</span>' : "");
    }

    const LAB_KEY = "entropysigner.simulator.wallet";

    function readStoredWallet() {
        try {
            const raw = localStorage.getItem(LAB_KEY);
            if (!raw) return null;
            const d = JSON.parse(raw);
            return validateImport(d.entropy, d.rng);
        } catch (e) {
            return null;
        }
    }

    function parseImport() {
        const params = new URLSearchParams(location.hash.slice(1));
        return validateImport(params.get("entropia"), params.get("rng"));
    }

    // The screen simulator only generates with the board connected, so its RNG bytes are always real.
    function validateImport(entropyHex, rngHex) {
        const hex = String(entropyHex || "").toLowerCase();
        if (!/^[0-9a-f]{64}$/.test(hex)) return null;
        rngHex = String(rngHex || "").toLowerCase();
        return new RegExp(`^[0-9a-f]{${2 * C.HW_RNG_BYTES}}$`).test(rngHex)
            ? { entropy: C.fromHex(hex), rng: C.fromHex(rngHex), origin: "esp32" }
            : { entropy: C.fromHex(hex), entropyOnly: true };
    }

    // ------------------------------------------------------------- run ---

    async function run() {
        const btn = $("run");
        btn.disabled = true;
        btn.textContent = "Calculando...";
        try {
            if ($("source").value === "imported" && (!imported || imported.entropyOnly)) selectSource("new");
            const source = $("source").value;
            let rng = null, input = null, entropy, origin = "simulado";
            if (source === "esp32") {
                if (!dev.connected()) await connectDevice();
                rng = await dev.getRng(C.HW_RNG_BYTES);
                origin = "esp32";
                input = C.conditioningInput(rng);
                entropy = await C.sha256(input.all);
            } else if (source === "imported") {
                origin = imported.origin;
                rng = imported.rng;
                input = C.conditioningInput(rng);
                entropy = await C.sha256(input.all);
                if (C.toHex(entropy) !== C.toHex(imported.entropy)) {
                    throw new Error("Los datos importados no reproducen la entropía del simulador.");
                }
            } else if (source === "new") {
                rng = crypto.getRandomValues(new Uint8Array(C.HW_RNG_BYTES));
                input = C.conditioningInput(rng);
                entropy = await C.sha256(input.all);
            } else if (source === "zero") {
                entropy = new Uint8Array(32);
            } else {
                const hex = $("manual").value.trim().toLowerCase();
                if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error("La entropía manual debe tener exactamente 64 caracteres hexadecimales.");
                entropy = C.fromHex(hex);
            }
            const passphrase = $("passphrase").value;
            current = { rng, entropy };

            renderSources(rng, origin);
            await renderConditioning(input, entropy);
            const mnemonic = await renderBip39(entropy);
            await renderLastWords(entropy);
            $("validate-input").value = mnemonic;
            await validate();
            const seed = await renderSeed(mnemonic, passphrase);
            const master = await renderMaster(seed);
            const btc = await traceDerivation(master, C.BTC_PATH);
            const eth = await traceDerivation(master, C.ETH_PATH);
            $("out-derive").innerHTML = derivationTable("Bitcoin " + C.BTC_PATH, btc) + derivationTable("Ethereum " + C.ETH_PATH, eth);
            const ref = { btc: (await C.bitcoinAddress(master)).address, eth: (await C.ethereumAddress(master)).address };
            const ptBtc = renderPub(btc.node.k);
            await renderBtc(ptBtc, ref.btc);
            renderEth(C.pointMul(eth.node.k, C.curve.G), ref.eth);
            renderOrigin(source, ref, passphrase);
        } catch (e) {
            alert(e.message);
        } finally {
            btn.disabled = false;
            selectSource($("source").value);
        }
    }

    function renderDevice(info) {
        const status = $("dev-status");
        $("connect").textContent = info ? "Desconectar ESP32" : "Conectar ESP32";
        $("connect").disabled = !dev.supported();
        status.style.color = info ? "var(--green)" : "";
        status.textContent = info
            ? `ESP32 real conectada (${info.chip}, firmware ${info.version} ${info.mode})`
            : dev.supported() ? "placa no conectada" : "sin Web Serial: us\u00e1 Chrome o Edge";
    }

    async function connectDevice() {
        $("dev-status").textContent = "conectando...";
        try {
            return await dev.connect();
        } catch (e) {
            renderDevice(null);
            if (e.name === "NotFoundError") throw new Error("No se eligió ningún puerto.");
            throw new Error(e.message + " Si el simulador de pantalla está conectado, desconectalo ahí: el puerto lo puede usar una sola pestaña.");
        }
    }

    $("connect").addEventListener("click", async () => {
        try {
            if (dev.connected()) await dev.disconnect();
            else await connectDevice();
        } catch (e) {
            $("dev-status").textContent = e.message;
        }
    });
    dev.onStatus(renderDevice);
    renderDevice(null);
    dev.autoConnect();

    $("run").addEventListener("click", run);
    $("run-stats").addEventListener("click", runStats);
    $("validate").addEventListener("click", validate);
    $("corrupt").addEventListener("click", corrupt);

    function selectSource(value) {
        $("source").value = value;
        $("manual").style.display = value === "manual" ? "" : "none";
        $("run").textContent = value === "imported" ? "Explicar wallet del simulador"
            : value === "esp32" ? "Generar con la ESP32 y explicar" : "Generar y explicar";
    }

    function useImported(data) {
        imported = data;
        $("opt-imported").hidden = !(data && !data.entropyOnly);
        if (data && !data.entropyOnly) {
            selectSource("imported");
        } else if (data) {
            $("manual").value = C.toHex(data.entropy);
            selectSource("manual");
        } else if ($("source").value === "imported") {
            selectSource("new");
        }
    }

    // Live link with the simulator tab: a new wallet there re-renders here; a wiped session is reported.
    window.addEventListener("storage", (e) => {
        if (e.key !== LAB_KEY) return;
        const data = readStoredWallet();
        if (data) {
            useImported(data);
            run();
        } else if (imported && $("source").value === "imported") {
            $("origin").insertAdjacentHTML("beforeend",
                '<br><span style="color:var(--amber)">El simulador borr&oacute; la sesi&oacute;n (como el firmware al volver a IDLE). ' +
                "Esta p&aacute;gina conserva la explicaci&oacute;n de la &uacute;ltima wallet.</span>");
        }
    });

    $("source").addEventListener("change", () => selectSource($("source").value));
    useImported(readStoredWallet() || parseImport());
    renderSecurity();
    if (imported) {
        run();
    } else {
        // Without a wallet from the simulator, wait for the board instead of silently using the browser RNG.
        selectSource("esp32");
        $("origin").className = "origin local";
        $("origin").innerHTML = "No hay ninguna wallet del simulador en memoria (no se gener&oacute; ninguna o ya se borr&oacute; al volver a IDLE). " +
            "Toc&aacute; <b>Conectar ESP32</b> para generar una con el RNG real de la placa, o eleg&iacute; " +
            "&laquo;RNG simulado&raquo; para practicar sin hardware.";
        dev.onStatus((info) => {
            if (info && !current && !imported) run();
        });
    }
})();

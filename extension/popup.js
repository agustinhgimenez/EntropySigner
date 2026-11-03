(function () {
    "use strict";

    const $ = (id) => document.getElementById(id);
    const NETWORKS = {
        mainnet: { rpc: "https://ethereum-rpc.publicnode.com", explorer: "https://etherscan.io", symbol: "ETH" },
        sepolia: { rpc: "https://ethereum-sepolia-rpc.publicnode.com", explorer: "https://sepolia.etherscan.io", symbol: "SepoliaETH" },
    };
    const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

    let state = { accounts: [], selected: null, network: "mainnet" };
    const balances = new Map();

    const short = (a) => `${a.slice(0, 6)}…${a.slice(-4)}`;
    const same = (a, b) => a && b && a.toLowerCase() === b.toLowerCase();

    function formatWei(wei) {
        const whole = wei / 10n ** 18n;
        const frac = (wei % 10n ** 18n).toString().padStart(18, "0").slice(0, 6).replace(/0+$/, "");
        return frac ? `${whole}.${frac}` : `${whole}`;
    }

    async function fetchBalance(address) {
        const key = `${state.network}:${address.toLowerCase()}`;
        if (balances.has(key)) return balances.get(key);
        const res = await fetch(NETWORKS[state.network].rpc, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getBalance", params: [address, "latest"] }),
        });
        const body = await res.json();
        if (body.error) throw new Error(body.error.message);
        const text = `${formatWei(BigInt(body.result))} ${NETWORKS[state.network].symbol}`;
        balances.set(key, text);
        return text;
    }

    function showBalance(address, node) {
        node.textContent = "…";
        node.classList.remove("error");
        fetchBalance(address).then(
            (text) => (node.textContent = text),
            () => {
                node.textContent = "sin conexión";
                node.classList.add("error");
            },
        );
    }

    async function save(patch) {
        Object.assign(state, patch);
        await chrome.storage.local.set(patch);
        render();
    }

    function render() {
        const { accounts, network } = state;
        const current = accounts.find((a) => same(a.address, state.selected)) || accounts[0];
        $("network").value = network;
        $("empty").hidden = accounts.length > 0;
        $("hero").hidden = !current;

        if (current) {
            $("hero-label").textContent = current.label;
            $("hero-address").textContent = current.address;
            $("hero-path").textContent = current.path ? `Ruta ${current.path}` : "Agregada a mano";
            $("explorer").href = `${NETWORKS[network].explorer}/address/${current.address}`;
            showBalance(current.address, $("hero-balance"));
        }

        const list = $("accounts");
        list.replaceChildren();
        for (const a of accounts) {
            const li = document.createElement("li");
            if (a === current) li.className = "selected";
            const info = document.createElement("div");
            const name = document.createElement("div");
            name.className = "name";
            name.textContent = a.label;
            const addr = document.createElement("div");
            addr.className = "short";
            addr.textContent = a.path ? `${short(a.address)} · ${a.path}` : short(a.address);
            info.append(name, addr);
            const bal = document.createElement("div");
            bal.className = "bal";
            showBalance(a.address, bal);
            li.append(info, bal);
            li.addEventListener("click", () => save({ selected: a.address }));
            list.append(li);
        }
    }

    function currentAccount() {
        return state.accounts.find((a) => same(a.address, state.selected)) || state.accounts[0];
    }

    $("network").addEventListener("change", (e) => save({ network: e.target.value }));

    $("copy").addEventListener("click", async () => {
        await navigator.clipboard.writeText(currentAccount().address);
        $("copy").textContent = "¡Copiada!";
        setTimeout(() => ($("copy").textContent = "Copiar"), 1200);
    });
    $("hero-address").addEventListener("click", () => $("copy").click());

    $("rename").addEventListener("click", () => {
        const acct = currentAccount();
        const input = document.createElement("input");
        input.value = acct.label;
        input.maxLength = 40;
        $("hero-label").replaceChildren(input);
        input.focus();
        input.select();
        const commit = () => {
            const label = input.value.trim() || acct.label;
            save({ accounts: state.accounts.map((a) => (a === acct ? { ...a, label } : a)) });
        };
        input.addEventListener("keydown", (e) => {
            if (e.key === "Enter") commit();
            if (e.key === "Escape") render();
        });
        input.addEventListener("blur", commit);
    });

    $("remove").addEventListener("click", () => {
        const acct = currentAccount();
        const accounts = state.accounts.filter((a) => a !== acct);
        save({ accounts, selected: accounts[0]?.address || null });
    });

    $("add").addEventListener("submit", (e) => {
        e.preventDefault();
        const input = $("add-address");
        const address = input.value.trim();
        if (!ADDRESS_RE.test(address)) {
            input.classList.add("error");
            input.title = "Tiene que ser 0x seguido de 40 caracteres hex";
            return;
        }
        input.classList.remove("error");
        input.value = "";
        if (state.accounts.some((a) => same(a.address, address))) return save({ selected: address });
        const entry = { address, path: "", label: `Cuenta ${state.accounts.length + 1}`, addedAt: Date.now() };
        save({ accounts: [...state.accounts, entry], selected: address });
    });

    chrome.storage.onChanged.addListener((changes) => {
        for (const [k, { newValue }] of Object.entries(changes)) state[k] = newValue;
        render();
    });

    chrome.storage.local.get(["accounts", "selected", "network"]).then((stored) => {
        state = { accounts: stored.accounts || [], selected: stored.selected || null, network: stored.network || "mainnet" };
        render();
    });
})();

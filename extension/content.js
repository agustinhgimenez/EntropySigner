// Bridge between the EntropySigner simulator page and the extension storage.
// Only public data crosses it: an Ethereum address, its derivation path and a label.
(function () {
    "use strict";

    const PAGE = "entropysigner-page";
    const EXT = "entropysigner-ext";
    const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
    const PATH_RE = /^m(\/\d+'?){1,6}$/;

    function reply(type, payload) {
        window.postMessage({ source: EXT, type, ...payload }, "*");
    }

    async function connect(account) {
        if (!account || !ADDRESS_RE.test(account.address) || (account.path && !PATH_RE.test(account.path))) {
            reply("error", { message: "Cuenta inválida" });
            return;
        }
        const { accounts = [] } = await chrome.storage.local.get("accounts");
        const existing = accounts.find((a) => a.address.toLowerCase() === account.address.toLowerCase());
        if (existing) {
            reply("connected", { address: existing.address, already: true });
            return;
        }
        const entry = {
            address: account.address,
            path: account.path || "",
            label: String(account.label || `Cuenta ${accounts.length + 1}`).slice(0, 40),
            addedAt: Date.now(),
        };
        const selected = (await chrome.storage.local.get("selected")).selected || entry.address;
        await chrome.storage.local.set({ accounts: [...accounts, entry], selected });
        reply("connected", { address: entry.address, already: false });
    }

    window.addEventListener("message", (e) => {
        if (e.source !== window || !e.data || e.data.source !== PAGE) return;
        if (e.data.type === "ping") reply("ready", { version: chrome.runtime.getManifest().version });
        if (e.data.type === "connect") connect(e.data.account);
    });

    reply("ready", { version: chrome.runtime.getManifest().version });
})();

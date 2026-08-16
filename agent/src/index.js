/**
 * Entry point for the Cerberus-ASF Frida agent. Built (not loaded raw) via
 * `agent/build.sh`, which bundles this file and its imports — including
 * frida-java-bridge — into agent/dist/core_hooks.js with frida-compile.
 *
 * Raw unbundled scripts do NOT get an implicit `Java` global on current
 * Frida (confirmed directly against a real device: `typeof Java` is
 * `undefined` in every runtime mode without bundling) — this is why the
 * previous single-file core_hooks.js never actually worked.
 */
import Java from "frida-java-bridge";
import { installRootBypass } from "./hooks/root-bypass.js";
import { installSslBypass } from "./hooks/ssl-bypass.js";
import { scanMemory } from "./hooks/memory-scan.js";

rpc.exports = {
    getFridaVersion: () => Frida.version,
    scanMemory: (pattern) => {
        send({ level: "crypto", message: "[Frida] Initializing heap & memory scanner for pattern: " + (pattern || "default tokens") });
        return scanMemory(pattern, send);
    },
    scan_memory: (pattern) => {
        send({ level: "crypto", message: "[Frida] Initializing heap & memory scanner for pattern: " + (pattern || "default tokens") });
        return scanMemory(pattern, send);
    },
};

recv("config", (msg) => {
    if (msg.root) installRootBypass(Java, send);
    if (msg.pinning) installSslBypass(Java, send);
});

send({ level: "info", message: "[Frida Engine] Hooks loaded into memory matrix." });

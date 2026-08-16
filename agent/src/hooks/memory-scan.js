import { stringToHexPattern, readSafeStringWithContext } from "../utils.js";

/**
 * Default keyword list. Generic bare keywords ("password", "secret",
 * "api_key" with nothing else) match that literal byte sequence anywhere
 * in process memory — including inside unrelated framework strings,
 * class/method metadata, and third-party SDK internals — which is why an
 * earlier version of this list produced thousands of hits dominated by
 * noise on a real scan. Assignment-shaped variants ("password=",
 * "password":"...") cut that noise substantially while still catching
 * real assignments. The already-distinctive patterns (AIza/AKIA/sk_live_/
 * PEM headers/JWT header) don't have this problem and are left as bare
 * prefixes, since they're inherently unlikely to appear incidentally.
 */
const DEFAULT_TARGETS = [
    { label: "API Key Assignment", text: "api_key=" },
    { label: "API Key Assignment (JSON)", text: "api_key\":\"" },
    { label: "Password Assignment", text: "password=" },
    { label: "Password Assignment (JSON)", text: "password\":\"" },
    { label: "Secret Assignment", text: "secret=" },
    { label: "Secret Assignment (JSON)", text: "secret\":\"" },
    { label: "Bearer Authorization Token", text: "Bearer " },
    { label: "HTTP Authentication Header", text: "Authorization: " },
    { label: "RSA / Cryptographic Private Key", text: "PRIVATE KEY" },
    { label: "PEM-Encoded Key/Cert Block", text: "-----BEGIN" },
    { label: "Active JWT Token Header", text: "eyJhbGciOi" },
    { label: "Google Cloud / Firebase API Key", text: "AIza" },
    { label: "AWS Access Key", text: "AKIA" },
    { label: "Stripe Live Secret Key", text: "sk_live_" },
    { label: "Stripe Live Restricted Key", text: "rk_live_" },
    { label: "SSH Public Key Material", text: "ssh-rsa" },
];

const SNIPPET_CONTEXT_BEFORE = 24;
const SNIPPET_TOTAL_LEN = 88; // 24 bytes before the match + ~64 after
const LIVE_MESSAGE_CAP = 50; // avoid flooding the telemetry console on large scans

export function scanMemory(customPattern, send) {
    const searchTargets = [];
    if (customPattern && customPattern.trim() !== "") {
        const cleanStr = customPattern.trim();
        searchTargets.push({ label: "Custom Search Match", text: cleanStr, pattern: stringToHexPattern(cleanStr) });
    } else {
        DEFAULT_TARGETS.forEach((item) => {
            searchTargets.push({ label: item.label, text: item.text, pattern: stringToHexPattern(item.text) });
        });
    }

    const results = [];
    let liveMessagesSent = 0;
    try {
        const ranges = Process.enumerateRanges("rw-").concat(Process.enumerateRanges("r--"));
        ranges.forEach((range) => {
            if (range.size > 15 * 1024 * 1024) return;
            try {
                searchTargets.forEach((target) => {
                    const matches = Memory.scanSync(range.base, range.size, target.pattern);
                    matches.forEach((match) => {
                        const snippet = readSafeStringWithContext(match.address, SNIPPET_CONTEXT_BEFORE, SNIPPET_TOTAL_LEN) || target.text;
                        const hit = {
                            address: match.address.toString(),
                            category: target.label,
                            snippet: snippet.replace(/(\r\n|\n|\r)/gm, " ").trim(),
                            identified_data: target.text,
                        };
                        results.push(hit);

                        // Sent for every hit, uncapped — this is the agent-to-backend
                        // link (fast local RPC), not the backend-to-browser websocket,
                        // so volume here is cheap. The backend accumulates these
                        // silently so that a scan interrupted mid-way (confirmed to
                        // happen in practice: a timeout, or the target process
                        // freezing/dying) still returns whatever was found before the
                        // interruption instead of losing it entirely along with the
                        // lost return value.
                        send({ kind: "memory_hit", hit: hit });

                        // Separate, human-readable, capped message for the visible
                        // telemetry console — this one WOULD flood the browser if
                        // sent uncapped (confirmed: thousands of console lines on a
                        // large scan), so it stays capped independently of the line
                        // above.
                        if (liveMessagesSent < LIVE_MESSAGE_CAP) {
                            send({ level: "crypto", message: "[Frida Memory Hit] Found '" + target.text + "' at offset " + match.address.toString() });
                            liveMessagesSent++;
                        }
                    });
                });
            } catch (innerErr) { /* unreadable range mid-scan, skip it */ }
        });
    } catch (e) {
        send({ level: "warning", message: "[Frida Memory Scan] Range iteration warning: " + e.toString() });
    }

    if (results.length > liveMessagesSent) {
        send({ level: "info", message: "[Frida Memory Scan] " + (results.length - liveMessagesSent) + " additional hits not shown live (see full results in the response)." });
    }
    send({ level: "info", message: "[Frida Memory Scan] Analysis complete. Extracted " + results.length + " live runtime memory blocks." });
    return results;
}

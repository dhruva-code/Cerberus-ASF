export function stringToHexPattern(str) {
    const hex = [];
    for (let i = 0; i < str.length; i++) {
        let code = str.charCodeAt(i).toString(16);
        if (code.length === 1) code = "0" + code;
        hex.push(code);
    }
    return hex.join(" ");
}

function decodePrintable(bytes) {
    let str = "";
    for (let i = 0; i < bytes.length; i++) {
        const b = bytes[i];
        if (b >= 32 && b <= 126) {
            str += String.fromCharCode(b);
        } else if (b === 10 || b === 13 || b === 9) {
            str += " ";
        } else {
            str += ".";
        }
    }
    return str;
}

export function readSafeString(address, maxLen) {
    try {
        const buf = Memory.readByteArray(address, maxLen);
        if (!buf) return null;
        const bytes = new Uint8Array(buf);
        let str = "";
        for (let i = 0; i < bytes.length; i++) {
            const b = bytes[i];
            if (b === 0 && i > 3) break; // terminate at null byte if we have at least 4 chars
            if (b >= 32 && b <= 126) {
                str += String.fromCharCode(b);
            } else if (b === 10 || b === 13 || b === 9) {
                str += " ";
            } else {
                str += ".";
            }
        }
        return str;
    } catch (e) {
        try {
            return Memory.readUtf8String(address);
        } catch (e2) {
            return "[Binary Buffer @ " + address + "]";
        }
    }
}

/**
 * Same idea as readSafeString, but also captures a few bytes *before* the
 * match address — a bare keyword match on its own ("password") is much
 * harder to judge than one with its preceding context ("userPassword=",
 * "confirm_password":). Falls back to a forward-only read (matching
 * readSafeString's own fallback chain) if the leading read fails — e.g.
 * the match sits right at the start of a mapped page and reading before
 * it would underflow into unmapped memory.
 */
export function readSafeStringWithContext(address, contextBefore, totalLen) {
    try {
        const start = address.sub(contextBefore);
        const buf = Memory.readByteArray(start, totalLen);
        if (!buf) return readSafeString(address, totalLen - contextBefore);
        return decodePrintable(new Uint8Array(buf));
    } catch (e) {
        return readSafeString(address, totalLen - contextBefore);
    }
}

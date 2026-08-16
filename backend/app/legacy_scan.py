"""
Legacy regex-over-raw-bytes signature matching.

This is the pre-rewrite detection path: patterns written in Java-call
syntax (e.g. "Log.d(", "Cipher.getInstance(") matched against printable
strings extracted directly from raw APK/DEX bytes. It's structurally
unable to match compiled bytecode (method calls in DEX reference a class
string and a method-name string separately — never as contiguous
"Class.method(" source text) and is kept only as a fallback for
environments where jadx is unavailable or decompilation fails, so a scan
still returns *something* rather than nothing.

Superseded by app.ast_engine.ASTAnalyzer whenever jadx is available.
"""

import re

LEGACY_SIGNATURES = [
    {"id": "CERBERUS-SEC-01", "title": "Insecure Symmetric Cryptography (ECB Mode)", "owasp": "M5: Insufficient Cryptography", "severity": "HIGH", "category": "Security Analysis", "description": "AES ECB mode detected. Identical plaintext inputs yield identical ciphertext repetitions.", "remediation": "Migrate your block initialization algorithms to secure authenticated alternatives like AES/GCM/NoPadding.", "patterns": [r"AES/ECB/PKCS5Padding", r"AES/ECB/NoPadding", r"Cipher\.getInstance\(\s*['\"]AES/ECB"]},
    {"id": "CERBERUS-SEC-02", "title": "Deprecated Hash Verification (MD5/SHA-1)", "owasp": "M5: Insufficient Cryptography", "severity": "MEDIUM", "category": "Security Analysis", "description": "MD5 or SHA-1 hashes used. These algorithms are known to have collision vulnerabilities.", "remediation": "Migrate verification routines to collision-resistant algorithms such as SHA-256 or SHA-512.", "patterns": [r"MessageDigest\.getInstance\(\s*['\"]MD5['\"]", r"MessageDigest\.getInstance\(\s*['\"]SHA-1['\"]"]},
    {"id": "CERBERUS-SEC-03", "title": "SQL Injection Risk (Raw Queries)", "owasp": "M2: Improper Injection", "severity": "HIGH", "category": "Security Analysis", "description": "Dynamic SQL queries constructed via string appending operations. Untrusted user input can cause SQL Injection.", "remediation": "Use parameterized bindings and compile-safe arguments.", "patterns": [r"rawQuery\s*\(", r"execSQL\s*\("]},
    {"id": "CERBERUS-SEC-04", "title": "Insecure Logging of Sensitive Information", "owasp": "M1: Insecure Data Storage", "severity": "INFO", "category": "Security Analysis", "description": "The App logs information using Android's Log class. Sensitive information should never be logged.", "remediation": "Remove Log.d, Log.e, Log.i, Log.v calls from production builds.", "patterns": [r"Log\.[vdeiw]\("]},
    {"id": "CERBERUS-SEC-05", "title": "Clipboard Data Exposure", "owasp": "M1: Insecure Data Storage", "severity": "INFO", "category": "Security Analysis", "description": "The App copies data to the clipboard. Other applications can access this sensitive data.", "remediation": "Avoid copying sensitive credentials or PII to the global clipboard manager.", "patterns": [r"ClipboardManager", r"setPrimaryClip"]},
    {"id": "CERBERUS-SEC-06", "title": "Insecure Random Number Generator", "owasp": "M5: Insufficient Cryptography", "severity": "MEDIUM", "category": "Security Analysis", "description": "The App uses an insecure Random Number Generator (java.util.Random).", "remediation": "Use java.security.SecureRandom for cryptographic operations.", "patterns": [r"java\.util\.Random"]},
    {"id": "CERBERUS-DEF-01", "title": "Certificate Pinning Implementation Detected", "owasp": "M3: Insecure Communication", "severity": "SAFE", "category": "Security Analysis", "description": "The App uses SSL certificate pinning to prevent MITM attacks.", "remediation": "Ensure the pinning configuration covers all critical API endpoints.", "patterns": [r"CertificatePinner", r"checkServerTrusted"]},
    {"id": "CERBERUS-DEF-02", "title": "Root/Jailbreak Detection Capabilities", "owasp": "M8: Code Tampering", "severity": "SAFE", "category": "Security Analysis", "description": "This App has root detection capabilities to prevent execution in compromised environments.", "remediation": "Regularly update root detection heuristics to combat tools like Magisk.", "patterns": [r"com/scottyab/rootbeer", r"RootBeer", r"test-keys", r"/system/xbin/su"]},
    {"id": "CERBERUS-MAL-01", "title": "Dynamic Bytecode Payload Hook", "owasp": "M10: Extraneous Functionality", "severity": "HIGH", "category": "Malware Analysis", "description": "The code initializes executable assets via dynamic loaders, risking remote code delivery.", "remediation": "Ensure all functional application paths are frozen natively within your production compilation.", "patterns": [r"DexClassLoader", r"PathClassLoader"]},
]


def match_signatures(content: str, filename: str) -> list:
    """Matches LEGACY_SIGNATURES against already-extracted printable string
    content from a single APK-internal file. Returns raw finding dicts
    (still carrying "patterns" — caller strips it, same as before)."""
    findings = []
    for rule in LEGACY_SIGNATURES:
        for pattern in rule["patterns"]:
            for match in re.finditer(pattern, content):
                start = max(0, match.start() - 60)
                end = min(len(content), match.end() + 60)
                findings.append({**rule, "target": filename, "line": "Binary Offset", "code": content[start:end].strip()})
    return findings

"""
Structural (AST) rule definitions for the tree-sitter-based static analyzer.

Each rule mirrors the metadata shape of the legacy regex signatures
(app/legacy_scan.py) but replaces "patterns" (regex strings matched against
raw extracted bytes) with "queries" (tree-sitter query strings matched
against a parsed Java AST of jadx-decompiled source).
"""

AST_RULES = [
    {
        "id": "CERBERUS-SEC-01",
        "title": "Insecure Symmetric Cryptography (ECB Mode)",
        "owasp": "M5: Insufficient Cryptography",
        "severity": "HIGH",
        "category": "Security Analysis",
        "description": "AES ECB mode detected. Identical plaintext inputs yield identical ciphertext repetitions.",
        "remediation": "Migrate your block initialization algorithms to secure authenticated alternatives like AES/GCM/NoPadding.",
        "queries": [
            """
            (method_invocation
              object: (identifier) @obj (#eq? @obj "Cipher")
              name: (identifier) @method (#eq? @method "getInstance")
              arguments: (argument_list
                (string_literal) @arg (#match? @arg "AES/ECB"))) @call
            """
        ],
    },
    {
        "id": "CERBERUS-SEC-02",
        "title": "Deprecated Hash Verification (MD5/SHA-1)",
        "owasp": "M5: Insufficient Cryptography",
        "severity": "MEDIUM",
        "category": "Security Analysis",
        "description": "MD5 or SHA-1 hashes used. These algorithms are known to have collision vulnerabilities.",
        "remediation": "Migrate verification routines to collision-resistant algorithms such as SHA-256 or SHA-512.",
        "queries": [
            """
            (method_invocation
              object: (identifier) @obj (#eq? @obj "MessageDigest")
              name: (identifier) @method (#eq? @method "getInstance")
              arguments: (argument_list
                (string_literal) @arg (#match? @arg "MD5|SHA-1"))) @call
            """
        ],
    },
    {
        "id": "CERBERUS-SEC-03",
        "title": "SQL Injection Risk (Raw Queries)",
        "owasp": "M2: Improper Injection",
        "severity": "HIGH",
        "category": "Security Analysis",
        "description": "Dynamic SQL queries constructed via string appending operations. Untrusted user input can cause SQL Injection.",
        "remediation": "Use parameterized bindings and compile-safe arguments.",
        "queries": [
            """
            (method_invocation
              name: (identifier) @method (#match? @method "^(rawQuery|execSQL)$")) @call
            """
        ],
    },
    {
        "id": "CERBERUS-SEC-04",
        "title": "Insecure Logging of Sensitive Information",
        "owasp": "M1: Insecure Data Storage",
        "severity": "INFO",
        "category": "Security Analysis",
        "description": "The App logs information using Android's Log class. Sensitive information should never be logged.",
        "remediation": "Remove Log.d, Log.e, Log.i, Log.v calls from production builds.",
        "queries": [
            """
            (method_invocation
              object: (identifier) @obj (#eq? @obj "Log")
              name: (identifier) @method (#match? @method "^[vdiew]$")) @call
            """
        ],
    },
    {
        "id": "CERBERUS-SEC-05",
        "title": "Clipboard Data Exposure",
        "owasp": "M1: Insecure Data Storage",
        "severity": "INFO",
        "category": "Security Analysis",
        "description": "The App copies data to the clipboard. Other applications can access this sensitive data.",
        "remediation": "Avoid copying sensitive credentials or PII to the global clipboard manager.",
        "queries": [
            """((type_identifier) @call (#eq? @call "ClipboardManager"))""",
            """
            (method_invocation
              name: (identifier) @method (#eq? @method "setPrimaryClip")) @call
            """,
        ],
    },
    {
        "id": "CERBERUS-SEC-06",
        "title": "Insecure Random Number Generator",
        "owasp": "M5: Insufficient Cryptography",
        "severity": "MEDIUM",
        "category": "Security Analysis",
        "description": "The App uses an insecure Random Number Generator (java.util.Random).",
        "remediation": "Use java.security.SecureRandom for cryptographic operations.",
        "queries": [
            """
            (import_declaration (scoped_identifier) @imp (#eq? @imp "java.util.Random")) @call
            """,
            """
            (object_creation_expression
              type: (type_identifier) @type (#eq? @type "Random")) @call
            """,
        ],
    },
    {
        "id": "CERBERUS-DEF-01",
        "title": "Certificate Pinning Implementation Detected",
        "owasp": "M3: Insecure Communication",
        "severity": "SAFE",
        "category": "Security Analysis",
        "description": "The App uses SSL certificate pinning to prevent MITM attacks.",
        "remediation": "Ensure the pinning configuration covers all critical API endpoints.",
        "queries": [
            """((type_identifier) @call (#eq? @call "CertificatePinner"))""",
            """
            (method_invocation
              name: (identifier) @method (#eq? @method "checkServerTrusted")) @call
            """,
        ],
    },
    {
        "id": "CERBERUS-DEF-02",
        "title": "Root/Jailbreak Detection Capabilities",
        "owasp": "M8: Code Tampering",
        "severity": "SAFE",
        "category": "Security Analysis",
        "description": "This App has root detection capabilities to prevent execution in compromised environments.",
        "remediation": "Regularly update root detection heuristics to combat tools like Magisk.",
        "queries": [
            """((type_identifier) @call (#eq? @call "RootBeer"))""",
            """
            (import_declaration (scoped_identifier) @imp (#match? @imp "com\\.scottyab\\.rootbeer")) @call
            """,
            """((string_literal) @call (#match? @call "test-keys|/system/xbin/su"))""",
        ],
    },
    {
        "id": "CERBERUS-MAL-01",
        "title": "Dynamic Bytecode Payload Hook",
        "owasp": "M10: Extraneous Functionality",
        "severity": "HIGH",
        "category": "Malware Analysis",
        "description": "The code initializes executable assets via dynamic loaders, risking remote code delivery.",
        "remediation": "Ensure all functional application paths are frozen natively within your production compilation.",
        "queries": [
            """
            (object_creation_expression
              type: (type_identifier) @type (#match? @type "^(DexClassLoader|PathClassLoader)$")) @call
            """
        ],
    },
]

import re
import zipfile
import logging
import math
import hashlib
import os
import json
import subprocess
import tempfile
import shutil
import datetime

from app.decompiler import JadxDecompiler
from app.ast_engine import ASTAnalyzer, SKIP_FILENAMES
from app import legacy_scan

# Package-presence framework signatures: more reliable than exact-filename
# checks against the raw zip (below), since those miss any SDK version/
# integration that doesn't ship the exact config/service file being
# checked for even though the SDK's own code is clearly present once
# decompiled (e.g. "com/google/android/gms/*" with thousands of files but
# no "google-services.json" asset).
FRAMEWORK_PACKAGE_SIGNATURES = [
    ("com/google/android/gms", "Google Play Services", "Google Mobile Services SDK"),
    ("com/google/firebase", "Firebase Services", "Google Cloud Infrastructure"),
    ("com/google/android/material", "Material Components", "Google Material Design Library"),
    ("androidx", "AndroidX", "Modern Android Jetpack Support Library"),
    ("android/support", "Android Support Library", "Legacy Android Support Library"),
    ("kotlin", "Kotlin", "Kotlin Application Base"),
    ("okhttp3", "OkHttp3", "Square Network Client"),
    ("retrofit2", "Retrofit", "Square REST Client"),
    ("com/squareup", "Square Libraries", "Square Inc. Open Source Libraries"),
    ("com/facebook", "Facebook SDK", "Meta Platform SDK"),
    ("com/bumptech/glide", "Glide", "Bump Technologies Image Loading Library"),
    ("com/scottyab/rootbeer", "RootBeer", "Anti-Root Security Library"),
    ("org/apache", "Apache Commons/HTTP Libraries", "Apache Software Foundation Libraries"),
]

try:
    from androguard.core.bytecodes.apk import APK
    from androguard.core.bytecodes.axml import AXMLPrinter
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False

class StaticAnalyzer:
    def __init__(self):
        # Structural code-level detection (crypto, logging, SQL, dynamic loading, etc.)
        # is handled by AST queries over jadx-decompiled source (see app/ast_engine.py,
        # app/rules/structural_rules.py) instead of regex-over-raw-bytes. The regex
        # signature list that used to live here now lives in app/legacy_scan.py, used
        # only as a fallback when jadx is unavailable/fails.
        self.ast_analyzer = ASTAnalyzer()

        self.secret_patterns = {
            "Google Cloud / Firebase API Key": (r"AIza[0-9A-Za-z\-_]{35}", "HIGH"),
            "Firebase Database URL": (r"https://[a-zA-Z0-9-]+\.firebaseio\.com", "HIGH"),
            "AWS Access Key": (r"AKIA[0-9A-Z]{16}", "HIGH"),
            "Stripe Key": (r"[sr]k_live_[0-9a-zA-Z]{24}", "HIGH"),
            "JSON Web Token (JWT)": (r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*", "HIGH"),
            "Generic API Key/Token": (r"(?i)(api_key|apikey|secret|token|password)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{16,})['\"]?", "MEDIUM"),
            "System UUID Identifier": (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "INFO"),
        }

        self.dangerous_perms = ["CAMERA", "CONTACTS", "LOCATION", "MICROPHONE", "PHONE", "SENSORS", "SMS", "STORAGE", "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "SYSTEM_ALERT_WINDOW", "DUMP"]
        self.url_pattern = r"https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s'\"]*)?"
        self.email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

    def _calculate_entropy(self, text):
        if not text: return 0
        entropy = 0
        for x in range(256):
            p_x = float(text.count(chr(x))) / len(text)
            if p_x > 0: entropy += - p_x * math.log(p_x, 2)
        return entropy

    def _extract_binary_strings(self, raw_bytes: bytes) -> str:
        strings = re.findall(b"[\\x20-\\x7E\\x0A\\x0D]{4,}", raw_bytes)
        return "\n".join([s.decode('utf-8', errors='ignore') for s in strings])

    def _map_permission(self, perm: str):
        perm_clean = perm.split('.')[-1].upper()
        if perm_clean in self.dangerous_perms:
            return {"name": perm, "status": "DANGEROUS", "description": "Dangerous permission. Poses a direct risk to user privacy or device operation."}
        elif perm.startswith("android.permission"):
            return {"name": perm, "status": "NORMAL", "description": "Standard Android platform permission."}
        return {"name": perm, "status": "UNKNOWN", "description": "Custom or undocumented application permission."}

    def _resolve_fq_name(self, name, package_name):
        if not name: return "Unknown"
        if name.startswith("."): return f"{package_name}{name}"
        elif "." not in name: return f"{package_name}.{name}"
        return name

    def _get_file_hashes(self, apk_path):
        md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
        try:
            with open(apk_path, 'rb') as f:
                while chunk := f.read(8192):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
        except Exception: pass
        return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()

    def _extract_aapt_meta(self, apk_path: str) -> dict:
        """Bulletproof extraction using Android Asset Packaging Tool."""
        meta = {
            "package_name": "generic.android.target", "app_name": "Unknown", "version_name": "Unknown",
            "version_code": "Unknown", "min_sdk": "Unknown", "target_sdk": "Unknown",
            "main_activity": "Unknown", "permissions": [], "native_code": [], "features": []
        }

        aapt_bin = shutil.which("aapt2") or shutil.which("aapt")
        if not aapt_bin:
            return meta

        try:
            proc = subprocess.run([aapt_bin, "dump", "badging", apk_path], capture_output=True, text=True, timeout=15)
            out = proc.stdout

            pkg = re.search(r"package:\s*name='([^']+)'", out)
            if pkg: meta['package_name'] = pkg.group(1)

            app_name = re.search(r"application-label:'([^']+)'", out) or re.search(r"application:\s*label='([^']+)'", out)
            if app_name: meta['app_name'] = app_name.group(1)

            act = re.search(r"launchable-activity:\s*name='([^']+)'", out)
            if act: meta['main_activity'] = act.group(1)

            vname = re.search(r"versionName='([^']+)'", out)
            if vname: meta['version_name'] = vname.group(1)

            vcode = re.search(r"versionCode='([^']+)'", out)
            if vcode: meta['version_code'] = vcode.group(1)

            min_sdk = re.search(r"sdkVersion:'([^']+)'", out)
            if min_sdk: meta['min_sdk'] = min_sdk.group(1)

            target_sdk = re.search(r"targetSdkVersion:'([^']+)'", out)
            if target_sdk: meta['target_sdk'] = target_sdk.group(1)

            meta['permissions'] = re.findall(r"uses-permission:\s*name='([^']+)'", out)

            nc = re.search(r"native-code:\s*(.*)", out)
            if nc: meta['native_code'] = [x.strip().strip("'") for x in nc.group(1).split()]

            meta['features'] = re.findall(r"uses-feature:\s*name='([^']+)'", out)
        except Exception as e:
            logging.error(f"AAPT Meta extraction failed: {e}")

        return meta

    def _get_manifest_xml(self, apk_path: str) -> str:
        """Robust multi-layered AndroidManifest.xml extractor."""
        manifest_raw = ""

        # Method 1: Apktool (Best - Resolves string references natively)
        if shutil.which("apktool"):
            extract_dir = tempfile.mkdtemp(prefix="cerberus_apktool_")
            try:
                subprocess.run(["apktool", "d", apk_path, "-s", "-f", "-q", "-o", extract_dir], check=True, timeout=30)
                man_path = os.path.join(extract_dir, "AndroidManifest.xml")
                if os.path.exists(man_path):
                    with open(man_path, 'r', encoding='utf-8') as f:
                        manifest_raw = f.read()
            except Exception: pass
            finally:
                shutil.rmtree(extract_dir, ignore_errors=True)

        # Method 2: Androguard Binary XML Printer Fallback
        if not manifest_raw and ANDROGUARD_AVAILABLE:
            try:
                with zipfile.ZipFile(apk_path, 'r') as z:
                    if "AndroidManifest.xml" in z.namelist():
                        xml_bytes = z.read("AndroidManifest.xml")
                        axml = AXMLPrinter(xml_bytes)
                        import xml.etree.ElementTree as ET
                        manifest_tree = axml.get_xml_obj()
                        manifest_raw = ET.tostring(manifest_tree, encoding='unicode')
            except Exception as e:
                logging.debug(f"AXML Fallback failed: {e}")

        # Method 3: AAPT Tree Dump (Last Resort)
        if not manifest_raw and shutil.which("aapt"):
            try:
                proc = subprocess.run(["aapt", "dump", "xmltree", apk_path, "AndroidManifest.xml"], capture_output=True, text=True, timeout=10)
                if proc.stdout: manifest_raw = proc.stdout
            except Exception: pass

        return manifest_raw if manifest_raw else "Manifest binary could not be parsed."

    def _detect_frameworks_from_source(self, decompiled_src_dir: str) -> list:
        detected = []
        for prefix, name, description in FRAMEWORK_PACKAGE_SIGNATURES:
            candidate_dir = os.path.join(decompiled_src_dir, *prefix.split("/"))
            if not os.path.isdir(candidate_dir):
                continue
            evidence = prefix + "/"
            for root, _, files in os.walk(candidate_dir):
                java_files = [f for f in files if f.endswith(".java") and f not in SKIP_FILENAMES]
                if java_files:
                    evidence = os.path.relpath(os.path.join(root, java_files[0]), decompiled_src_dir)
                    break
            detected.append({"framework": name, "evidence": evidence, "description": description})
        return detected

    def _extract_certs_apksigner(self, apk_path):
        cert_info = {"details": {}}
        try:
            if shutil.which("apksigner"):
                # --verbose is required: the "Verified using vX scheme" lines (needed for
                # the v1/v2/v3/v4 flags and Janus-vulnerability detection below) are only
                # printed with --verbose, not with --print-certs alone.
                proc = subprocess.run(["apksigner", "verify", "--print-certs", "--verbose", apk_path], capture_output=True, text=True)
                out = proc.stdout
                if "Signer #1" in out or "Verified using" in out:
                    cert_info["is_signed"] = True
                    cert_info["v1"] = "Verified using v1 scheme (JAR signing): true" in out
                    cert_info["v2"] = "Verified using v2 scheme (APK Signature Scheme v2): true" in out
                    cert_info["v3"] = "Verified using v3 scheme (APK Signature Scheme v3): true" in out
                    cert_info["v4"] = "Verified using v4 scheme (APK Signature Scheme v4): true" in out

                    details = {}
                    dn_match = re.search(r"Signer #1 certificate DN:\s*(.*)", out)
                    if dn_match: details["subject"] = dn_match.group(1).strip()

                    sha256_match = re.search(r"Signer #1 certificate SHA-256 digest:\s*(.*)", out)
                    if sha256_match: details["sha256"] = sha256_match.group(1).strip()

                    sha1_match = re.search(r"Signer #1 certificate SHA-1 digest:\s*(.*)", out)
                    if sha1_match: details["sha1"] = sha1_match.group(1).strip()

                    algo_match = re.search(r"Signer #1 key algorithm:\s*(.*)", out)
                    if algo_match: details["public_key_algo"] = algo_match.group(1).strip()

                    size_match = re.search(r"Signer #1 key size \(bits\):\s*(.*)", out)
                    if size_match: details["bit_size"] = size_match.group(1).strip()

                    cert_info["details"] = details
        except Exception: pass
        return cert_info

    def analyze_apk(self, apk_path: str, deep_scan: bool = False,
                     ai_provider: str = None, ai_api_key: str = None,
                     ai_base_url: str = None, ai_model_name: str = None):
        import time
        ai = None
        ai_time_taken = 0.0

        if deep_scan:
            from app.ai_providers import get_ai_assistant
            ai = get_ai_assistant(ai_provider, ai_api_key, ai_base_url, ai_model_name)
            if not ai.is_configured:
                raise Exception("No AI provider configured for this account. Add an API key under AI Settings before enabling Deep Scan.")
            if not shutil.which("jadx"):
                raise Exception("JADX binary not found in system PATH. Required for AI Deep Scan semantic analysis.")

        # --- DECOMPILATION (once; shared by the AST structural scan below and,
        # when deep_scan=True, the AI semantic pass later in this function) ---
        decompiler = None
        decompiled_src_dir = None
        if shutil.which("jadx"):
            decompiler = JadxDecompiler()
            try:
                decompiled_src_dir = decompiler.decompile(apk_path)
            except (subprocess.TimeoutExpired, RuntimeError) as e:
                if deep_scan:
                    raise Exception(f"JADX decompilation failed during AI Deep Scan: {e}")
                logging.error(f"jadx decompile failed, falling back to legacy regex-based structural scan: {e}")
                decompiled_src_dir = None
        else:
            logging.warning("jadx not found on PATH; falling back to legacy regex-based structural scan.")

        try:
            return self._analyze_apk_inner(apk_path, deep_scan, ai, ai_time_taken, decompiled_src_dir, time)
        finally:
            if decompiler:
                decompiler.cleanup()

    def _analyze_apk_inner(self, apk_path, deep_scan, ai, ai_time_taken, decompiled_src_dir, time):
        # HARD CACHE REMOVAL: No cache checks. Ensures fresh scans every single time.
        md5_hash, sha1_hash, sha256_hash = self._get_file_hashes(apk_path)
        file_size_mb = round(os.path.getsize(apk_path) / (1024 * 1024), 2) if os.path.exists(apk_path) else 0

        security_score = 100
        findings, secrets, apk_id_findings = [], [], []
        manifest_analysis = []
        recon_urls, recon_emails, deep_links = set(), set(), set()

        activities = {"total": 0, "exported": 0, "details": []}
        services = {"total": 0, "exported": 0, "details": []}
        receivers = {"total": 0, "exported": 0, "details": []}
        providers = {"total": 0, "exported": 0, "details": []}

        cert_data = {"is_signed": False, "v1": False, "v2": False, "v3": False, "v4": False, "janus_vulnerable": False, "details": {}, "issues": []}

        # --- CORE METADATA EXTRACTION ---
        aapt_data = self._extract_aapt_meta(apk_path)
        package_name = aapt_data.get("package_name", "generic.android.target")
        permissions_mapped = [self._map_permission(p) for p in aapt_data.get("permissions", [])]

        app_info = {
            "app_name": aapt_data.get("app_name", "Unknown"),
            "package_name": package_name,
            "main_activity": aapt_data.get("main_activity", "Unknown"),
            "target_sdk": aapt_data.get("target_sdk", "Unknown"),
            "min_sdk": aapt_data.get("min_sdk", "Unknown"),
            "max_sdk": "Unknown",
            "version_name": aapt_data.get("version_name", "Unknown"),
            "version_code": aapt_data.get("version_code", "Unknown"),
            "native_architectures": ", ".join(aapt_data.get("native_code", [])) or "None (Java/Kotlin Only)",
            "hardware_features": len(aapt_data.get("features", []))
        }

        file_info = {
            "name": os.path.basename(apk_path), "size": f"{file_size_mb} MB",
            "md5": md5_hash, "sha1": sha1_hash, "sha256": sha256_hash
        }

        # --- MANIFEST & COMPONENT AUDIT ---
        manifest_raw = self._get_manifest_xml(apk_path)

        if manifest_raw != "Manifest binary could not be parsed.":
            # 1. Clean XML for UI readability
            try:
                from xml.dom import minidom
                manifest_raw = minidom.parseString(manifest_raw).toprettyxml(indent="  ")
                manifest_raw = os.linesep.join([s for s in manifest_raw.splitlines() if s.strip()])
            except Exception: pass

            # 2. Extract Components using resilient Regex
            for tag, container, label in [("activity", activities, "Activity"), ("service", services, "Service"), ("receiver", receivers, "Broadcast Receiver"), ("provider", providers, "Content Provider")]:
                pattern = rf'<{tag}(.*?)(?:>(.*?)</{tag}>|/>)'
                for match in re.finditer(pattern, manifest_raw, re.DOTALL | re.IGNORECASE):
                    attrs = match.group(1)
                    inner = match.group(2) or ""

                    name_match = re.search(r'android:name="([^"]+)"', attrs)
                    if not name_match: continue
                    fq_name = self._resolve_fq_name(name_match.group(1), package_name)

                    is_exported = False
                    exp_match = re.search(r'android:exported="([^"]+)"', attrs)
                    if exp_match:
                        is_exported = exp_match.group(1).lower() == "true"
                    elif "<intent-filter" in inner:
                        is_exported = True

                    if not any(x["name"] == fq_name for x in container["details"]):
                        container["total"] += 1
                        if is_exported:
                            container["exported"] += 1
                            manifest_analysis.append({"issue": f"{label} ({fq_name}) is not Protected", "severity": "MEDIUM", "description": "Component is shared with other apps via IPC.", "remediation": "Set android:exported='false' or apply strong signature permissions.", "evidence": f'<{tag} android:name="{name_match.group(1)}" android:exported="true">'})
                            security_score -= 2
                        container["details"].append({"name": fq_name, "status": "EXPORTED" if is_exported else "INTERNAL"})

            # 3. Extract Missing Permissions
            perm_matches = re.findall(r'<uses-permission[^>]+android:name="([^"]+)"', manifest_raw)
            for p in set(perm_matches):
                if not any(x["name"] == p for x in permissions_mapped):
                    permissions_mapped.append(self._map_permission(p))

            # 4. Manifest Security Misconfigurations
            try:
                m_sdk = app_info["min_sdk"]
                if m_sdk and str(m_sdk).isdigit() and int(m_sdk) < 29:
                    manifest_analysis.append({"issue": f"Outdated MinSDK [android:minSdkVersion={m_sdk}]", "severity": "HIGH", "description": "App can be installed on older vulnerable Android versions.", "remediation": "Support an Android version >= 10 (API 29).", "evidence": f'android:minSdkVersion="{m_sdk}"'})
                    security_score -= 10
            except Exception: pass

            if 'android:debuggable="true"' in manifest_raw:
                manifest_analysis.append({"issue": "Debug Enabled [android:debuggable=true]", "severity": "HIGH", "description": "Debugging is enabled, allowing reverse engineers to attach debuggers.", "remediation": "Set android:debuggable='false' in production.", "evidence": 'android:debuggable="true"'})
                security_score -= 15

            if 'android:allowBackup="true"' in manifest_raw:
                manifest_analysis.append({"issue": "Application Data Backup Allowed [android:allowBackup=true]", "severity": "MEDIUM", "description": "Anyone can backup application data via adb.", "remediation": "Set android:allowBackup='false'.", "evidence": 'android:allowBackup="true"'})
                security_score -= 5

            if 'android:usesCleartextTraffic="true"' in manifest_raw:
                manifest_analysis.append({"issue": "Cleartext Traffic Allowed", "severity": "HIGH", "description": "App is configured to permit clear text HTTP traffic.", "remediation": "Set usesCleartextTraffic='false'.", "evidence": 'android:usesCleartextTraffic="true"'})
                security_score -= 10

        # --- STRUCTURAL AST ANALYSIS (crypto/logging/SQL/etc.) + FIELD SECRET DETECTION ---
        if decompiled_src_dir:
            ast_findings, ast_secrets = self.ast_analyzer.scan_directory(decompiled_src_dir, package_name)
            findings.extend(ast_findings)
            secrets.extend(ast_secrets)

        # --- TRUFFLEHOG SECRETS INTEGRATION ---
        extracted_dir = tempfile.mkdtemp(prefix="cerberus_th_")
        try:
            with zipfile.ZipFile(apk_path, 'r') as z:
                z.extractall(extracted_dir)
            if shutil.which("trufflehog"):
                th_cmd = ["trufflehog", "filesystem", extracted_dir, "--json", "--no-update"]
                th_proc = subprocess.run(th_cmd, capture_output=True, text=True)
                for line in th_proc.stdout.splitlines():
                    if line.strip():
                        try:
                            th_data = json.loads(line)
                            detector = th_data.get("DetectorName", "TruffleHog Secret")
                            raw_secret = th_data.get("Raw", "Hidden/Redacted")
                            verified = th_data.get("Verified", False)
                            f_meta = th_data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", "Unknown")
                            clean_file_path = f_meta.replace(extracted_dir, "").lstrip("/")

                            secrets.append({
                                "type": f"{detector} (Verified: {verified})",
                                "value": raw_secret[:60] + "..." if len(raw_secret) > 60 else raw_secret,
                                "severity": "HIGH" if verified else "MEDIUM",
                                "file": clean_file_path,
                                "scope": "unknown"
                            })
                        except Exception: pass
        except Exception: pass
        finally:
            shutil.rmtree(extracted_dir, ignore_errors=True)

        # --- CRYPTOGRAPHIC CERTIFICATE AUDIT ---
        apksigner_data = self._extract_certs_apksigner(apk_path)
        if apksigner_data.get("is_signed"):
            cert_data["is_signed"] = True
            cert_data["v1"], cert_data["v2"] = apksigner_data.get("v1", False), apksigner_data.get("v2", False)
            cert_data["v3"], cert_data["v4"] = apksigner_data.get("v3", False), apksigner_data.get("v4", False)
            cert_data["details"].update(apksigner_data.get("details", {}))

        c_details = cert_data.get("details", {})
        if c_details:
            if "Android Debug" in c_details.get("issuer", "") or "Android Debug" in c_details.get("subject", ""):
                cert_data["issues"].append({"issue": "Signed with Debug Certificate", "severity": "HIGH", "owasp": "M1: Insecure Data", "description": "Application is signed with an insecure debug certificate.", "remediation": "Sign with release keys.", "link": "https://developer.android.com/studio/publish/app-signing", "evidence": f"Certificate subject: {c_details.get('subject', 'Unknown')}"})
                security_score -= 15
            if "sha1" in c_details.get("hash", "").lower() or "sha1" in c_details.get("signature_algo", "").lower():
                cert_data["issues"].append({"issue": "Vulnerable hash collision (SHA-1)", "severity": "MEDIUM", "owasp": "M5: Insufficient Cryptography", "description": "App uses weak SHA-1 signatures.", "remediation": "Sign with SHA-256.", "link": "https://cve.mitre.org", "evidence": f"Signature algorithm: {c_details.get('public_key_algo', 'Unknown')}, SHA-1: {c_details.get('sha1', 'Unknown')}"})

        if cert_data.get("v1") and not cert_data.get("v2") and not cert_data.get("v3"):
            cert_data["janus_vulnerable"] = True
            cert_data["issues"].append({"issue": "Vulnerable to Janus Vulnerability", "severity": "HIGH", "owasp": "M5: Insufficient Cryptography", "description": "Application is signed with v1 signature scheme only.", "remediation": "Sign the APK using APK Signature Scheme v2 or v3 dynamically.", "link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13156", "evidence": f"Signature schemes verified — v1: {cert_data.get('v1')}, v2: {cert_data.get('v2')}, v3: {cert_data.get('v3')}, v4: {cert_data.get('v4')}"})
            security_score -= 20
        elif not cert_data.get("is_signed"):
            cert_data["issues"].append({"issue": "Unsigned Application Target", "severity": "HIGH", "owasp": "M1: Insecure Data", "description": "Application lacks a valid cryptographic code signing signature.", "remediation": "Configure signed outputs inside keystore publishing setups.", "evidence": "apksigner verify: no valid signing certificate found in APK"})

        # --- GLOBAL BINARY EXTRACTION (RECON, FRAMEWORKS, SECRET-PATTERN MATCHING, LEGACY FALLBACK) ---
        frameworks = []
        if decompiled_src_dir:
            frameworks.extend(self._detect_frameworks_from_source(decompiled_src_dir))
        try:
            with zipfile.ZipFile(apk_path, 'r') as archive:
                for f in archive.namelist():
                    # High-Accuracy Framework Heuristics
                    if "assets/www/cordova.js" in f or "assets/www/cordova_plugins.js" in f: frameworks.append({"framework": "Cordova / PhoneGap", "evidence": f, "description": "Hybrid Web Framework"})
                    elif "libflutter.so" in f: frameworks.append({"framework": "Flutter", "evidence": f, "description": "Google UI Toolkit"})
                    elif "libreactnativejni.so" in f or "assets/index.android.bundle" in f: frameworks.append({"framework": "React Native", "evidence": f, "description": "Meta UI Framework"})
                    elif "assets/bin/Data/Managed" in f: frameworks.append({"framework": "Unity 3D", "evidence": f, "description": "Game Engine"})
                    elif "libmonosgen-2.0.so" in f or "assemblies/" in f: frameworks.append({"framework": "Xamarin", "evidence": f, "description": "Microsoft .NET Framework"})
                    elif f.startswith("kotlin/") and f.endswith(".kotlin_builtins"): frameworks.append({"framework": "Kotlin", "evidence": f, "description": "Kotlin Application Base"})
                    elif "libtool-checker.so" in f or "RootBeer" in f: frameworks.append({"framework": "RootBeer", "evidence": f, "description": "Anti-Root Security Library"})
                    elif "google-services.json" in f or "META-INF/services/com.google.firebase.components.ComponentRegistrar" in f: frameworks.append({"framework": "Firebase Services", "evidence": f, "description": "Google Cloud Infrastructure"})
                    elif "META-INF/services/okhttp3.internal.tls.CertificateChainCleaner" in f: frameworks.append({"framework": "OkHttp3", "evidence": f, "description": "Square Network Client"})

                for filename in archive.namelist():
                    if any(filename.endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp3", ".mp4", ".wav", ".ttf", ".so", ".bin", ".pb", ".arsc"]):
                        continue

                    try:
                        with archive.open(filename) as f:
                            content = self._extract_binary_strings(f.read())

                            for u in set(re.findall(self.url_pattern, content)):
                                if not any(x in u for x in ["schema", "w3.org", "android"]): recon_urls.add(u)
                            for em in set(re.findall(self.email_pattern, content)):
                                if not em.endswith(".png") and not em.endswith(".xml"): recon_emails.add(em)

                            if not decompiled_src_dir:
                                for lf in legacy_scan.match_signatures(content, filename):
                                    lf["scope"] = "unknown"
                                    findings.append(lf)

                            for sec_name, (regex, sev) in self.secret_patterns.items():
                                for match in re.finditer(regex, content):
                                    val = match.group(0) if not match.groups() else match.group(match.lastindex)
                                    if len(val) > 8:
                                        secrets.append({"type": sec_name, "value": val, "severity": sev, "file": filename, "scope": "unknown"})
                                        if sev == "HIGH": security_score -= 5
                    except Exception: pass
        except Exception as e:
            logging.error(f"Binary global scan failed: {e}")

        # Final Formatting & Cleanup
        unique_findings = []
        seen_f = set()
        for f in findings:
            sig = f"{f['id']}-{f['target']}-{f.get('line', '')}"
            if sig not in seen_f:
                seen_f.add(sig)
                f_clean = {k: v for k, v in f.items() if k != 'patterns' and k != 'queries'}
                if deep_scan and ai and ai.is_configured:
                    t_start = time.time()
                    verification = ai.verify_finding(f_clean['title'], f_clean.get('code', ''))
                    ai_time_taken += (time.time() - t_start)

                    f_clean['ai_verified'] = verification.get('verified', True)
                    f_clean['ai_reason'] = verification.get('reason', '')
                    if not f_clean['ai_verified']:
                        continue # Drop false positive
                unique_findings.append(f_clean)

        unique_secrets = list({v['value']:v for v in secrets}.values())
        verified_secrets = []
        for s in unique_secrets:
            if deep_scan and ai and ai.is_configured:
                t_start = time.time()
                verification = ai.verify_secret(s['type'], s['value'], "Extracted from binary/TruffleHog")
                ai_time_taken += (time.time() - t_start)

                s['ai_verified'] = verification.get('verified', True)
                s['ai_reason'] = verification.get('reason', '')
                if not s['ai_verified']:
                    continue
            verified_secrets.append(s)
        unique_secrets = verified_secrets

        seen_fw = set()
        for fw in frameworks:
            if fw["framework"] not in seen_fw:
                seen_fw.add(fw["framework"])
                apk_id_findings.append(fw)

        security_score = max(10, security_score)

        # AI Deep Scan: semantic analysis over the already-decompiled sources
        if deep_scan and ai and ai.is_configured:
            if decompiled_src_dir:
                for act in activities["details"]:
                    if act["status"] == "EXPORTED":
                        java_path = os.path.join(decompiled_src_dir, act["name"].replace(".", "/") + ".java")
                        if os.path.exists(java_path):
                            with open(java_path, "r", encoding="utf-8") as jf:
                                java_code = jf.read()[:12000] # Limit size for AI context

                                t_start = time.time()
                                ai_findings = ai.deep_scan_source(act["name"] + ".java", java_code)
                                ai_time_taken += (time.time() - t_start)

                                for af in ai_findings:
                                    unique_findings.append({
                                        "id": "CERBERUS-AI-01",
                                        "title": af.get("title", "AI Semantic Finding"),
                                        "severity": af.get("severity", "MEDIUM"),
                                        "description": af.get("description", ""),
                                        "remediation": af.get("remediation", ""),
                                        "category": "Semantic Analysis",
                                        "target": act["name"] + ".java",
                                        "line": af.get("line", ""),
                                        "ai_verified": True,
                                        "ai_reason": "Discovered via JADX Semantic Deep Scan",
                                        "scope": "app"  # exported activities are always app-owned classes
                                    })
            else:
                logging.warning("Decompiled source unavailable; AI Deep Scan semantic pass skipped.")

        # Fallback safeguard if app has no traditional main activity mapped
        if activities["total"] == 0 and app_info["main_activity"] != "Unknown":
            activities["details"].append({"name": self._resolve_fq_name(app_info["main_activity"], package_name), "status": "EXPORTED"})
            activities["total"], activities["exported"] = 1, 1

        # --- PROVENANCE SUMMARY (app-code vs. third-party-SDK vs. unclassifiable) ---
        findings_summary = {"app": 0, "third_party": 0, "unknown": 0}
        for f in unique_findings:
            scope = f.get("scope", "unknown")
            findings_summary[scope] = findings_summary.get(scope, 0) + 1
        findings_summary["total"] = len(unique_findings)

        secrets_summary = {"app": 0, "third_party": 0, "unknown": 0}
        for s in unique_secrets:
            scope = s.get("scope", "unknown")
            secrets_summary[scope] = secrets_summary.get(scope, 0) + 1
        secrets_summary["total"] = len(unique_secrets)

        result_dict = {
            "app_info": app_info,
            "file_info": file_info,
            "package_name": package_name,
            "security_score": security_score,
            "permissions": permissions_mapped,
            "manifest_xml": manifest_raw,
            "manifest_analysis": manifest_analysis,
            "certificate": cert_data,
            "apk_id": apk_id_findings,
            "secrets": unique_secrets,
            "secrets_summary": secrets_summary,
            "components": {"activities": activities, "services": services, "receivers": receivers, "providers": providers},
            "reconnaissance": {"urls": list(recon_urls)[:40], "emails": list(recon_emails)[:15], "deep_links": list(deep_links)},
            "findings": unique_findings,
            "findings_summary": findings_summary,
            "ai_metadata": {
                "performed": deep_scan,
                "llm": ai.model_name if ai else "None",
                "time_taken_seconds": round(ai_time_taken, 2)
            }
        }

        return result_dict

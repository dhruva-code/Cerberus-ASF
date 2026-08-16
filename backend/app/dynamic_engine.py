import asyncio
import logging
import subprocess

from app.orchestrator import AndroidOrchestrator
from app.rules.secret_rules import tokenize

logger = logging.getLogger("Cerberus-ASF")


def _classify_telemetry(message: str, level: str) -> tuple:
    """Returns (issue, severity) for a telemetry message.

    Uses whole-token matching, not substring matching — the original
    `"su" in message` matched "su" inside "mea**su**rement", "re**su**lt",
    "con**su**mer", anything containing that 2-character fragment. Same
    class of bug as the HOCKEY/DIVING false positives fixed earlier in
    the static secret detector (app/rules/secret_rules.py), and fixed the
    same way: tokenize the text and require an exact token match. Reusing
    that same tokenize() here rather than writing a second implementation.
    """
    tokens = set(tokenize(message))
    if "pinning" in tokens or "ssl" in tokens:
        return "SSL Certificate Pinning Interception", "CRITICAL"
    if "root" in tokens or "su" in tokens or "magisk" in tokens:
        return "Root Detection / Execution Intercepted", "HIGH"
    if level == "error":
        return "Runtime Execution Error", "MEDIUM"
    return "Frida Runtime Event", "INFO"


class DynamicAnalyzer:
    def __init__(self):
        self.is_running = False
        self.logcat_process = None
        self.findings = []
        self.package_name = ""
        self.orchestrator = AndroidOrchestrator()
        self.websocket = None

        async def telemetry_callback(message: str, level: str):
            logger.info(f"[Frida Telemetry - {level.upper()}] {message}")
            if not any(f["desc"] == message for f in self.findings):
                issue, severity = _classify_telemetry(message, level)
                if issue != "Frida Runtime Event" or level in ["crypto", "warning", "error"]:
                    self.findings.append({"issue": issue, "severity": severity, "desc": message})

            if self.websocket:
                try:
                    await self.websocket.send_json({
                        "type": "telemetry",
                        "data": {"level": level, "message": message}
                    })
                except Exception as e:
                    logger.error(f"WebSocket telemetry transmission error: {e}")

        self.orchestrator.set_telemetry_callback(telemetry_callback)

    def set_websocket(self, websocket):
        self.websocket = websocket

    async def start_analysis(self, package_name, root_bypass, pinning_bypass):
        """Initializes Frida hooks via Orchestrator and sets up the analysis session."""
        self.is_running = True
        self.package_name = package_name
        self.findings = []

        # Foundational findings for runtime bypass status
        if root_bypass:
            self.findings.append({"issue": "Root Detection Evasion Enabled", "severity": "INFORMATIONAL", "desc": "Frida hooks configured to spoof su path checks and block root exec commands."})
        if pinning_bypass:
            self.findings.append({"issue": "SSL Pinning Bypass Enabled", "severity": "INFORMATIONAL", "desc": "Frida hooks configured to neutralize TrustManagerImpl and OkHttp CertificatePinner validation."})

        # Attempt actual dynamic orchestration with attached target device/emulator
        success = await self.orchestrator.initialize_agent(package_name, root_bypass, pinning_bypass)
        if not success:
            logger.warning("Frida device attachment unsuccessful or device offline.")
            self.findings = []
            self.is_running = False
            return False

        return True

    async def stop_analysis(self):
        """Stops the session and returns the final vulnerability summary."""
        self.is_running = False
        await self.orchestrator.stop_agent()
        if self.logcat_process:
            try:
                self.logcat_process.terminate()
            except Exception:
                pass
        return self.findings

    async def scan_process_memory(self, pattern: str = None) -> list:
        """Executes targeted memory forensics across process RAM segments for sensitive strings or patterns."""
        if self.websocket:
            try:
                await self.websocket.send_json({
                    "type": "telemetry",
                    "data": {"level": "info", "message": f"[Memory Forensics] Initializing RAM address range sweep for ({self.package_name or 'target process'})..."}
                })
            except Exception:
                pass

        results = await self.orchestrator.scan_memory(pattern)

        if results:
            issue_title = "Plaintext Credentials in Runtime Memory"
            desc = f"Memory forensics sweep extracted {len(results)} sensitive plaintext string occurrences in readable process RAM segments."
            if not any(f["issue"] == issue_title for f in self.findings):
                self.findings.append({"issue": issue_title, "severity": "CRITICAL", "desc": desc})

            # Individual hits are already reported live via the agent's own
            # send() calls during the scan (agent/src/hooks/memory-scan.js),
            # forwarded through orchestrator.py's message handler as they
            # happen — re-sending every entry from the returned `results`
            # array here as well would report each hit twice over the
            # websocket. Just send a completion summary; the full result
            # list is still returned to the HTTP caller regardless.
            if self.websocket:
                try:
                    await self.websocket.send_json({
                        "type": "telemetry",
                        "data": {"level": "warning", "message": f"[Memory Forensics] Sweep finished. Logged {len(results)} high-risk unencrypted RAM artifacts into findings."}
                    })
                except Exception:
                    pass
        return results

    async def stream_logcat(self, package_name, websocket):
        """Asynchronously streams the target application's logcat to the frontend via WebSockets without blocking the event loop."""
        try:
            loop = asyncio.get_running_loop()
            pid_output = ""
            # 1. First priority: Get exact PID directly from active Frida Orchestrator session
            if hasattr(self.orchestrator, "current_pid") and self.orchestrator.current_pid:
                pid_output = str(self.orchestrator.current_pid)

            # 2. Retry PID resolution via ADB shell up to 3 seconds (handles spawning delays & modern Android 8.0+ ps behavior)
            for _ in range(6):
                if pid_output:
                    break
                try:
                    # subprocess.check_output blocks the calling thread — running it
                    # directly here would freeze the whole event loop for its duration,
                    # same class of bug as the memory-scan RPC call fixed in
                    # orchestrator.py. Route it through the executor instead.
                    out = await loop.run_in_executor(
                        None,
                        lambda: subprocess.check_output(["adb", "shell", "pidof", package_name], stderr=subprocess.DEVNULL).decode().strip()
                    )
                    if out:
                        pid_output = out.split()[0]
                        break
                except Exception:
                    pass

                try:
                    out = await loop.run_in_executor(
                        None,
                        lambda: subprocess.check_output(["adb", "shell", "ps", "-A"], stderr=subprocess.DEVNULL).decode()
                    )
                    for line in out.splitlines():
                        if package_name in line and "grep" not in line and "logcat" not in line:
                            parts = line.split()
                            if len(parts) > 1 and parts[1].isdigit():
                                pid_output = parts[1]
                                break
                except Exception:
                    pass

                await asyncio.sleep(0.5)

            if not pid_output:
                await websocket.send_json({"type": "logcat", "data": {"message": f"[SYSTEM] Could not resolve specific PID for ({package_name}). Streaming global Logcat filtered by package..."}})
            else:
                await websocket.send_json({"type": "logcat", "data": {"message": f"[SYSTEM] Locked onto PID: {pid_output} ({package_name}). Live Logcat stream initialized."}})

            # 3. Build non-blocking asynchronous logcat subprocess
            cmd = ["adb", "logcat", "-v", "threadtime", "-T", "50"]
            if pid_output:
                cmd.extend(["--pid", str(pid_output)])

            self.logcat_process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )

            while self.is_running and self.logcat_process.returncode is None:
                try:
                    line = await asyncio.wait_for(self.logcat_process.stdout.readline(), timeout=0.5)
                    if line:
                        text_line = line.decode("utf-8", errors="ignore").strip()
                        # If PID couldn't be bound via --pid, dynamically filter stream by package name or runtime tags
                        if not pid_output and package_name not in text_line and "Frida" not in text_line and "AndroidRuntime" not in text_line:
                            continue
                        await websocket.send_json({"type": "logcat", "data": {"message": text_line}})
                    else:
                        if self.logcat_process.stdout.at_eof():
                            break
                except asyncio.TimeoutError:
                    continue

        except Exception as e:
            logger.error(f"Logcat streaming error: {e}")
            if websocket:
                try:
                    await websocket.send_json({"type": "logcat", "data": {"message": f"[SYSTEM ERROR] Logcat stream halted: {e}"}})
                except Exception:
                    pass

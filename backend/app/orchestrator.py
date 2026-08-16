import asyncio
import logging
import os
import subprocess

import frida

logger = logging.getLogger("Cerberus-ASF")

AGENT_SCRIPT_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../agent/dist/core_hooks.js")
)
MEMORY_SCAN_TIMEOUT = int(os.environ.get("CERBERUS_MEMORY_SCAN_TIMEOUT", "120"))


class AndroidOrchestrator:
    def __init__(self):
        self.device = None
        self.session = None
        self.script = None
        self.telemetry_callback = None
        self.current_pid = None
        self.script_path = AGENT_SCRIPT_PATH
        self._loop = None  # captured inside initialize_agent, used by the
                            # foreign-thread-safe message dispatcher below
        self._memory_scan_partial_hits = []  # see scan_memory() / _on_frida_message()

    def set_telemetry_callback(self, callback):
        self.telemetry_callback = callback

    def _dispatch_telemetry(self, message: str, level: str):
        """Schedules the (async) telemetry_callback from whatever thread
        calls this. _on_frida_message runs on Frida's own native callback
        thread, never the asyncio thread — loop.create_task() is
        documented as not thread-safe when called that way, and on this
        Python version it doesn't even degrade gracefully: it raises
        "there is no current event loop in thread 'Dummy-N'" and the
        message is silently dropped (confirmed directly: a live hook
        session reported success but zero telemetry events ever reached
        Python). run_coroutine_threadsafe is the actual thread-safe way
        to hand a coroutine to a loop running on a different thread."""
        if not self.telemetry_callback or not self._loop:
            return
        try:
            asyncio.run_coroutine_threadsafe(
                self.telemetry_callback(message, level), self._loop
            )
        except Exception as e:
            logger.error(f"Failed to dispatch telemetry from Frida callback thread: {e}")

    def _on_frida_message(self, message, data):
        if message["type"] == "send":
            payload = message.get("payload", {})
            if payload.get("kind") == "memory_hit":
                # Not forwarded to the browser telemetry stream (that's the
                # separate, capped, human-readable message the agent also
                # sends per hit) — accumulated here so scan_memory() can
                # still return whatever was found if the scan itself is
                # later interrupted (timeout, or the target process
                # freezing/dying mid-scan — both confirmed to happen in
                # practice) and its own return value is lost.
                hit = payload.get("hit")
                if hit is not None:
                    self._memory_scan_partial_hits.append(hit)
                return
            self._dispatch_telemetry(payload.get("message", ""), payload.get("level", "info"))
        elif message["type"] == "error":
            error_desc = message.get("description", "Unknown Frida Engine Error")
            logger.error(f"[Frida Hook Crash] {error_desc}")
            self._dispatch_telemetry(f"[Frida] Core Exception: {error_desc}", "error")

    def _resolve_target_pid(self, package_name: str):
        """enumerate_processes() has been observed to NOT list a confirmed
        -running app by name on some device/Android/Frida combinations
        (reproduced directly: ps -A and enumerate_applications() both show
        the process, enumerate_processes() doesn't) — attach-by-name then
        fails even though the app is definitely running. Resolving via
        enumerate_applications() and attaching by PID is more reliable."""
        try:
            for app in self.device.enumerate_applications():
                if app.identifier == package_name and app.pid:
                    return app.pid
        except Exception as e:
            logger.debug(f"enumerate_applications() failed: {e}")
        return None

    def _check_version_compatibility(self):
        """Frida's wire protocol needs the client and the on-device
        frida-server to be reasonably close in version. A mismatch
        otherwise surfaces as an opaque low-level failure deep in the
        connection — a direct check gives a much clearer diagnostic.

        There's no Python-side API to query the server's version before
        attaching (confirmed: Device has no such method, and
        query_system_parameters() returns OS/device info, not frida-server's
        own version) — Frida.version is only available as a JS global once
        a script has actually loaded, so this must run post-load via the
        getFridaVersion RPC export, not before."""
        try:
            exports = getattr(self.script, "exports_sync", self.script.exports)
            server_version = exports.get_frida_version()
            client_major = int(frida.__version__.split(".")[0])
            server_major = int(server_version.split(".")[0]) if server_version else None
            if server_major is not None and server_major != client_major:
                logger.warning(
                    f"Frida version mismatch: client {frida.__version__} vs "
                    f"frida-server {server_version} on device. This can cause "
                    f"unpredictable connection failures — reinstall a matching frida-server."
                )
                return False, frida.__version__, server_version
            return True, frida.__version__, server_version
        except Exception as e:
            logger.debug(f"Version compatibility check skipped: {e}")
            return True, frida.__version__, None

    async def initialize_agent(self, package_name: str, use_root: bool, use_pinning: bool) -> bool:
        self._loop = asyncio.get_running_loop()

        try:
            if not os.path.exists(self.script_path):
                fallback_paths = [
                    os.path.abspath(os.path.join(os.getcwd(), "agent/dist/core_hooks.js")),
                    os.path.abspath(os.path.join(os.getcwd(), "../agent/dist/core_hooks.js")),
                    os.path.abspath(os.path.join(os.path.dirname(__file__), "core_hooks.js")),
                ]
                for fp in fallback_paths:
                    if os.path.exists(fp):
                        self.script_path = fp
                        break
                else:
                    raise FileNotFoundError(
                        f"Missing built agent bundle at: {self.script_path}. "
                        f"Run agent/build.sh (or ./install.sh) to build it."
                    )

            # Auto-forward default Frida port for emulators and network devices
            try:
                subprocess.run(["adb", "forward", "tcp:27042", "tcp:27042"], capture_output=True, timeout=2)
            except Exception:
                pass

            # Multi-modal device resolution (supports physical USB, Emulators, WiFi ADB, and local TCP/IP)
            self.device = None
            try:
                self.device = frida.get_usb_device(timeout=2)
            except Exception:
                pass

            if not self.device:
                try:
                    for d in frida.enumerate_devices():
                        if d.type != "local" and "tcp" not in d.id.lower():
                            self.device = d
                            break
                        elif d.type == "remote" or "emulator" in d.name.lower() or "adb" in d.name.lower():
                            self.device = d
                            break
                except Exception as e:
                    logging.debug(f"Device enumeration error: {e}")

            if not self.device:
                try:
                    self.device = frida.get_remote_device()
                except Exception:
                    pass

            if not self.device or self.device.type == "local":
                raise Exception("No active Android USB device or Emulator detected by Frida.")

            # Identify if frida server is running via basic frida command verify
            try:
                self.device.enumerate_processes()
            except frida.ServerNotRunningError:
                await self._dispatch_and_wait("CRITICAL: frida-server daemon is not running on the target device.", "error")
                return False
            except Exception as e:
                logging.warning(f"Failed to enumerate processes: {e}")

            logging.info(f"Connected to Frida Target Device: {self.device.name} ({self.device.id})")

            # Try spawning target package, or attach directly if process already running
            pid = None
            try:
                pid = self.device.spawn([package_name])
                self.session = self.device.attach(pid)
            except Exception as e_spawn:
                logging.warning(f"Process spawn failed ({e_spawn}), attempting direct process attachment...")
                pid = self._resolve_target_pid(package_name)
                if pid:
                    self.session = self.device.attach(pid)
                else:
                    # Last resort: attach by name (works when enumerate_applications()
                    # also can't resolve it, but frida's own name lookup still can).
                    self.session = self.device.attach(package_name)
                    try:
                        proc = self.device.get_process(package_name)
                        pid = proc.pid
                    except Exception:
                        pass

            self.current_pid = pid

            with open(self.script_path, "r", encoding="utf-8") as f:
                source = f.read()

            self.script = self.session.create_script(source)
            self.script.on("message", self._on_frida_message)
            self.script.load()

            version_ok, client_version, server_version = self._check_version_compatibility()
            if not version_ok:
                await self._dispatch_and_wait(
                    f"WARNING: Frida version mismatch (client {client_version} vs server {server_version}). "
                    f"Connection may behave unpredictably — consider matching frida-server to the client version.",
                    "warning",
                )

            # Resume BEFORE posting the config message, not after. Confirmed directly
            # against a real spawned process: a message posted while the process is
            # still spawn-suspended is not reliably delivered — Java.perform() inside
            # the script never ran even several seconds after a later resume(), because
            # nothing was pumping the script's message queue yet while suspended. This
            # matters a lot in practice: it only manifests for apps where spawn()
            # actually succeeds (a normal launcher activity), so most real targets hit
            # it — the earlier "post config, then resume" ordering that both the
            # original code and an earlier pass of this rewrite used would silently
            # never install root/SSL bypass hooks on such apps.
            if pid and hasattr(self.device, "resume"):
                try:
                    self.device.resume(pid)
                    # Brief grace period for the process to actually start executing
                    # and start pumping its message queue — confirmed necessary:
                    # posting immediately after resume() (no delay) still lost the
                    # message in direct testing.
                    await asyncio.sleep(0.3)
                except Exception as e:
                    # A failed resume leaves the spawned target permanently suspended
                    # with no further signal — previously this was silently swallowed
                    # and just looked like the tool had hung.
                    logging.error(f"Failed to resume spawned process {pid}: {e}")
                    await self._dispatch_and_wait(
                        f"WARNING: Failed to resume spawned process (pid {pid}): {e}. "
                        f"The target may remain suspended — try launching it manually instead.",
                        "warning",
                    )

            self.script.post({
                "type": "config",
                "root": use_root,
                "pinning": use_pinning,
            })

            return True

        except frida.ServerNotRunningError:
            await self._dispatch_and_wait("CRITICAL: frida-server daemon is not running on the target device.", "error")
            return False
        except Exception as e:
            await self._dispatch_and_wait(f"Frida Injection Failed: {str(e)}", "error")
            return False

    async def _dispatch_and_wait(self, message: str, level: str):
        """Same as telemetry_callback, but awaited directly — used during
        initialize_agent itself, which already runs on the asyncio thread,
        so there's no thread-safety concern here (unlike _on_frida_message)."""
        if self.telemetry_callback:
            await self.telemetry_callback(message, level)

    async def stop_agent(self):
        if self.session:
            try:
                loop = asyncio.get_running_loop()
                await asyncio.wait_for(loop.run_in_executor(None, self.session.detach), timeout=2.0)
            except Exception as e:
                logging.warning(f"Error detaching session: {e}")
            finally:
                self.session = None
                self.script = None
            return True
        return False

    async def scan_memory(self, pattern: str = None) -> list:
        if not self.script or not self.session:
            await self._dispatch_and_wait("[System Error] No live Frida process attached. Memory scan aborted.", "error")
            return []

        self._memory_scan_partial_hits = []
        try:
            logging.info(f"Executing live Frida RAM memory scan for pattern: {pattern or 'default targets'}")
            exports = getattr(self.script, "exports_sync", self.script.exports)
            scan_fn = getattr(exports, "scan_memory", getattr(exports, "scanMemory", None))
            if not scan_fn:
                raise AttributeError("Neither 'scan_memory' nor 'scanMemory' found in script exports.")

            # This RPC call is synchronous and can take a while to walk process
            # memory — running it directly here would block the whole FastAPI
            # event loop (confirmed: freezes the websocket and every other
            # route for the duration of the scan). Route it through the
            # default executor instead. Wrapped in a timeout too: without one,
            # a hung/pathological scan on the JS side would leave this
            # specific HTTP request waiting forever with no bound, even though
            # it no longer blocks the rest of the server.
            loop = asyncio.get_running_loop()
            results = await asyncio.wait_for(
                loop.run_in_executor(None, scan_fn, pattern or ""),
                timeout=MEMORY_SCAN_TIMEOUT,
            )
            return results or []
        except asyncio.TimeoutError:
            logging.error(f"Memory scan timed out after {MEMORY_SCAN_TIMEOUT}s")
            return await self._recover_partial_scan_results(
                f"Memory scan timed out after {MEMORY_SCAN_TIMEOUT}s — the target process may be under heavy load or the scan range too large."
            )
        except Exception as e:
            logging.error(f"Live memory scan error via Frida RPC: {e}")
            return await self._recover_partial_scan_results(f"Memory scan RPC exception: {str(e)}")

    async def _recover_partial_scan_results(self, failure_reason: str) -> list:
        """Called when scan_memory()'s RPC call fails or times out entirely.
        Individual hits are reported live as they're found (see
        _on_frida_message's "memory_hit" handling) independently of the
        final return value, so a scan that never reaches its own `return`
        statement — confirmed to happen in practice, both from a timeout
        and from the target process freezing/dying mid-scan — doesn't have
        to lose everything that was already found."""
        partial = self._memory_scan_partial_hits
        if partial:
            await self._dispatch_and_wait(
                f"[Frida Error] {failure_reason} Returning {len(partial)} partial result(s) found before the interruption.",
                "warning",
            )
        else:
            await self._dispatch_and_wait(f"[Frida Error] {failure_reason}", "error")
        return partial

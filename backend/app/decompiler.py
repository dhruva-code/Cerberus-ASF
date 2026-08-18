import logging
import os
import shutil
import subprocess
import tempfile


class JadxDecompiler:
    """Single point of jadx invocation and temp-directory lifecycle."""

    def __init__(self, timeout: int = None):
        # 180s was the original default but is too tight for anything past a
        # small APK: a full no-resources decompile of a real-world app (tens
        # of thousands of classes) routinely takes several minutes, and heavy
        # GC pressure under low available RAM makes it worse — confirmed
        # directly via a production timeout on a 4-core/7GB host with no
        # other obvious cause. 600s is still a bound, not unlimited, and
        # remains overridable via CERBERUS_JADX_TIMEOUT.
        self.timeout = timeout or int(os.environ.get("CERBERUS_JADX_TIMEOUT", "600"))
        self.out_dir = None

    def decompile(self, apk_path: str) -> str:
        """Decompiles apk_path with jadx and returns the sources directory.

        Raises RuntimeError if jadx is missing or produces no output.
        """
        jadx_bin = shutil.which("jadx")
        if not jadx_bin:
            raise RuntimeError("jadx not found on PATH")

        # Leave one core free for the FastAPI/uvicorn process itself instead
        # of a hardcoded 4 — on a 4-core host that hardcoded value left no
        # headroom for the server during a decompile, compounding slowdowns
        # under concurrent load.
        jobs = max(1, (os.cpu_count() or 4) - 1)

        self.out_dir = tempfile.mkdtemp(prefix="cerberus_jadx_")
        proc = subprocess.run(
            [jadx_bin, "-d", self.out_dir, "--no-res", "-j", str(jobs), apk_path],
            capture_output=True, text=True, timeout=self.timeout,
        )

        sources_dir = os.path.join(self.out_dir, "sources")
        if not os.path.isdir(sources_dir):
            raise RuntimeError(f"jadx produced no sources (rc={proc.returncode}): {proc.stderr[:500]}")

        return sources_dir

    def cleanup(self):
        if self.out_dir:
            shutil.rmtree(self.out_dir, ignore_errors=True)
            self.out_dir = None

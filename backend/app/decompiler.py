import logging
import os
import shutil
import subprocess
import tempfile


class JadxDecompiler:
    """Single point of jadx invocation and temp-directory lifecycle."""

    def __init__(self, timeout: int = None):
        self.timeout = timeout or int(os.environ.get("CERBERUS_JADX_TIMEOUT", "180"))
        self.out_dir = None

    def decompile(self, apk_path: str) -> str:
        """Decompiles apk_path with jadx and returns the sources directory.

        Raises RuntimeError if jadx is missing or produces no output.
        """
        jadx_bin = shutil.which("jadx")
        if not jadx_bin:
            raise RuntimeError("jadx not found on PATH")

        self.out_dir = tempfile.mkdtemp(prefix="cerberus_jadx_")
        proc = subprocess.run(
            [jadx_bin, "-d", self.out_dir, "--no-res", "-j", "4", apk_path],
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

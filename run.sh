#!/bin/bash
#
# Starts the Cerberus-ASF server. Checks the Python venv, required Python
# packages, and external tool binaries first, and refuses to start (with
# a clear list of what's missing) if a hard requirement is absent. Missing
# recommended/optional tools produce a warning but don't block startup —
# this matches the app's own graceful-degradation behavior (e.g. static
# analysis still runs without jadx, just via a much weaker fallback).
#
#   ./run.sh
#
# Host/port default to 0.0.0.0:8000; override with CERBERUS_HOST / CERBERUS_PORT.
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$REPO_ROOT/backend"
VENV_PY="$BACKEND_DIR/venv/bin/python3"
VENV_UVICORN="$BACKEND_DIR/venv/bin/uvicorn"
HOST="${CERBERUS_HOST:-0.0.0.0}"
PORT="${CERBERUS_PORT:-8000}"

info() { echo -e "\033[34m[INFO]\033[0m $1"; }
ok()   { echo -e "\033[32m[OK]\033[0m $1"; }
warn() { echo -e "\033[33m[WARN]\033[0m $1"; }
err()  { echo -e "\033[31m[ERROR]\033[0m $1"; }

MISSING_REQUIRED=()
MISSING_RECOMMENDED=()
MISSING_OPTIONAL=()

# --- venv presence ---
if [ ! -x "$VENV_PY" ]; then
    err "Python virtual environment not found at backend/venv."
    err "Run ./install.sh first (or manually: cd backend && python3 -m venv venv && venv/bin/pip install -r requirements.txt)."
    exit 1
fi

if [ ! -x "$VENV_UVICORN" ]; then
    MISSING_REQUIRED+=("uvicorn (present in requirements.txt but not installed in backend/venv)")
fi

# --- required Python packages (import-name : requirements.txt entry) ---
declare -A REQUIRED_PY_PKGS=(
    [fastapi]="fastapi"
    [pydantic]="pydantic"
    [multipart]="python-multipart"
    [websockets]="websockets"
    [frida]="frida-tools"
    [bcrypt]="bcrypt"
    [openai]="openai"
    [anthropic]="anthropic"
    [tree_sitter]="tree-sitter"
    [tree_sitter_language_pack]="tree-sitter-language-pack"
    [reportlab]="reportlab"
)
for module in "${!REQUIRED_PY_PKGS[@]}"; do
    "$VENV_PY" -c "import ${module}" >/dev/null 2>&1 || MISSING_REQUIRED+=("${REQUIRED_PY_PKGS[$module]} (python package '${module}' not importable)")
done
"$VENV_PY" -c "import google.genai" >/dev/null 2>&1 || MISSING_REQUIRED+=("google-genai (python package 'google.genai' not importable)")
"$VENV_PY" -c "from cryptography.fernet import Fernet" >/dev/null 2>&1 || MISSING_REQUIRED+=("cryptography (python package 'cryptography' not importable)")

# --- sqlite3 module (stdlib, but some minimal Python builds omit it) ---
"$VENV_PY" -c "import sqlite3" >/dev/null 2>&1 || MISSING_REQUIRED+=("sqlite3 (missing from this Python build — user accounts/history storage needs it; reinstall Python with sqlite3 support)")

# --- external binaries: recommended (static analysis quality) ---
command -v java    >/dev/null 2>&1 || MISSING_RECOMMENDED+=("java (default-jre-headless — required by jadx and apksigner)")
command -v jadx     >/dev/null 2>&1 || MISSING_RECOMMENDED+=("jadx (AST-based static analysis + AI Deep Scan; falls back to a much weaker legacy regex scan without it)")
command -v apktool  >/dev/null 2>&1 || MISSING_RECOMMENDED+=("apktool (primary AndroidManifest.xml extraction method)")
{ command -v aapt >/dev/null 2>&1 || command -v aapt2 >/dev/null 2>&1; } || MISSING_RECOMMENDED+=("aapt/aapt2 (APK metadata extraction)")
command -v apksigner >/dev/null 2>&1 || MISSING_RECOMMENDED+=("apksigner (certificate/signature analysis)")

# --- tree-sitter Java grammar cache (AST-based static analysis) ---
# Downloaded from GitHub on first use and cached under ~/.cache/tree-sitter-
# language-pack/ — not fatal if missing/unreachable (app/ast_engine.py
# degrades gracefully and the server still starts), but worth flagging here
# since it silently weakens static analysis otherwise.
if ! "$VENV_PY" -c "
import sys
from tree_sitter_language_pack import downloaded_languages
sys.exit(0 if 'java' in downloaded_languages() else 1)
" >/dev/null 2>&1; then
    MISSING_RECOMMENDED+=("tree-sitter Java grammar not cached (AST-based structural analysis + secret-field detection will be skipped) — needs one successful outbound download from github.com on first use; re-run ./install.sh or see INSTALL.md's troubleshooting section")
fi

# --- dynamic analysis: the built Frida agent bundle ---
if [ ! -f "$REPO_ROOT/agent/dist/core_hooks.js" ]; then
    MISSING_RECOMMENDED+=("agent/dist/core_hooks.js (Frida agent not built — run 'agent/build.sh' or re-run ./install.sh; dynamic analysis won't work without it)")
fi

# --- external binaries: optional (dynamic analysis / extra signal) ---
command -v adb        >/dev/null 2>&1 || MISSING_OPTIONAL+=("adb (needed only for dynamic/Frida analysis against a real device or emulator)")
command -v trufflehog >/dev/null 2>&1 || MISSING_OPTIONAL+=("trufflehog (extra secret-scanning signal on top of the built-in detectors)")

# --- report ---
if [ ${#MISSING_REQUIRED[@]} -gt 0 ]; then
    err "Cannot start — missing required components:"
    printf '  - %s\n' "${MISSING_REQUIRED[@]}"
    echo
    echo "Fix with: cd backend && venv/bin/pip install -r requirements.txt"
    echo "(or re-run ./install.sh)"
    exit 1
fi

if [ ${#MISSING_RECOMMENDED[@]} -gt 0 ]; then
    warn "Missing recommended tools — the server will start, but static analysis quality will be degraded:"
    printf '  - %s\n' "${MISSING_RECOMMENDED[@]}"
fi
if [ ${#MISSING_OPTIONAL[@]} -gt 0 ]; then
    info "Optional tools not found (unrelated features simply won't be available):"
    printf '  - %s\n' "${MISSING_OPTIONAL[@]}"
fi

info "Starting Cerberus-ASF on http://${HOST}:${PORT} ..."
cd "$BACKEND_DIR" || exit 1
exec venv/bin/uvicorn app.main:app --host "$HOST" --port "$PORT"

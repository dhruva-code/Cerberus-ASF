#!/bin/bash
#
# Cerberus-ASF installer — Ubuntu/Debian.
#
# Installs system packages (Java runtime, Android tooling), creates a
# Python virtual environment under backend/venv, installs Python
# dependencies into it, and installs jadx (not packaged for apt on most
# Ubuntu releases, so it's fetched from its GitHub releases).
#
# Run as a normal user, NOT with sudo — this script calls sudo itself
# only for the system-package steps. Creating the venv / installing
# Python packages as root is bad practice and will cause permission
# problems later.
#
#   ./install.sh
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$REPO_ROOT/backend"
JADX_VERSION="1.5.6"
JADX_INSTALL_DIR="/opt/jadx"

REQUIRED_FAILURES=()
OPTIONAL_WARNINGS=()

info() { echo -e "\033[34m[INFO]\033[0m $1"; }
ok()   { echo -e "\033[32m[OK]\033[0m $1"; }
warn() { echo -e "\033[33m[WARN]\033[0m $1"; }
err()  { echo -e "\033[31m[ERROR]\033[0m $1"; }

if [ "$(id -u)" -eq 0 ]; then
    err "Do not run this script as root or with sudo — it calls sudo itself for the system-package steps."
    err "Run it as the user that will own and run the Cerberus-ASF server: ./install.sh"
    exit 1
fi

if ! command -v sudo >/dev/null 2>&1; then
    err "sudo is required (for installing system packages via apt) but was not found."
    exit 1
fi

if [ ! -f /etc/os-release ] || ! grep -qiE "ubuntu|debian" /etc/os-release; then
    warn "This installer targets Ubuntu/Debian. Continuing anyway, but apt-based steps may fail on this OS."
fi

# ------------------------------------------------------------------
# 1. System packages
# ------------------------------------------------------------------
info "Updating apt package index..."
sudo apt-get update -y

info "Installing system packages (Python toolchain, Java runtime, Android tooling, build headers)..."
# build-essential/python3-dev/libssl-dev/libffi-dev/pkg-config exist purely as
# insurance: if a future Python version here has no prebuilt wheel available
# on PyPI for a C-extension dependency (cryptography, bcrypt), pip needs to
# be able to compile it from source instead of failing outright.
if ! sudo apt-get install -y \
    python3 python3-venv python3-pip python3-dev \
    build-essential libssl-dev libffi-dev pkg-config \
    default-jre-headless \
    apktool aapt android-tools-adb \
    nodejs npm \
    unzip curl ca-certificates
then
    REQUIRED_FAILURES+=("one or more core apt packages failed to install (see output above)")
fi

# apksigner: a real apt package on recent Ubuntu (universe repo), but not
# guaranteed present on every release — fall back to a manual jar install
# (pointing java -cp directly at the extracted jars) if apt doesn't have it.
if command -v apksigner >/dev/null 2>&1; then
    ok "apksigner already present."
elif sudo apt-get install -y apksigner 2>/dev/null; then
    ok "apksigner installed via apt."
else
    warn "apksigner not available via apt on this release — installing manually from the apksigner/libapksig-java .debs."
    TMP_DIR=$(mktemp -d)
    if apt-get download apksigner libapksig-java -o Dir::Cache::archives="$TMP_DIR" >/dev/null 2>&1 \
        && sudo dpkg -i "$TMP_DIR"/apksigner_*.deb "$TMP_DIR"/libapksig-java_*.deb >/dev/null 2>&1
    then
        ok "apksigner installed manually."
    else
        OPTIONAL_WARNINGS+=("apksigner could not be installed automatically — certificate analysis will be degraded. See INSTALL.md's troubleshooting section for a manual install.")
    fi
    rm -rf "$TMP_DIR"
fi

# ------------------------------------------------------------------
# 2. jadx (no apt package on most Ubuntu releases — install from GitHub release)
# ------------------------------------------------------------------
if command -v jadx >/dev/null 2>&1; then
    ok "jadx already present ($(jadx --version 2>&1 | head -1))."
else
    info "Installing jadx ${JADX_VERSION} to ${JADX_INSTALL_DIR}..."
    TMP_DIR=$(mktemp -d)
    if curl -sL -o "$TMP_DIR/jadx.zip" \
        "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
        && sudo mkdir -p "$JADX_INSTALL_DIR" \
        && sudo unzip -q -o "$TMP_DIR/jadx.zip" -d "$JADX_INSTALL_DIR" \
        && sudo chmod +x "$JADX_INSTALL_DIR/bin/jadx" "$JADX_INSTALL_DIR/bin/jadx-gui" \
        && sudo ln -sf "$JADX_INSTALL_DIR/bin/jadx" /usr/local/bin/jadx
    then
        ok "jadx installed."
    else
        OPTIONAL_WARNINGS+=("jadx installation failed — AI Deep Scan and AST-based static analysis will fall back to a much weaker legacy regex scan. See INSTALL.md's troubleshooting section.")
    fi
    rm -rf "$TMP_DIR"
fi

# ------------------------------------------------------------------
# 3. trufflehog (optional — extra secret-scanning signal, app runs fine without it)
# ------------------------------------------------------------------
if command -v trufflehog >/dev/null 2>&1; then
    ok "trufflehog already present."
else
    info "Installing trufflehog (optional)..."
    if curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sudo sh -s -- -b /usr/local/bin >/dev/null 2>&1
    then
        ok "trufflehog installed."
    else
        OPTIONAL_WARNINGS+=("trufflehog installation failed — this only disables one extra secret-scanning signal, everything else still works.")
    fi
fi

# ------------------------------------------------------------------
# 4. Python virtual environment + dependencies
# ------------------------------------------------------------------
info "Setting up Python virtual environment at backend/venv..."
cd "$BACKEND_DIR" || { err "backend/ directory not found next to this script."; exit 1; }

if [ ! -d venv ]; then
    python3 -m venv venv
fi

venv/bin/pip install --upgrade pip >/dev/null
if venv/bin/pip install -r requirements.txt; then
    ok "Python dependencies installed."
else
    REQUIRED_FAILURES+=("pip install -r requirements.txt failed — see output above")
fi

cd "$REPO_ROOT" || exit 1
chmod +x run.sh 2>/dev/null

# ------------------------------------------------------------------
# 5. Frida agent bundle (dynamic analysis)
# ------------------------------------------------------------------
# Raw unbundled Frida scripts don't get an implicit `Java` global on
# current Frida versions (confirmed directly against a real device) —
# frida-java-bridge must be bundled in via frida-compile. agent/build.sh
# does this; its output (agent/dist/core_hooks.js) is what the backend
# actually loads for dynamic analysis.
info "Building the Frida agent bundle (dynamic analysis)..."
chmod +x agent/build.sh 2>/dev/null
if (cd agent && ./build.sh); then
    ok "Frida agent bundle built."
else
    OPTIONAL_WARNINGS+=("Frida agent build failed — dynamic analysis (root/SSL bypass, memory forensics) won't work until 'agent/build.sh' succeeds. Static analysis is unaffected.")
fi

# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------
echo
echo "=================================================================="
if [ ${#REQUIRED_FAILURES[@]} -gt 0 ]; then
    err "Installation finished with failures that must be fixed before running the server:"
    printf '  - %s\n' "${REQUIRED_FAILURES[@]}"
else
    ok "Installation complete."
fi
if [ ${#OPTIONAL_WARNINGS[@]} -gt 0 ]; then
    warn "Optional components had issues (the server will still run, with reduced functionality):"
    printf '  - %s\n' "${OPTIONAL_WARNINGS[@]}"
fi
echo
echo "Next steps:"
echo "  1. Start the server:  ./run.sh"
echo "  2. Open http://<this-server-ip>:8000 in a browser, register an account, and log in."
echo "  3. (Optional) Add an AI provider API key under 'AI Settings' in the UI to enable AI Deep Scan."
echo "  4. For dynamic analysis: a matching frida-server must be running on the target Android"
echo "     device/emulator first (this is a device-side step, not part of this installer) — see"
echo "     INSTALL.md's Dynamic Analysis Setup section."
echo "See INSTALL.md for full details, environment variable overrides, and troubleshooting."
echo "=================================================================="

[ ${#REQUIRED_FAILURES[@]} -eq 0 ]

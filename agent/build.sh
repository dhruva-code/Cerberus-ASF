#!/bin/bash
#
# Builds the Frida agent bundle. Raw unbundled Frida scripts don't get an
# implicit `Java` global on current Frida versions (confirmed directly
# against a real device) — frida-java-bridge must be bundled in via
# frida-compile. Run this after editing anything under src/, or as part
# of ./install.sh for a fresh setup.
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if ! command -v npm >/dev/null 2>&1; then
    echo "[ERROR] npm not found. Install Node.js/npm (e.g. 'sudo apt install nodejs npm') and re-run." >&2
    exit 1
fi

echo "[INFO] Installing agent build dependencies..."
npm install --no-fund --no-audit

echo "[INFO] Bundling agent/src/index.js -> agent/dist/core_hooks.js ..."
mkdir -p dist
npx frida-compile src/index.js -o dist/core_hooks.raw.js

# frida-compile writes a 3-line build-report header ("📦" / size+path /
# "✄" separator) directly into the -o file ahead of the actual JS. That's
# fine for frida's own tooling but not valid as plain JS for our Python
# client to load raw via session.create_script() — strip it.
if head -1 dist/core_hooks.raw.js | grep -q "📦"; then
    tail -n +4 dist/core_hooks.raw.js > dist/core_hooks.js
else
    mv dist/core_hooks.raw.js dist/core_hooks.js
fi
rm -f dist/core_hooks.raw.js

node --check dist/core_hooks.js
echo "[OK] Built dist/core_hooks.js"

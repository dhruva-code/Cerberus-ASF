# Cerberus-ASF — Installation Guide

This covers installing Cerberus-ASF from scratch on a fresh Ubuntu server: what gets installed, where, why, and how to run it afterward.

## 1. What you're installing

Cerberus-ASF is a Python (FastAPI) backend that serves a static HTML/JS frontend directly — there's no separate frontend build step. It has two analysis pipelines:

- **Static analysis**: decompiles APKs with `jadx`, runs structural checks via `tree-sitter`, cross-checks manifests/certificates/frameworks with `apktool`/`aapt`/`apksigner`, and optionally sends code to an AI provider (Gemini / Anthropic / any OpenAI-compatible endpoint — configured per-user in the web UI, not via environment variable) for deeper semantic review.
- **Dynamic analysis**: uses `frida` + `adb` to instrument a real Android device or emulator over USB/network. The Frida hook script (`agent/src/`) is bundled with `frida-compile` into `agent/dist/core_hooks.js` at install time — this is a real Frida requirement, not an optional optimization: current Frida versions don't expose a `Java` global to raw unbundled scripts (confirmed directly against a physical device), so the bundle is what actually makes root-detection/SSL-pinning bypass work at all.

User accounts, sessions, and scan history are stored locally in a SQLite database on the server. There is no external database, message queue, or cloud dependency — everything runs on one host.

## 2. System requirements

- Ubuntu 22.04 LTS or newer (24.04/26.04 both confirmed working; other recent Debian-based distros will likely work but aren't the primary target)
- A regular user account with `sudo` access (don't run the installer as root — see below)
- Outbound internet access during install (apt, GitHub releases, PyPI)
- If you'll use dynamic analysis: a USB-connected Android device or emulator reachable from this host

## 3. Python: use a venv (not system Python)

**Use a virtual environment.** This isn't just a style preference here:

- Modern Ubuntu (23.04+, including the LTS releases above) marks the system Python as "externally managed" (PEP 668) — a plain `pip install` against system Python is *refused* outright unless you pass a flag that risks breaking OS-managed packages. A venv sidesteps this entirely and is the sanctioned path.
- Cerberus-ASF pins fairly specific dependency versions (`tree-sitter`, `cryptography`, `bcrypt`, provider SDKs). Installing them system-wide risks colliding with whatever Python tooling the OS itself depends on.
- It keeps the installation self-contained and disposable — `rm -rf backend/venv` and re-running the installer is always a safe way to start over.

The install script creates it at **`backend/venv`** (i.e. `python3 -m venv backend/venv`) and the run script always invokes `backend/venv/bin/uvicorn` directly — you never need to remember to `source venv/bin/activate` yourself.

## 4. Where external tools get installed

These are installed system-wide (via `sudo`), not per-user, so the server runs correctly regardless of which OS user starts it and regardless of shell (`PATH` doesn't need editing — everything lands in directories already on the default system `PATH`):

| Tool | Installed via | Ends up at | Used for |
|---|---|---|---|
| Python 3, venv, pip | apt (`python3`, `python3-venv`, `python3-pip`) | `/usr/bin/python3` | running the app |
| Java runtime | apt (`default-jre-headless`) | `/usr/bin/java` | required by `jadx` and `apksigner`, both of which are Java tools |
| `apktool` | apt | `/usr/bin/apktool` | primary AndroidManifest.xml extraction |
| `aapt` | apt | `/usr/bin/aapt` | APK metadata extraction (package name, SDK versions, permissions) |
| `adb` | apt (`android-tools-adb`) | `/usr/bin/adb` | dynamic analysis device connectivity |
| `apksigner` | apt if available, else a manual `.deb`-jar install | `/usr/bin/apksigner` | certificate/signature analysis |
| `jadx` | **not packaged for apt on most Ubuntu releases** — downloaded from its GitHub releases | `/opt/jadx`, symlinked to `/usr/local/bin/jadx` | APK decompilation (feeds both structural static analysis and AI Deep Scan) |
| Node.js, npm | apt (`nodejs`, `npm`) | `/usr/bin/node`, `/usr/bin/npm` | build-time only, for bundling the Frida agent (`frida-compile`) — not needed at server runtime |
| Frida agent bundle | `agent/build.sh` (`npm install` + `frida-compile`) | `agent/dist/core_hooks.js` | the actual script injected into target apps for dynamic analysis; rebuild this after editing anything under `agent/src/` |
| `trufflehog` (optional) | official install script | `/usr/local/bin/trufflehog` | an extra secret-scanning signal layered on top of the app's own detectors |

`apksigner` is worth calling out specifically: on recent Ubuntu it's a real `apt` package (`apksigner`, from the `android-platform-tools-apksig` source, wrapping `libapksig-java`) and `sudo apt install apksigner` should just work. If your release's `universe` repo doesn't carry it, the installer falls back to downloading the `.deb`s directly and installing them with `dpkg` — same end result, just bypassing `apt`'s dependency resolution.

## 5. Quick start (recommended)

```bash
git clone <this-repo-url> Cerberus-ASF   # or copy the project directory over however you prefer
cd Cerberus-ASF
./install.sh   # do NOT run this with sudo — it calls sudo itself where needed
./run.sh
```

Then open `http://<server-ip>:8000` in a browser, register an account, log in, and (optionally) add an AI provider key under **AI Settings** to enable AI Deep Scan.

`install.sh` is safe to re-run — it skips anything already installed and reports a clear summary of what succeeded, what's missing, and what to do about it.

## 6. Manual installation (if you want to do it by hand, or the script fails on your setup)

```bash
# 1. System packages
sudo apt-get update
sudo apt-get install -y \
    python3 python3-venv python3-pip python3-dev \
    build-essential libssl-dev libffi-dev pkg-config \
    default-jre-headless \
    apktool aapt android-tools-adb apksigner \
    unzip curl ca-certificates

# 2. jadx (adjust version as needed — check https://github.com/skylot/jadx/releases for the latest)
JADX_VERSION=1.5.6
curl -sL -o /tmp/jadx.zip "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip"
sudo mkdir -p /opt/jadx
sudo unzip -q -o /tmp/jadx.zip -d /opt/jadx
sudo chmod +x /opt/jadx/bin/jadx /opt/jadx/bin/jadx-gui
sudo ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx

# 3. trufflehog (optional)
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sudo sh -s -- -b /usr/local/bin

# 4. Python virtual environment + dependencies
cd backend
python3 -m venv venv
venv/bin/pip install --upgrade pip
venv/bin/pip install -r requirements.txt
cd ..

# 5. Frida agent bundle (needed for dynamic analysis — see section 4 above for why)
cd agent && ./build.sh && cd ..

# 6. Run
./run.sh
# or directly:
cd backend && venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## 7. Configuration (environment variables)

All optional — sensible defaults are used if unset, and the app works out of the box with none of these set.

| Variable | Default | Purpose |
|---|---|---|
| `CERBERUS_DB_PATH` | `backend/app/cerberus-asf.db` | Where the SQLite database (users, sessions, AI credentials, scan history) is stored |
| `CERBERUS_SECRET_PATH` | `backend/app/.instance_secret` | The Fernet encryption key used to encrypt stored AI provider API keys at rest — **treat this file like a password**; if it's lost, stored API keys become permanently undecryptable, and if it leaks, every stored key is compromised |
| `CERBERUS_JADX_TIMEOUT` | `180` (seconds) | Max time allowed for a single jadx decompile; increase if you're scanning unusually large APKs and seeing timeout failures |
| `CERBERUS_MEMORY_SCAN_TIMEOUT` | `120` (seconds) | Max time allowed for a single dynamic-analysis memory forensics sweep; if it's hit, whatever hits were already found before the timeout are still returned rather than lost |
| `CERBERUS_HOST` | `0.0.0.0` | Bind address, read by `run.sh` (not by the app itself — see below) |
| `CERBERUS_PORT` | `8000` | Bind port, read by `run.sh` |

Note there is **no AI API key environment variable** — that was true in an earlier version of this app but AI provider credentials are now entered per-user through the web UI (**AI Settings**) after logging in, encrypted at rest with the key above. If you're migrating from an older setup that used `GEMINI_API_KEY`, that variable is no longer read; re-enter the key through the UI instead.

`CERBERUS_DB_PATH` and `CERBERUS_SECRET_PATH` default to living inside `backend/app/` alongside the source code. That's fine for a single-server self-hosted setup, but back both files up together (a DB backup without the secret file is useless — the stored API keys can't be decrypted without it), and never commit either to version control.

## 8. First run

1. Open `http://<server-ip>:8000`. You'll land on a login/register screen — there's no default account, the first user you register is a normal account (not an implicit admin; every user's data — AI credentials, scan history — is private to them).
2. Register, then log in.
3. To enable AI Deep Scan: click **AI Settings**, pick a provider (Gemini / Anthropic / OpenAI-compatible — the latter also covers Azure OpenAI, OpenRouter, Groq, Together, local Ollama, etc. via its `base_url` field), paste an API key, save.
4. Upload an APK to run a static scan. Deep Scan is opt-in per scan via the checkbox on the upload screen.

## 9. Dynamic analysis setup (device-side — not part of `install.sh`)

Dynamic analysis instruments a real app process on an Android device via Frida, so unlike static analysis it needs one-time setup **on the device itself**, separate from anything `install.sh` does on the server. Validated directly against a physical rooted device while building this:

1. **Root access is required on the device.** Dynamic analysis attaches Frida to arbitrary app processes and installs hooks inside them — this needs `frida-server` running as root on the device (Magisk-rooted devices work fine; this is unrelated to whether the *target app* itself checks for root, which is exactly what the root-detection bypass hooks are for).

2. **Download a `frida-server` build that matches your client's Frida version, for the device's architecture.** Check the installed client version with `backend/venv/bin/python3 -c "import frida; print(frida.__version__)"`, then grab the matching `frida-server-<version>-android-<arch>.xz` from Frida's GitHub releases (`arm64` for basically all modern phones). **Version matching matters** — the app now detects and warns on a mismatch (surfaced as a `warning`-level telemetry message during session start), but a large gap can still cause connection failures or unpredictable behavior rather than a clean error.

3. **Push and run it:**
   ```bash
   adb push frida-server-<version>-android-arm64 /data/local/tmp/frida-server
   adb shell "su -c 'chmod 755 /data/local/tmp/frida-server; /data/local/tmp/frida-server -D'"
   adb forward tcp:27042 tcp:27042
   ```
   `-D` runs it as a background daemon. `install.sh`/`run.sh` don't do this step for you — it has to happen on the device, and typically after every device reboot (`frida-server` doesn't persist across reboots unless you set that up separately, e.g. a Magisk module).

4. **Confirm it's actually reachable** before trying it through the UI: `adb shell "su -c 'ps -A | grep frida-server'"` should show exactly **one** `frida-server` process. If you see more than one (e.g. from a previous session left running), kill all of them and start exactly one fresh — a duplicate/stale `frida-server` process was directly observed to make the *entire* client connection hang (specifically, `session.create_script()` blocking indefinitely with no error) even though the agent bundle and target app were both completely fine. Symptom: dynamic scans in the UI just spin with no telemetry and no error.

5. Enter the target app's exact package name (not its display name) in the **Target Package Identifier** field and click **Launch Pipeline**.

## 10. Running as a persistent service (recommended for a real server)

`run.sh` runs in the foreground, which is fine for testing but won't survive a logout or reboot. For a real deployment, wrap it in a systemd unit:

```ini
# /etc/systemd/system/cerberus-asf.service
[Unit]
Description=Cerberus-ASF MAST Platform
After=network.target

[Service]
Type=simple
User=<the-user-you-installed-as>
WorkingDirectory=/path/to/Cerberus-ASF
ExecStart=/path/to/Cerberus-ASF/run.sh
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cerberus-asf
sudo systemctl status cerberus-asf
journalctl -u cerberus-asf -f   # live logs
```

## 11. Security notes for a real deployment

- The API's CORS policy allows any origin (`allow_origins=["*"]`) and the server serves plain HTTP with no TLS. This is fine on a trusted private network (home lab, office LAN, VPN) but **should not be exposed directly to the public internet as-is**. If you need remote access, put it behind a reverse proxy (nginx, Caddy) that terminates TLS, and restrict access at the network layer (firewall / VPN / IP allowlist) rather than relying on the app alone.
- Auth uses bearer tokens with no expiry — logout is the only revocation path. This is an intentional simplification for a self-hosted single-operator tool, not a hardened multi-tenant design (no rate limiting, no password reset flow, no email verification).
- `CERBERUS_SECRET_PATH`'s file is created with `0600` permissions on first run automatically — don't loosen that.
- If you're running dynamic analysis against a physical USB Android device and hit permission errors, you likely need a udev rule granting your user access to the device (or run as a user in the appropriate group for your distro) — this is a standard Android/adb-on-Linux setup step, not specific to Cerberus-ASF.

## 12. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `./install.sh` refuses to run, says "Do not run as root" | You ran it with `sudo` | Run `./install.sh` as your normal user — it escalates internally only for apt steps |
| `./run.sh` exits immediately listing missing Python packages | venv wasn't created or `pip install` failed/was skipped | `cd backend && venv/bin/pip install -r requirements.txt`, or re-run `./install.sh` |
| Certificate Analysis section shows "Unsigned" for an APK you know is signed | `apksigner` isn't installed (check `which apksigner`) | `sudo apt install apksigner`, or see the manual jar-install fallback in `install.sh` |
| Static scans return almost no findings, feel much weaker than expected | `jadx` isn't installed/found (check `which jadx`) | Re-run the jadx install step in section 6, then restart the server — `run.sh` will also warn about this on every start if it's missing |
| Framework ID / Component Topography look sparse | Same as above — both structural findings and framework detection depend on a successful jadx decompile; the app falls back to a much weaker legacy path without it |
| `pip install -r requirements.txt` fails trying to compile a package from source | No prebuilt wheel available for your exact Python version | Confirm `build-essential python3-dev libssl-dev libffi-dev pkg-config` are installed (the installer includes these already); as a last resort, use a Python version with broader wheel support (3.10–3.13 have the widest current coverage) |
| Dynamic analysis can't see a USB-connected device | Missing udev rule / device permissions, or `adb` not installed | `sudo apt install android-tools-adb`; check `adb devices` directly outside the app first |
| Dynamic scan says "success" but no telemetry ever appears, root/SSL bypass hooks never seem to activate | The Frida agent wasn't built (`agent/dist/core_hooks.js` missing) — raw unbundled Frida scripts have no `Java` global on current Frida versions, so hooks silently can't install | `cd agent && ./build.sh`, then restart the server — `run.sh` also warns about this on every start if the bundle is missing |
| Dynamic scan hangs indefinitely with no error, no telemetry, even though the agent bundle exists and looks fine | More than one `frida-server` process running on the device (confirmed directly: `session.create_script()` blocks forever with a duplicate/stale server) | `adb shell "su -c 'ps -A \| grep frida-server'"` — if more than one row appears, kill all of them and start exactly one fresh (see section 9) |
| A telemetry warning says "Frida version mismatch" | The on-device `frida-server` version's major version differs from the installed Python `frida` client | Download a `frida-server` build matching the client version (section 9, step 2) — a mismatch doesn't always hard-fail, but behaves unpredictably |
| `agent/build.sh` fails with "npm not found" | Node.js/npm not installed | `sudo apt install nodejs npm`, or re-run `./install.sh` |
| Lost access to stored AI provider keys after restoring a backup | `CERBERUS_SECRET_PATH`'s file wasn't backed up alongside the database | Keys are unrecoverable without that exact file — restore it from backup, or re-enter API keys through the UI if it's truly gone |

## 13. Uninstall / reset

```bash
# Remove just the app's own data (accounts, scan history, stored keys) — irreversible:
rm -f backend/app/cerberus-asf.db backend/app/.instance_secret

# Remove the Python environment:
rm -rf backend/venv

# Remove the Frida agent's build artifacts (Node.js deps + built bundle):
rm -rf agent/node_modules agent/dist agent/package-lock.json

# Remove system tools this installer added (only if nothing else on the host needs them):
sudo rm -rf /opt/jadx /usr/local/bin/jadx /usr/local/bin/trufflehog
sudo apt-get remove --purge apktool aapt android-tools-adb apksigner nodejs npm
```

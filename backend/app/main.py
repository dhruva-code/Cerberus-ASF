import os
import re
import shutil
import tempfile
import json
import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Optional, Dict, Any
from pydantic import BaseModel
from fastapi import FastAPI, UploadFile, File, Form, BackgroundTasks, WebSocket, WebSocketDisconnect, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, Response

from app.static_engine import StaticAnalyzer
from app.dynamic_engine import DynamicAnalyzer
from app import report_engine
from app import db
from app import auth
from app import crypto_utils

# ==========================================
# ENTERPRISE LOGGING CONFIGURATION
# ==========================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("Cerberus-ASF")

# ==========================================
# FASTAPI APPLICATION SETUP
# ==========================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    logger.info(f"Database initialized at {db.DB_PATH}")
    yield

app = FastAPI(
    title="Cerberus-ASF Enterprise API",
    description="Automated MAST (Mobile Application Security Testing) Core Pipeline",
    version="2.1",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Core Analysis Engines
static_engine = StaticAnalyzer()

# Dynamic analysis needs one DynamicAnalyzer (and its live Frida session)
# per user, not a single shared instance — otherwise two logged-in users
# hitting /api/scan/start would stomp on each other's session state. Created
# lazily on first use per user id.
dynamic_sessions: Dict[int, DynamicAnalyzer] = {}


def get_dynamic_session(user_id: int) -> DynamicAnalyzer:
    if user_id not in dynamic_sessions:
        dynamic_sessions[user_id] = DynamicAnalyzer()
    return dynamic_sessions[user_id]

# ==========================================
# PYDANTIC DATA MODELS
# ==========================================
class FuzzRequest(BaseModel):
    package_name: str
    activities_json: str

class RegisterRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class AICredentialRequest(BaseModel):
    provider: str
    api_key: str
    base_url: Optional[str] = None
    model_name: Optional[str] = None

VALID_PROVIDERS = {"gemini", "anthropic", "openai_compatible"}

# ==========================================
# FRONTEND UI ROUTE
# ==========================================
@app.get("/")
async def serve_frontend():
    """Serves the main Cerberus-ASF Dashboard UI directly from the backend."""
    path_1 = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../frontend/index.html"))
    path_2 = os.path.abspath(os.path.join(os.getcwd(), "../frontend/index.html"))
    path_3 = os.path.abspath(os.path.join(os.getcwd(), "frontend/index.html"))
    path_4 = os.path.abspath(os.path.join(os.getcwd(), "../../../frontend/index.html"))
    path_5 = os.path.abspath(os.path.join(os.path.dirname(__file__), "index.html"))

    for ui_path in [path_1, path_2, path_3, path_4, path_5]:
        if os.path.exists(ui_path):
            logger.info(f"Serving UI from: {ui_path}")
            return FileResponse(ui_path)

    error_msg = f"<h3>404 - Enterprise UI Not Found</h3><p>Could not locate index.html.</p>"
    logger.error("Frontend index.html could not be located.")
    return HTMLResponse(content=error_msg, status_code=404)

# ==========================================
# AUTH ROUTES
# ==========================================
@app.post("/api/auth/register")
async def register(req: RegisterRequest):
    """Creates a new user account and immediately logs them in."""
    if not req.username.strip() or not req.password:
        raise HTTPException(status_code=400, detail="Username and password are required.")
    if db.get_user_by_username(req.username):
        raise HTTPException(status_code=409, detail="Username already taken.")

    password_hash = auth.hash_password(req.password)
    user_id = db.create_user(req.username, password_hash)

    token = auth.generate_session_token()
    db.create_session(token, user_id)
    logger.info(f"New user registered: {req.username}")
    return {"token": token, "username": req.username}

@app.post("/api/auth/login")
async def login(req: LoginRequest):
    user_row = db.get_user_by_username(req.username)
    if not user_row or not auth.verify_password(req.password, user_row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials.")

    token = auth.generate_session_token()
    db.create_session(token, user_row["id"])
    return {"token": token, "username": user_row["username"]}

@app.get("/api/auth/me")
async def get_me(current_user: dict = Depends(auth.get_current_user)):
    return {"id": current_user["id"], "username": current_user["username"]}

@app.post("/api/auth/logout")
async def logout(current_user: dict = Depends(auth.get_current_user)):
    db.delete_session(current_user["_session_token"])
    return {"status": "ok"}

# ==========================================
# AI PROVIDER CREDENTIAL ROUTES
# ==========================================
@app.get("/api/ai/credentials")
async def get_ai_credentials(current_user: dict = Depends(auth.get_current_user)):
    """Returns the caller's configured AI provider metadata. The API key
    itself is never included in the response, decrypted or otherwise."""
    cred = db.get_ai_credential(current_user["id"])
    if not cred:
        return {"configured": False}
    return {
        "configured": True,
        "provider": cred["provider"],
        "base_url": cred["base_url"],
        "model_name": cred["model_name"],
    }

@app.post("/api/ai/credentials")
async def save_ai_credentials(req: AICredentialRequest, current_user: dict = Depends(auth.get_current_user)):
    if req.provider not in VALID_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unknown provider. Must be one of: {', '.join(sorted(VALID_PROVIDERS))}")
    if not req.api_key.strip():
        raise HTTPException(status_code=400, detail="API key is required.")

    encrypted = crypto_utils.encrypt(req.api_key.strip())
    db.upsert_ai_credential(current_user["id"], req.provider, encrypted, req.base_url, req.model_name)
    return {"status": "ok"}

# ==========================================
# SCAN HISTORY ROUTES
# ==========================================
@app.get("/api/scans")
async def list_scans(current_user: dict = Depends(auth.get_current_user)):
    rows = db.list_scans_for_user(current_user["id"])
    return [dict(r) for r in rows]

@app.get("/api/scans/{scan_id}")
async def get_scan_detail(scan_id: int, current_user: dict = Depends(auth.get_current_user)):
    row = db.get_scan(scan_id)
    # Same 404 whether the scan doesn't exist or belongs to someone else —
    # avoids confirming "that ID exists" to a user probing sequential IDs.
    if not row or row["user_id"] != current_user["id"]:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return json.loads(row["result_json"])

@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: int, current_user: dict = Depends(auth.get_current_user)):
    """Permanently deletes a scan from the caller's history. Ownership is
    enforced at the SQL level in db.delete_scan(), not just here."""
    deleted = db.delete_scan(scan_id, current_user["id"])
    if not deleted:
        # Same 404 for "doesn't exist" and "not yours" — see get_scan_detail above.
        raise HTTPException(status_code=404, detail="Scan not found.")
    logger.info(f"Deleted scan {scan_id} (user: {current_user['username']})")
    return {"status": "ok"}

# ==========================================
# STATIC ANALYSIS ROUTES
# ==========================================
@app.post("/api/static/upload")
async def static_upload(file: UploadFile = File(...), deep_scan: bool = Form(False), include_third_party: bool = Form(True),
                         current_user: dict = Depends(auth.get_current_user)):
    """Receives target APK, writes to secure temp storage, and triggers static analysis.

    include_third_party controls whether findings/secrets tagged scope="third_party"
    (bundled vendor SDKs, not the app's own code) are included in the response body.
    The *_summary blocks always report full counts regardless of this flag, so a caller
    can always see what was filtered out even when include_third_party=False.
    """
    logger.info(f"Initiating static analysis for uploaded binary: {file.filename} (Deep Scan: {deep_scan}, user: {current_user['username']})")

    ai_provider = ai_api_key = ai_base_url = ai_model_name = None
    if deep_scan:
        cred = db.get_ai_credential(current_user["id"])
        if not cred:
            return {"status": "error", "message": "No AI provider configured for this account. Add an API key under AI Settings before enabling Deep Scan."}
        ai_provider = cred["provider"]
        ai_api_key = crypto_utils.decrypt(cred["api_key_encrypted"])
        ai_base_url = cred["base_url"]
        ai_model_name = cred["model_name"]

    fd, tmp_path = tempfile.mkstemp(suffix=".apk")
    try:
        with os.fdopen(fd, "wb") as f:
            shutil.copyfileobj(file.file, f)

        result = static_engine.analyze_apk(
            tmp_path, deep_scan=deep_scan,
            ai_provider=ai_provider, ai_api_key=ai_api_key,
            ai_base_url=ai_base_url, ai_model_name=ai_model_name,
        )

        try:
            scan_id = db.create_scan(
                user_id=current_user["id"],
                package_name=result.get("package_name"),
                app_name=result.get("app_info", {}).get("app_name"),
                file_name=file.filename,
                security_score=result.get("security_score"),
                deep_scan_used=deep_scan,
                result_json=json.dumps(result),
            )
            result["scan_id"] = scan_id
        except Exception as e:
            logger.error(f"Failed to persist scan to history: {e}")

        if not include_third_party and "findings" in result and "secrets" in result:
            result["findings"] = [f for f in result["findings"] if f.get("scope") != "third_party"]
            result["secrets"] = [s for s in result["secrets"] if s.get("scope") != "third_party"]

        logger.info(f"Static analysis completed successfully for {file.filename}.")
        return result

    except Exception as e:
        logger.error(f"Failed to analyze APK: {str(e)}")
        return {"status": "error", "message": str(e)}

    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

# ==========================================
# DYNAMIC ANALYSIS ROUTES
# ==========================================
@app.post("/api/scan/start")
async def start_dynamic_scan(package_name: str, use_root_bypass: bool = True, use_pinning_bypass: bool = True,
                              current_user: dict = Depends(auth.get_current_user)):
    """Initializes Frida and hooks the target application."""
    logger.info(f"Starting dynamic instrumentation for package: {package_name} (user: {current_user['username']})")
    engine = get_dynamic_session(current_user["id"])
    success = await engine.start_analysis(package_name, use_root_bypass, use_pinning_bypass)
    return {"status": "success" if success else "failed"}

@app.post("/api/scan/stop")
async def stop_dynamic_scan(current_user: dict = Depends(auth.get_current_user)):
    """Detaches instrumentation and compiles dynamic findings."""
    logger.info(f"Halting dynamic analysis session (user: {current_user['username']}).")
    engine = get_dynamic_session(current_user["id"])
    findings = await engine.stop_analysis()
    return {"status": "success", "findings": findings}

@app.post("/api/scan/memory")
async def scan_memory_forensics(pattern: Optional[str] = None, current_user: dict = Depends(auth.get_current_user)):
    """Triggers dynamic RAM memory forensics scanning for secret patterns and plaintext artifacts."""
    logger.info(f"Initiating memory forensics sweep (pattern: {pattern or 'default standards'}, user: {current_user['username']}).")
    engine = get_dynamic_session(current_user["id"])
    results = await engine.scan_process_memory(pattern)
    return {"status": "success", "results": results}


# ==========================================
# TELEMETRY & WEBSOCKET ROUTES
# ==========================================
@app.websocket("/ws/telemetry")
async def websocket_endpoint(websocket: WebSocket, token: Optional[str] = Query(None)):
    """Maintains a persistent connection for streaming framework telemetry and Live Logcat.

    Browsers can't set custom headers on a WebSocket handshake, so the
    session token travels as a query param here instead of the
    Authorization header used by every other route.
    """
    user = auth.get_user_by_token(token) if token else None
    if not user:
        await websocket.close(code=1008)
        return

    engine = get_dynamic_session(user["id"])

    await websocket.accept()
    await websocket.send_json({
        "type": "telemetry",
        "data": {"level": "info", "message": "Cerberus-ASF Telemetry Channel Connected."}
    })
    engine.set_websocket(websocket)

    try:
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)

            if msg.get("action") == "start_logcat":
                pkg = msg.get("package_name")
                logger.info(f"Client requested logcat stream for: {pkg} (user: {user['username']})")
                engine.is_running = True
                asyncio.create_task(engine.stream_logcat(pkg, websocket))

            elif msg.get("action") == "stop_logcat":
                logger.info("Client requested logcat stream halt.")
                engine.is_running = False

    except WebSocketDisconnect:
        engine.set_websocket(None)
        # Actually tear down the Frida session on disconnect instead of just
        # flipping a flag — otherwise closing the browser tab mid-session
        # leaves an instrumented process running live on the device
        # indefinitely with no way to reach it from the UI anymore.
        if engine.is_running or engine.orchestrator.session:
            logger.info(f"Client disconnected mid-session (user: {user['username']}) — tearing down Frida session.")
            await engine.stop_analysis()
        logger.info(f"Frontend dashboard disconnected from telemetry socket (user: {user['username']}).")

# ==========================================
# REPORT GENERATION ROUTES
# ==========================================
@app.post("/api/report/pdf")
async def export_pdf_report(payload: Dict[str, Any], current_user: dict = Depends(auth.get_current_user)):
    """Generates a full VAPT-style PDF static analysis report from a scan result.

    payload is the full scan result object (the same shape returned by
    /api/static/upload and /api/scans/{id}) — not a hand-picked subset —
    so the report has everything it needs: app metadata, components,
    permissions, certificate/manifest issues, findings, and secrets.
    """
    package_name = payload.get("package_name") or "report"
    logger.info(f"Generating PDF export for {package_name} (user: {current_user['username']})")

    try:
        pdf_bytes = report_engine.generate_pdf_report(payload)
    except Exception as e:
        logger.error(f"PDF report generation failed for {package_name}: {e}")
        raise HTTPException(status_code=500, detail=f"PDF report generation failed: {e}")

    # package_name can originate from an attacker-controlled APK and flows
    # into an HTTP response header below — whitelist-sanitize it so it can't
    # inject a malformed/oversized filename or break the header.
    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", package_name)[:80] or "report"
    filename = f"Cerberus-ASF_{safe_name}_StaticAnalysis_Report.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

@app.post("/api/report/fuzz")
async def generate_fuzz_script(req: FuzzRequest, current_user: dict = Depends(auth.get_current_user)):
    """Generates a bash script leveraging ADB to fuzz exported activities."""
    logger.info(f"Generating ADB Fuzz script for {req.package_name}")
    script_content = "#!/bin/bash\necho 'Starting Automated Intent Fuzzing...'\n\n"

    try:
        activities = json.loads(req.activities_json)
        for act in activities:
            if act.get('status') == 'EXPORTED':
                script_content += f"adb shell am start -n {req.package_name}/{act['name']} -a android.intent.action.VIEW --es \"fuzz_key\" \"A\"*1000\nsleep 2\n\n"
    except Exception as e:
        script_content += f"# Error parsing components for fuzz generation: {str(e)}\n"

    script_path = os.path.join(tempfile.gettempdir(), f"cerberus_fuzz_{req.package_name}.sh")
    with open(script_path, "w", encoding="utf-8") as f:
        f.write(script_content)

    return FileResponse(script_path, filename=f"cerberus_fuzz_{req.package_name}.sh")

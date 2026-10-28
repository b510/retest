"""Web 前台與 API。"""
import os
import shutil
import time
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import auth, pipeline, store

STATIC = Path(__file__).resolve().parent / "static"
_VERSION_FILE = Path(__file__).resolve().parent.parent / "VERSION"
VERSION = _VERSION_FILE.read_text().strip() if _VERSION_FILE.exists() else ""
app = FastAPI(title="Retest", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=STATIC), name="static")

# __main__ 啟動前把實際 bind host 寫進 RETEST_BIND；綁公網時強制登入
AUTH_ON = auth.enabled(os.environ.get("RETEST_BIND", "127.0.0.1"))
PUBLIC_PATHS = {"/login", "/api/auth/login", "/static/style.css"}


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if AUTH_ON and path not in PUBLIC_PATHS and not auth.check_session(request.cookies.get(auth.COOKIE)):
        if path.startswith("/api/"):
            return JSONResponse({"detail": "未登入或 session 已過期"}, status_code=401)
        return RedirectResponse("/login", status_code=302)
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    return resp


def _client_ip(request: Request) -> str:
    peer = request.client.host if request.client else ""
    if peer in ("127.0.0.1", "::1"):  # 經本機反向代理/隧道時才採信轉發標頭
        fwd = request.headers.get("cf-connecting-ip") or request.headers.get("x-forwarded-for", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return peer or "unknown"


def _login(request: Request, token: str, resp):
    ip = _client_ip(request)
    if not auth.throttle_ok(ip):
        raise HTTPException(429, "嘗試次數過多，請 5 分鐘後再試")
    got = auth.consume_token(token.strip())
    auth.record_attempt(ip, bool(got))
    if not got:
        return None
    session, expires = got
    secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    resp.set_cookie(auth.COOKIE, session, httponly=True, samesite="lax", secure=secure,
                    max_age=int(expires - time.time()))
    return resp


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, t: str = ""):
    if not AUTH_ON:
        return RedirectResponse("/")
    error = ""
    if t:
        resp = _login(request, t, RedirectResponse("/", status_code=302))
        if resp:
            return resp
        error = "登入 token 無效、已使用或已過期。"
    return (STATIC / "login.html").read_text().replace("<!--ERROR-->", error)


class LoginIn(BaseModel):
    token: str


@app.post("/api/auth/login")
def login_api(body: LoginIn, request: Request):
    if not AUTH_ON:
        return {"status": "auth-disabled"}
    resp = _login(request, body.token, JSONResponse({"status": "ok"}))
    if not resp:
        raise HTTPException(401, "登入 token 無效、已使用或已過期")
    return resp


@app.get("/api/auth/logout")
def logout(request: Request):
    auth.drop_session(request.cookies.get(auth.COOKIE))
    resp = RedirectResponse("/login" if AUTH_ON else "/", status_code=302)
    resp.delete_cookie(auth.COOKIE)
    return resp


@app.get("/api/auth/status")
def auth_status():
    return {"auth": AUTH_ON, "version": VERSION}


class NewProject(BaseModel):
    name: str
    authorized: bool = False
    allow_fin_write: bool = False


def _meta(pid: str) -> dict:
    try:
        m = store.get(pid)
    except (FileNotFoundError, ValueError):
        raise HTTPException(404, "找不到專案")
    m["running"] = pipeline.is_running(pid)
    m["stage_label"] = store.STAGE_LABEL.get(m["stage"], m["stage"])
    return m


@app.get("/", response_class=HTMLResponse)
def index():
    return (STATIC / "index.html").read_text()


@app.get("/api/config")
def get_config():
    return store.load_config()


@app.put("/api/config")
def put_config(cfg: dict):
    cur = store.load_config()
    for k in ("model", "effort", "agent_timeout_min", "poc_timeout_sec"):
        if k in cfg:
            cur[k] = cfg[k]
    store.save_config(cur)
    return cur


@app.get("/api/projects")
def list_projects():
    return [dict(m, running=pipeline.is_running(m["id"]),
                 stage_label=store.STAGE_LABEL.get(m["stage"], m["stage"])) for m in store.all_projects()]


@app.post("/api/projects")
def create_project(p: NewProject):
    if not p.name.strip():
        raise HTTPException(400, "專案名稱必填")
    if not p.authorized:
        raise HTTPException(400, "請勾選授權聲明")
    meta = store.create(p.name.strip(), [], "", allow_fin_write=p.allow_fin_write)
    return store.update(meta["id"], authorized_at=store.now())


@app.get("/api/projects/{pid}")
def project(pid: str):
    return _meta(pid)


@app.delete("/api/projects/{pid}")
def delete_project(pid: str):
    m = _meta(pid)
    if m["running"]:
        raise HTTPException(409, "執行中不可刪除，請先停止複測")
    try:
        store.delete(pid)
    except FileNotFoundError:
        raise HTTPException(404, "找不到專案")
    return {"ok": True, "deleted": pid, "name": m.get("name")}


UPLOAD_EXT = {".zip", ".pdf", ".md", ".html", ".htm", ".py", ".sh", ".txt"}


def _safe_upname(name: str) -> str:
    import re
    return re.sub(r"[^\w.\-]+", "_", Path(name).name).strip("_.")[:120] or "file"


def _uploads(pid: str) -> list[str]:
    up = store.pdir(pid) / "uploads"
    return sorted(p.name for p in up.glob("*") if p.is_file()) if up.exists() else []


def _sync_uploads(pid: str) -> dict:
    """把目前累積的上傳清單寫回 meta；沒有任何檔案時 stage 退回 created。"""
    names = _uploads(pid)
    legacy = (store.pdir(pid) / "upload.zip").exists()
    summary = "、".join(names[:3]) + (f" 等 {len(names)} 份" if len(names) > 3 else "")
    stage = "uploaded" if (names or legacy) else "created"
    (store.pdir(pid) / "inventory.json").unlink(missing_ok=True)
    return store.update(pid, stage=stage, uploads=names, upload_name=summary, error=None)


@app.post("/api/projects/{pid}/upload")
async def upload(pid: str, files: list[UploadFile] = File(...)):
    m = _meta(pid)
    if m["running"]:
        raise HTTPException(409, "執行中不可上傳")
    up = store.pdir(pid) / "uploads"
    up.mkdir(parents=True, exist_ok=True)
    saved = []
    for file in files:
        ext = Path(file.filename or "").suffix.lower()
        if ext not in UPLOAD_EXT:
            raise HTTPException(400, f"不支援的檔案類型：{file.filename}（可上傳 zip / pdf / md / html / py / sh / txt）")
        base = _safe_upname(file.filename)
        dest, stem, suf = up / base, Path(base).stem, Path(base).suffix
        i = 1
        while dest.exists():  # 同名不覆蓋，累加
            dest = up / f"{stem}_{i}{suf}"
            i += 1
        with open(dest, "wb") as f:
            shutil.copyfileobj(file.file, f)
        saved.append(dest.name)
    store.log(pid, f"⬆️ 上傳 {'、'.join(saved)}（目前共 {len(_uploads(pid))} 份）")
    return _sync_uploads(pid)


@app.delete("/api/projects/{pid}/uploads/{name}")
def delete_upload(pid: str, name: str):
    m = _meta(pid)
    if m["running"]:
        raise HTTPException(409, "執行中不可移除上傳檔案")
    p = store.pdir(pid) / "uploads" / Path(name).name
    if p.exists() and p.is_file():
        p.unlink()
        store.log(pid, f"🗑️ 移除上傳檔案 {Path(name).name}")
    return _sync_uploads(pid)


@app.post("/api/projects/{pid}/run")
def run(pid: str, resume: bool = False):
    m = _meta(pid)
    if not _uploads(pid) and not (store.pdir(pid) / "upload.zip").exists():
        raise HTTPException(400, "請先上傳報告/腳本（zip 或散檔）")
    try:
        pipeline.start(pid, resume=resume)
    except RuntimeError as e:
        raise HTTPException(409, str(e))
    return _meta(pid)


@app.post("/api/projects/{pid}/stop")
def stop(pid: str):
    _meta(pid)
    pipeline.stop(pid)
    return {"ok": True}


@app.get("/api/projects/{pid}/log", response_class=PlainTextResponse)
def log(pid: str, offset: int = 0):
    _meta(pid)
    p = store.pdir(pid) / "pipeline.log"
    if not p.exists():
        return ""
    with open(p, "rb") as f:
        f.seek(offset)
        return f.read().decode("utf-8", errors="replace")


@app.get("/api/projects/{pid}/report", response_class=HTMLResponse)
def view_report(pid: str):
    _meta(pid)
    p = store.pdir(pid) / "output" / "report.html"
    if not p.exists():
        raise HTTPException(404, "報告尚未產生")
    return p.read_text()


@app.get("/api/projects/{pid}/screenshots/{name}")
def screenshot(pid: str, name: str):
    _meta(pid)
    p = store.pdir(pid) / "output" / "screenshots" / Path(name).name
    if not p.exists():
        raise HTTPException(404)
    return FileResponse(p)


@app.get("/api/projects/{pid}/download")
def download(pid: str):
    m = _meta(pid)
    if not m.get("zip_name"):
        raise HTTPException(404, "交付包尚未產生")
    return FileResponse(store.pdir(pid) / "output" / m["zip_name"], filename=m["zip_name"])

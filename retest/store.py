"""專案儲存：每個專案一個資料夾，狀態放在 meta.json。"""
import json
import secrets
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROJECTS = ROOT / "projects"
CONFIG_PATH = ROOT / "config.json"
_lock = threading.Lock()

STAGES = ["uploaded", "extract", "agent", "poc_run", "screenshot", "report", "done"]
STAGE_LABEL = {
    "created": "已建立，等待上傳",
    "uploaded": "已上傳，等待開始",
    "extract": "解壓與解析報告",
    "agent": "AI 複測與重構 POC",
    "poc_run": "框架最終執行 POC",
    "screenshot": "產生 POC 截圖",
    "report": "產生報告與打包",
    "done": "完成",
    "failed": "失敗",
    "stopped": "已停止",
}


def load_config() -> dict:
    return json.loads(CONFIG_PATH.read_text())


def save_config(cfg: dict) -> None:
    CONFIG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=2))


def pdir(pid: str) -> Path:
    if not pid.isalnum():
        raise ValueError("bad project id")
    return PROJECTS / pid


def now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def create(name: str, targets: list[str], notes: str) -> dict:
    pid = secrets.token_hex(6)
    d = pdir(pid)
    d.mkdir(parents=True)
    meta = {
        "id": pid, "name": name, "targets": targets, "notes": notes,
        "stage": "created", "created": now(), "updated": now(),
        "upload_name": None, "error": None, "blocked": None, "summary": None,
    }
    (d / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2))
    return meta


def get(pid: str) -> dict:
    return json.loads((pdir(pid) / "meta.json").read_text())


def update(pid: str, **kw) -> dict:
    with _lock:
        meta = get(pid)
        meta.update(kw, updated=now())
        (pdir(pid) / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2))
        return meta


def all_projects() -> list[dict]:
    out = []
    for d in PROJECTS.iterdir() if PROJECTS.exists() else []:
        if (d / "meta.json").exists():
            out.append(json.loads((d / "meta.json").read_text()))
    return sorted(out, key=lambda m: m["created"], reverse=True)


def log(pid: str, msg: str) -> None:
    with open(pdir(pid) / "pipeline.log", "a", encoding="utf-8") as f:
        f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")

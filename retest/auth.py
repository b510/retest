"""公網存取的單一持有者登入（同 RedFrame：一次性 token → session cookie）。

- 在伺服器本機執行 `python3 -m retest token --url https://<外部位址>:<port>`，
  取得一次性登入連結（預設 30 秒內有效、只能用一次）。
- 瀏覽器開啟後 token 立即註銷，換發 HttpOnly session cookie。
- session 從登入起算固定 10 小時到期，不續期；到期後須重新簽發 token。
- 伺服端只存 SHA-256 雜湊，狀態放在 auth.json（權限 0600，不進版控）。
"""
import hashlib
import json
import secrets
import time

from . import store

AUTH_FILE = store.ROOT / "auth.json"
COOKIE = "retest_session"
LOOPBACK = ("127.0.0.1", "::1", "localhost")


def settings() -> dict:
    cfg = store.load_config()
    return {
        "mode": str(cfg.get("auth", "auto")).lower(),
        "token_ttl": int(cfg.get("token_ttl_sec", 30)),
        "session_hours": float(cfg.get("session_hours", 10)),
    }


def enabled(bind_host: str) -> bool:
    """auto：綁非 loopback 位址時強制開啟。"""
    mode = settings()["mode"]
    if mode == "on":
        return True
    if mode == "off":
        return False
    return bool(bind_host) and bind_host not in LOOPBACK


def _h(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _load() -> dict:
    try:
        data = json.loads(AUTH_FILE.read_text())
        data.setdefault("tokens", {})
        data.setdefault("sessions", {})
        return data
    except Exception:
        return {"tokens": {}, "sessions": {}}


def _save(data: dict) -> None:
    AUTH_FILE.write_text(json.dumps(data, indent=1))
    AUTH_FILE.chmod(0o600)


def _cleanup(data: dict, now: float) -> None:
    data["tokens"] = {k: v for k, v in data["tokens"].items() if v["expires"] > now and not v.get("used")}
    data["sessions"] = {k: v for k, v in data["sessions"].items() if v["expires"] > now}


def issue_token(ttl: int | None = None) -> str:
    token = secrets.token_urlsafe(24)
    now = time.time()
    data = _load()
    _cleanup(data, now)
    data["tokens"][_h(token)] = {"created": now, "expires": now + (ttl or settings()["token_ttl"]), "used": False}
    _save(data)
    return token


def consume_token(token: str) -> tuple[str, float] | None:
    """兌換一次性 token，成功回傳 (session, 到期時間)。"""
    if not token:
        return None
    now = time.time()
    data = _load()
    entry = data["tokens"].get(_h(token))
    if not entry or entry.get("used") or entry["expires"] <= now:
        return None
    entry["used"] = True
    session = secrets.token_urlsafe(32)
    expires = now + settings()["session_hours"] * 3600
    _cleanup(data, now)
    data["sessions"][_h(session)] = {"created": now, "expires": expires}
    _save(data)
    return session, expires


def check_session(session: str | None) -> bool:
    if not session:
        return False
    entry = _load()["sessions"].get(_h(session))
    return bool(entry and entry["expires"] > time.time())


def drop_session(session: str | None) -> None:
    if not session:
        return
    data = _load()
    if data["sessions"].pop(_h(session), None) is not None:
        _save(data)


# 登入嘗試速率限制：每 IP 每分鐘 5 次，連續失敗 5 次鎖 5 分鐘
_ATTEMPTS: dict[str, list[float]] = {}
_LOCKOUT: dict[str, float] = {}


def throttle_ok(ip: str) -> bool:
    now = time.time()
    if _LOCKOUT.get(ip, 0) > now:
        return False
    _ATTEMPTS[ip] = [t for t in _ATTEMPTS.get(ip, []) if now - t < 60]
    return len(_ATTEMPTS[ip]) < 5


def record_attempt(ip: str, success: bool) -> None:
    now = time.time()
    if success:
        _ATTEMPTS.pop(ip, None)
        _LOCKOUT.pop(ip, None)
        return
    _ATTEMPTS.setdefault(ip, []).append(now)
    if len([t for t in _ATTEMPTS[ip] if now - t < 300]) >= 5:
        _LOCKOUT[ip] = now + 300
        _ATTEMPTS[ip] = []

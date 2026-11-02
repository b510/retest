"""公網存取的單一持有者登入（同 RedFrame：一次性 token → session cookie）。

- 在伺服器本機執行 `python3 -m retest token --url https://<外部位址>:<port>`，
  取得一次性登入連結（預設 30 秒內有效、只能用一次）。
- 瀏覽器開啟後 token 立即註銷，換發 HttpOnly session cookie。
- session 效期依來源分層（網段 7 天、公網 10 小時），不續期；到期後須重新簽發 token。
  伺服器本機（loopback、無轉發標頭）免 token、免 session，直接放行並視為管理員。
- 伺服端只存 SHA-256 雜湊，狀態放在 auth.json（權限 0600，不進版控）。
"""
import hashlib
import ipaddress
import json
import secrets
import time

from . import store

AUTH_FILE = store.ROOT / "auth.json"
COOKIE = "retest_session"
LOOPBACK = ("127.0.0.1", "::1", "localhost")
NO_EXPIRY = 100 * 365 * 86400  # 實質無限（本機、網段無時效 session/token 用）


def settings() -> dict:
    cfg = store.load_config()
    return {
        "mode": str(cfg.get("auth", "auto")).lower(),
        "token_ttl": int(cfg.get("token_ttl_sec", 30)),
        "session_hours": float(cfg.get("session_hours", 10)),
        "lan_session_sec": int(cfg.get("lan_session_days", 7)) * 86400,
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


def issue_token(ttl: int | None = None, label: str = "", admin: bool = False) -> str:
    """簽發一次性 token。label = 顯示在中控台的持有者名稱；admin = 可進中控台。"""
    token = secrets.token_urlsafe(24)
    now = time.time()
    data = _load()
    _cleanup(data, now)
    data["tokens"][_h(token)] = {"created": now, "expires": now + (ttl or settings()["token_ttl"]),
                                 "used": False, "label": label or "", "admin": bool(admin)}
    _save(data)
    return token


def consume_token(token: str, ip: str = "", ua: str = "", session_ttl: float | None = None) -> tuple[str, float] | None:
    """兌換一次性 token，成功回傳 (session, 到期時間)；把 label/admin 與來源寫進 session。

    session_ttl（秒）由呼叫端依來源分層決定：網段 7 天、公網 10 小時；
    不給則沿用 config 的 session_hours。
    """
    if not token:
        return None
    now = time.time()
    data = _load()
    entry = data["tokens"].get(_h(token))
    if not entry or entry.get("used") or entry["expires"] <= now:
        return None
    entry["used"] = True
    session = secrets.token_urlsafe(32)
    expires = now + (session_ttl if session_ttl is not None else settings()["session_hours"] * 3600)
    _cleanup(data, now)
    data["sessions"][_h(session)] = {"created": now, "expires": expires,
                                     "label": entry.get("label", ""), "admin": bool(entry.get("admin")),
                                     "ip": ip, "ua": (ua or "")[:200], "sid": secrets.token_hex(8)}
    _save(data)
    return session, expires


def check_session(session: str | None) -> bool:
    if not session:
        return False
    entry = _load()["sessions"].get(_h(session))
    return bool(entry and entry["expires"] > time.time())


def session_info(session: str | None) -> dict | None:
    """唯讀取得有效 session 的 entry（不記活動），過期/不存在回 None。"""
    if not session:
        return None
    entry = _load()["sessions"].get(_h(session))
    return entry if entry and entry["expires"] > time.time() else None


def drop_session(session: str | None) -> None:
    if not session:
        return
    data = _load()
    entry = data["sessions"].pop(_h(session), None)
    if entry is not None:
        _ACTIVITY.pop(entry.get("sid", ""), None)
        _save(data)


# ── 中控台：線上 session 活動（存記憶體、不落地；伺服器重啟即歸零，session 本身仍存在 auth.json） ──
_ACTIVITY: dict[str, dict] = {}  # sid -> {last_seen, ip, path}


def touch(session: str | None, ip: str = "", path: str = "") -> dict | None:
    """每個已驗證請求呼叫：驗證 session 並更新其活動狀態。回傳 entry 或 None。"""
    if not session:
        return None
    data = _load()
    entry = data["sessions"].get(_h(session))
    if not entry or entry["expires"] <= time.time():
        return None
    sid = entry.get("sid")
    if not sid:  # 舊版（無 sid）session 補發，使其可在中控台被管理
        sid = secrets.token_hex(8)
        entry["sid"] = sid
        _save(data)
    _ACTIVITY[sid] = {"last_seen": time.time(), "ip": ip, "path": path}
    return entry


def list_sessions() -> list[dict]:
    """中控台用：目前所有有效 session，合併記憶體中的活動狀態。"""
    now = time.time()
    data = _load()
    _cleanup(data, now)
    dirty = False
    out = []
    for e in data["sessions"].values():
        if not e.get("sid"):  # 舊版 session 補發 sid，使其在中控台立即可被撤銷
            e["sid"] = secrets.token_hex(8)
            dirty = True
        sid = e.get("sid", "")
        act = _ACTIVITY.get(sid, {})
        out.append({
            "sid": sid,
            "label": e.get("label") or "(未命名)",
            "admin": bool(e.get("admin")),
            "ip": act.get("ip") or e.get("ip") or "",
            "login": e.get("created"),
            "expires": e.get("expires"),
            "last_seen": act.get("last_seen"),
            "path": act.get("path", ""),
        })
    if dirty:
        _save(data)
    return sorted(out, key=lambda s: s.get("login") or 0)


def revoke_by_sid(sid: str) -> dict | None:
    """當下撤銷某個 session；其下一個請求即被擋回登入。"""
    if not sid:
        return None
    data = _load()
    for h, e in list(data["sessions"].items()):
        if e.get("sid") == sid:
            data["sessions"].pop(h, None)
            _save(data)
            _ACTIVITY.pop(sid, None)
            return e
    return None


def ip_allowed(ip: str, allow: list) -> bool:
    """來源 IP 是否落在允許的 CIDR 清單內；allow 為空代表不設限（loopback 由呼叫端另行放行）。"""
    if not allow:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in allow:
        try:
            if addr in ipaddress.ip_network(str(cidr), strict=False):
                return True
        except ValueError:
            continue
    return False


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

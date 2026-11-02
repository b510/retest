"""Retest CLI：python3 -m retest serve / token"""
import argparse
import ipaddress
import os
from urllib.parse import urlparse

from . import auth, store

NO_EXPIRY_TTL = 100 * 365 * 24 * 3600  # 約 100 年＝實質無時效（內網一次性連結用）


def _is_lan_url(url: str) -> bool:
    """URL 指向內網私有位址 → 視為內網連結。"""
    if not url:
        return False
    host = urlparse(url if "://" in url else "http://" + url).hostname or ""
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False  # 網域名稱（如 trycloudflare.com）視為公網


def main():
    cfg = store.load_config()
    ap = argparse.ArgumentParser(prog="retest")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sv = sub.add_parser("serve", help="啟動 Web 前台")
    sv.add_argument("--host", default=cfg.get("host", "127.0.0.1"))
    sv.add_argument("--port", type=int, default=cfg.get("port", 8780))
    sv.add_argument("--ssl-cert", default=cfg.get("ssl_cert", ""))
    sv.add_argument("--ssl-key", default=cfg.get("ssl_key", ""))
    tk = sub.add_parser("token", help="簽發一次性登入 token（公網/內網存取用）")
    tk.add_argument("--url", default="", help="存取位址，例如 http://192.0.2.20:8780")
    tk.add_argument("--ttl", type=int, default=0, help="token 效期（秒）；不給則：內網無時效、公網依 config.json")
    tk.add_argument("--name", default="", help="簽發給誰（顯示在中控台，例如「王小明」）")
    tk.add_argument("--admin", action="store_true", help="簽發管理員 token（可進中控台管理/撤銷其他 session）")
    tk.add_argument("--lan", action="store_true", help="強制視為內網連結（無時效）")
    tk.add_argument("--public", action="store_true", help="強制視為公網連結（套用 config 的 3 分鐘時效）")
    args = ap.parse_args()

    if args.cmd == "serve":
        if args.host not in auth.LOOPBACK and not auth.enabled(args.host):
            raise SystemExit(f"拒絕啟動：綁定 {args.host} 為公網/非本機位址，但 config.json 的 auth 設為 off。")
        if bool(args.ssl_cert) != bool(args.ssl_key):
            raise SystemExit("ssl_cert 與 ssl_key 必須成對設定")
        os.environ["RETEST_BIND"] = args.host
        if auth.enabled(args.host):
            s = auth.settings()
            allow = store.load_config().get("lan_allow") or []
            print(f"[retest] 登入驗證已啟用｜本機免 token｜"
                  f"網段 session {s['lan_session_sec'] // 86400:g} 天、token 無時效｜"
                  f"公網 session {s['session_hours']:g} 小時、token {s['token_ttl']} 秒")
            print(f"[retest] 簽發連結：python3 -m retest token --name <姓名> "
                  f"--url http{'s' if args.ssl_cert else ''}://<位址>:{args.port}")
            if allow:
                print(f"[retest] 網段白名單：{'、'.join(allow)}（其餘直連來源一律 403）")
            print(f"[retest] 管理員加 --admin 可進中控台 /console 檢視與撤銷線上 session")
        import uvicorn
        # proxy_headers=False：不要讓 uvicorn 用 X-Forwarded-For 改寫 request.client。
        # 本框架的網段閘與分層刻意看「原始 TCP peer」（隧道經本機 cloudflared 連入 → peer=127.0.0.1
        # 才能 bypass 網段閘並判為公網），轉發標頭由 _client_ip() 自行解析。若交給 uvicorn 改寫，
        # 隧道來源會變成公網 IP、被網段白名單 403，公網一次性連結就失效。
        uvicorn.run("retest.web:app", host=args.host, port=args.port,
                    ssl_certfile=args.ssl_cert or None, ssl_keyfile=args.ssl_key or None,
                    proxy_headers=False)
    else:
        # 內網一次性連結無時效（僅限使用一次）；公網連結沿用 config 的 token_ttl（預設 3 分鐘）。
        lan = args.lan or (_is_lan_url(args.url) and not args.public)
        if args.ttl:
            ttl = args.ttl
        elif lan:
            ttl = NO_EXPIRY_TTL
        else:
            ttl = auth.settings()["token_ttl"]
        no_expiry = ttl >= NO_EXPIRY_TTL
        token = auth.issue_token(ttl, label=args.name, admin=args.admin)
        who = f"給「{args.name}」" if args.name else ""
        role = "，管理員（可進中控台）" if args.admin else ""
        valid = "無時效、僅限使用一次（內網）" if no_expiry else f"{ttl} 秒內有效、只能使用一次"
        # session 壽命在登入當下依來源分層決定：內網連結 → 7 天、公網 → session_hours。
        sess = (f"{auth.settings()['lan_session_sec'] // 86400:g} 天" if lan
                else f"{auth.settings()['session_hours']:g} 小時")
        print(f"一次性登入 token{who}（{valid}，登入後 session {sess}{role}）：")
        if args.url:
            print(f"  {args.url.rstrip('/')}/login?t={token}")
        else:
            print(f"  {token}")
            print("開啟 /login 貼上，或組成連結：http://<位址>:<port>/login?t=<token>")


if __name__ == "__main__":
    main()

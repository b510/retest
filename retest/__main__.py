"""Retest CLI：python3 -m retest serve / token"""
import argparse
import os

from . import auth, store


def main():
    cfg = store.load_config()
    ap = argparse.ArgumentParser(prog="retest")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sv = sub.add_parser("serve", help="啟動 Web 前台")
    sv.add_argument("--host", default=cfg.get("host", "127.0.0.1"))
    sv.add_argument("--port", type=int, default=cfg.get("port", 8780))
    sv.add_argument("--ssl-cert", default=cfg.get("ssl_cert", ""))
    sv.add_argument("--ssl-key", default=cfg.get("ssl_key", ""))
    tk = sub.add_parser("token", help="簽發一次性登入 token（公網存取用）")
    tk.add_argument("--url", default="", help="外部位址，例如 https://203.0.113.5:8780")
    tk.add_argument("--ttl", type=int, default=0, help="token 效期（秒），預設依 config.json")
    args = ap.parse_args()

    if args.cmd == "serve":
        if args.host not in auth.LOOPBACK and not auth.enabled(args.host):
            raise SystemExit(f"拒絕啟動：綁定 {args.host} 為公網/非本機位址，但 config.json 的 auth 設為 off。")
        if bool(args.ssl_cert) != bool(args.ssl_key):
            raise SystemExit("ssl_cert 與 ssl_key 必須成對設定")
        os.environ["RETEST_BIND"] = args.host
        if auth.enabled(args.host):
            s = auth.settings()
            print(f"[retest] 登入驗證已啟用（session {s['session_hours']:g} 小時）；"
                  f"用 `python3 -m retest token --url http{'s' if args.ssl_cert else ''}://<外部位址>:{args.port}` 簽發登入連結")
        import uvicorn
        uvicorn.run("retest.web:app", host=args.host, port=args.port,
                    ssl_certfile=args.ssl_cert or None, ssl_keyfile=args.ssl_key or None)
    else:
        token = auth.issue_token(args.ttl or None)
        ttl = args.ttl or auth.settings()["token_ttl"]
        print(f"一次性登入 token（{ttl} 秒內有效、只能使用一次，登入後 session {auth.settings()['session_hours']:g} 小時）：")
        if args.url:
            print(f"  {args.url.rstrip('/')}/login?t={token}")
        else:
            print(f"  {token}")
            print("開啟 /login 貼上，或組成連結：https://<位址>:<port>/login?t=<token>")


if __name__ == "__main__":
    main()

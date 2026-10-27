#!/usr/bin/env bash
# 啟動 Retest Web 前台（host/port/TLS 讀 config.json，可用參數覆寫）：
#   bash run.sh                                    → http://127.0.0.1:8780
#   bash run.sh --host 0.0.0.0                     → 公網存取，強制一次性 token 登入
# 公網登入連結：python3 -m retest token --url https://<外部位址>:8780
cd "$(dirname "$0")"
exec python3 -m retest serve "$@"

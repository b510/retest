#!/usr/bin/env bash
# 啟動 Retest Web 前台：bash run.sh  → http://127.0.0.1:8780
cd "$(dirname "$0")"
HOST=$(python3 -c 'import json;print(json.load(open("config.json"))["host"])')
PORT=$(python3 -c 'import json;print(json.load(open("config.json"))["port"])')
exec python3 -m uvicorn retest.web:app --host "$HOST" --port "$PORT"

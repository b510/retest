# Retest — Web 漏洞複測框架

上傳原始滲透測試報告（PDF / MD / HTML）與複測腳本（py / sh）的 zip，框架會：

1. 安全解壓（防 zip-slip、符號連結、大小上限），把報告轉成純文字。
2. 交給 Claude Code（預設 `claude-opus-4-8`，effort `xhigh`）依報告逐項複測：
   - 只保留 **嚴重 / 高 / 中** 風險，低與資訊列為排除項目。
   - 每個漏洞重構成 bash POC（`pocs/Vxx_*.sh`），用 `lib/poc_lib.sh` 逐步印出「【第 N 步】在做什麼」和實際指令。
3. 框架**獨立重跑**每支 POC（不採信 AI 自述），以結束碼判定：`0` 仍存在 / `1` 已修復 / `2` 無法判定。
4. 把每次執行的終端輸出渲染成截圖。
5. 產出 `report.html`（左側章節與漏洞索引、可搜尋），打包成 zip：`report.html + pocs/ + lib/ + screenshots/`。

## 啟動

```bash
bash run.sh          # http://127.0.0.1:8780
```

需求：python3（fastapi、uvicorn、python-multipart、pillow）、`claude` CLI、chromium、pdftotext。

## 設定 `config.json`（前台「設定」也可改）

| 欄位 | 預設 | 說明 |
|---|---|---|
| model | claude-opus-4-8 | Claude Code `--model` |
| effort | xhigh | Claude Code `--effort` |
| agent_timeout_min | 240 | AI 複測總時限 |
| poc_timeout_sec | 300 | 框架重跑單一 POC 的時限 |

## 安全設計

- 建立專案只需填**專案名稱與 zip**。複測範圍在解壓時從報告與腳本中的目標網址自動辨識（排除 OWASP、CWE 等參考連結），
  顯示在專案頁與報告中。Claude 的每個 Bash 指令都會經過 PreToolUse hook（`retest/assets/scope_guard.py`）檢查，
  指令和指令引用的 .sh/.py 檔裡的主機不在範圍內就擋下；框架重跑 POC 前也做同樣檢查。
  本機位址（127.0.0.1 / localhost）必須明確寫 port 才放行，因為這台機器上其他服務有真實客戶資料。
- AI 被使用政策或分類器擋下時，框架**只記錄、不換模型重試**。已完成的項目照常產出，未完成的標示「需人工複測」。
- 上傳內容視為不可信資料；POC 只證明、不破壞。
- Web 前台預設只綁 127.0.0.1，沒有登入機制。要開給別人用請自行加反向代理和驗證。

## 專案資料夾 `projects/<id>/`

```
meta.json          狀態
upload.zip         原始上傳
input/ input_text/ 解壓結果與報告純文字
work/              Claude 的工作目錄（TASK.md、pocs/、lib/、findings.json）
agent.jsonl        Claude 原始 stream-json
pipeline.log       前台顯示的進度日誌
output/            report.html、screenshots/、Vxx.log、交付 zip
```

「續跑」會沿用已解壓的資料，並讓 AI 從現有的 `findings.json` 接著做。

"""呼叫 Claude Code CLI 執行複測，並把 stream-json 轉成可讀的進度日誌。

被分類器 / 使用政策擋下時只記錄並回報，不換模型重試。
"""
import json
import os
import signal
import subprocess
import time
from pathlib import Path

from . import store

ASSETS = Path(__file__).resolve().parent / "assets"
BLOCK_HINTS = ("usage policy", "acceptable use", "unable to help with", "can't help with",
               "cannot help with", "無法協助")

_procs: dict[str, subprocess.Popen] = {}


def prepare_workdir(pid: str, inventory: dict) -> Path:
    d = store.pdir(pid)
    meta = store.get(pid)
    work = d / "work"
    for sub in ("pocs", "lib", "scratch", ".claude"):
        (work / sub).mkdir(parents=True, exist_ok=True)
    (work / "lib" / "poc_lib.sh").write_text((ASSETS / "poc_lib.sh").read_text())
    (work / "scope.json").write_text(json.dumps({"targets": meta["targets"]}, ensure_ascii=False))
    settings = {
        "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{
            "type": "command",
            "command": f"python3 -I {ASSETS / 'scope_guard.py'} {work / 'scope.json'}",
        }]}]}
    }
    (work / ".claude" / "retest-settings.json").write_text(json.dumps(settings, indent=2))

    def inv_lines():
        for r in inventory["reports"]:
            yield f"  - 報告 `{r['file']}` → 純文字 `{r['text']}`"
        for s in inventory["scripts"]:
            yield f"  - 腳本 `{s}`"
        for o in inventory["others"][:50]:
            yield f"  - 其他 `{o}`"

    if meta.get("allow_fin_write"):
        fin_policy = ("本專案**已授權「可逆金流寫入」**。可實際執行到證明成立：儲值金額竄改類送出被改金額的建單請求、停在未付款；"
                      "負數鑄幣/餘額竄改類**只對你自己用漏洞建立的測試帳號**打，證明餘額確實變動後反向還原；改密/重置類只對自己的測試帳號。"
                      "每一筆改動逐筆記 `created.json`，由 `cleanup.sh` 還原並刪除測試帳號。仍受上面「不可逆動作」底線約束。")
    else:
        fin_policy = "**未授權金流寫入**：儲值/鑄幣/改餘額等金流寫入只證明端點可達即停，不實際改動餘額或建單，判 `vulnerable` 並在 `notes` 註明「僅證明可達」。"
    task = (ASSETS / "TASK.md").read_text().format(
        name=meta["name"],
        targets="\n".join(f"- `{t}`" for t in meta["targets"]),
        input_dir=d / "input",
        text_dir=d / "input_text",
        inventory="\n".join(inv_lines()) or "  （無）",
        fin_policy=fin_policy,
    )
    (work / "TASK.md").write_text(task)
    return work


# 控制流量（Claude CLI → Anthropic）必須直連，不經代理；只有目標請求（curl 等子程序）走代理
NO_PROXY_CTRL = ("anthropic.com,.anthropic.com,api.anthropic.com,claude.ai,.claude.ai,"
                 "statsig.anthropic.com,sentry.io,localhost,127.0.0.1,::1")


def proxy_env(proxy: str | None) -> dict:
    """目標流量走 SOCKS 代理（curl 原生吃 ALL_PROXY，POC 無須寫 -x），Anthropic 控制流量直連。"""
    if not proxy:
        return {}
    return {"ALL_PROXY": proxy, "all_proxy": proxy, "NO_PROXY": NO_PROXY_CTRL, "no_proxy": NO_PROXY_CTRL}


def _short(s, n=300):
    s = str(s).replace("\n", " ⏎ ")
    return s if len(s) <= n else s[:n] + "…"


def _render(ev: dict) -> list[str]:
    t = ev.get("type")
    out = []
    if t == "assistant":
        for c in ev.get("message", {}).get("content", []):
            if c.get("type") == "text" and c.get("text", "").strip():
                out.append("🤖 " + _short(c["text"], 600))
            elif c.get("type") == "tool_use":
                inp = c.get("input", {})
                if c["name"] == "Bash":
                    desc = inp.get("description") or ""
                    out.append(f"⚙️  {desc}\n    $ {_short(inp.get('command', ''), 400)}")
                elif c["name"] in ("Read", "Write", "Edit"):
                    out.append(f"📄 {c['name']} {inp.get('file_path', '')}")
                elif c["name"] == "TodoWrite":
                    todos = inp.get("todos", [])
                    done = sum(1 for x in todos if x.get("status") == "completed")
                    cur = next((x.get("content") for x in todos if x.get("status") == "in_progress"), "")
                    out.append(f"📋 進度 {done}/{len(todos)}　目前：{cur}")
                else:
                    out.append(f"🔧 {c['name']} {_short(json.dumps(inp, ensure_ascii=False), 200)}")
    elif t == "user":
        for c in ev.get("message", {}).get("content", []) if isinstance(ev.get("message", {}).get("content"), list) else []:
            if c.get("type") == "tool_result":
                content = c.get("content")
                if isinstance(content, list):
                    content = " ".join(x.get("text", "") for x in content if isinstance(x, dict))
                tag = "⛔" if c.get("is_error") else "   ↳"
                out.append(f"{tag} {_short(content, 300)}")
    elif t == "result":
        out.append(f"🏁 結束：{ev.get('subtype')}，花費 ${ev.get('total_cost_usd', 0):.2f}，"
                   f"{ev.get('num_turns', '?')} 回合")
    return out


def run(pid: str, work: Path, resume: bool = False) -> dict:
    """執行 Claude，回傳 {ok, blocked, result_text, session_id}。"""
    cfg = store.load_config()
    d = store.pdir(pid)
    prompt = "請閱讀當前目錄的 TASK.md 並完整執行其中的複測任務。"
    if resume:
        pocs = sorted(p.name for p in (work / "pocs").glob("*.sh")) if (work / "pocs").exists() else []
        if (work / "findings.json").exists():
            prompt += "注意：findings.json 已存在，這是中斷後的續跑，請接續未完成的項目，不要重做已完成且有 POC 的項目。"
        elif pocs:
            prompt += (f"注意：這是中斷後的續跑。先前已完成 {len(pocs)} 支 POC（在 pocs/：{', '.join(pocs)}），"
                       "以及 scratch/ 下的工作筆記（如 master_findings.md）。請**先盤點既有 POC 與筆記**，"
                       "接續完成剩餘漏洞的複測，**不要重做已經有 POC 的項目**（尤其是會在目標上重複建帳號/寫入的），"
                       "然後把全部結果彙整寫出 findings.json。")
    cmd = [
        cfg["claude_bin"], "-p", prompt,
        "--model", cfg["model"], "--effort", cfg["effort"],
        "--output-format", "stream-json", "--verbose",
        "--permission-mode", "acceptEdits",
        "--allowedTools", "Bash", "Read", "Write", "Edit", "Glob", "Grep", "TodoWrite",
        "--disallowedTools", "WebFetch", "WebSearch",
        "--settings", str(work / ".claude" / "retest-settings.json"),
        "--add-dir", str(d / "input"), str(d / "input_text"),
    ]
    store.log(pid, f"啟動 Claude：model={cfg['model']} effort={cfg['effort']}")
    raw = open(d / "agent.jsonl", "a", encoding="utf-8")
    proc = subprocess.Popen(cmd, cwd=work, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, text=True, start_new_session=True,
                            env={**os.environ, "POC_COLOR": "1", **proxy_env(store.get(pid).get("proxy"))})
    _procs[pid] = proc
    deadline = time.time() + cfg["agent_timeout_min"] * 60
    result = {"ok": False, "blocked": None, "result_text": "", "session_id": None}
    try:
        for line in proc.stdout:
            raw.write(line)
            raw.flush()
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                store.log(pid, "   " + _short(line.strip(), 300))
                continue
            for msg in _render(ev):
                store.log(pid, msg)
            if ev.get("type") == "result":
                result["session_id"] = ev.get("session_id")
                result["result_text"] = ev.get("result") or ""
                result["ok"] = not ev.get("is_error") and ev.get("subtype") == "success"
                text = (result["result_text"] + " " + str(ev.get("subtype"))).lower()
                if not result["ok"] or (ev.get("stop_reason") == "refusal"):
                    result["blocked"] = _short(result["result_text"] or ev.get("subtype"), 500)
                elif any(h in text for h in BLOCK_HINTS) and len(text) < 600:
                    result["blocked"] = _short(result["result_text"], 500)
            if time.time() > deadline:
                store.log(pid, "⏱️ 超過時限，終止 Claude")
                stop(pid)
                result["blocked"] = "超過 agent_timeout_min 時限"
                break
        proc.wait()
    finally:
        raw.close()
        _procs.pop(pid, None)
    if proc.returncode not in (0, None) and not result["result_text"]:
        result["blocked"] = result["blocked"] or f"Claude 結束碼 {proc.returncode}"
    return result


def stop(pid: str) -> bool:
    proc = _procs.get(pid)
    if not proc or proc.poll() is not None:
        return False
    os.killpg(proc.pid, signal.SIGTERM)
    return True

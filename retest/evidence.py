"""框架獨立執行最終 POC，並把終端輸出（含 ANSI 顏色）渲染成截圖。"""
import html
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

from PIL import Image

from . import store

ASSETS = Path(__file__).resolve().parent / "assets"
ANSI_RE = re.compile(r"\x1b\[([0-9;]*)m")
COLORS = {30: "#6e7681", 31: "#ff7b72", 32: "#3fb950", 33: "#d29922", 34: "#58a6ff",
          35: "#d2a8ff", 36: "#56d4dd", 37: "#c9d1d9", 90: "#8b949e", 91: "#ffa198",
          92: "#56d364", 93: "#e3b341", 94: "#79c0ff", 95: "#e2c5ff", 96: "#76e3ea", 97: "#f0f6fc"}
VERDICT = {0: "仍存在", 1: "已修復", 2: "無法判定"}


def scope_check(script: Path, cwd: Path) -> str | None:
    """用同一支 scope_guard 檢查 POC 內容，回傳錯誤訊息或 None。"""
    import json
    ev = json.dumps({"tool_name": "Bash", "tool_input": {"command": f"bash {script.relative_to(cwd)}"},
                     "cwd": str(cwd)})
    r = subprocess.run(["python3", "-I", str(ASSETS / "scope_guard.py"), str(cwd / "scope.json")],
                       input=ev, capture_output=True, text=True)
    return r.stderr.strip() if r.returncode == 2 else None


def run_poc(pid: str, work: Path, poc_rel: str) -> dict:
    cfg = store.load_config()
    script = (work / poc_rel).resolve()
    if not str(script).startswith(str(work.resolve()) + "/") or not script.is_file():
        return {"rc": None, "status": "需人工複測", "output": f"找不到 POC：{poc_rel}", "secs": 0}
    if err := scope_check(script, work):
        return {"rc": None, "status": "需人工複測", "output": err, "secs": 0}
    t0 = time.time()
    try:
        r = subprocess.run(["bash", str(script)], cwd=script.parent, capture_output=True, text=True,
                           timeout=cfg["poc_timeout_sec"], env={**os.environ, "POC_COLOR": "1"})
        out, rc = r.stdout + (("\n" + r.stderr) if r.stderr.strip() else ""), r.returncode
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        out += f"\n（執行超過 {cfg['poc_timeout_sec']} 秒，已中止）"
        rc = 2
    return {"rc": rc, "status": VERDICT.get(rc, "無法判定"), "output": out, "secs": round(time.time() - t0, 1)}


def ansi_to_html(text: str) -> str:
    out, open_spans, pos = [], 0, 0
    for m in ANSI_RE.finditer(text):
        out.append(html.escape(text[pos:m.start()]))
        pos = m.end()
        codes = [int(c) for c in m.group(1).split(";") if c.isdigit()] or [0]
        style = []
        for c in codes:
            if c == 0:
                out.append("</span>" * open_spans)
                open_spans = 0
            elif c == 1:
                style.append("font-weight:bold")
            elif c == 2:
                style.append("opacity:.65")
            elif c in COLORS:
                style.append(f"color:{COLORS[c]}")
        if style:
            out.append(f'<span style="{";".join(style)}">')
            open_spans += 1
    out.append(html.escape(text[pos:]))
    out.append("</span>" * open_spans)
    return "".join(out)


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def screenshot(title: str, text: str, out_path: Path) -> Path | None:
    cfg = store.load_config()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    page = f"""<!doctype html><html><head><meta charset="utf-8"><style>
body {{ background:#0d1117; margin:0; padding:20px; font-family:"DejaVu Sans Mono","Droid Sans Fallback",monospace; }}
.term {{ background:#161b22; border:1px solid #30363d; border-radius:8px; overflow:hidden; }}
.bar {{ background:#21262d; color:#8b949e; font-size:13px; padding:8px 14px; }}
.bar i {{ display:inline-block; width:11px; height:11px; border-radius:50%; margin-right:6px; vertical-align:-1px; }}
pre {{ color:#c9d1d9; font-size:14px; line-height:1.5; white-space:pre-wrap; word-break:break-all; margin:0; padding:14px; }}
</style></head><body><div class="term"><div class="bar"><i style="background:#ff5f56"></i><i style="background:#ffbd2e"></i><i style="background:#27c93f"></i>&nbsp;{html.escape(title)}</div>
<pre>{ansi_to_html(text)}</pre></div></body></html>"""
    fd, tmp = tempfile.mkstemp(suffix=".html")
    os.close(fd)
    Path(tmp).write_text(page, encoding="utf-8")

    def width(s):
        return sum(2 if ord(c) > 0x2E7F else 1 for c in s)
    plain = strip_ansi(text)
    lines = sum(max(1, -(-width(l) // 108)) for l in plain.split("\n"))
    height = min(140 + lines * 21, 16000)
    try:
        subprocess.run([cfg["chromium"], "--headless=new", "--no-sandbox", "--disable-gpu",
                        "--hide-scrollbars", f"--screenshot={out_path}", f"--window-size=1100,{height}",
                        "--virtual-time-budget=1500", f"file://{tmp}"],
                       capture_output=True, timeout=90)
    finally:
        Path(tmp).unlink(missing_ok=True)
    if not out_path.exists():
        return None
    _crop_tail(out_path)
    return out_path


def _crop_tail(p: Path) -> None:
    """裁掉高度估多時留下的底部空白。"""
    im = Image.open(p).convert("RGB")
    w, h = im.size
    bg = im.getpixel((2, h - 2))
    px = im.load()
    y = h - 1
    while y > 60 and all(px[x, y] == bg for x in range(0, w, 7)):
        y -= 1
    if y < h - 30:
        im.crop((0, 0, w, min(h, y + 24))).save(p)

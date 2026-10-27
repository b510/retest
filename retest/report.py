"""產生複測報告 HTML（含章節/漏洞索引）並打包 zip（報告 + POC + 截圖）。"""
import base64
import json
import html
import zipfile
from pathlib import Path

from . import store

SEV_ORDER = {"嚴重": 0, "高": 1, "中": 2}
SEV_ALIAS = {"critical": "嚴重", "high": "高", "medium": "中", "moderate": "中",
             "嚴重": "嚴重", "高": "高", "中": "中", "高風險": "高", "中風險": "中", "嚴重風險": "嚴重"}
STATUS_CLASS = {"仍存在": "st-vuln", "已修復": "st-fixed", "無法判定": "st-unk", "需人工複測": "st-manual"}
E = html.escape


def norm_sev(s: str) -> str | None:
    return SEV_ALIAS.get(str(s).strip().lower())


def _img(p: Path | None) -> str:
    if not p or not p.exists():
        return '<p class="muted">（無截圖）</p>'
    b64 = base64.b64encode(p.read_bytes()).decode()
    return f'<a href="screenshots/{E(p.name)}" target="_blank"><img src="data:image/png;base64,{b64}" alt="POC 截圖 {E(p.name)}"></a>'


CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1f2328;--muted:#656d76;--line:#d0d7de;--side:#fff;--code:#0d1117;
--crit:#8b0000;--high:#d1242f;--med:#bf8700;--ok:#1a7f37;--accent:#0969da}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--card:#161b22;--fg:#e6edf3;--muted:#8d96a0;--line:#30363d;--side:#010409;--accent:#4493f8}}
*{box-sizing:border-box}a{color:var(--accent)}html{scroll-behavior:smooth;scroll-padding-top:16px}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.65 "Noto Sans TC","Microsoft JhengHei","PingFang TC",system-ui,sans-serif}
nav{position:fixed;top:0;left:0;bottom:0;width:290px;overflow:auto;background:var(--side);border-right:1px solid var(--line);padding:18px 14px}
nav h2{font-size:15px;margin:0 0 10px}nav input{width:100%;padding:7px 9px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);margin-bottom:12px}
nav a{display:block;color:var(--fg);text-decoration:none;padding:3px 6px;border-radius:5px;font-size:14px}nav a:hover{background:var(--bg)}
nav .sub a{padding-left:16px;font-size:13px}nav .sec{color:var(--muted);font-size:12px;margin:12px 0 4px;letter-spacing:.05em}
main{margin-left:290px;padding:28px 36px;max-width:1240px}
@media (max-width:860px){nav{position:static;width:auto;border-right:0;border-bottom:1px solid var(--line)}main{margin-left:0;padding:16px}}
h1{font-size:26px;margin:0 0 4px}h2{font-size:21px;border-bottom:1px solid var(--line);padding-bottom:6px;margin-top:36px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px 22px;margin:18px 0}
.muted{color:var(--muted)}table{border-collapse:collapse;width:100%;font-size:14px}th,td{border:1px solid var(--line);padding:7px 9px;text-align:left;vertical-align:top}
th{background:var(--bg)}td{overflow-wrap:anywhere}table.sum{table-layout:fixed}table.sum th:nth-child(1){width:64px}table.sum th:nth-child(2){width:38%}table.sum th:nth-child(3){width:70px}dd code{overflow-wrap:anywhere}.badge{display:inline-block;padding:1px 9px;border-radius:999px;font-size:12.5px;font-weight:600;color:#fff;white-space:nowrap}
.sev-嚴重{background:var(--crit)}.sev-高{background:var(--high)}.sev-中{background:var(--med)}
.st-vuln{background:var(--high)}.st-fixed{background:var(--ok)}.st-unk{background:#6e7781}.st-manual{background:#8250df}
.kpis{display:flex;gap:12px;flex-wrap:wrap}.kpi{flex:1;min-width:120px;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px}
.kpi b{display:block;font-size:26px}dl{display:grid;grid-template-columns:120px 1fr;gap:6px 14px;margin:0}dt{color:var(--muted)}dd{margin:0}
pre,code{font-family:"DejaVu Sans Mono",Consolas,monospace;font-size:13px}pre{background:var(--code);color:#c9d1d9;padding:12px;border-radius:8px;overflow:auto;white-space:pre-wrap;word-break:break-all}
ol.steps li{margin-bottom:8px}ol.steps code{display:block;margin-top:3px;background:var(--bg);padding:4px 8px;border-radius:5px;word-break:break-all;white-space:pre-wrap}
img{max-width:100%;border:1px solid var(--line);border-radius:8px}.hidden{display:none}.top{font-size:13px;float:right}
"""

JS = """
const q=document.getElementById('q');q.addEventListener('input',()=>{const v=q.value.trim().toLowerCase();
document.querySelectorAll('nav .vlink').forEach(a=>a.classList.toggle('hidden',v&&!a.dataset.k.includes(v)));
document.querySelectorAll('tr.vrow').forEach(r=>r.classList.toggle('hidden',v&&!r.dataset.k.includes(v)));});
"""


def build(pid: str, findings: list[dict], platform: dict) -> Path:
    meta = store.get(pid)
    d = store.pdir(pid)
    out = d / "output"
    findings = sorted(findings, key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["id"]))
    counts = {s: sum(1 for f in findings if f["final_status"] == s) for s in STATUS_CLASS}

    def key(f):
        return E(" ".join(str(f.get(k, "")) for k in ("id", "title", "category", "affected", "severity", "final_status")).lower())

    nav_v = "".join(
        f'<a class="vlink" data-k="{key(f)}" href="#{E(f["id"])}"><span class="badge sev-{E(f["severity"])}">{E(f["severity"])}</span> '
        f'{E(f["id"])} {E(f["title"])}</a>' for f in findings)
    rows = "".join(
        f'<tr class="vrow" data-k="{key(f)}"><td><a href="#{E(f["id"])}">{E(f["id"])}</a></td><td>{E(f["title"])}</td>'
        f'<td><span class="badge sev-{E(f["severity"])}">{E(f["severity"])}</span></td><td>{E(f.get("affected", ""))}</td></tr>'
        for f in findings)

    details = []
    for i, f in enumerate(findings, 1):
        steps = "".join(
            f'<li>{E(s.get("desc", ""))}{f"<code>{E(s.get("cmd", ""))}</code>" if s.get("cmd") else ""}</li>'
            for s in f.get("steps", []))
        poc = f.get("poc") or ""
        run_cmd = f"bash {poc}" if poc else "（無 POC）"
        details.append(f"""
<section class="card" id="{E(f['id'])}"><a class="top" href="#toc">↑ 回索引</a>
<h3>3.{i}　{E(f['id'])}　{E(f['title'])}</h3>
<dl>
<dt>風險等級</dt><dd><span class="badge sev-{E(f['severity'])}">{E(f['severity'])}</span></dd>
<dt>複測結果</dt><dd><span class="badge {STATUS_CLASS.get(f['final_status'], 'st-unk')}">{E(f['final_status'])}</span></dd>
<dt>漏洞類型</dt><dd>{E(f.get('category', ''))}</dd>
<dt>受影響位置</dt><dd><code>{E(f.get('affected', ''))}</code></dd>
</dl>
<h4>漏洞說明</h4><p>{E(f.get('summary', ''))}</p>
<h4>影響</h4><p>{E(f.get('impact', ''))}</p>
<h4>復現步驟</h4><ol class="steps">{steps or '<li class="muted">見 POC</li>'}</ol>
<h4>POC</h4><p>檔案：<code>{E(poc or '無')}</code>　執行：<code>{E(run_cmd)}</code></p>
<h4>POC 執行截圖</h4>{_img(out / 'screenshots' / f['screenshot']) if f.get('screenshot') else '<p class="muted">（無截圖）</p>'}
<h4>修補建議（僅供參考）</h4><p>{E(f.get('recommendation', ''))}</p>
</section>""")

    sub = "　·　".join(x for x in (
        E(platform.get("name") or ""),
        f"前台：{E(platform['frontend_url'])}" if platform.get("frontend_url") else "",
        f"後台：{E(platform['backend_url'])}" if platform.get("backend_url") else "",
    ) if x)
    blocked = f'<p><b>注意：</b>AI 複測過程未完整結束（{E(meta["blocked"])}），未完成的項目已標示為「需人工複測」。</p>' if meta.get("blocked") else ""

    doc = f"""<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{E(meta['name'])}</title><style>{CSS}</style></head><body>
<nav id="toc"><h2>索引</h2><input id="q" placeholder="搜尋漏洞（編號、名稱、類型、狀態）">
<div class="sec">章節</div>
<a href="#s1">1. 複測摘要</a><a href="#s2">2. 漏洞總表</a><a href="#s3">3. 漏洞詳情</a>
<div class="sub">{nav_v}</div></nav>
<main>
<h1>{E(meta['name'])}</h1>
<p class="muted">{sub}</p>

<h2 id="s1">1. 複測摘要</h2>
<div class="kpis">
<div class="kpi"><b>{len(findings)}</b>複測項目（中風險以上）</div>
<div class="kpi"><b style="color:var(--high)">{counts['仍存在']}</b>仍存在</div>
<div class="kpi"><b style="color:var(--ok)">{counts['已修復']}</b>已修復</div>
<div class="kpi"><b>{counts['無法判定'] + counts['需人工複測']}</b>無法判定 / 需人工</div>
</div>{blocked}

<h2 id="s2">2. 漏洞總表</h2>
<table class="sum"><thead><tr><th>編號</th><th>漏洞名稱</th><th>風險</th><th>受影響位置</th></tr></thead><tbody>{rows}</tbody></table>

<h2 id="s3">3. 漏洞詳情</h2>
{''.join(details)}
</main><script>{JS}</script></body></html>"""
    out.mkdir(parents=True, exist_ok=True)
    rp = out / "report.html"
    rp.write_text(doc, encoding="utf-8")
    return rp


def rebuild(pid: str) -> Path:
    """只依既有結果重新產生報告與交付包，不重跑 AI 與 POC。"""
    d = store.pdir(pid)
    findings = json.loads((d / "final_findings.json").read_text())
    data = json.loads((d / "work" / "findings.json").read_text())
    build(pid, findings, data.get("platform") or {})
    return package(pid, findings)


def package(pid: str, findings: list[dict]) -> Path:
    d = store.pdir(pid)
    meta = store.get(pid)
    work, out = d / "work", d / "output"
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in meta["name"])[:40] or pid
    zp = out / f"retest_{safe}_{pid}.zip"
    with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(out / "report.html", "report.html")
        z.write(work / "lib" / "poc_lib.sh", "lib/poc_lib.sh")
        for p in sorted((work / "pocs").glob("*")):
            if p.is_file():
                z.write(p, f"pocs/{p.name}")
        for p in sorted((out / "screenshots").glob("*.png")):
            z.write(p, f"screenshots/{p.name}")
    return zp

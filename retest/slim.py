"""精簡版複測報告 renderer：吃模型合併 pass 產出的 clusters（對抗覆核＋同根因合併後），
輸出左側可點擊索引、每條折疊 POC＋內嵌截圖的自包含單檔 HTML。

clusters.json 結構（由 MERGE.md 的合併 pass 寫出）：
{
  "scope_note": "一句話交代輸入/收斂規則（哪些被降級剔除、哪些併入哪）",
  "clusters": [
    {"name": "一、跨租戶隔離失效", "sev": "嚴重",
     "items": [{"id":"R1","sev":"嚴重","title":"...","refs":["V03","V05"],
                "root":"...","impact":"...","logic":"...","proof":["log 摘句",...],"fix":"..."}]}
  ]
}
refs 填原始 finding id；renderer 依 id 自動掛上 work/pocs/<id>_*.sh 與 output/screenshots/<id>.png。
"""
import base64
import glob
import html
import json
from datetime import date
from pathlib import Path

from . import store

E = html.escape
SEVC = {"嚴重": "#b4232a", "高": "#c76a12", "中": "#9a8700", "低": "#4a7"}
SEV_IDX = {"嚴重": 0, "高": 1, "中": 2, "低": 3}


def _poc_for(pocdir: Path, vid: str):
    g = sorted(pocdir.glob(f"{vid}_*.sh")) or sorted(pocdir.glob(f"{vid}.sh"))
    if not g:
        return None
    return {"vid": vid, "fn": g[0].name, "code": g[0].read_text(encoding="utf-8", errors="replace").rstrip()}


def _shot_for(shotdir: Path, vid: str):
    p = shotdir / f"{vid}.png"
    if not p.exists():
        return None
    b64 = base64.b64encode(p.read_bytes()).decode()
    return {"vid": vid, "src": f"data:image/png;base64,{b64}"}


def render(title: str, when: str, target: str, scope_note: str, clusters: list[dict],
           pocdir: Path, shotdir: Path) -> str:
    total = sum(len(c["items"]) for c in clusters)
    sevcount: dict[str, int] = {}
    for c in clusters:
        for it in c["items"]:
            sevcount[it["sev"]] = sevcount.get(it["sev"], 0) + 1
    sevline = "　".join(f'<b style="color:{SEVC.get(s)}">{s} {n}</b>'
                        for s, n in sorted(sevcount.items(), key=lambda x: SEV_IDX.get(x[0], 9)))
    nav = []
    for c in clusters:
        nav.append(f'<div class="navgrp">{E(c["name"])}</div>')
        for it in c["items"]:
            dot = SEVC.get(it["sev"], "#888")
            nav.append(f'<a class="navlink" href="#{it["id"]}">'
                       f'<span class="dot" style="background:{dot}"></span>'
                       f'<span class="nid">{E(it["id"])}</span>{E(it["title"])}</a>')
    body = []
    for c in clusters:
        body.append(f'<h2 class="cluster">{E(c["name"])}</h2>')
        for it in c["items"]:
            dot = SEVC.get(it["sev"], "#888")
            refs = " ".join(f'<code>{E(r)}</code>' for r in it.get("refs", []))
            proof = "".join(f'<li><code class="ev">{E(p)}</code></li>' for p in it.get("proof", []))
            pocs = ""
            for v in it.get("refs", []):
                p = _poc_for(pocdir, v)
                if p:
                    pocs += (f'<details class="repro"><summary>POC 腳本 · <code>{E(p["vid"])}</code>'
                             f' <span class="fn">{E(p["fn"])}</span></summary>'
                             f'<pre class="poc">{E(p["code"])}</pre></details>')
            shots = ""
            for v in it.get("refs", []):
                s = _shot_for(shotdir, v)
                if s:
                    shots += (f'<details class="repro"><summary>複測截圖 · <code>{E(s["vid"])}</code></summary>'
                              f'<img class="shot" loading="lazy" alt="{E(s["vid"])} screenshot" '
                              f'src="{s["src"]}"></details>')
            evid = ""
            if pocs or shots:
                evid = f'<div class="row"><span class="k">可複現</span><span class="v repros">{pocs}{shots}</span></div>'
            body.append(f'''<section id="{E(it["id"])}" class="vuln">
  <div class="vhead"><span class="badge" style="background:{dot}">{E(it["sev"])}</span>
    <span class="vid">{E(it["id"])}</span><h3>{E(it["title"])}</h3></div>
  <div class="meta">原始對應：{refs or "—"}</div>
  <div class="row"><span class="k">根因</span><span class="v">{E(it.get("root", ""))}</span></div>
  <div class="row"><span class="k">實際危害</span><span class="v">{E(it.get("impact", ""))}</span></div>
  <div class="row"><span class="k">證明邏輯</span><span class="v">{E(it.get("logic", ""))}</span></div>
  <div class="row"><span class="k">決定性證據</span><span class="v"><ul class="evs">{proof}</ul></span></div>
  {evid}
  <div class="row"><span class="k">修補</span><span class="v">{E(it.get("fix", ""))}</span></div>
  <a class="top" href="#top">↑ 回索引</a>
</section>''')
    return TPL.format(title=E(title), date=E(when), target=E(target), scope=E(scope_note),
                      total=total, sevline=sevline, nav="\n".join(nav), body="\n".join(body))


def build(pid: str, clusters: list[dict], scope_note: str) -> Path:
    """由 clusters 產 output/report_slim.html，自動掛 POC/截圖。回傳檔案路徑。"""
    meta = store.get(pid)
    d = store.pdir(pid)
    out, work = d / "output", d / "work"
    html_text = render(
        title=f"{meta['name']} 滲透測試複測報告",
        when=date.today().isoformat(),
        target="、".join(meta.get("targets", [])) or meta["name"],
        scope_note=scope_note,
        clusters=clusters,
        pocdir=work / "pocs",
        shotdir=out / "screenshots",
    )
    p = out / "report_slim.html"
    p.write_text(html_text, encoding="utf-8")
    return p


def load_and_build(pid: str) -> Path | None:
    """讀 output/clusters.json → 產 report_slim.html。檔不存在或格式不符回 None。"""
    d = store.pdir(pid)
    cj = d / "output" / "clusters.json"
    if not cj.exists():
        return None
    data = json.loads(cj.read_text(encoding="utf-8"))
    clusters = data.get("clusters")
    if not clusters:
        return None
    return build(pid, clusters, data.get("scope_note", ""))


TPL = """<!DOCTYPE html><html lang="zh-Hant"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title><style>
:root{{--bg:#f6f7f9;--fg:#1c2230;--mut:#667;--card:#fff;--line:#e3e6ea;--nav:#20283a;--navfg:#dfe5f0;--acc:#2d6cdf}}
@media(prefers-color-scheme:dark){{:root:not([data-theme=light]){{--bg:#11151c;--fg:#e6eaf0;--mut:#9aa3b2;--card:#171c25;--line:#273042;--nav:#0d111a;--navfg:#cdd6e5}}}}
:root[data-theme=dark]{{--bg:#11151c;--fg:#e6eaf0;--mut:#9aa3b2;--card:#171c25;--line:#273042;--nav:#0d111a;--navfg:#cdd6e5}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}
body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.65 -apple-system,"Noto Sans TC",Segoe UI,Roboto,sans-serif}}
.wrap{{display:flex;max-width:1180px;margin:0 auto;gap:0}}
nav{{position:sticky;top:0;align-self:flex-start;height:100vh;overflow-y:auto;width:300px;flex:0 0 300px;
  background:var(--nav);color:var(--navfg);padding:16px 12px 40px}}
nav .nhdr{{font-weight:700;font-size:15px;padding:4px 8px 10px;border-bottom:1px solid #ffffff22;margin-bottom:8px}}
.navgrp{{font-size:11.5px;letter-spacing:.04em;color:#8ea0c0;margin:14px 8px 4px;font-weight:700}}
a.navlink{{display:flex;align-items:baseline;gap:7px;padding:5px 8px;border-radius:6px;color:var(--navfg);
  text-decoration:none;font-size:12.8px;line-height:1.35}}
a.navlink:hover{{background:#ffffff14}}
a.navlink .nid{{font:600 11px ui-monospace,Menlo,monospace;color:#9fb3d6;flex:0 0 auto}}
.dot{{width:8px;height:8px;border-radius:50%;flex:0 0 auto;transform:translateY(1px)}}
main{{flex:1;min-width:0;padding:24px 28px 80px}}
.hero h1{{margin:0 0 4px;font-size:23px}}
.hero .sub{{color:var(--mut);font-size:13px;margin-bottom:12px}}
.summary{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:10px 0 8px}}
.summary .big{{font-size:28px;font-weight:800}}
.tag{{display:inline-block;background:#2d6cdf1a;color:var(--acc);border:1px solid #2d6cdf44;border-radius:999px;
  padding:1px 10px;font-size:12px;font-weight:700;margin-left:8px;vertical-align:middle}}
.scope{{color:var(--mut);font-size:12.5px;margin-top:6px}}
h2.cluster{{font-size:16px;margin:30px 0 8px;padding-bottom:6px;border-bottom:2px solid var(--line)}}
.vuln{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:12px 0;scroll-margin-top:12px}}
.vhead{{display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
.vhead h3{{margin:0;font-size:16px;flex:1 1 auto;min-width:200px}}
.badge{{color:#fff;font-size:12px;font-weight:700;border-radius:6px;padding:2px 9px}}
.vid{{font:700 13px ui-monospace,Menlo,monospace;color:var(--mut)}}
.meta{{color:var(--mut);font-size:12.5px;margin:8px 0 10px}}
.meta code,code{{font:600 12px ui-monospace,Menlo,monospace;background:#8882;padding:1px 6px;border-radius:5px}}
.row{{display:flex;gap:12px;padding:5px 0;border-top:1px dashed var(--line)}}
.row .k{{flex:0 0 76px;color:var(--mut);font-size:12.5px;font-weight:700;padding-top:2px}}
.row .v{{flex:1;min-width:0}}
ul.evs{{margin:2px 0;padding-left:0;list-style:none}}
ul.evs li{{margin:4px 0}}
code.ev{{display:block;white-space:pre-wrap;word-break:break-all;background:#0b0f16;color:#9fe0a0;
  border:1px solid var(--line);border-radius:6px;padding:7px 9px;font:12px/1.5 ui-monospace,Menlo,monospace}}
.repros{{display:flex;flex-direction:column;gap:6px}}
details.repro{{border:1px solid var(--line);border-radius:7px;background:#8881;overflow:hidden}}
details.repro>summary{{cursor:pointer;padding:6px 10px;font-size:12.5px;font-weight:600;color:var(--fg);
  list-style:none;user-select:none}}
details.repro>summary::-webkit-details-marker{{display:none}}
details.repro>summary::before{{content:"▸ ";color:var(--mut)}}
details.repro[open]>summary::before{{content:"▾ "}}
details.repro>summary .fn{{font:500 11px ui-monospace,Menlo,monospace;color:var(--mut);font-weight:400}}
pre.poc{{margin:0;padding:11px 13px;white-space:pre;overflow-x:auto;background:#0b0f16;color:#c9d4e3;
  border-top:1px solid var(--line);font:11.5px/1.55 ui-monospace,Menlo,monospace}}
img.shot{{display:block;max-width:100%;height:auto;border-top:1px solid var(--line)}}
a.top{{display:inline-block;margin-top:10px;font-size:12px;color:var(--acc);text-decoration:none}}
@media(max-width:820px){{.wrap{{flex-direction:column}}nav{{position:static;height:auto;width:auto;flex:none;max-height:42vh}}main{{padding:16px}}}}
</style></head><body><a id="top"></a><div class="wrap">
<nav><div class="nhdr">快速索引</div>{nav}</nav>
<main>
<div class="hero"><h1>{title}<span class="tag">精簡版</span></h1>
<div class="sub">目標：{target}　·　{date}</div></div>
<div class="summary"><span class="big">{total}</span> 個漏洞（對抗覆核＋同根因合併後）　{sevline}
<div class="scope">{scope}</div></div>
{body}
</main></div></body></html>"""

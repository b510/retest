"""安全解壓 zip，並把 PDF / HTML 報告轉成純文字方便模型閱讀。"""
import html
import re
import stat
import subprocess
import zipfile
from html.parser import HTMLParser
from pathlib import Path

MAX_FILES = 5000
MAX_TOTAL = 500 * 1024 * 1024
REPORT_EXT = {".pdf", ".md", ".html", ".htm"}
SCRIPT_EXT = {".py", ".sh"}

TARGET_URL_RE = re.compile(r"\b(https?|wss?)://([A-Za-z0-9.\-]+|\[[0-9a-fA-F:]+\])(?::(\d{1,5}))?", re.I)
# 報告裡的文件參考連結，不是受測目標（資產、設定外洩所在的第三方主機不在此列，照樣複測）
REFERENCE_HOSTS = ("owasp.org", "mitre.org", "nist.gov", "cve.org", "first.org", "w3.org", "mozilla.org",
                   "portswigger.net", "wikipedia.org", "schema.org", "apache.org", "python.org", "readthedocs.io",
                   "hackerone.com", "cwe.mitre.org", "rfc-editor.org", "ietf.org")
# 報告用來示意的佔位主機，送請求沒有意義
PLACEHOLDER_RE = re.compile(r"(^|\.)(example\.(com|org|net)|[a-z0-9-]+\.(example|invalid|test))$|^(attacker|evil)\.", re.I)
DEFAULT_PORT = {"http": "80", "ws": "80", "https": "443", "wss": "443"}


def safe_extract(zip_path: Path, dest: Path) -> list[Path]:
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    out = []
    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_FILES:
            raise ValueError(f"zip 內檔案過多（{len(infos)}）")
        if sum(i.file_size for i in infos) > MAX_TOTAL:
            raise ValueError("zip 解壓後超過 500MB")
        for info in infos:
            name = info.filename
            # 部分 Windows 壓縮工具的中文檔名不是 UTF-8
            if not info.flag_bits & 0x800:
                try:
                    name = name.encode("cp437").decode("utf-8")
                except UnicodeError:
                    try:
                        name = name.encode("cp437").decode("big5")
                    except UnicodeError:
                        pass
            if stat.S_ISLNK(info.external_attr >> 16):
                continue
            target = (dest / name).resolve()
            if not str(target).startswith(str(root) + "/"):
                raise ValueError(f"zip 內含不安全路徑：{name}")
            if name.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
                continue
            if "__MACOSX" in name or Path(name).name.startswith("._"):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as dst:
                dst.write(src.read())
            out.append(target)
    return out


class _Text(HTMLParser):
    BLOCK = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "table", "section"}

    def __init__(self):
        super().__init__()
        self.parts, self.skip = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.skip += 1
        elif tag in self.BLOCK:
            self.parts.append("\n")
        if tag == "img":
            alt = dict(attrs).get("alt") or ""
            self.parts.append(f"[圖片 {alt}]")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self.skip:
            self.skip -= 1
        elif tag in ("td", "th"):
            self.parts.append(" | ")

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


def html_to_text(raw: str) -> str:
    p = _Text()
    p.feed(raw)
    return re.sub(r"\n{3,}", "\n\n", html.unescape("".join(p.parts))).strip()


def derive_targets(input_dir: Path, text_dir: Path) -> list[str]:
    """從報告純文字與複測腳本中找出受測目標（host 或 host:port）。

    報告與腳本裡出現的主機都視為授權範圍（報告就是授權測試的結果），只排除文件參考連結與佔位主機。
    本機位址只有在報告沒有其他目標時才納入（例如本機靶站），且一律帶 port；
    否則報告裡的 127.0.0.1 指的是目標自己的本機（SSRF payload），從這台機器送出會打到別的服務。
    """
    found, local = set(), set()
    files = list(text_dir.glob("*.txt")) + [p for p in input_dir.rglob("*") if p.suffix.lower() in SCRIPT_EXT]
    for f in files:
        for m in TARGET_URL_RE.finditer(f.read_text(errors="replace")):
            scheme, host, port = m.group(1).lower(), m.group(2).lower().strip(".-"), m.group(3)
            if not host or "." not in host and host != "localhost" and not host.startswith("["):
                continue
            if any(host == r or host.endswith("." + r) for r in REFERENCE_HOSTS) or PLACEHOLDER_RE.search(host):
                continue
            if host in ("localhost", "[::1]") or host.startswith("127."):
                local.add(f"{host}:{port or DEFAULT_PORT[scheme]}")
                continue
            found.add(f"{host}:{port}" if port else host)
    return sorted(found) or sorted(local)


def extract_texts(files: list[Path], input_dir: Path, text_dir: Path) -> dict:
    """回傳清單 {reports: [...], scripts: [...], others: [...]}（相對 input_dir 路徑）。"""
    text_dir.mkdir(parents=True, exist_ok=True)
    inv = {"reports": [], "scripts": [], "others": []}
    for f in sorted(files):
        rel = f.relative_to(input_dir)
        ext = f.suffix.lower()
        if ext in REPORT_EXT:
            txt_name = re.sub(r"[^\w.-]+", "_", str(rel)) + ".txt"
            txt = text_dir / txt_name
            if ext == ".pdf":
                subprocess.run(["pdftotext", "-layout", str(f), str(txt)], timeout=120, check=False)
                if not txt.exists():
                    txt.write_text("（pdftotext 轉換失敗，請直接閱讀原始 PDF）")
            elif ext in (".html", ".htm"):
                txt.write_text(html_to_text(f.read_text(errors="replace")))
            else:
                txt.write_text(f.read_text(errors="replace"))
            inv["reports"].append({"file": str(rel), "text": txt_name, "chars": txt.stat().st_size})
        elif ext in SCRIPT_EXT:
            inv["scripts"].append(str(rel))
        else:
            inv["others"].append(str(rel))
    return inv

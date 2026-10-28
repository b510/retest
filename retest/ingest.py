"""安全解壓 zip，並把 PDF / HTML 報告轉成純文字方便模型閱讀。"""
import html
import re
import shutil
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
# 報告常以裸主機名（無 http:// 前綴）寫出雲端儲存/主機資產，TARGET_URL_RE 抓不到，另行辨識
CLOUD_HOST_RE = re.compile(
    r"\b([a-z0-9][a-z0-9.-]*\.(?:"
    r"s3[.-][a-z0-9-]*\.amazonaws\.com|s3\.amazonaws\.com|[a-z0-9-]*\.compute\.amazonaws\.com"
    r"|[a-z0-9-]+\.amazonaws\.com|[a-z0-9-]+\.blob\.core\.windows\.net|[a-z0-9-]+\.web\.core\.windows\.net"
    r"|oss-[a-z0-9-]+\.aliyuncs\.com|[a-z0-9-]+\.cos\.[a-z0-9-]+\.myqcloud\.com"
    r"|storage\.googleapis\.com|[a-z0-9-]+\.r2\.cloudflarestorage\.com))\b", re.I)
S3_URI_RE = re.compile(r"\bs3://([a-z0-9][a-z0-9.-]+)", re.I)
# 原始授權測試若經代理（報告「代理通道」欄），複測沿用同一條以還原白名單出口 IP 與內網可達性
PROXY_RE = re.compile(r"\bsocks5h?://(?:(?:\d{1,3}\.){3}\d{1,3}|localhost):\d{1,5}", re.I)


def reports_reference_proxy(input_dir: Path, text_dir: Path) -> str | None:
    """報告/腳本是否以 SOCKS 代理進行測試（回傳第一個樣例字串，僅供記錄）。

    各報告可能寫不同的 socks5；但從本機 Kali 出去一律走設定檔的 egress_proxy（127.0.0.1:9050），
    不照抄報告裡的位址。只要有任一份用到代理，複測就沿用本機出口以還原白名單出口 IP／內網可達性。
    """
    files = list(text_dir.glob("*.txt")) + [p for p in input_dir.rglob("*") if p.suffix.lower() in SCRIPT_EXT]
    for f in files:
        m = PROXY_RE.search(f.read_text(errors="replace"))
        if m:
            return m.group(0).lower()
    return None


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


def _safe_name(name: str) -> str:
    return re.sub(r"[^\w.\-]+", "_", Path(name).name).strip("_.") or "file"


def collect_inputs(uploads_dir: Path, dest: Path, legacy_zip: Path | None = None) -> list[Path]:
    """彙整一個專案累積上傳的所有來源（多個 zip＋散檔）到 input/。

    - 每個 .zip 解壓進 input/<zip去副檔名>/，避免不同 zip 內同名檔互相覆蓋。
    - 散檔（PDF/MD/HTML/PY/SH/TXT）複製進 input/_files/。
    - legacy_zip：相容舊專案單一 upload.zip。
    """
    dest.mkdir(parents=True, exist_ok=True)
    out: list[Path] = []
    srcs: list[Path] = []
    if legacy_zip and legacy_zip.exists():
        srcs.append(legacy_zip)
    if uploads_dir.exists():
        srcs += sorted(p for p in uploads_dir.iterdir() if p.is_file())
    for s in srcs:
        if s.suffix.lower() == ".zip":
            sub = dest / _safe_name(s.stem)
            i = 1
            while sub.exists():
                sub = dest / f"{_safe_name(s.stem)}_{i}"
                i += 1
            out += safe_extract(s, sub)
        else:
            fdir = dest / "_files"
            fdir.mkdir(parents=True, exist_ok=True)
            target = fdir / _safe_name(s.name)
            i = 1
            while target.exists():
                target = fdir / f"{target.stem}_{i}{target.suffix}"
                i += 1
            shutil.copy2(s, target)
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
        text = f.read_text(errors="replace")
        for m in TARGET_URL_RE.finditer(text):
            scheme, host, port = m.group(1).lower(), m.group(2).lower().strip(".-"), m.group(3)
            if not host or "." not in host and host != "localhost" and not host.startswith("["):
                continue
            if any(host == r or host.endswith("." + r) for r in REFERENCE_HOSTS) or PLACEHOLDER_RE.search(host):
                continue
            if host in ("localhost", "[::1]") or host.startswith("127."):
                local.add(f"{host}:{port or DEFAULT_PORT[scheme]}")
                continue
            found.add(f"{host}:{port}" if port else host)
        # 裸主機名寫出的雲端儲存/主機資產（報告既列為資產即視為授權範圍）
        for m in CLOUD_HOST_RE.finditer(text):
            found.add(m.group(1).lower().strip(".-"))
        for m in S3_URI_RE.finditer(text):
            found.add(f"{m.group(1).lower().strip('.-')}.s3.amazonaws.com")
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

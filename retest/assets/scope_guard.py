#!/usr/bin/env python3
"""Claude Code PreToolUse hook：擋下打到授權範圍以外主機的 Bash 指令。

用法（由框架寫進 settings）：python3 -I scope_guard.py <scope.json>
scope.json = {"targets": ["example.com", "10.0.0.5:8443", "*.example.com"]}

規則：
- 指令字串裡出現的 URL / host:port，以及指令引用到的 .sh/.py 檔案內容裡的 URL，
  主機都必須在 targets 內。
- 回環位址 / 本機一律禁止，除非 targets 明確寫出含 port 的那一筆（本機上有其他服務存放真實資料）。
- 阻擋時 exit 2，stderr 會回給模型。
"""
import ipaddress
import json
import re
import sys
from fnmatch import fnmatch
from pathlib import Path

URL_RE = re.compile(r"\b(?:https?|wss?)://([^/\s'\"`<>?#\\})\]]+)", re.I)
HOSTPORT_RE = re.compile(r"(?<![\w.@/-])((?:\d{1,3}\.){3}\d{1,3}|localhost)(?::(\d{1,5}))?(?![\w.])")
LOCAL_DESTRUCTIVE = [
    re.compile(r"\brm\s+-[a-z]*r[a-z]*f?\s+(/|~|\$HOME)(\s|$)"),
    re.compile(r"\bmkfs\b|\bdd\s+if=.*\bof=/dev/"),
    re.compile(r"\b(shutdown|reboot|poweroff)\b"),
]
LOCAL_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost"}
# 只有長得像真正可連線主機的字串才檢查：FQDN（含點、合法 TLD）、IPv4、localhost。
# 其餘（grep/sed 的 [a-z] 正規片段、殘缺字串）一律當非主機略過。
HOSTNAME_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9]$"
    r"|^(?:\d{1,3}\.){3}\d{1,3}$|^localhost$", re.I)


def parse_target(t: str):
    t = t.strip().lower()
    t = re.sub(r"^[a-z]+://", "", t).split("/")[0]
    if t.count(":") == 1:
        host, port = t.split(":")
        return host, port
    return t, None


def split_hostport(hp: str):
    hp = hp.lower().split("@")[-1]
    if hp.startswith("["):
        host = hp[1:hp.find("]")]
        rest = hp[hp.find("]") + 1:]
        return host, rest[1:] if rest.startswith(":") else None
    if hp.count(":") == 1:
        h, p = hp.split(":")
        return h, p or None
    return hp, None


def is_local(host: str) -> bool:
    if host in LOCAL_NAMES:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_unspecified
    except ValueError:
        return False


def allowed(host: str, port, targets) -> bool:
    for th, tp in targets:
        if not fnmatch(host, th):
            continue
        if is_local(host):
            # 本機必須明確指定 port 才放行
            if tp is not None and port == tp:
                return True
            continue
        if tp is None or port is None or port == tp:
            return True
    return False


# 以下片段是「送給目標的資料」，不是連線目標，掃描前先抹除，避免把 payload 裡的主機誤判成要連的對象：
# - 任何 HTTP 標頭的值（-H "Name: value"）：CORS/CSRF/IP 偽造等測試常把其他主機寫進 Origin、Referer、X-Forwarded-For 等
# - curl 的 -e/--referer
# - 請求主體（-d/--data*）
# - shell for 迴圈的清單（for v in "ip1" "ip2"; do）常是要輪送的偽造值
DATA_RES = [
    re.compile(r"""(?:-H|--header)\s*(['"]).*?:[^'"]*\1""", re.I),
    re.compile(r"""(?:-H|--header)\s*=?\s*[^\s'"]+:[^\s'"]+"""),
    re.compile(r"""(?:-e|--referer)\s+(['"]?)\S+?\1(?=\s|$)"""),
    re.compile(r"""(?:-x|--proxy|--socks5(?:-hostname)?|--socks4a?|--preproxy)\s+\S+"""),  # 代理為授權測試基礎設施，非目標
    re.compile(r"""(?:--data(?:-raw|-binary|-urlencode)?|-d)\s*(['"])(?:\\.|(?!\1).)*\1""", re.I | re.S),
    re.compile(r"""\bfor\s+\w+\s+in\s+[^;\n]*;?\s*do\b"""),
]


def hosts_in(text: str, bare_hosts: bool = True):
    for rx in DATA_RES:
        text = rx.sub(" ", text)
    found = []
    for m in URL_RE.finditer(text):
        hp = m.group(1)
        if "$" in hp or "{" in hp:
            continue  # 變數，交給檔案內容掃描
        if m.start() and text[m.start() - 1] in "=&":
            continue  # 查詢參數值（?url=http://… 的 SSRF payload），是資料不是連線目標
        host, port = split_hostport(hp)
        if not host or not HOSTNAME_RE.match(host):
            continue  # 不是真正的主機（grep/sed 正規片段 https://[a-z]+、殘缺字串等）
        found.append((host, port))
    # 帶協定的完整網址（上面）是可靠的連線訊號；裸 IP 太容易是資料（標頭值、偽造 IP、說明文字、SSRF payload）。
    # 只有本機回環位址的裸寫法才攔——這是唯一可能誤打到這台機器其他服務的情況；其餘裸 IP 一律放行，靠完整網址把關。
    if bare_hosts:
        for m in HOSTPORT_RE.finditer(URL_RE.sub(" ", text)):
            host = m.group(1).lower()
            if host in LOCAL_NAMES or host == "localhost" or host.startswith("127.") or host == "0.0.0.0":
                found.append((host, m.group(2)))
    return found


def main():
    targets = [parse_target(t) for t in json.loads(Path(sys.argv[1]).read_text())["targets"] if t.strip()]
    ev = json.load(sys.stdin)
    if ev.get("tool_name") != "Bash":
        sys.exit(0)
    cmd = ev.get("tool_input", {}).get("command", "")
    cwd = Path(ev.get("cwd") or ".")

    for rx in LOCAL_DESTRUCTIVE:
        if rx.search(cmd):
            print("[Retest 平台管控] 這個指令可能破壞本機環境，已阻擋。", file=sys.stderr)
            sys.exit(2)

    texts = [("指令", cmd)]
    for tok in re.findall(r"[\w./~-]+\.(?:sh|py|bash)\b", cmd):
        p = (cwd / tok).expanduser()
        if p.is_file() and p.stat().st_size < 2_000_000:
            texts.append((tok, p.read_text(errors="replace")))

    bad = []
    for src, text in texts:
        for host, port in hosts_in(text, bare_hosts=(src == "指令")):
            if host in ("0.0.0.0",) or host.startswith("255."):
                continue
            if not allowed(host, port, targets):
                bad.append(f"{host}{':' + port if port else ''}（出現在{src}）")
    if bad:
        print(
            "[Retest 平台管控・非目標防禦] 以下主機不在本專案授權範圍內，指令未執行："
            + "、".join(sorted(set(bad)))
            + "。請只對授權目標進行複測；若這是報告中的目標但漏填範圍，請在最終結果中標註「需人工複測」並說明。",
            file=sys.stderr,
        )
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()

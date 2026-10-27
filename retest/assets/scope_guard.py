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


# Origin / Referer 標頭的值只是送給目標的字串（CORS、CSRF 測試），不會連線到該主機
HEADER_VALUE_RES = [
    re.compile(r"""(?:-H|--header)\s*(['"])\s*(?:Origin|Referer)\s*:[^'"]*\1""", re.I),
    re.compile(r"""(?:-e|--referer)\s+(['"]?)\S+?\1(?=\s|$)"""),
    re.compile(r"""(['"])(?:Origin|Referer)\1\s*:\s*(['"])[^'"]*\2""", re.I),
]


def hosts_in(text: str, bare_hosts: bool = True):
    for rx in HEADER_VALUE_RES:
        text = rx.sub(" ", text)
    found = []
    for m in URL_RE.finditer(text):
        hp = m.group(1)
        if "$" in hp or "{" in hp:
            continue  # 變數，交給檔案內容掃描
        host, port = split_hostport(hp)
        if not host or re.search(r"[\^*+()|\[\]]", host):
            continue  # grep/sed 正規表示式片段（例如 https://[^ ]+），不是可連線的主機
        found.append((host, port))
    # 裸 IP / localhost 只看指令本身；檔案內容裡的裸 IP 多半是說明文字（例如出口 IP），不是連線目標
    if bare_hosts:
        for m in HOSTPORT_RE.finditer(URL_RE.sub(" ", text)):
            found.append((m.group(1).lower(), m.group(2)))
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

#!/usr/bin/env bash
# =====================================================================
#  Retest POC 共用函式庫
#  每個 POC 腳本都以：
#      source "$(dirname "$0")/../lib/poc_lib.sh"
#  載入本檔。執行時會逐步印出「第 N 步：在做什麼」與實際送出的指令，
#  讓接手的開發人員看得懂每一步、也能單獨複製某一步重跑。
#
#  結束碼約定：
#      0 = 漏洞仍存在 (VULNERABLE)
#      1 = 漏洞已修復 / 無法重現 (NOT VULNERABLE)
#      2 = 無法判定（連線失敗、前置條件不足等）
#
#  可調環境變數：
#      POC_BODY_LINES  回應內容最多顯示幾行（預設 40）
#      POC_COLOR       設為 1 強制輸出顏色（預設：終端機才上色）
#      POC_INSECURE    設為 1 時 curl 加 -k（自簽憑證環境）
# =====================================================================

: "${POC_BODY_LINES:=40}"
POC_STEP=0
STEP_OUT=""
STEP_RC=0

if [ -t 1 ] || [ "${POC_COLOR:-0}" = "1" ]; then
  C_RST=$'\e[0m'; C_B=$'\e[1m'; C_DIM=$'\e[2m'
  C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'; C_BLU=$'\e[34m'; C_MAG=$'\e[35m'; C_CYN=$'\e[36m'
else
  C_RST=""; C_B=""; C_DIM=""; C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_MAG=""; C_CYN=""
fi

CURL_OPTS=(-sS --max-time 30)
[ "${POC_INSECURE:-0}" = "1" ] && CURL_OPTS+=(-k)

# 將參數組成可直接複製貼上的指令字串
_poc_quote() {
  local out="" a
  for a in "$@"; do
    if [[ "$a" =~ ^[A-Za-z0-9_./:=@%+,-]+$ ]]; then
      out+="$a "
    else
      out+="'${a//\'/\'\\\'\'}' "
    fi
  done
  printf '%s' "${out% }"
}

# poc_header <編號> <標題> <風險等級> <目標>
poc_header() {
  local line="======================================================================"
  echo "${C_B}${line}${C_RST}"
  echo "${C_B} 漏洞編號：${C_RST}$1"
  echo "${C_B} 漏洞名稱：${C_RST}$2"
  echo "${C_B} 風險等級：${C_RST}${C_RED}$3${C_RST}"
  echo "${C_B} 測試目標：${C_RST}$4"
  echo "${C_B} 執行時間：${C_RST}$(date '+%Y-%m-%d %H:%M:%S %Z')"
  echo "${C_B}${line}${C_RST}"
}

# note <文字>：補充說明，不執行任何動作
note() { echo "${C_DIM}  # $*${C_RST}"; }

# step <這一步在做什麼> <指令與參數...>
#   會印出步驟標題與完整指令後執行；輸出存在 $STEP_OUT、結束碼存在 $STEP_RC
step() {
  local desc="$1"; shift
  POC_STEP=$((POC_STEP + 1))
  echo
  echo "${C_B}${C_CYN}【第 ${POC_STEP} 步】${desc}${C_RST}"
  echo "${C_YEL}\$ $(_poc_quote "$@")${C_RST}"
  STEP_OUT="$("$@" 2>&1)"; STEP_RC=$?
  local total; total=$(printf '%s\n' "$STEP_OUT" | wc -l)
  printf '%s\n' "$STEP_OUT" | head -n "$POC_BODY_LINES" | sed 's/^/  │ /'
  if [ "$total" -gt "$POC_BODY_LINES" ]; then
    echo "${C_DIM}  │ ……（共 ${total} 行，僅顯示前 ${POC_BODY_LINES} 行）${C_RST}"
  fi
  [ "$STEP_RC" -ne 0 ] && echo "${C_DIM}  (指令結束碼 ${STEP_RC})${C_RST}"
  return 0
}

# http <curl 參數...>：預設帶入逾時等共用選項的 curl，-i 顯示回應標頭
http() { curl "${CURL_OPTS[@]}" -i "$@"; }

# body_of <curl -i 的輸出>：去掉 HTTP 標頭只留 body
body_of() { printf '%s' "$1" | awk 'BEGIN{b=0} b{print; next} /^\r?$/{b=1}'; }

# status_of <curl -i 的輸出>：取最後一個 HTTP 狀態碼
status_of() { printf '%s' "$1" | grep -oE '^HTTP/[0-9.]+ [0-9]{3}' | tail -n1 | awk '{print $2}'; }

# jget <JSON 文字> <路徑，例如 data.token 或 items.0.id>
jget() {
  printf '%s' "$1" | python3 -c '
import json, sys
raw = sys.stdin.read()
i = min([p for p in (raw.find("{"), raw.find("[")) if p >= 0] or [0])
try:
    v = json.loads(raw[i:])
    for k in sys.argv[1].split("."):
        if k == "": continue
        v = v[int(k)] if isinstance(v, list) else v[k]
    print(v if isinstance(v, str) else json.dumps(v, ensure_ascii=False))
except Exception:
    pass' "$2"
}

# rget <文字> <正規表示式，含一個擷取群組>
rget() { printf '%s' "$1" | python3 -c 'import re,sys; m=re.search(sys.argv[1], sys.stdin.read(), re.S); print(m.group(1) if m else "")' "$2"; }

# extract <變數名> <值> <說明>：把上一步取得的值存成變數並印出來
extract() {
  printf -v "$1" '%s' "$2"
  local shown="$2"; [ ${#shown} -gt 120 ] && shown="${shown:0:120}…"
  echo "${C_MAG}  ↳ 取得 $3：\$$1 = ${shown:-<空值>}${C_RST}"
}

# check <條件說明> <測試指令...>：條件成立印 ✔ 並回傳 0，否則印 ✘ 回傳 1
check() {
  local desc="$1"; shift
  if "$@"; then echo "${C_GRN}  ✔ ${desc}${C_RST}"; return 0
  else echo "${C_DIM}  ✘ ${desc}${C_RST}"; return 1; fi
}

contains() { printf '%s' "$1" | grep -qE -- "$2"; }

_verdict_box() {
  echo
  echo "${C_B}----------------------------------------------------------------------${C_RST}"
  echo "${C_B} 複測結論：$1${C_RST}"
  echo " 判定依據：$2"
  echo "${C_B}----------------------------------------------------------------------${C_RST}"
}
vulnerable()   { _verdict_box "${C_RED}漏洞仍存在 (VULNERABLE)${C_RST}" "$1"; exit 0; }
fixed()        { _verdict_box "${C_GRN}已修復 / 無法重現 (NOT VULNERABLE)${C_RST}" "$1"; exit 1; }
inconclusive() { _verdict_box "${C_YEL}無法判定 (INCONCLUSIVE)${C_RST}" "$1"; exit 2; }

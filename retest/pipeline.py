"""複測流程：解壓 → AI 複測 → 框架重跑 POC → 截圖 → 報告與打包。"""
import json
import shutil
import threading
import traceback

from . import agent, evidence, ingest, report, store

_running: dict[str, threading.Thread] = {}
_stop_flags: set[str] = set()


def is_running(pid: str) -> bool:
    t = _running.get(pid)
    return bool(t and t.is_alive())


def start(pid: str, resume: bool = False) -> None:
    if is_running(pid):
        raise RuntimeError("此專案正在執行中")
    _stop_flags.discard(pid)
    t = threading.Thread(target=_run, args=(pid, resume), daemon=True)
    _running[pid] = t
    t.start()


def stop(pid: str) -> None:
    _stop_flags.add(pid)
    agent.stop(pid)


def _check_stop(pid):
    if pid in _stop_flags:
        raise InterruptedError


def _run_cleanup(pid: str, work, out) -> dict:
    """複測後執行 AI 產生的 cleanup.sh，清掉在目標上留下的足跡，並整理清單。"""
    created = []
    cj = work / "created.json"
    if cj.exists():
        try:
            created = json.loads(cj.read_text())
        except json.JSONDecodeError:
            created = []
    script = work / "cleanup.sh"
    result = {"created": created, "ran": False, "status": None, "output": ""}
    if not created and not script.exists():
        store.log(pid, "🧹 複測未在目標上新建/竄改資料，無須清理")
        return result
    if not script.exists():
        store.log(pid, f"⚠️ 有 {len(created)} 筆足跡但缺 cleanup.sh，全數留待人工清理")
        result["status"] = "需人工清理"
        return result
    store.log(pid, f"🧹 執行足跡清理：bash cleanup.sh（{len(created)} 筆）")
    r = evidence.run_poc(pid, work, "cleanup.sh")
    result.update(ran=True, status=r["status"], output=r["output"])
    (out / "cleanup.log").write_text(r["output"])
    if evidence.screenshot("$ bash cleanup.sh   —   足跡清理", r["output"], out / "screenshots" / "cleanup.png"):
        result["screenshot"] = "cleanup.png"
    # 重讀 created.json（cleanup.sh 會把已還原的標 restored:true）
    try:
        result["created"] = json.loads(cj.read_text())
    except Exception:
        pass
    left = [c for c in result["created"] if not c.get("restored")]
    store.log(pid, f"🧹 清理完成：{len(result['created']) - len(left)} 已清除，{len(left)} 待人工清除")
    return result


def _run(pid: str, resume: bool) -> None:
    d = store.pdir(pid)
    try:
        store.update(pid, error=None, blocked=None)
        work = d / "work"
        inv_path = d / "inventory.json"

        if not (resume and inv_path.exists()):
            store.update(pid, stage="extract")
            store.log(pid, "📦 解壓上傳檔案")
            for sub in ("input", "input_text"):
                shutil.rmtree(d / sub, ignore_errors=True)
            files = ingest.safe_extract(d / "upload.zip", d / "input")
            inv = ingest.extract_texts(files, d / "input", d / "input_text")
            inv_path.write_text(json.dumps(inv, ensure_ascii=False, indent=2))
            store.log(pid, f"   報告 {len(inv['reports'])} 份、腳本 {len(inv['scripts'])} 支、其他 {len(inv['others'])} 個")
            if not inv["reports"]:
                raise ValueError("zip 裡找不到任何報告（PDF / MD / HTML）")
            targets = ingest.derive_targets(d / "input", d / "input_text")
            if not targets:
                raise ValueError("報告與腳本中找不到任何目標網址（http(s)://…），無法判定複測範圍")
            store.update(pid, targets=targets)
            store.log(pid, f"🎯 從報告自動辨識複測範圍：{'、'.join(targets)}")
        inv = json.loads(inv_path.read_text())
        _check_stop(pid)

        store.update(pid, stage="agent")
        work = agent.prepare_workdir(pid, inv)
        res = agent.run(pid, work, resume=resume)
        _check_stop(pid)
        if res["blocked"]:
            # 不換模型重試，只記錄並繼續把已完成的部分產出
            store.update(pid, blocked=res["blocked"])
            store.log(pid, f"⚠️ AI 複測未正常完成：{res['blocked']}。已完成的項目照常產出，其餘標示「需人工複測」。")

        fpath = work / "findings.json"
        if not fpath.exists():
            raise RuntimeError("AI 沒有產出 findings.json，無法產生報告" + (f"（{res['blocked']}）" if res["blocked"] else ""))
        data = json.loads(fpath.read_text())

        findings, excluded = [], list(data.get("excluded", []))
        for f in data.get("findings", []):
            sev = report.norm_sev(f.get("severity", ""))
            if sev is None:  # 低/資訊一律不進報告
                excluded.append({"original_ref": f.get("original_ref", ""), "title": f.get("title", ""),
                                 "severity": f.get("severity", ""), "reason": "非中風險以上，不列入"})
                continue
            f["severity"] = sev
            findings.append(f)

        store.update(pid, stage="poc_run")
        out = d / "output"
        shutil.rmtree(out, ignore_errors=True)
        (out / "screenshots").mkdir(parents=True)
        for f in findings:
            _check_stop(pid)
            if not f.get("poc"):
                f["final_status"] = "需人工複測"
                store.log(pid, f"⏭️ {f['id']} 無 POC，標示需人工複測")
                continue
            store.log(pid, f"▶️ 框架重跑 {f['id']}：bash {f['poc']}")
            r = evidence.run_poc(pid, work, f["poc"])
            status = r["status"]
            if status == "無法判定" and f.get("agent_status") == "需人工複測":
                status = "需人工複測"  # POC 刻意停在前置檢查（白名單、寫入、範圍外），沿用 AI 的分類
            f.update(final_status=status, poc_rc=r["rc"], poc_secs=r["secs"])
            (out / f"{f['id']}.log").write_text(r["output"])
            store.log(pid, f"   → {r['status']}（rc={r['rc']}，{r['secs']}s）")

        store.update(pid, stage="screenshot")
        for f in findings:
            _check_stop(pid)
            log = out / f"{f['id']}.log"
            if not log.exists():
                continue
            name = f"{f['id']}.png"
            title = f"$ bash {f['poc']}   —   {f['id']} {f.get('title', '')}"
            if evidence.screenshot(title, log.read_text(), out / "screenshots" / name):
                f["screenshot"] = name
                store.log(pid, f"📸 {name}")
            else:
                store.log(pid, f"⚠️ {f['id']} 截圖失敗")

        store.update(pid, stage="cleanup")
        cleanup = _run_cleanup(pid, work, out)
        (d / "cleanup_result.json").write_text(json.dumps(cleanup, ensure_ascii=False, indent=2))

        store.update(pid, stage="report")
        report.build(pid, findings, data.get("platform") or {}, cleanup)
        zp = report.package(pid, findings)
        (d / "final_findings.json").write_text(json.dumps(findings, ensure_ascii=False, indent=2))
        summary = {s: sum(1 for f in findings if f["final_status"] == s) for s in report.STATUS_CLASS}
        summary["total"] = len(findings)
        store.update(pid, stage="done", summary=summary, zip_name=zp.name)
        store.log(pid, f"✅ 完成：{summary}，交付包 {zp.name}")
    except InterruptedError:
        store.update(pid, stage="stopped")
        store.log(pid, "⏹️ 已由使用者停止")
    except Exception as e:
        store.update(pid, stage="failed", error=str(e))
        store.log(pid, f"❌ 失敗：{e}")
        (d / "error.txt").write_text(traceback.format_exc())

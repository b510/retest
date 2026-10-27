const STAGES = [["extract", "解析報告"], ["agent", "AI 複測"], ["poc_run", "重跑 POC"], ["screenshot", "截圖"], ["report", "報告"], ["done", "完成"]];
let current = null, logOffset = 0, timer = null;

const api = async (path, opts = {}) => {
  const r = await fetch(path, opts);
  if (r.status === 401) { location.href = "/login"; throw new Error("session 已過期，請重新登入"); }
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText);
  return r.headers.get("content-type")?.includes("json") ? r.json() : r.text();
};

async function loadList() {
  const list = await api("/api/projects");
  const ul = document.getElementById("plist");
  ul.innerHTML = "";
  for (const p of list) {
    const li = document.createElement("li");
    li.className = p.id === current ? "on" : "";
    li.innerHTML = `<b></b><small></small>`;
    li.querySelector("b").textContent = p.name;
    li.querySelector("small").textContent = `${p.stage_label}${p.running ? " · 執行中" : ""} · ${p.created}`;
    li.onclick = () => open(p.id);
    ul.appendChild(li);
  }
}

function render(m) {
  const main = document.getElementById("main");
  let sec = main.querySelector(".proj");
  if (!sec || sec.dataset.id !== m.id) {
    main.innerHTML = "";
    sec = document.getElementById("tplProject").content.firstElementChild.cloneNode(true);
    sec.dataset.id = m.id;
    main.appendChild(sec);
    sec.querySelector(".file").onchange = e => upload(m.id, e.target.files[0]);
    sec.querySelector(".act-run").onclick = () => run(m.id, false);
    sec.querySelector(".act-resume").onclick = () => run(m.id, true);
    sec.querySelector(".act-stop").onclick = () => api(`/api/projects/${m.id}/stop`, { method: "POST" }).then(refresh);
  }
  sec.querySelector(".pname").textContent = m.name;
  sec.querySelector(".pmeta").textContent = `範圍（自動辨識）：${m.targets.length ? m.targets.join("、") : "解析報告後產生"}　·　建立 ${m.created}`;
  sec.querySelector(".stage").textContent = m.stage_label + (m.running ? "…" : "");
  const idx = STAGES.findIndex(s => s[0] === m.stage);
  sec.querySelector(".stages").innerHTML = STAGES.map(([k, label], i) =>
    `<div class="${m.stage === "done" || i < idx ? "done" : i === idx ? "cur" : ""}">${label}</div>`).join("");
  sec.querySelector(".upname").textContent = m.upload_name ? `已上傳：${m.upload_name}` : "尚未上傳";
  sec.querySelector(".file").disabled = m.running;
  sec.querySelector(".act-run").disabled = m.running || !m.upload_name;
  sec.querySelector(".act-resume").disabled = m.running || !m.upload_name;
  sec.querySelector(".act-stop").disabled = !m.running;
  const alert = sec.querySelector(".alert");
  const msg = m.error ? `失敗：${m.error}` : m.blocked ? `AI 複測未正常完成：${m.blocked}（未完成項目已標示「需人工複測」，不會自動換模型重試）` : "";
  alert.textContent = msg;
  alert.classList.toggle("hidden", !msg);
  const res = sec.querySelector(".result");
  res.classList.toggle("hidden", m.stage !== "done");
  if (m.stage === "done" && m.summary) {
    const s = m.summary;
    res.querySelector(".kpis").innerHTML =
      `<div><b>${s.total}</b>複測項目</div><div><b style="color:var(--danger)">${s["仍存在"]}</b>仍存在</div>` +
      `<div><b style="color:var(--ok)">${s["已修復"]}</b>已修復</div><div><b>${s["無法判定"] + s["需人工複測"]}</b>無法判定/需人工</div>`;
    res.querySelector(".act-report").href = `/api/projects/${m.id}/report`;
    res.querySelector(".act-zip").href = `/api/projects/${m.id}/download`;
  }
}

async function pollLog() {
  if (!current) return;
  const txt = await api(`/api/projects/${current}/log?offset=${logOffset}`);
  if (txt) {
    logOffset += new TextEncoder().encode(txt).length;
    const pre = document.querySelector(".log");
    const atBottom = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 30;
    pre.textContent += txt;
    if (atBottom) pre.scrollTop = pre.scrollHeight;
  }
}

async function refresh() {
  if (!current) return;
  render(await api(`/api/projects/${current}`));
  await pollLog();
  loadList();
}

async function open(id) {
  current = id; logOffset = 0;
  document.getElementById("main").innerHTML = "";
  await refresh();
  clearInterval(timer);
  timer = setInterval(refresh, 2500);
}

async function upload(id, file) {
  if (!file) return;
  const fd = new FormData();
  fd.append("file", file);
  try { await api(`/api/projects/${id}/upload`, { method: "POST", body: fd }); } catch (e) { alert(e.message); }
  refresh();
}

async function run(id, resume) {
  try { await api(`/api/projects/${id}/run?resume=${resume}`, { method: "POST" }); } catch (e) { alert(e.message); }
  refresh();
}

document.getElementById("btnNew").onclick = () => document.getElementById("dlgNew").showModal();
document.getElementById("btnCreate").onclick = async e => {
  e.preventDefault();
  const f = document.getElementById("formNew");
  if (!f.reportValidity()) return;
  const btn = document.getElementById("btnCreate");
  btn.disabled = true;
  try {
    const p = await api("/api/projects", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: f.elements.name.value, authorized: f.elements.authorized.checked }) });
    const fd = new FormData();
    fd.append("file", f.elements.zip.files[0]);
    await api(`/api/projects/${p.id}/upload`, { method: "POST", body: fd });
    await api(`/api/projects/${p.id}/run`, { method: "POST" });
    document.getElementById("dlgNew").close(); f.reset();
    await loadList(); open(p.id);
  } catch (err) { alert(err.message); }
  btn.disabled = false;
};
document.getElementById("btnCfg").onclick = async () => {
  const cfg = await api("/api/config"), f = document.getElementById("formCfg");
  for (const k of ["model", "effort", "agent_timeout_min", "poc_timeout_sec"]) f.elements[k].value = cfg[k];
  document.getElementById("dlgCfg").showModal();
};
document.getElementById("btnSaveCfg").onclick = async e => {
  e.preventDefault();
  const f = document.getElementById("formCfg"), body = Object.fromEntries(new FormData(f));
  body.agent_timeout_min = +body.agent_timeout_min; body.poc_timeout_sec = +body.poc_timeout_sec;
  await api("/api/config", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  document.getElementById("dlgCfg").close();
};
api("/api/auth/status").then(s => document.getElementById("btnLogout").classList.toggle("hidden", !s.auth));
loadList();

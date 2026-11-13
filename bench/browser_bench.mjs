// Browser-level experiments in real headless Chrome, one isolated profile
// (--user-data-dir) per role, driven through the DevTools protocol. No npm
// packages. Each repetition starts a fresh API process on a throw-away copy of
// the committed database, so the production quota (3 per pair per hour) is
// never changed and never reached, and the repository's data/demo.db is not
// touched.
//
// Usage (repo root, after ./build.sh):
//   node bench/browser_bench.mjs heat|profile|load|robust [reps]
//
// Outputs (results/): e6_browser.csv, e7_traffic.csv, e8_browser.csv,
// e9_longtasks.csv, e9_browser_load.csv, e13_robustness.csv
//
// What the driver does and does not do: it presses each button as soon as it
// becomes enabled (polled every 50 ms) and never calls the page's tick(); the
// protocol advances only through the application's own one-second timer.
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, cpSync, writeFileSync, appendFileSync, existsSync, renameSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const CHROME = process.env.CHROME || "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const ACCOUNTS = { police: "police@demo.local", carlos: "carlos@demo.local", fer: "fer@demo.local", ximena: "ximena@demo.local" };
const USERS = ["carlos", "fer", "ximena"];
const CHROME_FLAGS = ["--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-extensions",
  "--disable-background-timer-throttling", "--disable-renderer-backgrounding", "--disable-backgrounding-occluded-windows",
  "--window-size=1100,900"];
const sleep = ms => new Promise(r => setTimeout(r, ms));
const now = () => performance.now();
const work = mkdtempSync(path.join(tmpdir(), "pp-bench-"));
const repo = process.cwd();
const stamp = new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14);

// ---------------------------------------------------------------- CSV
function openCsv(name, header) {
  const file = path.join("results", name);
  mkdirSync(path.join("results", "raw"), { recursive: true });
  if (existsSync(file)) renameSync(file, path.join("results", "raw", name.replace(".csv", `-replaced-at-${stamp}.csv`)));
  writeFileSync(file, header.join(",") + "\n");
  const q = v => { const s = String(v ?? ""); return /[",\n]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s; };
  return row => appendFileSync(file, header.map(h => q(row[h])).join(",") + "\n");
}

// ---------------------------------------------------------------- page instrumentation (measurement only)
const HOOK = `(() => {
  window.__lt = [];
  try { new PerformanceObserver(l => { for (const e of l.getEntries()) window.__lt.push([e.startTime, e.duration]); }).observe({ type: "longtask", buffered: true }); } catch (e) {}
  window.__wasm = {};
  const orig = WebAssembly.instantiateStreaming;
  if (orig) WebAssembly.instantiateStreaming = async function (src, imp) {
    const t0 = performance.now();
    const r = await orig.call(WebAssembly, src, imp);
    window.__wasm.t0 = t0; window.__wasm.t1 = performance.now(); window.__wasm.inst = r.instance;
    return r;
  };
  let pc;
  try { Object.defineProperty(window, "partyCall", { configurable: true, get() { return pc; }, set(v) { pc = v; window.__wasm.ready = performance.now(); } }); } catch (e) {}
})()`;

// ---------------------------------------------------------------- CDP
class Tab {
  static async open(port, role) {
    const info = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: "PUT" })).json();
    const tab = new Tab();
    Object.assign(tab, { port, role, id: info.id, next: 1, pending: new Map(), requests: new Map(), capture: false });
    tab.ws = new WebSocket(info.webSocketDebuggerUrl);
    await new Promise((res, rej) => { tab.ws.onopen = res; tab.ws.onerror = rej; });
    tab.ws.onmessage = ev => tab.onMessage(JSON.parse(ev.data));
    await tab.send("Page.enable");
    await tab.send("Runtime.enable");
    await tab.send("Network.enable");
    await tab.send("Performance.enable");
    await tab.send("Page.addScriptToEvaluateOnNewDocument", { source: HOOK });
    return tab;
  }
  onMessage(msg) {
    if (msg.id) {
      const p = this.pending.get(msg.id);
      if (p) { this.pending.delete(msg.id); msg.error ? p.rej(new Error(msg.error.message)) : p.res(msg.result); }
      return;
    }
    const p = msg.params || {};
    const rec = id => { if (!this.requests.has(id)) this.requests.set(id, { req: 0, resp: 0 }); return this.requests.get(id); };
    if (msg.method === "Network.requestWillBeSent") Object.assign(rec(p.requestId), { url: p.request.url, method: p.request.method, t: now() });
    else if (msg.method === "Network.requestWillBeSentExtraInfo") {
      const h = Object.fromEntries(Object.entries(p.headers || {}).map(([k, v]) => [k.toLowerCase(), v]));
      rec(p.requestId).req = Number(h["content-length"] || 0);
    } else if (msg.method === "Network.responseReceived") rec(p.requestId).status = p.response.status;
    else if (msg.method === "Network.loadingFinished") { const r = rec(p.requestId); r.resp = p.encodedDataLength; r.done = true; }
    else if (msg.method === "Page.javascriptDialogOpening") this.send("Page.handleJavaScriptDialog", { accept: true }).catch(() => {});
  }
  send(method, params = {}) {
    const id = this.next++;
    return new Promise((res, rej) => { this.pending.set(id, { res, rej }); this.ws.send(JSON.stringify({ id, method, params })); });
  }
  async eval(expression) {
    const r = await this.send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
    return r.result.value;
  }
  async goto(url) { await this.send("Page.navigate", { url }); await sleep(150); }
  async until(expression, what, timeoutMs = 90000, step = 50) {
    const end = now() + timeoutMs;
    while (now() < end) {
      try { if (await this.eval(expression)) return now(); } catch (_) { /* navigating */ }
      await sleep(step);
    }
    throw new Error(`timeout waiting for ${what} (${this.role})`);
  }
  async metrics() {
    const m = Object.fromEntries((await this.send("Performance.getMetrics")).metrics.map(x => [x.name, x.value]));
    let wasm = 0;
    try { wasm = await this.eval("window.__wasm && __wasm.inst ? __wasm.inst.exports.mem.buffer.byteLength : 0"); } catch (_) {}
    return { jsHeap: m.JSHeapUsedSize, task: m.TaskDuration, script: m.ScriptDuration, wasm };
  }
  async close() { try { this.ws.close(); await fetch(`http://127.0.0.1:${this.port}/json/close/${this.id}`); } catch (_) {} }
}

// ---------------------------------------------------------------- processes
const browsers = {};
let apiProc = null, apiSeq = 0;

async function startBrowsers(roles) {
  let port = 9340;
  for (const role of roles) {
    port++;
    const profile = path.join(work, `profile-${role}`);
    mkdirSync(profile, { recursive: true });
    const proc = spawn(CHROME, [...CHROME_FLAGS, `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, "about:blank"], { stdio: "ignore" });
    browsers[role] = { role, port, profile, proc };
  }
  for (const b of Object.values(browsers)) {
    for (let i = 0; i < 80; i++) {
      try { b.version = (await (await fetch(`http://127.0.0.1:${b.port}/json/version`)).json()).Browser; break; } catch (_) { await sleep(250); }
    }
    if (!b.version) throw new Error(`Chrome for ${b.role} did not start`);
  }
}

async function startApi() {
  if (apiProc) { apiProc.kill(); await sleep(300); }
  apiSeq++;
  const dir = path.join(work, `api-${apiSeq}`);
  mkdirSync(path.join(dir, "data"), { recursive: true });
  writeFileSync(path.join(dir, "data", "demo.db"), execFileSync("git", ["show", "HEAD:data/demo.db"], { maxBuffer: 1 << 26 }));
  cpSync(path.join(repo, "data", "schema.sql"), path.join(dir, "data", "schema.sql"));
  cpSync(path.join(repo, "bin", "lattigo-api"), path.join(dir, "lattigo-api.exe"));
  const port = 8100 + apiSeq;
  apiProc = spawn(path.join(dir, "lattigo-api.exe"), [], { cwd: dir, stdio: "ignore", env: { ...process.env, ADDR: `127.0.0.1:${port}`, WEB_DIR: path.join(repo, "web") } });
  const base = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 80; i++) { try { await fetch(base + "/"); return base; } catch (_) { await sleep(150); } }
  throw new Error("API did not start");
}

function shutdown() {
  for (const b of Object.values(browsers)) { try { b.proc.kill(); } catch (_) {} }
  try { apiProc?.kill(); } catch (_) {}
}

// One OS sample of every Chrome instance (grouped by profile directory) and of the API.
function osSample() {
  const ps = `Get-CimInstance Win32_Process -Filter "Name='chrome.exe' OR Name='lattigo-api.exe'" | Select-Object ProcessId,Name,WorkingSetSize,PrivatePageCount,KernelModeTime,UserModeTime,CommandLine | ConvertTo-Json -Compress`;
  let list = JSON.parse(execFileSync("powershell", ["-NoProfile", "-NonInteractive", "-Command", ps], { maxBuffer: 1 << 26 }).toString() || "[]");
  if (!Array.isArray(list)) list = [list];
  const out = {};
  const add = (key, p) => {
    const o = out[key] ||= { ws: 0, priv: 0, cpuMs: 0, procs: 0 };
    o.ws += Number(p.WorkingSetSize); o.priv += Number(p.PrivatePageCount); o.procs++;
    o.cpuMs += (Number(p.KernelModeTime) + Number(p.UserModeTime)) / 1e4;
  };
  for (const p of list) {
    if (p.Name === "lattigo-api.exe") { if (apiProc && p.ProcessId === apiProc.pid) add("api", p); continue; }
    for (const b of Object.values(browsers)) if ((p.CommandLine || "").includes(b.profile)) add(b.role, p);
  }
  return out;
}

// ---------------------------------------------------------------- protocol driving
const tokens = {};
async function login(role, base) {
  const tab = await Tab.open(browsers[role].port, role);
  await tab.goto(`${base}/demo-login.html?account=${role}`);
  await tab.until("location.pathname.endsWith('-dashboard.html') && typeof api === 'function'", "login");
  tokens[role] = await tab.eval("sessionStorage.getItem('pp_auth_token')");
  return tab;
}
async function authedTab(role, base) {
  const tab = await Tab.open(browsers[role].port, role);
  await tab.goto(`${base}/login.html`);
  await tab.until("document.readyState === 'complete'", "login page");
  await tab.eval(`sessionStorage.setItem('pp_auth_token', ${JSON.stringify(tokens[role])}); true`);
  return tab;
}

const RESULT = "/RADIO|LIMITE/.test(document.getElementById('result').textContent)";
const ERRORED = "document.getElementById('result').classList.contains('error')";
const setPoint = (x, y) => `document.getElementById('x').value = ${x}; document.getElementById('y').value = ${y}; document.getElementById('sendBtn').click(); true`;

// Creates `cases` cases, each for the given users; returns [{targetId, user}].
async function createAssignments(policeDash, users, cases, radius = 5) {
  const list = await policeDash.eval(`api("/api/police/suspects").then(d => d.users || d.suspects || Object.values(d).find(Array.isArray))`);
  const ids = users.map(u => list.find(s => (s.email || s.suspectEmail) === ACCOUNTS[u]).id);
  const out = [];
  for (let c = 0; c < cases; c++) {
    const title = `bench ${Date.now()} ${c}`;
    await policeDash.eval(`api("/api/police/cases", { method: "POST", body: JSON.stringify({ title: ${JSON.stringify(title)}, radius: ${radius}, suspectIds: ${JSON.stringify(ids)} }) }).then(() => true)`);
    const targets = await policeDash.eval(`api("/api/police/cases").then(d => d.cases.find(c => c.title === ${JSON.stringify(title)}).targets.map(t => ({ id: t.id, suspectId: t.suspectId ?? t.suspect_user_id ?? t.suspectUserId })))`);
    targets.forEach((t, i) => out.push({ targetId: t.id, user: users[ids.indexOf(t.suspectId)] ?? users[i], caseIndex: c }));
  }
  return out;
}

// Opens both protocol pages of one assignment and waits until the WASM client is ready.
async function openAssignment(a, base) {
  a.police = await authedTab("police", base);
  a.userTab = await authedTab(a.user, base);
  await a.police.goto(`${base}/crypto.html?target=${a.targetId}`);
  await a.userTab.goto(`${base}/crypto.html?target=${a.targetId}`);
  await a.police.until("!document.getElementById('initBtn').disabled", "police client ready");
  await a.userTab.until("!document.getElementById('initBtn').disabled", "user client ready");
}

// Runs one assignment from the first click to the class on the Police page.
async function runAssignment(a, point = [11, 22], hooks = {}) {
  const t = { start: now() };
  await a.police.eval("document.getElementById('initBtn').click()");
  await a.userTab.eval("document.getElementById('initBtn').click()");
  t.setup = await a.police.until("!document.getElementById('sendBtn').disabled", "CPK/RLK ready");
  if (hooks.afterSetup) await hooks.afterSetup();
  await a.police.eval(setPoint(10, 20));
  await a.userTab.until("!document.getElementById('sendBtn').disabled", "police input stored");
  await a.userTab.eval(setPoint(point[0], point[1]));
  t.inputs = now();
  t.result = await a.police.until(`${RESULT} || ${ERRORED}`, "result", 120000);
  a.text = (await a.police.eval("document.getElementById('result').textContent")).trim();
  a.timing = { setup_s: (t.setup - t.start) / 1000, input_to_result_s: (t.result - t.inputs) / 1000, total_s: (t.result - t.start) / 1000 };
  return a;
}

async function closeAll(assignments) { for (const a of assignments) { await a.police?.close(); await a.userTab?.close(); } }

function phaseOf(method, url) {
  const p = new URL(url).pathname;
  if (/\/setup\/share$/.test(p)) return "CPK + RLK r1 shares";
  if (/\/setup\/artifacts$/.test(p)) return "CPK + RLK r1 aggregate";
  if (/\/setup\/r2$/.test(p)) return "RLK r2 share";
  if (/\/input$/.test(p)) return "Ciphertexts";
  if (/\/delta$/.test(p)) return "Enc(delta)";
  if (/\/e2s$/.test(p)) return method === "POST" ? "E2S share" : "E2S aggregate";
  const gc = /\/gc\/(\w+)$/.exec(p);
  if (gc) return `${method === "POST" ? "send" : "fetch"} ${gc[1]}`;
  if (/\/api\/sessions\/[^/]+$/.test(p)) return "polling (session state)";
  if (/\/result$/.test(p)) return "Result";
  if (p === "/party.wasm") return "static: party.wasm";
  if (!p.startsWith("/api/")) return "static: other";
  return "other API";
}

// ---------------------------------------------------------------- E6 + E7: heat map and traffic
async function heat(reps) {
  const row6 = openCsv("e6_browser.csv", ["experiment", "users", "assignments_per_pair", "mode", "rep", "user", "case_index", "ok", "class", "error",
    "t_setup_s", "t_input_to_result_s", "t_total_s", "cell_latency_s", "chrome_version"]);
  const row7 = openCsv("e7_traffic.csv", ["experiment", "rep", "role", "phase", "method", "path", "status", "request_body_bytes", "response_wire_bytes"]);
  const cells = [];
  for (const u of [1, 2, 3]) for (const a of [1, 2, 3]) cells.push([u, a, "concurrent"]);
  for (const u of [1, 2, 3]) cells.push([u, 1, "sequential"]);
  for (const [u, per, mode] of cells) {
    for (let rep = 0; rep < reps; rep++) {
      const base = await startApi();
      const dash = await login("police", base);
      const users = USERS.slice(0, u);
      const userDash = [];
      for (const usr of users) userDash.push(await login(usr, base));
      let assignments = [], cellLatency = "", err = "";
      try {
        assignments = await createAssignments(dash, users, per);
        for (const a of assignments) await openAssignment(a, base);
        const t0 = now();
        const guard = a => runAssignment(a).catch(e => { a.error = String(e.message || e); return a; });
        if (mode === "concurrent") await Promise.all(assignments.map(guard));
        else for (const a of assignments) await guard(a);
        cellLatency = ((now() - t0) / 1000).toFixed(3);
      } catch (e) { err = String(e.message || e); }
      for (const a of assignments) {
        row6({ experiment: "e6_browser", users: u, assignments_per_pair: per, mode, rep, user: a.user, case_index: a.caseIndex,
          ok: !a.error && a.text === "DENTRO DEL RADIO", class: a.text, error: a.error || err,
          t_setup_s: a.timing?.setup_s.toFixed(3), t_input_to_result_s: a.timing?.input_to_result_s.toFixed(3), t_total_s: a.timing?.total_s.toFixed(3),
          cell_latency_s: cellLatency, chrome_version: browsers.police.version });
      }
      if (!assignments.length) row6({ experiment: "e6_browser", users: u, assignments_per_pair: per, mode, rep, ok: false, error: err });
      if (u === 1 && per === 1 && mode === "concurrent") {
        await sleep(300);
        for (const a of assignments) for (const tab of [a.police, a.userTab]) for (const r of tab.requests.values()) {
          if (!r.url || !r.url.startsWith("http")) continue;
          row7({ experiment: "e7_traffic", rep, role: tab.role === "police" ? "police" : "user", phase: phaseOf(r.method, r.url), method: r.method,
            path: new URL(r.url).pathname.replace(/\/\d+/g, "/{id}").replace(/sessions\/[^/]+/, "sessions/{id}"), status: r.status, request_body_bytes: r.req, response_wire_bytes: Math.round(r.resp) });
        }
      }
      await closeAll(assignments);
      await dash.close();
      for (const d of userDash) await d.close();
      console.log(`heat users=${u} per_pair=${per} ${mode} rep ${rep}: ${cellLatency} s ${assignments.map(a => a.error ? "ERR" : "ok").join(" ")} ${err}`);
    }
  }
}

// ---------------------------------------------------------------- E8 + long tasks: one pair, sampled per phase
async function profile(reps) {
  const row8 = openCsv("e8_browser.csv", ["experiment", "rep", "role", "phase", "processes", "working_set_bytes", "private_bytes", "cpu_ms_cumulative",
    "js_heap_used_bytes", "wasm_memory_bytes", "task_duration_s", "script_duration_s"]);
  const rowL = openCsv("e9_longtasks.csv", ["experiment", "rep", "role", "start_ms", "duration_ms"]);
  for (let rep = 0; rep < reps; rep++) {
    const base = await startApi();
    const dash = await login("police", base);
    const udash = await login("carlos", base);
    const [a] = await createAssignments(dash, ["carlos"], 1);
    await openAssignment(a, base);
    const sample = async phase => {
      const os = osSample();
      const tabs = { police: a.police, carlos: a.userTab };
      for (const role of ["police", "carlos", "api"]) {
        const m = tabs[role] ? await tabs[role].metrics() : {};
        const o = os[role] || {};
        row8({ experiment: "e8_browser", rep, role: role === "carlos" ? "user" : role, phase, processes: o.procs, working_set_bytes: o.ws, private_bytes: o.priv,
          cpu_ms_cumulative: o.cpuMs?.toFixed(1), js_heap_used_bytes: m.jsHeap, wasm_memory_bytes: m.wasm, task_duration_s: m.task?.toFixed(4), script_duration_s: m.script?.toFixed(4) });
      }
    };
    let error = "";
    try {
      await sample("1 client loaded");
      await runAssignment(a, [11, 22], { afterSetup: () => sample("2 keys generated") });
      await sample("3 result shown");
    } catch (e) { error = String(e.message || e); }
    for (const [role, tab] of [["police", a.police], ["user", a.userTab]]) {
      for (const [start, dur] of await tab.eval("window.__lt || []")) rowL({ experiment: "e9_longtasks", rep, role, start_ms: start.toFixed(1), duration_ms: dur.toFixed(1) });
    }
    await closeAll([a]); await dash.close(); await udash.close();
    console.log(`profile rep ${rep}: ${a.text || ""} ${error}`);
  }
}

// ---------------------------------------------------------------- E9: load time, cold and warm cache
async function load(reps) {
  const row = openCsv("e9_browser_load.csv", ["experiment", "series", "run_id", "wasm_transfer_bytes", "wasm_decoded_bytes", "fetch_ms", "instantiate_streaming_ms",
    "compile_instantiate_ms", "ready_ms", "wasm_memory_bytes", "chrome_version"]);
  const base = await startApi();
  const dash = await login("police", base);
  await login("carlos", base);
  const [a] = await createAssignments(dash, ["carlos"], 1);
  const tab = await authedTab("police", base);
  const once = async (series, i) => {
    if (series === "cold") await tab.send("Network.clearBrowserCache");
    await tab.goto(`${base}/crypto.html?target=${a.targetId}`);
    await tab.until("window.__wasm && __wasm.ready > 0", "WASM ready");
    const m = await tab.eval(`(() => { const e = performance.getEntriesByType("resource").find(x => x.name.endsWith("/party.wasm")) || {};
      return { transfer: e.transferSize, decoded: e.decodedBodySize, fetch: e.responseEnd - e.startTime, total: __wasm.t1 - __wasm.t0, ready: __wasm.ready - __wasm.t0, mem: __wasm.inst.exports.mem.buffer.byteLength }; })()`);
    if (i >= 0) row({ experiment: "e9_browser_load", series, run_id: i, wasm_transfer_bytes: m.transfer, wasm_decoded_bytes: m.decoded, fetch_ms: m.fetch?.toFixed(2),
      instantiate_streaming_ms: m.total.toFixed(2), compile_instantiate_ms: (m.total - (m.fetch || 0)).toFixed(2), ready_ms: m.ready.toFixed(2),
      wasm_memory_bytes: m.mem, chrome_version: browsers.police.version });
  };
  for (const series of ["cold", "warm"]) {
    for (let i = -3; i < reps; i++) await once(series, i); // 3 warm-up loads discarded
    console.log(`load ${series}: ${reps} runs`);
  }
}

// ---------------------------------------------------------------- E13: robustness
async function robust() {
  const row = openCsv("e13_robustness.csv", ["experiment", "scenario", "expected", "observed", "ok", "detail"]);
  const record = (scenario, expected, observed, ok, detail = "") => { row({ experiment: "e13", scenario, expected, observed, ok, detail }); console.log(`robust ${scenario}: ${observed} ok=${ok} ${detail}`); };
  const fresh = async () => {
    const base = await startApi();
    const dash = await login("police", base);
    await login("carlos", base);
    const [a] = await createAssignments(dash, ["carlos"], 1);
    await openAssignment(a, base);
    return { base, dash, a };
  };
  const startBoth = async a => {
    await a.police.eval("document.getElementById('initBtn').click()");
    await a.userTab.eval("document.getElementById('initBtn').click()");
    await a.police.until("!document.getElementById('sendBtn').disabled", "CPK/RLK ready");
  };

  // (a) The User disappears before answering the oblivious transfer; (b) it comes back.
  try {
    const { base, a } = await fresh();
    await startBoth(a);
    await a.police.eval(setPoint(10, 20));
    await a.userTab.until("!document.getElementById('sendBtn').disabled", "police input stored");
    await a.userTab.eval(setPoint(11, 22));
    await a.userTab.until("state().then(s => !!(s.gcMessages && s.gcMessages.otA))", "otA published", 60000, 20);
    const before = await a.userTab.eval("state().then(s => s.gcMessages)");
    await a.userTab.close();
    await sleep(15000);
    const st = await a.police.eval("state().then(s => s.gcMessages)");
    const text = (await a.police.eval("document.getElementById('result').textContent")).trim();
    const stuck = !st.otE && !/RADIO|LIMITE/.test(text);
    if (before.otE) record("missing_ot_response", "assignment stays pending", "not testable: the User answered before the tab could be closed", false, JSON.stringify(before));
    else record("missing_ot_response", "assignment stays pending, no class, no crash", stuck ? "pending after 15 s without the User" : "completed anyway", stuck, `otR=${!!st.otR} otE=${!!st.otE}; police page: ${text}`);

    a.userTab = await authedTab("carlos", base);
    await a.userTab.goto(`${base}/crypto.html?target=${a.targetId}`);
    await a.police.until(RESULT, "result after the User returned", 60000);
    const final = (await a.police.eval("document.getElementById('result').textContent")).trim();
    const log = await a.userTab.eval("document.getElementById('log').textContent");
    record("user_reopens_page", "state restored from IndexedDB, protocol completes with DENTRO DEL RADIO", final, final === "DENTRO DEL RADIO",
      /restaurado desde IndexedDB/.test(log) ? "user log: state restored from IndexedDB" : "restore message not found in the user log");
    await closeAll([a]);
  } catch (e) { record("missing_ot_response", "assignment stays pending", "error", false, String(e.message || e)); }

  // (c) Police reloads the page after key generation, before sending its input.
  try {
    const { a } = await fresh();
    await startBoth(a);
    await a.police.send("Page.reload");
    await sleep(500);
    await a.police.until("!document.getElementById('sendBtn').disabled", "police restored after reload");
    const log = await a.police.eval("document.getElementById('log').textContent");
    await a.police.eval(setPoint(10, 20));
    await a.userTab.until("!document.getElementById('sendBtn').disabled", "police input stored");
    await a.userTab.eval(setPoint(14, 24));
    await a.police.until(RESULT, "result");
    const final = (await a.police.eval("document.getElementById('result').textContent")).trim();
    record("police_reload_after_keygen", "same key share restored, protocol completes with FUERA DEL RADIO", final, final === "FUERA DEL RADIO",
      /restaurado desde IndexedDB/.test(log) ? "police log: state restored from IndexedDB" : "restore message not found in the police log");
    await closeAll([a]);
  } catch (e) { record("police_reload_after_keygen", "protocol completes", "error", false, String(e.message || e)); }

  // (d) A modified client skips the range check of crypto.js and encrypts x = 200.
  try {
    const { a } = await fresh();
    await startBoth(a);
    await a.police.eval(setPoint(10, 20));
    await a.userTab.until("!document.getElementById('sendBtn').disabled", "police input stored");
    const sent = await a.userTab.eval(`(async () => {
      try {
        const enc = wasmCall({ op: "encryptPoint", cpk, x: 200, y: 20 });
        await api("/api/sessions/" + sessionId + "/input", { method: "POST", body: JSON.stringify({ role, ctX: enc.ctX, ctY: enc.ctY, crsSeed: currentCRSSeed }) });
        inputSent = true;
        return "accepted";
      } catch (e) { return "rejected: " + e.message; }
    })()`);
    if (sent !== "accepted") record("out_of_range_input", "unknown (measured)", sent, true, "the modified client was stopped; true delta would be 36075");
    else {
      await a.police.until(RESULT, "result");
      const final = (await a.police.eval("document.getElementById('result').textContent")).trim();
      record("out_of_range_input", "true class is FUERA DEL RADIO (delta = 190^2 - 25 = 36075)", final, final === "FUERA DEL RADIO",
        "server accepted the ciphertexts; 36075 exceeds 32768, so the circuit sees 36075 - 65537 = -29462");
    }
    await closeAll([a]);
  } catch (e) { record("out_of_range_input", "measured outcome", "error", false, String(e.message || e)); }
}

// ---------------------------------------------------------------- main
const [mode, repsArg] = process.argv.slice(2);
const reps = Number(repsArg || { heat: 5, profile: 10, load: 30 }[mode] || 1);
process.on("exit", shutdown);
try {
  await startBrowsers(Object.keys(ACCOUNTS));
  if (mode === "heat") await heat(reps);
  else if (mode === "profile") await profile(reps);
  else if (mode === "load") await load(reps);
  else if (mode === "robust") await robust();
  else throw new Error("usage: node bench/browser_bench.mjs heat|profile|load|robust [reps]");
  console.log(`${mode} done (${browsers.police.version})`);
  process.exit(0);
} catch (e) { console.error(e); process.exit(2); }

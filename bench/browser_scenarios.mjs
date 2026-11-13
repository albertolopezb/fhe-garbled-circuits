// The four browser scenarios (three classes + the quota error), driven in a
// real headless Chrome through the DevTools protocol, with a screenshot of each.
//
// Usage (API already running, see bench/browser_scenarios.sh):
//   node bench/browser_scenarios.mjs http://127.0.0.1:8090 9333 paper/figures results/e1_browser.csv
//
// Police and User run in two tabs of one browser profile; each tab has its own
// sessionStorage token, exactly like the demo. The script only presses the
// buttons a person would press and calls the page's own tick() to avoid
// waiting for the one-second timer. It uses no npm packages.
import { writeFile, mkdir } from "node:fs/promises";

const [base, port, shotDir, csvPath] = process.argv.slice(2);
const sleep = ms => new Promise(r => setTimeout(r, ms));

class Tab {
  static async open(port) {
    const info = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: "PUT" })).json();
    const tab = new Tab();
    tab.ws = new WebSocket(info.webSocketDebuggerUrl);
    tab.next = 1;
    tab.pending = new Map();
    await new Promise((res, rej) => { tab.ws.onopen = res; tab.ws.onerror = rej; });
    tab.ws.onmessage = ev => {
      const msg = JSON.parse(ev.data);
      const p = tab.pending.get(msg.id);
      if (p) { tab.pending.delete(msg.id); msg.error ? p.rej(new Error(msg.error.message)) : p.res(msg.result); }
    };
    await tab.send("Page.enable");
    await tab.send("Runtime.enable");
    await tab.send("Emulation.setDeviceMetricsOverride", { width: 1100, height: 1250, deviceScaleFactor: 1, mobile: false });
    // The reset button uses confirm(); nothing here should open a dialog, but never block on one.
    return tab;
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
  async goto(url) {
    await this.send("Page.navigate", { url });
    await sleep(300);
  }
  async until(expression, what, timeoutMs = 60000) {
    const end = Date.now() + timeoutMs;
    while (Date.now() < end) {
      try { if (await this.eval(expression)) return; } catch (_) { /* page still loading */ }
      await sleep(200);
    }
    throw new Error("timeout waiting for " + what);
  }
  async shot(path) {
    const r = await this.send("Page.captureScreenshot", { format: "png" });
    await writeFile(path, Buffer.from(r.data, "base64"));
  }
}

const tickBoth = async (...tabs) => { for (const t of tabs) { try { await t.eval("typeof tick === 'function' ? tick() : null"); } catch (_) {} } };

async function scenario(police, user, s, suspectId) {
  // Police creates a case for this one user and opens the protocol page.
  await police.goto(`${base}/police-dashboard.html`);
  await police.until("typeof api === 'function' && location.pathname === '/police-dashboard.html'", "police dashboard");
  const title = `Paper scenario ${s.id} (${Date.now()})`;
  await police.eval(`api("/api/police/cases", { method: "POST", body: JSON.stringify({ title: ${JSON.stringify(title)}, radius: ${s.r}, suspectIds: [${suspectId}] }) }).then(() => true)`);
  const targetId = await police.eval(`api("/api/police/cases").then(d => d.cases.find(c => c.title === ${JSON.stringify(title)}).targets[0].id)`);

  await police.goto(`${base}/crypto.html?target=${targetId}`);
  await police.until("!document.getElementById('initBtn').disabled", "police WASM ready");
  await police.eval("document.getElementById('initBtn').click()");
  await user.goto(`${base}/crypto.html?target=${targetId}`);
  await user.until("!document.getElementById('initBtn').disabled", "user WASM ready");
  await user.eval("document.getElementById('initBtn').click()");

  const setPoint = (x, y) => `document.getElementById('x').value = ${x}; document.getElementById('y').value = ${y}; document.getElementById('sendBtn').click(); true`;
  const waitFor = async (tab, expr, what) => {
    const end = Date.now() + 90000;
    while (Date.now() < end) {
      await tickBoth(police, user);
      if (await tab.eval(expr)) return;
      await sleep(250);
    }
    throw new Error("timeout waiting for " + what);
  };
  await waitFor(police, "!document.getElementById('sendBtn').disabled", "CPK/RLK ready (police)");
  await police.eval(setPoint(s.px, s.py));
  await waitFor(user, "!document.getElementById('sendBtn').disabled", "police input stored");
  await user.eval(setPoint(s.ux, s.uy));

  // Either the Police page shows a class, or one of the pages shows an error.
  const done = "(() => { const r = document.getElementById('result'); return /RADIO|LIMITE/.test(r.textContent) || r.classList.contains('error'); })()";
  const end = Date.now() + 120000;
  let policeDone = false, userError = false;
  while (Date.now() < end && !policeDone && !userError) {
    await tickBoth(police, user);
    policeDone = await police.eval(done);
    userError = await user.eval("document.getElementById('result').classList.contains('error')");
    await sleep(250);
  }
  const policeText = (await police.eval("document.getElementById('result').textContent")).trim();
  const userText = (await user.eval("document.getElementById('result').textContent")).trim();
  await police.eval("window.scrollTo(0, 0)");
  await user.eval("window.scrollTo(0, 0)");
  await police.shot(`${shotDir}/appendix_${s.id}_police.png`);
  await user.shot(`${shotDir}/appendix_${s.id}_user.png`);
  return { targetId, policeText, userText };
}

async function main() {
  await mkdir(shotDir, { recursive: true });
  const police = await Tab.open(port);
  const user = await Tab.open(port);
  await police.goto(`${base}/demo-login.html?account=police`);
  await police.until("location.pathname === '/police-dashboard.html'", "police login");
  await user.goto(`${base}/demo-login.html?account=carlos`);
  await user.until("location.pathname === '/suspect-dashboard.html'", "user login");
  await police.until("typeof api === 'function'", "police scripts");
  const suspects = await police.eval(`api("/api/police/suspects")`);
  const list = suspects.users || suspects.suspects || Object.values(suspects).find(Array.isArray);
  const carlos = list.find(u => (u.email || u.suspectEmail) === "carlos@demo.local");

  // P = (10, 20), R = 5 in all four; the fourth is a fourth evaluation of the same pair.
  const scenarios = [
    { id: "1_inside", px: 10, py: 20, ux: 11, uy: 22, r: 5, delta: -20, expect: "DENTRO DEL RADIO" },
    { id: "2_boundary", px: 10, py: 20, ux: 13, uy: 24, r: 5, delta: 0, expect: "EXACTAMENTE EN EL LIMITE" },
    { id: "3_outside", px: 10, py: 20, ux: 14, uy: 24, r: 5, delta: 7, expect: "FUERA DEL RADIO" },
    { id: "4_quota", px: 10, py: 20, ux: 11, uy: 22, r: 5, delta: -20, expect: "QUOTA ERROR" },
  ];
  const rows = ["experiment,scenario,px,py,ux,uy,r,delta_true,expected,police_page_text,user_page_text,ok,error,chrome_version"];
  const version = (await (await fetch(`http://127.0.0.1:${port}/json/version`)).json()).Browser;
  let failures = 0;
  for (const s of scenarios) {
    let out = { policeText: "", userText: "" }, error = "";
    try { out = await scenario(police, user, s, carlos.id); } catch (e) { error = String(e.message || e); }
    const quotaSeen = /l[ií]mite de tres evaluaciones/i.test(out.policeText + " " + out.userText);
    const ok = error === "" && (s.expect === "QUOTA ERROR" ? quotaSeen : out.policeText === s.expect);
    if (!ok) failures++;
    const q = v => `"${String(v).replaceAll('"', '""')}"`;
    rows.push([ "e1_browser", s.id, s.px, s.py, s.ux, s.uy, s.r, s.delta, q(s.expect), q(out.policeText), q(out.userText), ok, q(error), q(version) ].join(","));
    console.log(`${s.id}: expected ${s.expect} | police page: ${out.policeText} | user page: ${out.userText} | ok=${ok} ${error}`);
  }
  await writeFile(csvPath, rows.join("\n") + "\n");
  console.log(`wrote ${csvPath} and screenshots in ${shotDir}; ${failures} scenario(s) failed`);
  process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(2); });

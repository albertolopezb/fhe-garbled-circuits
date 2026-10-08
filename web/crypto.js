const targetId = new URLSearchParams(location.search).get("target");
const initBtn = document.getElementById("initBtn");
const resetBtn = document.getElementById("resetBtn");
const sendBtn = document.getElementById("sendBtn");
const logEl = document.getElementById("log");
const sessionStatus = document.getElementById("sessionStatus");
const cryptoStatus = document.getElementById("cryptoStatus");
const resultEl = document.getElementById("result");

let role = "";
let sessionId = "";
let radius = 0;
let context;
let currentCRSSeed = "";
let localInitialized = false;
let r2Sent = false;
let cpk = "";
let inputSent = false;
let pcksSent = false;
let outputDecrypted = false;
let ticking = false;

function log(line = "") {
  logEl.textContent += line + "\n";
  logEl.scrollTop = logEl.scrollHeight;
}

function wasmCall(payload) {
  if (typeof window.partyCall !== "function") throw new Error("party.wasm todavía no está listo");
  const out = JSON.parse(window.partyCall(JSON.stringify(payload)));
  if (!out.ok) throw new Error(out.error || "Error dentro de party.wasm");
  return out;
}

async function loadWasm() {
  const go = new Go();
  let result;
  if (WebAssembly.instantiateStreaming) {
    result = await WebAssembly.instantiateStreaming(fetch("/party.wasm"), go.importObject);
  } else {
    const bytes = await (await fetch("/party.wasm")).arrayBuffer();
    result = await WebAssembly.instantiate(bytes, go.importObject);
  }
  go.run(result.instance);
  for (let i = 0; i < 100; i++) {
    if (typeof window.partyCall === "function") return;
    await new Promise(r => setTimeout(r, 20));
  }
  throw new Error("partyCall no apareció después de cargar WASM");
}

async function state() {
  return api(`/api/sessions/${encodeURIComponent(sessionId)}`);
}

const CRYPTO_DB_NAME = "private-proximity-local";
const CRYPTO_DB_VERSION = 1;
const CRYPTO_STORE = "cryptoStates";
let cryptoDBPromise;

function cryptoRecordId() {
  return `${sessionId}:${role}`;
}

function openCryptoDB() {
  if (cryptoDBPromise) return cryptoDBPromise;
  cryptoDBPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(CRYPTO_DB_NAME, CRYPTO_DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(CRYPTO_STORE)) {
        db.createObjectStore(CRYPTO_STORE, { keyPath: "id" });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error("No pude abrir IndexedDB"));
  });
  return cryptoDBPromise;
}

async function getLocalCryptoRecord() {
  const db = await openCryptoDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(CRYPTO_STORE, "readonly");
    const req = tx.objectStore(CRYPTO_STORE).get(cryptoRecordId());
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error || new Error("No pude leer el estado criptográfico local"));
  });
}

async function putLocalCryptoRecord(patch) {
  const db = await openCryptoDB();
  const previous = (await getLocalCryptoRecord()) || { id: cryptoRecordId() };
  const record = { ...previous, ...patch, id: cryptoRecordId(), updatedAt: Date.now() };
  return new Promise((resolve, reject) => {
    const tx = db.transaction(CRYPTO_STORE, "readwrite");
    tx.objectStore(CRYPTO_STORE).put(record);
    tx.oncomplete = () => resolve(record);
    tx.onerror = () => reject(tx.error || new Error("No pude guardar el estado criptográfico local"));
    tx.onabort = () => reject(tx.error || new Error("IndexedDB abortó el guardado"));
  });
}

async function clearLocalCryptoState() {
  const db = await openCryptoDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(CRYPTO_STORE, "readwrite");
    tx.objectStore(CRYPTO_STORE).delete(cryptoRecordId());
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error || new Error("No pude borrar el estado criptográfico local"));
  });
}

async function persistLocalState(extra = {}) {
  const exported = wasmCall({ op: "exportState" });
  await putLocalCryptoRecord({
    localState: exported.localState,
    crsSeed: currentCRSSeed,
    ...extra,
  });
}

function syncFlagsFromServer(st) {
  r2Sent = r2Sent || !!st.r2Submitted?.[role];
  inputSent = inputSent || !!st.inputSubmitted?.[role];
  pcksSent = pcksSent || !!st.pcksSubmitted?.[role];
  if (inputSent) sendBtn.disabled = true;
}

async function restoreLocalCrypto(st) {
  const record = await getLocalCryptoRecord();

  if (record?.localState && record.crsSeed && record.crsSeed !== st.crsSeed) {
    await clearLocalCryptoState();
    log("[LOCAL] La sesión criptográfica fue reiniciada. El estado local anterior se descartó.");
    return false;
  }

  if (!record?.localState) return false;

  wasmCall({ op: "importState", localState: record.localState });
  localInitialized = true;
  initBtn.disabled = true;
  syncFlagsFromServer(st);
  log("[LOCAL] Estado criptográfico restaurado desde IndexedDB local del navegador.");
  log("[PRIVACIDAD] El estado local nunca fue enviado a la API ni guardado en SQLite.");

  if (!st.setupSubmitted?.[role]) {
    if (!record.setupBody) {
      throw new Error("Hay una llave local restaurada, pero falta la share inicial. Reinicia esta sesión criptográfica.");
    }
    await api(`/api/sessions/${sessionId}/setup/share`, {
      method: "POST",
      body: record.setupBody,
    });
    log("[RECOVERY] Reenvié las shares públicas de setup que estaban pendientes.");
  }

  if (role === "police" && !st.pkOutReady && record.pkOutBody) {
    await api(`/api/sessions/${sessionId}/output-key`, {
      method: "POST",
      body: record.pkOutBody,
    });
    log("[RECOVERY] Reenvié pk_out; sk_out permaneció local.");
  }

  cryptoStatus.className = "status ok";
  cryptoStatus.textContent = "Estado criptográfico local restaurado. Puedes continuar sin generar otra secret key.";
  return true;
}

async function initializeLocalCrypto() {
  initBtn.disabled = true;
  try {
    const st = await state();
    currentCRSSeed = st.crsSeed;

    if (st.setupSubmitted?.[role]) {
      throw new Error("Esta sesión ya tiene una secret key registrada para este rol. Usa la pestaña original o reinicia la sesión criptográfica.");
    }

    const init = wasmCall({ op: "init", role, crsSeed: st.crsSeed });
    localInitialized = true;
    const setupBody = JSON.stringify({ role, ckgShare: init.ckgShare, rkgR1: init.rkgR1 });
    await persistLocalState({ setupBody });

    log("[LOCAL] Secret key generada dentro de este navegador.");
    log("[LOCAL] Se conserva solo en IndexedDB local para sobrevivir navegación/recarga; NO se envía a la API.");
    log("[CPK] CKG share y RKG round 1 generadas localmente.");

    await api(`/api/sessions/${sessionId}/setup/share`, {
      method: "POST",
      body: setupBody,
    });
    log("[API] Recibió únicamente shares públicas de setup.");

    if (role === "police") {
      const out = wasmCall({ op: "generateOutputKey" });
      // sk_out cambió el estado local: persistir ANTES del request HTTP.
      const pkBody = JSON.stringify({ role, pkOut: out.pkOut });
      await persistLocalState({ pkOutBody: pkBody });
      await api(`/api/sessions/${sessionId}/output-key`, {
        method: "POST",
        body: pkBody,
      });
      log("[LOCAL] sk_out permanece local; solo pk_out fue registrada.");
    }

    cryptoStatus.className = "status ok";
    cryptoStatus.textContent = "Secret key local creada. Esperando completar CPK/RLK con la otra parte…";
    resetBtn.hidden = false;
    await tick();
  } catch (err) {
    cryptoStatus.className = "status error";
    cryptoStatus.textContent = err.message;
    log(`[ERROR] ${err.message}`);
    resetBtn.hidden = false;
    initBtn.disabled = localInitialized || false;
  }
}

async function advanceSetup(st) {
  if (!localInitialized) return;
  syncFlagsFromServer(st);

  if (st.round1Ready && !r2Sent) {
    const artifacts = await api(`/api/sessions/${sessionId}/setup/artifacts`);
    cpk = artifacts.cpk;
    const r2 = wasmCall({ op: "rkgRound2", r1Combined: artifacts.r1Combined });
    await api(`/api/sessions/${sessionId}/setup/r2`, {
      method: "POST",
      body: JSON.stringify({ role, rkgR2: r2.rkgR2 }),
    });
    r2Sent = true;
    log("[RLK] Round 2 generada con la secret key local y enviada como share.");
  }

  if (st.setupReady) {
    if (!cpk) {
      const artifacts = await api(`/api/sessions/${sessionId}/setup/artifacts`);
      cpk = artifacts.cpk;
    }
    cryptoStatus.className = "status ok";
    cryptoStatus.textContent = "Collective Public Key y Collective RLK listas.";
    if (!inputSent) sendBtn.disabled = false;
  }
}

async function sendEncryptedInput() {
  if (!cpk || !localInitialized) return;
  sendBtn.disabled = true;
  try {
    const x = Number(document.getElementById("x").value);
    const y = Number(document.getElementById("y").value);
    if (!Number.isInteger(x) || !Number.isInteger(y)) throw new Error("Las coordenadas deben ser enteros");

    const enc = wasmCall({ op: "encryptPoint", cpk, x, y });
    const payload = { role, ctX: enc.ctX, ctY: enc.ctY };
    if (role === "police") payload.radius = radius;

    await api(`/api/sessions/${sessionId}/input`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    inputSent = true;
    log("[INPUT] Coordenadas cifradas localmente bajo la CPK.");
    log("[API] Recibió ctX/ctY; no recibió las coordenadas en claro.");
    resultEl.textContent = "Ciphertexts enviados. Esperando a la otra parte y la evaluación homomórfica…";
    await tick();
  } catch (err) {
    log(`[ERROR INPUT] ${err.message}`);
    resultEl.className = "status error";
    resultEl.textContent = err.message;
    sendBtn.disabled = false;
  }
}

async function maybeSendPCKS(st) {
  syncFlagsFromServer(st);
  if (!localInitialized || pcksSent || !st.deltaReady || !st.pkOutReady) return;

  log("[SERVER] Evaluación homomórfica terminada: Enc(dx), Enc(dy), Enc(D²) y Enc(Δ) listos.");
  log("[SERVER] Ningún valor intermedio fue revelado en claro.");

  const d = await api(`/api/sessions/${sessionId}/delta`);
  const share = wasmCall({ op: "pcksShare", ctDelta: d.ctDelta, pkOut: d.pkOut });
  await api(`/api/sessions/${sessionId}/pcks`, {
    method: "POST",
    body: JSON.stringify({ role, pcksShare: share.pcksShare }),
  });
  pcksSent = true;
  log("[PCKS] Share generada con la secret key local y enviada a la API.");
}

async function maybeDecryptOutput(st) {
  if (role !== "police" || outputDecrypted || !st.outputReady) return;
  const out = await api(`/api/sessions/${sessionId}/output`);
  const final = wasmCall({ op: "decryptOutput", ctOut: out.ctOut });
  outputDecrypted = true;
  resultEl.className = "status ok";
  resultEl.textContent = final.classification;
  log("[POLICE LOCAL] Ciphertext final descifrado con sk_out.");
  log(`[RESULTADO] ${final.classification}. Δ no se muestra ni se guarda en la base de datos.`);

  await api(`/api/targets/${targetId}/result`, {
    method: "POST",
    body: JSON.stringify({ classification: final.classification }),
  });
}

function updateStatus(st) {
  const phase = st.outputReady ? "salida lista" : st.deltaReady ? "evaluación lista" : st.setupReady ? "setup listo" : "setup en progreso";
  sessionStatus.textContent = `Sesión activa · ${phase} · servidor con secret keys: NO`;

  if (!st.setupReady && localInitialized) {
    const otherRole = role === "police" ? "suspect" : "police";
    const otherLabel = role === "police" ? context.target.suspectName : "Policía";
    const mineReady = !!st.setupSubmitted?.[role];
    const otherReady = !!st.setupSubmitted?.[otherRole];
    if (mineReady && !otherReady) {
      cryptoStatus.className = "status ok";
      cryptoStatus.textContent = `Tu parte del setup ya está lista. Esperando a ${otherLabel} para construir CPK/RLK…`;
    } else if (mineReady && otherReady && !st.setupReady) {
      cryptoStatus.className = "status ok";
      cryptoStatus.textContent = "Ambas shares iniciales están listas. Completando RKG round 2…";
    }
  }
}

async function tick() {
  if (ticking || !sessionId) return;
  ticking = true;
  try {
    const st = await state();

    // Si la otra parte reinició la sesión, el CRS cambia. La memoria WASM vieja ya no sirve.
    if (currentCRSSeed && st.crsSeed !== currentCRSSeed) {
      await clearLocalCryptoState();
      log("[RESET] Detecté que la sesión fue reiniciada. Recargando estado local…");
      location.reload();
      return;
    }

    currentCRSSeed = st.crsSeed;
    syncFlagsFromServer(st);
    updateStatus(st);
    await advanceSetup(st);
    const st2 = await state();
    syncFlagsFromServer(st2);
    await maybeSendPCKS(st2);
    const st3 = await state();
    syncFlagsFromServer(st3);
    await maybeDecryptOutput(st3);
  } catch (err) {
    log(`[POLL] ${err.message}`);
  } finally {
    ticking = false;
  }
}

function configureUI(u) {
  userName.textContent = u.displayName;
  roleBadge.textContent = role === "police" ? "Cliente Policía" : "Cliente Usuario";
  pageTitle.textContent = role === "police" ? "Escena del crimen" : "Ubicación privada";
  pageSubtitle.textContent = role === "police"
    ? `Protocolo con ${context.target.suspectName}. La ubicación de la escena se cifra localmente.`
    : `Solicitud de ${context.target.policeName}. Tu ubicación no se envía en claro.`;
  caseName.textContent = context.target.caseTitle;
  otherName.textContent = context.otherPartyName;
  radiusText.textContent = `R = ${context.target.radius}`;
  radius = context.target.radius;
  backLink.href = role === "police" ? "/police-dashboard.html" : "/suspect-dashboard.html";

  if (role === "police") {
    inputTitle.textContent = "2. Cifrar escena del crimen";
    xLabel.firstChild.textContent = "Px ";
    yLabel.firstChild.textContent = "Py ";
    x.value = 10; y.value = 20;
  } else {
    inputTitle.textContent = "2. Cifrar mi ubicación";
    xLabel.firstChild.textContent = "Qx ";
    yLabel.firstChild.textContent = "Qy ";
    x.value = 12; y.value = 21;
    resultEl.textContent = "El resultado final se entrega únicamente a la vista de Policía.";
  }
}

async function boot() {
  if (!targetId) throw new Error("Falta ?target=... en la URL");
  const u = await me();
  context = await api(`/api/targets/${targetId}/context`);
  role = context.role;
  sessionId = context.target.cryptoSession;
  configureUI(u);

  const st = await state();
  currentCRSSeed = st.crsSeed;
  await loadWasm();

  log(`[AUTH] ${u.displayName} autenticado como ${role}.`);
  log("[BOOT] La API coordina material público, shares y ciphertexts.");
  log("[PRIVACIDAD] La consola omite coordenadas, secret keys, D² y Δ.");

  const restored = await restoreLocalCrypto(st);
  if (!restored) {
    if (st.setupSubmitted?.[role]) {
      cryptoStatus.className = "status error";
      cryptoStatus.textContent = "La API ya tiene una share de este rol, pero esta pestaña no tiene la secret key correspondiente. Esto ocurre al abrir la misma sesión desde otra pestaña o después de perder el estado local.";
      initBtn.disabled = true;
      resetBtn.hidden = false;
      log("[RECOVERY] El servidor conserva una share, pero esta pestaña no conserva la secret key que la creó.");
      log("[RECOVERY] Usa la pestaña original o pulsa ‘Reiniciar sesión criptográfica’. ");
    } else {
      cryptoStatus.textContent = "party.wasm listo. Aún no se ha generado ninguna secret key para esta sesión.";
      initBtn.disabled = false;
    }
  } else {
    resetBtn.hidden = false;
  }

  setInterval(tick, 1000);
  await tick();
}

async function resetCryptoSession() {
  if (!confirm("Esto reiniciará CPK/RLK, inputs y PCKS de esta pareja. Ambas partes tendrán que generar nuevamente su estado local. ¿Continuar?")) return;
  resetBtn.disabled = true;
  try {
    await api(`/api/sessions/${sessionId}/reset`, { method: "POST", body: "{}" });
    await clearLocalCryptoState();
    log("[RESET] Sesión criptográfica reiniciada.");
    location.reload();
  } catch (err) {
    resetBtn.disabled = false;
    log(`[RESET ERROR] ${err.message}`);
    cryptoStatus.className = "status error";
    cryptoStatus.textContent = err.message;
  }
}

toggleConsole.onclick = () => {
  consolePanel.hidden = !consolePanel.hidden;
  toggleConsole.textContent = consolePanel.hidden ? "Ver consola" : "Ocultar consola";
};
initBtn.addEventListener("click", initializeLocalCrypto);
sendBtn.addEventListener("click", sendEncryptedInput);
resetBtn.addEventListener("click", resetCryptoSession);

boot().catch(err => {
  sessionStatus.className = "status error";
  sessionStatus.textContent = err.message;
  log(`[BOOT ERROR] ${err.message}`);
});

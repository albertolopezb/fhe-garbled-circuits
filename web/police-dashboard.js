const caseList = document.getElementById("caseList");
const createCard = document.getElementById("createCard");
const checklist = document.getElementById("suspectChecklist");
const createStatus = document.getElementById("createStatus");
let currentUser;
const caseMetrics = document.getElementById("caseMetrics");
const mapPreferences = new Map();
let lastCases = null;
const deleteDialog = document.getElementById("deleteCaseDialog");
const deleteForm = document.getElementById("deleteCaseForm");
const deleteName = document.getElementById("deleteCaseName");
const deleteError = document.getElementById("deleteCaseError");
const cancelDelete = document.getElementById("cancelDeleteCase");
const confirmDelete = document.getElementById("confirmDeleteCase");

async function loadPolice() {
  currentUser = await me();
  if (currentUser.role !== "police") return location.href = "/suspect-dashboard.html";
  userName.textContent = currentUser.displayName;
  logoutBtn.onclick = logout;
  await Promise.all([loadSuspects(), loadCases()]);
  setInterval(loadCases, 2500);
}

async function loadSuspects() {
  const data = await api("/api/police/suspects");
  if (!data.users.length) {
    checklist.innerHTML = '<div class="empty">Todavía no hay usuarios registrados.</div>';
    return;
  }
  checklist.innerHTML = data.users.map(u => `
    <label class="check-row">
      <input type="checkbox" value="${u.id}" checked />
      <span><strong>${escapeHTML(u.displayName)}</strong><br><span class="muted">${escapeHTML(u.email)}</span></span>
    </label>`).join("");
}

function personRow(t) {
  return `
    <div class="person-row">
      <div class="person">
        <div class="avatar">${escapeHTML(initials(t.suspectName))}</div>
        <div class="person-meta"><strong>${escapeHTML(t.suspectName)}</strong><span>${escapeHTML(t.suspectEmail)}</span></div>
      </div>
      <div>${statusPill(t.status)}</div>
      <div>${resultPill(t.classification)}</div>
      ${t.status === "complete" ? '<span class="pill complete">Resultado guardado</span>' : `<a class="button secondary" href="/crypto.html?target=${t.id}">Abrir protocolo</a>`}
    </div>`;
}

/* ============================================================
   Mapa ilustrativo de proximidad
   IMPORTANTE: estas posiciones NO usan las coordenadas privadas.
   Solo representan visualmente DENTRO / FUERA / LÍMITE.
   ============================================================ */

function hashString(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function seededUnit(seed) {
  let x = seed >>> 0;
  x ^= x << 13;
  x ^= x >>> 17;
  x ^= x << 5;
  return (x >>> 0) / 4294967296;
}

function mapKind(target) {
  const classification = String(target.classification || "").toUpperCase();
  if (classification.includes("DENTRO")) return "inside";
  if (classification.includes("FUERA")) return "outside";
  if (classification.includes("LIMITE") || classification.includes("LÍMITE")) return "boundary";
  if (target.status === "processing") return "processing";
  return "pending";
}

function mapStatusLabel(kind) {
  return {
    inside: "DENTRO",
    outside: "FUERA",
    boundary: "LÍMITE",
    processing: "EN PROCESO",
    pending: "PENDIENTE",
  }[kind] || "PENDIENTE";
}

function visualPosition(caseData, target, index, centerX, centerY, radius) {
  const kind = mapKind(target);
  if (!["inside", "outside", "boundary"].includes(kind)) return null;

  // La semilla usa únicamente identificadores/resultado; nunca Px/Py/Qx/Qy.
  const seed = hashString(`${caseData.id || caseData.title}-${target.id || target.suspectName}-${kind}`);
  const angle = (seededUnit(seed + 17) * Math.PI * 2) + (index * 0.67);

  let distance;
  if (kind === "inside") {
    distance = radius * (0.32 + seededUnit(seed + 53) * 0.43); // 0.32R..0.75R
  } else if (kind === "outside") {
    distance = radius * (1.22 + seededUnit(seed + 89) * 0.24); // 1.22R..1.46R
  } else {
    distance = radius;
  }

  return {
    kind,
    x: centerX + Math.cos(angle) * distance,
    y: centerY + Math.sin(angle) * distance,
  };
}

function mapColors(kind) {
  // Consistente con los pills actuales: dentro = alerta roja, fuera = verde.
  if (kind === "inside") return { fill: "#f2635e", stroke: "#9f4948" };
  if (kind === "outside") return { fill: "#4fb58a", stroke: "#387b61" };
  return { fill: "#e9a23b", stroke: "#956724" };
}

function renderCaseMap(caseData, mapOpen) {
  const targets = caseData.targets || [];
  const width = 760;
  const height = 440;
  const centerX = 355;
  const centerY = 215;
  const radius = 116;

  const completed = targets.filter(t => ["inside", "outside", "boundary"].includes(mapKind(t)));
  const counts = targets.reduce((acc, t) => {
    acc[mapKind(t)] += 1;
    return acc;
  }, { inside: 0, outside: 0, boundary: 0, processing: 0, pending: 0 });

  const peopleSvg = completed.map((target, index) => {
    const pos = visualPosition(caseData, target, index, centerX, centerY, radius);
    if (!pos) return "";
    const colors = mapColors(pos.kind);
    const name = escapeHTML(target.suspectName || "Usuario");
    const shortName = escapeHTML((target.suspectName || "Usuario").split(/\s+/)[0]);
    const labelInitials = escapeHTML(initials(target.suspectName || "?"));

    return `
      <g class="map-person-node" transform="translate(${pos.x.toFixed(1)}, ${pos.y.toFixed(1)})" aria-label="${name}: ${mapStatusLabel(pos.kind)}">
        <circle class="map-person-halo" cx="0" cy="0" r="27" fill="${colors.fill}" opacity="0.12"></circle>
        <circle cx="0" cy="0" r="20" fill="${colors.fill}" stroke="${colors.stroke}" stroke-width="3"></circle>
        <text x="0" y="5" text-anchor="middle" font-size="10.5" font-weight="800" fill="#17171b">${labelInitials}</text>
        <rect x="-38" y="27" width="76" height="22" rx="11" fill="#17171b" stroke="#3a3a40"></rect>
        <text x="0" y="42" text-anchor="middle" font-size="11" font-weight="700" fill="#f2f2f3">${shortName}</text>
      </g>`;
  }).join("");

  const emptyText = completed.length === 0
    ? `<g><text x="${centerX}" y="${centerY + radius + 72}" text-anchor="middle" font-size="13" fill="#a5a5ad">Los usuarios aparecerán cuando exista una clasificación.</text></g>`
    : "";

  const svg = `
    <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Representación ilustrativa del radio de proximidad">
      <defs>
        <pattern id="grid-${caseData.id}" width="32" height="32" patternUnits="userSpaceOnUse">
          <path d="M 32 0 L 0 0 0 32" fill="none" stroke="#3a3a40" stroke-width="1" opacity="0.45"></path>
        </pattern>
      </defs>
      <rect x="0" y="0" width="${width}" height="${height}" rx="18" fill="#0d0d0f"></rect>
      <rect x="0" y="0" width="${width}" height="${height}" rx="18" fill="url(#grid-${caseData.id})"></rect>

      <g fill="none" stroke="#333238" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M-20 310 95 272 165 258 232 268 312 295 382 314 452 304 541 266 636 252 780 278" stroke-width="12" opacity=".36"></path>
        <path d="M-10 100 95 93 177 110 258 80 356 86 475 45 623 53 782 12 M-8 224 95 207 181 216 280 185 384 192 502 167 626 181 784 148 M-12 378 82 359 175 369 291 342 402 362 524 347 649 315 777 323" stroke-width="4"></path>
        <path d="M55-10 77 55 95 93 109 170 95 207 95 272 82 359 87 455 M170-10 164 53 177 110 195 164 181 216 165 258 175 369 156 455 M302-12 279 46 258 80 268 138 280 185 277 259 291 342 307 455 M414-16 400 46 394 76 379 141 384 192 398 257 382 314 402 362 436 456 M545-15 538 48 519 110 502 167 513 216 541 266 524 347 546 455 M658-15 623 53 631 115 626 181 636 252 649 315 686 455" stroke-width="3"></path>
        <path d="M109 170 195 164 268 138 379 141 519 110 631 115 779 88 M-10 165 109 170 M277 259 398 257 513 216 632 220 784 213 M180 404 306 411 419 405 532 396 668 392 781 365" stroke-width="2" opacity=".7"></path>
      </g>
      <circle cx="${centerX}" cy="${centerY}" r="${radius + 12}" fill="#a87ef5" opacity="0.045"></circle>
      <circle cx="${centerX}" cy="${centerY}" r="${radius}" fill="#a87ef5" fill-opacity="0.075" stroke="#a87ef5" stroke-width="3" stroke-dasharray="9 8"></circle>

      <g class="crime-scene-node">
        <circle cx="${centerX}" cy="${centerY}" r="24" fill="#241c32" stroke="#a87ef5" stroke-width="2"></circle>
        <text x="${centerX}" y="${centerY + 6}" text-anchor="middle" font-size="20" fill="#e3d6fc">★</text>
        <rect x="${centerX - 70}" y="${centerY + 34}" width="140" height="26" rx="13" fill="#17171b" stroke="#3a3a40"></rect>
        <text x="${centerX}" y="${centerY + 52}" text-anchor="middle" font-size="12" font-weight="800" fill="#f2f2f3">ESCENA DEL CRIMEN</text>
      </g>

      <g>
        <rect x="${centerX + radius - 17}" y="${centerY - 13}" width="74" height="26" rx="13" fill="#241c32" stroke="#604387"></rect>
        <text x="${centerX + radius + 20}" y="${centerY + 5}" text-anchor="middle" font-size="12" font-weight="800" fill="#e3d6fc">R = ${escapeHTML(caseData.radius)}</text>
      </g>

      ${peopleSvg}
      ${emptyText}
    </svg>`;

  const legend = targets.map(target => {
    const kind = mapKind(target);
    return `
      <div class="legend-item">
        <div class="legend-person">
          <div class="legend-avatar">${escapeHTML(initials(target.suspectName))}</div>
          <div class="legend-copy">
            <strong>${escapeHTML(target.suspectName)}</strong>
            <span>${kind === "pending" || kind === "processing" ? "Aún no se posiciona" : "Posición ilustrativa"}</span>
          </div>
        </div>
        <span class="legend-status status-${kind}">${mapStatusLabel(kind)}</span>
      </div>`;
  }).join("");

  return `
    <section class="case-visualization" data-case-map="${caseData.id}" ${mapOpen ? "" : "hidden"}>
      <div class="map-summary-row">
        <div>
          <h3>Mapa ilustrativo de proximidad</h3>
          <p class="muted map-subtitle">El aro representa el radio público. Los iconos solo indican si cada persona quedó dentro o fuera; su posición no corresponde a su ubicación real.</p>
        </div>
        <div class="map-counts" aria-label="Resumen de resultados">
          <span class="map-count inside-count"><strong>${counts.inside}</strong> dentro</span>
          <span class="map-count outside-count"><strong>${counts.outside}</strong> fuera</span>
          <span class="map-count boundary-count"><strong>${counts.boundary}</strong> al límite</span>
          <span class="map-count pending-count"><strong>${counts.pending + counts.processing}</strong> pendientes</span>
        </div>
      </div>

      <div class="map-layout">
        <div class="case-map">${svg}</div>
        <aside class="map-legend">
          <h4>Personas del caso</h4>
          <div class="map-legend-list">${legend || '<div class="empty">Sin participantes.</div>'}</div>
          <div class="map-privacy-note">
            <span class="privacy-icon">🔒</span>
            <div><strong>Visualización protegida</strong><span>No se utilizan Px/Py ni Qx/Qy para colocar los iconos.</span></div>
          </div>
        </aside>
      </div>
    </section>`;
}

function caseCard(c, mapOpen) {
  return `
    <article class="card case-card" data-case-id="${c.id}">
      <div class="case-header">
        <div>
          <h2 style="margin-bottom:4px">${escapeHTML(c.title)}</h2>
          <span class="muted">Radio público R = ${c.radius}</span>
        </div>
        <div class="case-header-actions">
          <span class="badge">${c.targets.length} participante${c.targets.length === 1 ? "" : "s"}</span>
          <button class="secondary map-toggle" type="button" data-map-toggle="${c.id}" aria-expanded="${mapOpen}">${mapOpen ? "Ocultar mapa" : "Ver mapa ilustrativo"}</button>
          <button class="secondary danger" type="button" data-delete-case="${c.id}">Borrar caso</button>
        </div>
      </div>
      <div class="case-content ${mapOpen ? "with-map" : ""}">
        <section class="case-participants" aria-label="Participantes del caso">
          <h3>Participantes</h3>
          <div class="person-list">${c.targets.map(personRow).join("")}</div>
        </section>
        ${renderCaseMap(c, mapOpen)}
      </div>
    </article>`;
}

function updateCaseMetrics(cases) {
  const totals = { pending: 0, processing: 0, complete: 0 };
  for (const { targets } of cases) {
    for (const { status } of targets) {
      if (Object.hasOwn(totals, status)) totals[status]++;
    }
  }
  document.getElementById("metricCases").textContent = cases.length;
  document.getElementById("metricPending").textContent = totals.pending;
  document.getElementById("metricProcessing").textContent = totals.processing;
  document.getElementById("metricComplete").textContent = totals.complete;
  caseMetrics.hidden = false;
}

async function loadCases() {
  try {
    const { cases } = await api("/api/police/cases");
    const snapshot = JSON.stringify(cases);
    if (snapshot === lastCases) return;
    lastCases = snapshot;
    updateCaseMetrics(cases);
    if (!cases.length) {
      caseList.innerHTML = '<div class="empty">Todavía no hay casos. Crea el primero para comenzar.</div>';
      return;
    }

    caseList.innerHTML = cases.map((c, index) =>
      caseCard(c, mapPreferences.get(String(c.id)) ?? index === 0)
    ).join("");
  } catch (err) {
    lastCases = null;
    caseList.innerHTML = `<div class="status error">${escapeHTML(err.message)}</div>`;
  }
}

caseList.addEventListener("click", event => {
  const deleteButton = event.target.closest("[data-delete-case]");
  if (deleteButton) {
    deleteForm.dataset.caseId = deleteButton.dataset.deleteCase;
    deleteName.textContent = deleteButton.closest(".case-card").querySelector("h2").textContent;
    deleteError.hidden = true;
    deleteDialog.showModal();
    return;
  }

  const button = event.target.closest("[data-map-toggle]");
  if (!button) return;

  const id = button.dataset.mapToggle;
  const panel = caseList.querySelector(`[data-case-map="${CSS.escape(id)}"]`);
  if (!panel) return;

  panel.hidden = !panel.hidden;
  const open = !panel.hidden;
  mapPreferences.set(id, open);
  panel.closest(".case-content").classList.toggle("with-map", open);
  button.textContent = open ? "Ocultar mapa" : "Ver mapa ilustrativo";
  button.setAttribute("aria-expanded", String(open));

  if (open) panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
});

cancelDelete.onclick = () => deleteDialog.close();
deleteDialog.addEventListener("cancel", event => {
  if (confirmDelete.disabled) event.preventDefault();
});
deleteForm.addEventListener("submit", async event => {
  event.preventDefault();
  if (confirmDelete.disabled) return;
  confirmDelete.disabled = cancelDelete.disabled = true;
  deleteError.hidden = true;
  try {
    await api(`/api/police/cases/${encodeURIComponent(deleteForm.dataset.caseId)}`, { method: "DELETE" });
    mapPreferences.delete(deleteForm.dataset.caseId);
    deleteDialog.close();
    await loadCases();
  } catch (err) {
    deleteError.textContent = err.message;
    deleteError.hidden = false;
  } finally {
    confirmDelete.disabled = cancelDelete.disabled = false;
  }
});

toggleCreate.onclick = () => createCard.hidden = false;
cancelCreate.onclick = () => createCard.hidden = true;
createCaseBtn.onclick = async () => {
  const suspectIds = [...checklist.querySelectorAll('input[type="checkbox"]:checked')].map(x => Number(x.value));
  createStatus.hidden = false;
  try {
    await api("/api/police/cases", {
      method: "POST",
      body: JSON.stringify({ title: caseTitle.value, radius: Number(caseRadius.value), suspectIds }),
    });
    createStatus.className = "status ok";
    createStatus.textContent = "Caso creado. Cada persona tiene una sesión multiparty independiente.";
    await loadCases();
    setTimeout(() => { createCard.hidden = true; }, 700);
  } catch (err) {
    createStatus.className = "status error";
    createStatus.textContent = err.message;
  }
};

loadPolice().catch(err => { caseList.innerHTML = `<div class="status error">${escapeHTML(err.message)}</div>`; });

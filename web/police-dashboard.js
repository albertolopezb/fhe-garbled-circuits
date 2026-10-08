const caseList = document.getElementById("caseList");
const createCard = document.getElementById("createCard");
const checklist = document.getElementById("suspectChecklist");
const createStatus = document.getElementById("createStatus");
let currentUser;

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
      <span><strong>${u.displayName}</strong><br><span class="muted">${u.email}</span></span>
    </label>`).join("");
}

function personRow(t) {
  return `
    <div class="person-row">
      <div class="person">
        <div class="avatar">${initials(t.suspectName)}</div>
        <div class="person-meta"><strong>${t.suspectName}</strong><span>${t.suspectEmail}</span></div>
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

function escapeSvgText(value = "") {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function mapColors(kind) {
  // Consistente con los pills actuales: dentro = alerta roja, fuera = verde.
  if (kind === "inside") return { fill: "#dc2626", stroke: "#991b1b" };
  if (kind === "outside") return { fill: "#10b981", stroke: "#047857" };
  return { fill: "#f59e0b", stroke: "#92400e" };
}

function renderCaseMap(caseData) {
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
    const name = escapeSvgText(target.suspectName || "Usuario");
    const shortName = escapeSvgText((target.suspectName || "Usuario").split(/\s+/)[0]);
    const labelInitials = escapeSvgText(initials(target.suspectName || "?"));

    return `
      <g class="map-person-node" transform="translate(${pos.x.toFixed(1)}, ${pos.y.toFixed(1)})" aria-label="${name}: ${mapStatusLabel(pos.kind)}">
        <circle class="map-person-halo" cx="0" cy="0" r="27" fill="${colors.fill}" opacity="0.12"></circle>
        <circle cx="0" cy="0" r="20" fill="${colors.fill}" stroke="${colors.stroke}" stroke-width="3"></circle>
        <text x="0" y="5" text-anchor="middle" font-size="10.5" font-weight="800" fill="#ffffff">${labelInitials}</text>
        <rect x="-38" y="27" width="76" height="22" rx="11" fill="#ffffff" stroke="#dbe3ef"></rect>
        <text x="0" y="42" text-anchor="middle" font-size="11" font-weight="700" fill="#0f172a">${shortName}</text>
      </g>`;
  }).join("");

  const emptyText = completed.length === 0
    ? `<g><text x="${centerX}" y="${centerY + radius + 72}" text-anchor="middle" font-size="13" fill="#64748b">Los usuarios aparecerán cuando exista una clasificación.</text></g>`
    : "";

  const svg = `
    <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Representación ilustrativa del radio de proximidad">
      <defs>
        <pattern id="grid-${caseData.id}" width="32" height="32" patternUnits="userSpaceOnUse">
          <path d="M 32 0 L 0 0 0 32" fill="none" stroke="#dbe3ef" stroke-width="1" opacity="0.45"></path>
        </pattern>
      </defs>
      <rect x="0" y="0" width="${width}" height="${height}" rx="18" fill="#f8fbff"></rect>
      <rect x="0" y="0" width="${width}" height="${height}" rx="18" fill="url(#grid-${caseData.id})"></rect>

      <circle cx="${centerX}" cy="${centerY}" r="${radius + 12}" fill="#2563eb" opacity="0.045"></circle>
      <circle cx="${centerX}" cy="${centerY}" r="${radius}" fill="#2563eb" fill-opacity="0.075" stroke="#2563eb" stroke-width="3" stroke-dasharray="9 8"></circle>

      <g class="crime-scene-node">
        <circle cx="${centerX}" cy="${centerY}" r="24" fill="#0f172a"></circle>
        <text x="${centerX}" y="${centerY + 6}" text-anchor="middle" font-size="20" fill="#ffffff">★</text>
        <rect x="${centerX - 70}" y="${centerY + 34}" width="140" height="26" rx="13" fill="#ffffff" stroke="#dbe3ef"></rect>
        <text x="${centerX}" y="${centerY + 52}" text-anchor="middle" font-size="12" font-weight="800" fill="#0f172a">ESCENA DEL CRIMEN</text>
      </g>

      <g>
        <rect x="${centerX + radius - 17}" y="${centerY - 13}" width="74" height="26" rx="13" fill="#eff6ff" stroke="#bfdbfe"></rect>
        <text x="${centerX + radius + 20}" y="${centerY + 5}" text-anchor="middle" font-size="12" font-weight="800" fill="#1d4ed8">R = ${escapeSvgText(caseData.radius)}</text>
      </g>

      ${peopleSvg}
      ${emptyText}
    </svg>`;

  const legend = targets.map(target => {
    const kind = mapKind(target);
    return `
      <div class="legend-item">
        <div class="legend-person">
          <div class="legend-avatar">${initials(target.suspectName)}</div>
          <div class="legend-copy">
            <strong>${target.suspectName}</strong>
            <span>${kind === "pending" || kind === "processing" ? "Aún no se posiciona" : "Posición ilustrativa"}</span>
          </div>
        </div>
        <span class="legend-status status-${kind}">${mapStatusLabel(kind)}</span>
      </div>`;
  }).join("");

  return `
    <section class="case-visualization" data-case-map="${caseData.id}" hidden>
      <div class="map-summary-row">
        <div>
          <h3>Mapa ilustrativo de proximidad</h3>
          <p class="muted map-subtitle">El aro representa el radio público. Los iconos solo indican si cada persona quedó dentro o fuera; su posición no corresponde a su ubicación real.</p>
        </div>
        <div class="map-counts" aria-label="Resumen de resultados">
          <span class="map-count inside-count"><strong>${counts.inside}</strong> dentro</span>
          <span class="map-count outside-count"><strong>${counts.outside}</strong> fuera</span>
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

function caseCard(c) {
  return `
    <article class="card case-card" data-case-id="${c.id}">
      <div class="case-header">
        <div>
          <h2 style="margin-bottom:4px">${c.title}</h2>
          <span class="muted">Radio público R = ${c.radius}</span>
        </div>
        <div class="case-header-actions">
          <span class="badge">${c.targets.length} participante${c.targets.length === 1 ? "" : "s"}</span>
          <button class="secondary map-toggle" type="button" data-map-toggle="${c.id}" aria-expanded="false">Ver mapa ilustrativo</button>
        </div>
      </div>
      <div class="person-list">${c.targets.map(personRow).join("")}</div>
      ${renderCaseMap(c)}
    </article>`;
}

async function loadCases() {
  try {
    const data = await api("/api/police/cases");
    if (!data.cases.length) {
      caseList.innerHTML = '<div class="empty">Todavía no hay casos. Crea el primero para comenzar.</div>';
      return;
    }

    // Conserva qué mapas estaban abiertos aunque el dashboard haga polling.
    const openMaps = new Set(
      [...caseList.querySelectorAll("[data-case-map]:not([hidden])")]
        .map(el => String(el.dataset.caseMap))
    );

    caseList.innerHTML = data.cases.map(caseCard).join("");

    for (const id of openMaps) {
      const panel = caseList.querySelector(`[data-case-map="${CSS.escape(id)}"]`);
      const button = caseList.querySelector(`[data-map-toggle="${CSS.escape(id)}"]`);
      if (panel && button) {
        panel.hidden = false;
        button.textContent = "Ocultar mapa";
        button.setAttribute("aria-expanded", "true");
      }
    }
  } catch (err) {
    caseList.innerHTML = `<div class="status error">${err.message}</div>`;
  }
}

caseList.addEventListener("click", event => {
  const button = event.target.closest("[data-map-toggle]");
  if (!button) return;

  const id = button.dataset.mapToggle;
  const panel = caseList.querySelector(`[data-case-map="${CSS.escape(id)}"]`);
  if (!panel) return;

  panel.hidden = !panel.hidden;
  const open = !panel.hidden;
  button.textContent = open ? "Ocultar mapa" : "Ver mapa ilustrativo";
  button.setAttribute("aria-expanded", String(open));

  if (open) panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
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

loadPolice().catch(err => { caseList.innerHTML = `<div class="status error">${err.message}</div>`; });

const list = document.getElementById("assignmentList");

async function loadAssignments() {
  const u = await me();
  if (u.role !== "suspect") return location.href = "/police-dashboard.html";
  userName.textContent = u.displayName;
  logoutBtn.onclick = logout;

  const data = await api("/api/suspect/assignments");
  if (!data.assignments.length) {
    list.innerHTML = '<div class="empty">No tienes solicitudes asignadas por el momento.</div>';
    return;
  }
  list.innerHTML = data.assignments.map(t => `
    <article class="card">
      <div class="case-header">
        <div><h2 style="margin-bottom:4px">${t.caseTitle}</h2><span class="muted">Solicitado por ${t.policeName} · R = ${t.radius}</span></div>
        ${statusPill(t.status)}
      </div>
      <p class="muted">Tu ubicación se cifra localmente. La API recibirá únicamente ciphertexts y shares del protocolo.</p>
      <div class="actions">
        ${t.status === "complete" ? '<span class="pill complete">Protocolo finalizado</span>' : `<a class="button" href="/crypto.html?target=${t.id}">Abrir sesión segura</a>`}
      </div>
    </article>`).join("");
}

loadAssignments().catch(err => list.innerHTML = `<div class="status error">${err.message}</div>`);
setInterval(() => loadAssignments().catch(()=>{}), 3000);

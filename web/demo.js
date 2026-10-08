const accounts = ["police", "carlos", "fer", "ximena"];
const statusEl = document.getElementById("demoStatus");
const openAllBtn = document.getElementById("openAllBtn");

function demoURL(account) {
  return `/demo-login.html?account=${encodeURIComponent(account)}`;
}

function openRole(account) {
  const win = window.open(demoURL(account), `_pp_${account}_${Date.now()}`);
  return !!win;
}

document.querySelectorAll(".open-role").forEach(btn => {
  btn.addEventListener("click", () => {
    if (!openRole(btn.dataset.account)) {
      statusEl.hidden = false;
      statusEl.className = "status error";
      statusEl.textContent = "El navegador bloqueó la nueva pestaña. Permite pop-ups para localhost o usa los botones individuales.";
    }
  });
});

openAllBtn.addEventListener("click", () => {
  let opened = 0;
  for (const account of accounts) if (openRole(account)) opened++;
  statusEl.hidden = false;
  if (opened === accounts.length) {
    statusEl.className = "status ok";
    statusEl.textContent = "Listo: se abrieron Policía, Carlos, Fer y Ximena en pestañas independientes.";
  } else {
    statusEl.className = "status error";
    statusEl.textContent = `Se abrieron ${opened} de ${accounts.length} vistas. El navegador probablemente bloqueó algunas pestañas; puedes abrirlas con los botones individuales.`;
  }
});

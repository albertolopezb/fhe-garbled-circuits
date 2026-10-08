const demoAccounts = {
  police: { label: "Policía", email: "police@demo.local", password: "Police123!", next: "/police-dashboard.html" },
  carlos: { label: "Carlos Mendoza", email: "carlos@demo.local", password: "Demo1234!", next: "/suspect-dashboard.html" },
  fer: { label: "Fernanda Santos", email: "fer@demo.local", password: "Demo1234!", next: "/suspect-dashboard.html" },
  ximena: { label: "Ximena Villarreal", email: "ximena@demo.local", password: "Demo1234!", next: "/suspect-dashboard.html" },
};

const loadingTitle = document.getElementById("loadingTitle");
const loadingText = document.getElementById("loadingText");
const statusEl = document.getElementById("status");

async function bootDemoAccount() {
  const accountName = new URLSearchParams(location.search).get("account") || "";
  const account = demoAccounts[accountName];
  if (!account) throw new Error("Cuenta demo inválida");

  loadingTitle.textContent = `Abriendo ${account.label}`;
  loadingText.textContent = "Esta pestaña tendrá su propio token y su propia instancia criptográfica.";

  // Evita heredar una sesión de la pestaña que abrió esta ventana.
  setAuthToken("");
  const data = await loginWithCredentials(account.email, account.password);
  statusEl.className = "status ok";
  statusEl.textContent = `Sesión independiente creada para ${data.user.displayName}. Redirigiendo…`;
  setTimeout(() => location.replace(account.next), 350);
}

bootDemoAccount().catch(err => {
  statusEl.className = "status error";
  statusEl.textContent = err.message;
  loadingText.textContent = "Vuelve al Demo Control Center e intenta de nuevo.";
});

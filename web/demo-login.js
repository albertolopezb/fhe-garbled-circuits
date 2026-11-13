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
  if (!account || (demoFrameAccount && demoFrameAccount !== accountName)) {
    throw new Error("Cuenta demo inválida para este panel.");
  }

  loadingTitle.textContent = `Abriendo ${account.label}`;
  loadingText.textContent = "Conectando con la cuenta demo…";

  if (demoFrameAccount && getAuthToken()) {
    try {
      const user = await me();
      if (user.email === account.email) {
        location.replace(account.next);
        return;
      }
    } catch (err) {
      if (getAuthToken()) throw err;
    }
  }

  setAuthToken("");
  await loginWithCredentials(account.email, account.password);
  location.replace(account.next);
}

bootDemoAccount().catch(err => {
  statusEl.className = "status error";
  statusEl.textContent = err.message;
  loadingText.textContent = "Vuelve a cargar la demo e intenta de nuevo.";
});

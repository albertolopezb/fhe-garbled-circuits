const statusEl = document.getElementById("status");

function showStatus(message, error = false) {
  if (!statusEl) return;
  statusEl.hidden = false;
  statusEl.className = `status ${error ? "error" : "ok"}`;
  statusEl.textContent = message;
}

async function redirectIfLoggedIn() {
  if (!getAuthToken()) return;
  try {
    const data = await api("/api/me");
    location.href = data.user.role === "police" ? "/police-dashboard.html" : "/suspect-dashboard.html";
  } catch {}
}
redirectIfLoggedIn();

const loginForm = document.getElementById("loginForm");
if (loginForm) {
  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const data = await loginWithCredentials(
        document.getElementById("email").value,
        document.getElementById("password").value,
      );
      location.href = data.user.role === "police" ? "/police-dashboard.html" : "/suspect-dashboard.html";
    } catch (err) {
      showStatus(err.message, true);
    }
  });
}

const registerForm = document.getElementById("registerForm");
if (registerForm) {
  registerForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const data = await api("/api/auth/register", {
        method: "POST",
        body: JSON.stringify({
          displayName: document.getElementById("displayName").value,
          email: document.getElementById("email").value,
          password: document.getElementById("password").value,
        }),
      });
      setAuthToken(data.token);
      location.href = "/suspect-dashboard.html";
    } catch (err) {
      showStatus(err.message, true);
    }
  });
}

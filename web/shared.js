// Same-origin iframes share sessionStorage. Give every demo role its own key.
const demoFrameAccount = window.parent !== window
  ? /^pp-demo-(police|carlos|fer|ximena)$/.exec(window.name)?.[1]
  : undefined;
const AUTH_TOKEN_KEY = demoFrameAccount ? `pp_auth_token:demo:${demoFrameAccount}` : "pp_auth_token";
if (demoFrameAccount) {
  document.documentElement.classList.add("demo-embedded");
  document.documentElement.dataset.account = demoFrameAccount;
}

function getAuthToken() {
  return sessionStorage.getItem(AUTH_TOKEN_KEY) || "";
}

function setAuthToken(token) {
  if (token) sessionStorage.setItem(AUTH_TOKEN_KEY, token);
  else sessionStorage.removeItem(AUTH_TOKEN_KEY);
}

async function api(path, options = {}) {
  const token = getAuthToken();
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(path, {
    credentials: demoFrameAccount ? "omit" : "same-origin",
    ...options,
    headers,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401) {
      setAuthToken("");
      const publicPages = ["/", "/login.html", "/register.html", "/demo-login.html"];
      if (!publicPages.includes(location.pathname)) {
        location.replace(demoFrameAccount
          ? `/demo-login.html?account=${demoFrameAccount}`
          : "/login.html");
      }
    }
    const retryAfter = Number(res.headers.get("Retry-After"));
    if (res.status === 429 && retryAfter > 0) {
      throw new Error(`${data.error || "Límite alcanzado"}. Puedes volver a intentar en ${Math.ceil(retryAfter / 60)} min.`);
    }
    const error = new Error(data.error || `${res.status} ${res.statusText}`);
    error.status = res.status;
    throw error;
  }
  return data;
}

async function me() {
  return (await api("/api/me")).user;
}

async function loginWithCredentials(email, password) {
  const data = await api("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
  setAuthToken(data.token);
  return data;
}

async function logout() {
  try {
    await api("/api/auth/logout", { method: "POST", body: "{}" });
  } catch (_) {}
  setAuthToken("");
  location.href = "/";
}

function initials(name = "?") {
  return name.split(/\s+/).filter(Boolean).slice(0,2).map(x => x[0]).join("").toUpperCase();
}

function resultPill(classification) {
  if (!classification) return '<span class="pill pending">Sin resultado</span>';
  const cls = classification.includes("DENTRO") ? "inside" : classification.includes("FUERA") ? "outside" : "limit";
  return `<span class="pill ${cls}">${classification}</span>`;
}

function statusPill(status) {
  const map = { pending: ["pending", "Pendiente"], processing: ["processing", "En proceso"], complete: ["complete", "Completo"] };
  const [cls, text] = map[status] || ["pending", status];
  return `<span class="pill ${cls}">${text}</span>`;
}

function escapeHTML(value = "") {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}


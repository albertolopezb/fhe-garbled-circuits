const AUTH_TOKEN_KEY = "pp_auth_token";

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
    credentials: "same-origin",
    ...options,
    headers,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401) {
      setAuthToken("");
      const publicPages = ["/", "/login.html", "/register.html", "/demo-login.html"];
      if (!publicPages.includes(location.pathname)) location.href = "/login.html";
    }
    throw new Error(data.error || `${res.status} ${res.statusText}`);
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

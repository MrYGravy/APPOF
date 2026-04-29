// ── Shared auth helpers ───────────────────────────────────────
function getToken()    { return localStorage.getItem('nike_token'); }
function getUsername() { return localStorage.getItem('nike_username'); }
function getRole()     { return localStorage.getItem('nike_role'); }

function authHeaders() {
  return { 'Content-Type': 'application/json', 'x-auth-token': getToken() };
}

function authFetch(url, opts = {}) {
  // iOS Safari: ensure headers object exists
  if (!opts.headers) opts.headers = {};
  opts.headers = { ...(opts.headers || {}), 'x-auth-token': getToken() };
  return fetch(url, opts).then(res => {
    if (res.status === 401) { logout(); return Promise.reject('session_expired'); }
    return res;
  });
}

function logout() {
  const token = getToken();
  if (token) fetch('/api/logout', { method: 'POST', headers: { 'x-auth-token': token } }).catch(()=>{});
  localStorage.removeItem('nike_token');
  localStorage.removeItem('nike_username');
  localStorage.removeItem('nike_role');
  window.location.href = '/login.html';
}

// Guard: redirect to login if no session or wrong role
function requireRole(role) {
  const token = getToken();
  if (!token) { window.location.href = '/login.html'; return false; }
  // With the new system, just check that a token exists
  // Role enforcement is done server-side; client just needs a valid session
  return true;
}

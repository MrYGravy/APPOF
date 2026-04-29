// ── VERSIÓN — cambia este número cada vez que subas cambios ──
// Así todos los dispositivos descargan la versión nueva de inmediato
const VERSION = 'nike-v50';
const CACHE   = VERSION;

const STATIC = [
  '/',
  '/index.html',
  '/bodega.html',
  '/login.html',
  '/auth.js',
  '/img/nike-logo.png'
];

// ── Install: cachea archivos y activa de inmediato ────────────
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE)
      .then(c => c.addAll(STATIC))
      .then(() => self.skipWaiting()) // activa sin esperar a que cierren las tabs
  );
});

// ── Activate: borra cachés de versiones anteriores ───────────
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(k => k !== CACHE) // borra todo excepto la versión actual
          .map(k => caches.delete(k))
      )
    ).then(() => clients.claim()) // toma control de todas las tabs abiertas
  );
});

// ── IndexedDB para cola offline ───────────────────────────────
function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('nikeOffline', 1);
    req.onupgradeneeded = e => {
      e.target.result.createObjectStore('queue', { keyPath: 'id', autoIncrement: true });
    };
    req.onsuccess = e => resolve(e.target.result);
    req.onerror   = e => reject(e.target.error);
  });
}

async function enqueue(request) {
  const db   = await openDB();
  const body = await request.text();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('queue', 'readwrite');
    tx.objectStore('queue').add({
      url: request.url, method: request.method,
      headers: Object.fromEntries(request.headers.entries()), body
    });
    tx.oncomplete = resolve;
    tx.onerror    = reject;
  });
}

async function flushQueue() {
  const db    = await openDB();
  const tx    = db.transaction('queue', 'readwrite');
  const store = tx.objectStore('queue');
  const all   = await new Promise((res, rej) => {
    const r = store.getAll();
    r.onsuccess = () => res(r.result);
    r.onerror   = rej;
  });
  for (const item of all) {
    try {
      await fetch(item.url, { method: item.method, headers: item.headers, body: item.body });
      store.delete(item.id);
    } catch(e) { break; }
  }
}

// ── Fetch handler ─────────────────────────────────────────────
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // Socket.io — nunca interceptar
  if (url.pathname.startsWith('/socket.io/')) return;

  // API POST — intentar en red, si falla encolar
  if (url.pathname.startsWith('/api/') && e.request.method === 'POST') {
    e.respondWith(
      fetch(e.request.clone()).catch(async () => {
        await enqueue(e.request.clone());
        return new Response(JSON.stringify({ ok: true, offline: true, queued: true }), {
          headers: { 'Content-Type': 'application/json' }
        });
      })
    );
    return;
  }

  // API GET — red primero, fallback caché
  if (url.pathname.startsWith('/api/')) {
    e.respondWith(
      fetch(e.request).catch(() =>
        new Response('{"error":"offline"}', { headers: { 'Content-Type': 'application/json' } })
      )
    );
    return;
  }

  // Archivos estáticos (.html, .js, imágenes) — NETWORK FIRST con fallback caché
  // Esto garantiza que siempre se intenta la red primero, actualizando automáticamente
  if (
    STATIC.some(s => url.pathname === s) ||
    url.pathname.startsWith('/img/') ||
    url.pathname.endsWith('.js') ||
    url.pathname.endsWith('.css')
  ) {
    e.respondWith(
      fetch(e.request)
        .then(res => {
          // Si la red respondió, actualiza el caché y devuelve la respuesta fresca
          const clone = res.clone();
          caches.open(CACHE).then(c => c.put(e.request, clone));
          return res;
        })
        .catch(() =>
          // Sin red: usa el caché como fallback
          caches.match(e.request)
        )
    );
    return;
  }

  // Todo lo demás — red primero
  e.respondWith(
    fetch(e.request).catch(() => caches.match(e.request))
  );
});

// ── Sync background ───────────────────────────────────────────
self.addEventListener('sync', e => {
  if (e.tag === 'sync-queue') e.waitUntil(flushQueue());
});

self.addEventListener('message', e => {
  if (e.data === 'flush') flushQueue();
});

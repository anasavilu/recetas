// Service worker mínimo: hace la web instalable y deja abrir la pantalla aunque no haya conexión.
// Siempre intenta primero la red (así los cambios nuevos se ven en cuanto se despliegan); los datos (/api) nunca se guardan.
const V = 'recetario-v1';
self.addEventListener('install', e => {
  e.waitUntil(caches.open(V).then(c => c.addAll(['/', '/manifest.webmanifest', '/icons/icon-192.png'])).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== V).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const r = e.request, u = new URL(r.url);
  if (r.method !== 'GET' || u.origin !== location.origin || u.pathname.startsWith('/api/') || u.pathname.startsWith('/r/')) return;
  e.respondWith(
    fetch(r).then(res => {
      if (res.ok && !u.search) { const copia = res.clone(); caches.open(V).then(c => c.put(r, copia)); }
      return res;
    }).catch(() => caches.match(r).then(m => m || caches.match('/')))
  );
});

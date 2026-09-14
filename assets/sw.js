const CACHE = 'attendpro-v2'
const ASSETS = ['./index.html','./web.js','./web.css','./bridge.js','./manifest.webmanifest','./icon.svg','./icon-192.png','./icon-512.png']
self.addEventListener('install', event => event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(ASSETS))))
self.addEventListener('activate', event => event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(key => key.startsWith('attendpro-') && key !== CACHE).map(key => caches.delete(key))))))
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url)
  if (event.request.method !== 'GET' || url.origin !== location.origin || !url.pathname.startsWith(new URL('./', location.href).pathname)) return
  event.respondWith(fetch(event.request).then(response => {
    if (response.ok) { const copy = response.clone(); event.waitUntil(caches.open(CACHE).then(cache => cache.put(event.request, copy))) }
    return response
  }).catch(() => caches.match(event.request)))
})

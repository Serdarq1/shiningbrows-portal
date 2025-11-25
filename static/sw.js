self.addEventListener('install', (event) => {
  self.skipWaiting();
});
self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});
// Simple pass-through fetch so we have a registered service worker for PWA installability
self.addEventListener('fetch', () => {});

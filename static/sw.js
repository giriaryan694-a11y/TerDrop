/**
 * TerDrop Service Worker
 * Handles PWA installability AND notification display.
 *
 * Mobile browsers (Chrome/Android in particular) throw "Illegal constructor"
 * for `new Notification()` — the only supported way to show a notification
 * there is via a service worker's showNotification(). We route ALL
 * notification requests through here (even on desktop) so one code path
 * works everywhere, triggered by postMessage from the page.
 *
 * Deliberately does NOT cache any application data, file listings, or
 * downloads — this app deals in access-controlled and encrypted files, so
 * offline caching could leak content to a device's cache after permissions
 * are revoked. Every request passes straight through to the network.
 */

const CACHE_NAME = "terdrop-shell-v1";

// Only the static, non-sensitive shell assets are safe to cache — never
// HTML pages (they carry session-specific, permission-filtered content).
const SHELL_ASSETS = [
  "/static/css/style.css",
  "/static/js/app.js",
  "/static/icons/icon-192.png",
  "/static/icons/icon-512.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);

  // Only ever serve cached responses for the exact static shell assets
  // above. Everything else (pages, API calls, downloads) always goes to
  // the network — this app's content is permission-gated and must never
  // be served stale or offline.
  if (SHELL_ASSETS.includes(url.pathname)) {
    event.respondWith(
      caches.match(event.request).then((cached) => cached || fetch(event.request))
    );
    return;
  }

  event.respondWith(fetch(event.request));
});

// ── Notification bridge ─────────────────────────────────────────────
// The page can't reliably call `new Notification()` on mobile, so it
// posts a message here instead and the service worker shows it.
self.addEventListener("message", (event) => {
  const data = event.data || {};
  if (data.type === "SHOW_NOTIFICATION") {
    self.registration.showNotification(data.title || "TerDrop", {
      body: data.body || "",
      icon: "/static/icons/icon-192.png",
      badge: "/static/icons/icon-192.png",
      tag: data.tag || undefined,   // reusing a tag replaces the previous notification instead of stacking
      renotify: !!data.tag,
    });
  }
});

// Clicking a notification focuses/opens the app instead of leaving a dead notification.
self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((clientsList) => {
      for (const client of clientsList) {
        if ("focus" in client) return client.focus();
      }
      if (self.clients.openWindow) return self.clients.openWindow("/dashboard");
    })
  );
});

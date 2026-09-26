/**
 * sw.js — عامل خدمة يسمح بتثبيت التطبيق (PWA) على الشاشة الرئيسية.
 *
 * قرار متعمَّد: هذا نظام أعمال ببيانات حيّة (مخزون، حالات مالية، أوامر
 * شغل) — لا يُخزَّن أي محتوى ديناميكي (صفحات index.php) في الكاش أبداً،
 * لتفادي عرض أرقام مخزون أو حالات قديمة للمستخدم دون علمه واتخاذ قرار
 * خاطئ بناءً عليها. يُخزَّن فقط الغلاف الثابت (الأيقونات وصفحة عدم
 * الاتصال)، ويُستخدَم استراتيجية "الشبكة أولاً دائماً" لكل شيء آخر.
 */

const CACHE_VERSION = "fms-shell-v2"; // v2: أيقونات جديدة + شاشات إقلاع iOS
const SHELL_ASSETS = [
  "./manifest.json",
  "./icons/icon-192.png",
  "./icons/icon-512.png",
  "./icons/icon-maskable-512.png",
  "./icons/icon-180.png",
  "./icons/apple-touch-icon.png",
  "./offline.html",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_VERSION).then((cache) => cache.addAll(SHELL_ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_VERSION).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;

  const url = new URL(req.url);
  const isShellAsset = SHELL_ASSETS.some((a) => url.pathname.endsWith(a.replace("./", "/")));

  if (isShellAsset) {
    event.respondWith(
      caches.match(req).then((cached) => {
        const network = fetch(req).then((res) => {
          if (res.ok) caches.open(CACHE_VERSION).then((c) => c.put(req, res.clone()));
          return res;
        }).catch(() => cached);
        return cached || network;
      })
    );
    return;
  }

  if (req.mode === "navigate") {
    event.respondWith(
      fetch(req).catch(() => caches.match("./offline.html"))
    );
  }
});

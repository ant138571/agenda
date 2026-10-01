/* Service worker da Agenda de Tarefas: permite abrir e usar o app sem internet. */
const VERSION = "agenda-v20";
const SHELL = ["./", "./index.html", "./manifest.webmanifest?v=7", "./vendor/supabase.js",
  "./icons/icon-192.png?v=7", "./icons/icon-512.png?v=7", "./icons/apple-touch-icon.png?v=7", "./icons/icon-maskable-512.png?v=7"];

self.addEventListener("install", e => {
  e.waitUntil(caches.open(VERSION).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== VERSION).map(k => caches.delete(k))))
    .then(() => self.clients.claim()));
});
self.addEventListener("fetch", e => {
  const req = e.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  // Dados do Supabase nunca passam pelo cache (a sincronização cuida disso).
  if (url.hostname.endsWith("supabase.co") || url.hostname.endsWith("supabase.in")) return;
  const sameOrigin = url.origin === self.location.origin;
  const isFont = url.hostname === "fonts.googleapis.com" || url.hostname === "fonts.gstatic.com";
  if (!sameOrigin && !isFont) return;
  // Configurações › Procurar atualização: a consulta de versão vai sempre à rede e não fica guardada.
  if (sameOrigin && url.searchParams.has("versao")) return;
  if (req.mode === "navigate") {
    // Página: tenta a rede (para receber atualizações) e cai para o cache se estiver offline.
    // cache: "no-cache": confere com o servidor em vez de usar a cópia guardada pelo navegador (o GitHub Pages guarda por 10 min)
    // só a página do app (./ ou index.html) com resposta válida vira a cópia offline; guias e páginas de erro não a substituem
    const isApp = /\/(index\.html)?$/.test(url.pathname);
    e.respondWith(fetch(req.url, { cache: "no-cache", credentials: "same-origin" }).then(res => { if (isApp && res.ok) { const copy = res.clone(); caches.open(VERSION).then(c => c.put("./index.html", copy)); } return res; })
      .catch(() => caches.match("./index.html").then(r => r || caches.match("./"))));
    return;
  }
  // Ícones e manifesto: sempre da rede primeiro (para o ícone do app atualizar), cache só sem internet.
  if (sameOrigin && (url.pathname.includes("/icons/") || url.pathname.endsWith(".webmanifest"))) {
    e.respondWith(fetch(req, { cache: "no-cache" }).then(res => { if (res && res.ok) { const copy = res.clone(); caches.open(VERSION).then(c => c.put(req, copy)); } return res; })
      .catch(() => caches.match(req)));
    return;
  }
  // Demais arquivos: responde do cache e atualiza em segundo plano.
  e.respondWith(caches.open(VERSION).then(async cache => {
    const hit = await cache.match(req);
    const net = fetch(req).then(res => { if (res && (res.ok || res.type === "opaque")) cache.put(req, res.clone()); return res; }).catch(() => hit);
    return hit || net;
  }));
});

/* Lembretes: notificação enviada pelo servidor (chega mesmo com o app fechado). */
self.addEventListener("push", e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (err) { d = { body: e.data ? e.data.text() : "" }; }
  const id = typeof d.id === "string" ? d.id.slice(0, 80) : "";
  e.waitUntil(self.registration.showNotification(String(d.title || "Lembrete").slice(0, 80), {
    body: String(d.body || "").slice(0, 300), tag: id ? "rem-" + id : "rem-teste", renotify: true, requireInteraction: true,
    icon: "icons/icon-192.png?v=7", badge: "icons/icon-192.png?v=7", data: { id }
  }));
});
/* Toque na notificação: abre o app (ou traz para frente) já na tarefa. */
self.addEventListener("notificationclick", e => {
  e.notification.close();
  const id = (e.notification.data && e.notification.data.id) || "";
  e.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then(list => {
    for (const c of list) {
      if (new URL(c.url).origin === self.location.origin && "focus" in c) { c.postMessage({ type: "open-task", id }); return c.focus(); }
    }
    return self.clients.openWindow("./" + (id ? "?t=" + encodeURIComponent(id) : ""));
  }));
});

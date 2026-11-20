// @ts-nocheck
/* Agenda de Tarefas — função "lembretes" (Supabase Edge Function)
 *
 * O que faz:
 *   GET                         → devolve a chave pública de notificações (VAPID) para o app se inscrever.
 *   POST  (cabeçalho x-cron-secret) → chamada a cada minuto pelo agendador: envia os lembretes vencidos
 *                                 (push e, v34, e-mail) e o aviso diário por e-mail (v34).
 *   POST  {"action":"test"} com o login do usuário → envia uma notificação de teste para os aparelhos dele.
 *   POST  {"action":"test-email"} com o login do usuário → (v34) envia um e-mail de teste.
 *
 * Segredos necessários (Edge Functions › Secrets):
 *   VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, VAPID_SUBJECT (ex.: mailto:voce@exemplo.com), CRON_SECRET
 * E-mail (v34; os mesmos segredos do "Enviar agora", guia ENVIO-EMAIL — os segredos valem para todas as funções):
 *   GAS_URL e GAS_SECRET (Gmail pelo script do Google) ou BREVO_API_KEY e BREVO_SENDER (Brevo);
 *   ENVIO_USUARIOS (só essas contas recebem lembretes e avisos por e-mail); SENDER_NAME (opcional).
 * SUPABASE_URL e SUPABASE_SERVICE_ROLE_KEY já existem automaticamente.
 * Publique com "Verify JWT" DESLIGADO: a própria função confere o segredo do agendador e o login do usuário.
 *
 * Lembretes e avisos por e-mail (v34): ligados no app em Configurações › Lembretes e avisos por e-mail, gravados no
 * documento meta/perfil da conta: emailLembrete (e-mail na hora do lembrete), emailAviso (aviso diário com as tarefas
 * de hoje e as atrasadas), emailHora (hora do aviso, 5–10, horário de Brasília; padrão 7), appUrl (endereço do app,
 * para o link "Abrir"). Destino: o e-mail de Meus dados (perfil.email) ou, sem ele, o e-mail da conta.
 * O aviso diário é marcado em push_sent (doc_id "aviso-diario", remind_at = data) para sair uma vez por dia.
 *
 * Sem bibliotecas externas: a criptografia do Web Push (RFC 8291 / aes128gcm) e a assinatura VAPID
 * (RFC 8292 / ES256) usam só a WebCrypto do próprio Deno.
 */

const enc = new TextEncoder();
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};
// Só envia para serviços de push conhecidos (evita que a função seja usada para chamar endereços arbitrários).
const PUSH_HOSTS = [/^fcm\.googleapis\.com$/, /^android\.googleapis\.com$/, /(^|\.)push\.services\.mozilla\.com$/,
  /(^|\.)push\.apple\.com$/, /(^|\.)notify\.windows\.com$/, /(^|\.)push\.api\.chrome\.google\.com$/];

export const b64u = (buf) => {
  const bytes = new Uint8Array(buf); let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
export const ub64u = (str) => {
  let s = String(str).replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "=";
  const bin = atob(s); const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
async function hkdf(salt, ikm, info, len) {
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, len * 8));
}

export function allowedEndpoint(endpoint) {
  try { const u = new URL(endpoint); return u.protocol === "https:" && PUSH_HOSTS.some((re) => re.test(u.hostname)); }
  catch { return false; }
}

/* Assinatura VAPID (JWT ES256) */
export async function vapidHeader(endpoint, env) {
  const pub = ub64u(env.VAPID_PUBLIC_KEY);
  const jwk = { kty: "EC", crv: "P-256", d: env.VAPID_PRIVATE_KEY, x: b64u(pub.slice(1, 33)), y: b64u(pub.slice(33, 65)), ext: true };
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const head = b64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const body = b64u(enc.encode(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: env.VAPID_SUBJECT || "mailto:agenda@example.com" })));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(head + "." + body));
  return `vapid t=${head}.${body}.${b64u(sig)}, k=${env.VAPID_PUBLIC_KEY}`;
}

/* Criptografia da mensagem (RFC 8291, aes128gcm) */
export async function encryptPayload(sub, plaintext) {
  const uaPub = ub64u(sub.p256dh), authSecret = ub64u(sub.auth);
  const eph = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPub = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", uaPub, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const ecdh = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, eph.privateKey, 256));
  const ikm = await hkdf(authSecret, ecdh, concat(enc.encode("WebPush: info\0"), uaPub, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 12);
  const aes = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const data = concat(typeof plaintext === "string" ? enc.encode(plaintext) : plaintext, new Uint8Array([2]));
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aes, data));
  const rs = new Uint8Array([0, 0, 16, 0]); // 4096
  return concat(salt, rs, new Uint8Array([asPub.length]), asPub, cipher);
}

export async function sendPush(sub, payload, env, fetchImpl = fetch) {
  if (!allowedEndpoint(sub.endpoint)) return { status: 0, skipped: true };
  const body = await encryptPayload(sub, JSON.stringify(payload));
  const res = await fetchImpl(sub.endpoint, {
    method: "POST",
    headers: { TTL: "86400", Urgency: "high", "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream",
      Authorization: await vapidHeader(sub.endpoint, env) },
    body,
  });
  return { status: res.status };
}

/* Acesso ao banco com a chave de serviço (só dentro da função) */
async function rest(env, f, method, path, body, extra = {}) {
  const res = await f(`${env.SUPABASE_URL}/rest/v1/${path}`, {
    method,
    headers: { apikey: env.SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json", ...extra },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${method} ${path.split("?")[0]}: ${res.status} ${await res.text()}`);
  const txt = await res.text();
  return txt ? JSON.parse(txt) : null;
}
const UUID = /^[0-9a-f-]{36}$/i;
async function subsOf(env, f, userIds) {
  const ids = userIds.filter((u) => UUID.test(u));
  if (!ids.length) return [];
  return await rest(env, f, "GET", `push_subs?select=user_id,endpoint,p256dh,auth&user_id=in.(${ids.join(",")})`);
}
async function deliver(env, f, subs, payload) {
  let sent = 0, gone = 0;
  for (const s of subs) {
    try {
      const r = await sendPush(s, payload, env, f);
      if (r.status >= 200 && r.status < 300) sent++;
      else if (r.status === 404 || r.status === 410) {
        gone++; await rest(env, f, "DELETE", `push_subs?endpoint=eq.${encodeURIComponent(s.endpoint)}`, undefined, { Prefer: "return=minimal" });
      }
    } catch (e) { console.error("push falhou", e?.message || e); }
  }
  return { sent, gone };
}

/* ================= E-mail (v34) ================= */
const TZ = "America/Sao_Paulo";
const GAS_RE = /^https:\/\/script\.google\.com\/macros\/s\/[\w-]+\/exec$/;
const BREVO_URL = "https://api.brevo.com/v3/smtp/email";
const EMAIL_RE = /^[^\s@<>(),;:"]+@[^\s@<>(),;:"]+\.[^\s@<>(),;:"]+$/;
const oneLine = (s) => String(s || "").replace(/[\r\n]+/g, " ").trim();
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
export const emailConfigurado = (env) => !!((env.GAS_URL && env.GAS_SECRET) || (env.BREVO_API_KEY && env.BREVO_SENDER));
const permitidos = (env) => String(env.ENVIO_USUARIOS || "").split(/[,;\s]+/).map((s) => s.trim().toLowerCase()).filter(Boolean);

async function enviarEmail(env, f, para, assunto, texto, html) {
  const nome = oneLine(env.SENDER_NAME || env.BREVO_SENDER_NAME || "Agenda de Tarefas").slice(0, 70);
  if (env.GAS_URL && env.GAS_SECRET) {
    if (!GAS_RE.test(env.GAS_URL.trim())) throw new Error("O segredo GAS_URL não é um endereço de app da Web do Google (…/macros/s/…/exec).");
    const res = await f(env.GAS_URL.trim(), { method: "POST", redirect: "follow", headers: { "Content-Type": "text/plain;charset=utf-8" },
      body: JSON.stringify({ segredo: env.GAS_SECRET, to: [para], name: nome, subject: assunto, text: texto, ...(html ? { html } : {}) }) });
    const txt = await res.text(); let j = null; try { j = JSON.parse(txt); } catch { /* página de erro do Google */ }
    if (!j) throw new Error("O script do Google não respondeu como esperado (guia ENVIO-EMAIL).");
    if (!j.ok) throw new Error(j.error ? `Google: ${j.error}` : "O Google recusou o envio.");
    return;
  }
  if (env.BREVO_API_KEY && env.BREVO_SENDER) {
    const res = await f(BREVO_URL, { method: "POST", headers: { "api-key": env.BREVO_API_KEY, "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ sender: { name: nome, email: env.BREVO_SENDER }, to: [{ email: para }], subject: assunto, textContent: texto, ...(html ? { htmlContent: html } : {}) }) });
    if (!res.ok) throw new Error(`O Brevo recusou o envio (código ${res.status}).`);
    return;
  }
  throw new Error("Envio por e-mail não configurado (segredos GAS_URL e GAS_SECRET; guia ENVIO-EMAIL).");
}

/* meta/perfil das contas (opções de e-mail) */
async function perfisDe(env, f, userIds) {
  const ids = userIds.filter((u) => UUID.test(u));
  if (!ids.length) return {};
  const l = (await rest(env, f, "GET", `docs?select=user_id,data&id=eq.meta%2Fperfil&deleted=is.false&user_id=in.(${ids.join(",")})`)) || [];
  return Object.fromEntries(l.map((r) => [r.user_id, r.data && typeof r.data === "object" ? r.data : {}]));
}
async function contaEmail(env, f, uid) {
  const res = await f(`${env.SUPABASE_URL}/auth/v1/admin/users/${uid}`, { headers: { apikey: env.SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}` } });
  if (!res.ok) return "";
  const u = await res.json();
  return u && typeof u.email === "string" ? u.email : "";
}
/* destino: e-mail de Meus dados ou, sem ele, o da conta; só contas de ENVIO_USUARIOS */
async function destinoDe(env, f, uid, perfil) {
  const conta = await contaEmail(env, f, uid);
  if (!conta || !permitidos(env).includes(conta.toLowerCase())) return "";
  const pe = perfil && typeof perfil.email === "string" ? perfil.email.trim() : "";
  return pe && EMAIL_RE.test(pe) ? pe : conta;
}
const appLink = (perfil, id) => {
  const u = perfil && typeof perfil.appUrl === "string" ? perfil.appUrl.trim() : "";
  if (!/^https:\/\/[^\s"'<>]+$/.test(u) || u.length > 300) return "";
  return id ? u + (u.includes("?") ? "&" : "?") + "t=" + encodeURIComponent(id) : u;
};

/* datas no fuso do Brasil */
const pad = (n) => String(n).padStart(2, "0");
export const hojeBR = (agora = new Date()) => new Intl.DateTimeFormat("en-CA", { timeZone: TZ, year: "numeric", month: "2-digit", day: "2-digit" }).format(agora);
export const horaBR = (agora = new Date()) => +new Intl.DateTimeFormat("en-GB", { timeZone: TZ, hour: "2-digit", hourCycle: "h23" }).format(agora);
const fmtBR = (k) => { const [y, m, d] = k.split("-"); return `${d}/${m}/${y}`; };
const fmtHora = (iso) => { try { return new Intl.DateTimeFormat("pt-BR", { timeZone: TZ, day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" }).format(new Date(iso)); } catch { return ""; } };
const parseYmd = (s) => { const [y, m, d] = s.split("-").map(Number); return new Date(Date.UTC(y, m - 1, d)); };
const DIAS = ["dom", "seg", "ter", "qua", "qui", "sex", "sáb"];
const diaCurto = (k) => DIAS[parseYmd(k).getUTCDay()] + " " + fmtBR(k).slice(0, 5);

/* recorrência (mesma regra do app: occursOn / recOn) */
const FREQS = ["daily", "weekdays", "weekly", "monthly"];
const isRec = (t) => !!(t && t.repeat && FREQS.includes(t.repeat.freq) && t.due);
function occursOn(t, key) {
  const r = t.repeat, d = parseYmd(key), w = d.getUTCDay();
  if (r.freq === "daily") return true;
  if (r.freq === "weekdays") return w >= 1 && w <= 5;
  if (r.freq === "weekly") return (Array.isArray(r.days) && r.days.length ? r.days : [parseYmd(t.due).getUTCDay()]).includes(w);
  if (r.freq === "monthly") { const md = r.day || parseYmd(t.due).getUTCDate(), last = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 0)).getUTCDate(); return d.getUTCDate() === Math.min(md, last); }
  return false;
}
const recClosed = (t, key) => (t.doneDates || []).includes(key) || (t.skipDates || []).includes(key);
const recOn = (t, key) => isRec(t) && !t.done && (key === t.due || (key > t.due && occursOn(t, key) && !recClosed(t, key)));

/* "minhas" tarefas (mesma regra do app: isMine) — sem responsável ou com "eu" entre os responsáveis */
function ehMinha(t, id, projetos) {
  let outro = false;
  for (const g of Array.isArray(t.tags) ? t.tags : []) {
    const p = projetos[g]; if (!p) continue;
    const l = p.atrib && Array.isArray(p.atrib[id]) ? p.atrib[id] : [];
    if (!l.length) continue;
    if (l.includes("eu")) return true;
    outro = true;
  }
  return !outro;
}
async function docsDe(env, f, uid) {
  const out = [];
  for (let off = 0; off < 200000; off += 1000) {
    const q = `docs?select=id,data&user_id=eq.${uid}&deleted=eq.false&or=${encodeURIComponent("(id.like.tasks/*,id.like.projects/*)")}&order=id.asc&limit=1000&offset=${off}`;
    const rows = (await rest(env, f, "GET", q)) || [];
    out.push(...rows);
    if (rows.length < 1000) break;
  }
  return out;
}
/* tarefas do aviso diário: atrasadas e de hoje (prazo hoje, Meu Dia de hoje ou ocorrência de hoje das recorrentes) */
export function tarefasDoAviso(rows, td) {
  const projetos = {}, tarefas = [];
  for (const r of rows) {
    if (!r.data || typeof r.data !== "object") continue;
    if (r.id.startsWith("projects/")) projetos[r.id.slice(9)] = r.data;
    else if (r.id.startsWith("tasks/")) tarefas.push({ id: r.id.slice(6), ...r.data });
  }
  const hoje = [], atrasadas = [];
  for (const t of tarefas) {
    if (!t || typeof t.title !== "string" || t.done === true || !ehMinha(t, t.id, projetos)) continue;
    const myDay = typeof t.myDay === "string" ? t.myDay : "";
    if (isRec(t)) { if (myDay !== "no:" + td && (recOn(t, td) || myDay === td)) hoje.push(t); continue; }
    if (myDay === td || (t.due === td && myDay !== "no:" + td)) hoje.push(t);
    else if (typeof t.due === "string" && t.due < td) atrasadas.push(t);
  }
  const ord = (a, b) => (a.priority || 2) - (b.priority || 2) || (b.importance || 2) - (a.importance || 2) || String(a.due || "9").localeCompare(String(b.due || "9")) || a.title.localeCompare(b.title, "pt-BR");
  return { hoje: hoje.sort(ord), atrasadas: atrasadas.sort((a, b) => String(a.due).localeCompare(String(b.due)) || ord(a, b)) };
}
const marca = (t) => [t.priority === 1 ? "P1" : "", t.importance === 3 ? "★" : ""].filter(Boolean).join(" ");
export function avisoTexto(av, td, link) {
  const linha = (t, comPrazo) => "• " + oneLine(t.title) + (comPrazo && t.due ? " (prazo " + diaCurto(t.due) + ")" : "") + (marca(t) ? " · " + marca(t) : "");
  const partes = [`Suas tarefas de hoje, ${diaCurto(td)}.`, ""];
  partes.push(`HOJE (${av.hoje.length})`, ...(av.hoje.length ? av.hoje.map((t) => linha(t, false)) : ["Nada para hoje."]), "");
  if (av.atrasadas.length) partes.push(`ATRASADAS (${av.atrasadas.length})`, ...av.atrasadas.map((t) => linha(t, true)), "");
  if (link) partes.push("Abrir a agenda: " + link, "");
  partes.push("Aviso diário da Agenda de Tarefas. Para desligar: Configurações › Lembretes e avisos por e-mail.");
  const li = (t, comPrazo) => `<li style="margin:3px 0">${esc(oneLine(t.title))}${comPrazo && t.due ? ` <span style="color:#c0392b">· prazo ${esc(diaCurto(t.due))}</span>` : ""}${marca(t) ? ` <b style="color:#F0643C">${esc(marca(t))}</b>` : ""}</li>`;
  const html = `<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#1f2328;max-width:600px">
<p>Suas tarefas de hoje, <b>${esc(diaCurto(td))}</b>.</p>
<h3 style="margin:16px 0 6px;font-size:15px">Hoje (${av.hoje.length})</h3>${av.hoje.length ? `<ul style="padding-left:20px;margin:0">${av.hoje.map((t) => li(t, false)).join("")}</ul>` : `<p style="color:#666">Nada para hoje.</p>`}
${av.atrasadas.length ? `<h3 style="margin:16px 0 6px;font-size:15px;color:#c0392b">Atrasadas (${av.atrasadas.length})</h3><ul style="padding-left:20px;margin:0">${av.atrasadas.map((t) => li(t, true)).join("")}</ul>` : ""}
${link ? `<p style="margin-top:18px"><a href="${esc(link)}" style="background:#F0643C;color:#fff;text-decoration:none;padding:8px 14px;border-radius:8px">Abrir a agenda</a></p>` : ""}
<p style="color:#888;font-size:12px;margin-top:18px">Aviso diário da Agenda de Tarefas. Para desligar: Configurações › Lembretes e avisos por e-mail.</p></div>`;
  return { texto: partes.join("\n"), html };
}
export function lembreteTexto(r, t, link) {
  const titulo = oneLine((t && t.title) || r.title || "Tarefa");
  const quando = fmtHora(r.remind_at);
  const prazo = t && typeof t.due === "string" && /^\d{4}-\d{2}-\d{2}$/.test(t.due) ? diaCurto(t.due) : "";
  const notas = t && typeof t.notes === "string" ? t.notes.trim().slice(0, 1500) : "";
  const texto = [`Lembrete: ${titulo}`, quando ? `Hora do lembrete: ${quando}` : "", prazo ? `Prazo: ${prazo}` : "", notas ? `\nAnotações:\n${notas}` : "",
    link ? `\nAbrir a tarefa: ${link}` : "", "\nLembrete da Agenda de Tarefas. Para desligar: Configurações › Lembretes e avisos por e-mail."].filter(Boolean).join("\n");
  const html = `<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#1f2328;max-width:600px">
<p style="font-size:16px"><b>${esc(titulo)}</b></p>
${quando ? `<p style="margin:4px 0;color:#555">Hora do lembrete: ${esc(quando)}</p>` : ""}${prazo ? `<p style="margin:4px 0;color:#555">Prazo: ${esc(prazo)}</p>` : ""}
${notas ? `<p style="white-space:pre-wrap;margin-top:12px">${esc(notas)}</p>` : ""}
${link ? `<p style="margin-top:18px"><a href="${esc(link)}" style="background:#F0643C;color:#fff;text-decoration:none;padding:8px 14px;border-radius:8px">Abrir a tarefa</a></p>` : ""}
<p style="color:#888;font-size:12px;margin-top:18px">Lembrete da Agenda de Tarefas. Para desligar: Configurações › Lembretes e avisos por e-mail.</p></div>`;
  return { assunto: "Lembrete: " + titulo.slice(0, 180), texto, html };
}

/* e-mails dos lembretes vencidos (rows de lembretes_pendentes) para as contas com perfil.emailLembrete */
async function lembretesPorEmail(env, f, rows) {
  if (!emailConfigurado(env) || !permitidos(env).length) return 0;
  const perfis = await perfisDe(env, f, [...new Set(rows.map((r) => r.user_id))]);
  const quer = rows.filter((r) => perfis[r.user_id] && perfis[r.user_id].emailLembrete === true);
  if (!quer.length) return 0;
  const destinos = {};
  for (const uid of new Set(quer.map((r) => r.user_id))) destinos[uid] = await destinoDe(env, f, uid, perfis[uid]);
  let n = 0;
  for (const r of quer) {
    const para = destinos[r.user_id]; if (!para) continue;
    try {
      const l = (await rest(env, f, "GET", `docs?select=data&user_id=eq.${r.user_id}&id=eq.${encodeURIComponent(r.doc_id)}`)) || [];
      const t = l[0] && l[0].data, id = String(r.doc_id).replace(/^tasks\//, "");
      const m = lembreteTexto(r, t, appLink(perfis[r.user_id], id));
      await enviarEmail(env, f, para, m.assunto, m.texto, m.html); n++;
    } catch (e) { console.error("e-mail do lembrete falhou", e?.message || e); }
  }
  return n;
}
/* aviso diário: uma vez por dia, a partir da hora escolhida (horário de Brasília) */
async function avisosDiarios(env, f, agora = new Date()) {
  if (!emailConfigurado(env) || !permitidos(env).length) return 0;
  const td = hojeBR(agora), hora = horaBR(agora);
  const l = (await rest(env, f, "GET", `docs?select=user_id,data&id=eq.meta%2Fperfil&deleted=is.false&data->>emailAviso=eq.true`)) || [];
  const prontos = l.filter((r) => { const h = Number.isInteger(r.data && r.data.emailHora) && r.data.emailHora >= 5 && r.data.emailHora <= 10 ? r.data.emailHora : 7; return hora >= h; });
  if (!prontos.length) return 0;
  const ja = new Set(((await rest(env, f, "GET", `push_sent?select=user_id&doc_id=eq.aviso-diario&remind_at=eq.${td}&user_id=in.(${prontos.map((r) => r.user_id).filter((u) => UUID.test(u)).join(",")})`)) || []).map((r) => r.user_id));
  let n = 0;
  for (const r of prontos) {
    if (ja.has(r.user_id) || !UUID.test(r.user_id)) continue;
    // marca antes de enviar: se o envio falhar, não tenta de novo a cada minuto
    await rest(env, f, "POST", "push_sent", [{ user_id: r.user_id, doc_id: "aviso-diario", remind_at: td }], { Prefer: "resolution=ignore-duplicates,return=minimal" });
    try {
      const para = await destinoDe(env, f, r.user_id, r.data); if (!para) continue;
      const av = tarefasDoAviso(await docsDe(env, f, r.user_id), td);
      const m = avisoTexto(av, td, appLink(r.data, ""));
      await enviarEmail(env, f, para, `Agenda · ${diaCurto(td)}: ${av.hoje.length} para hoje` + (av.atrasadas.length ? `, ${av.atrasadas.length} atrasada(s)` : ""), m.texto, m.html); n++;
    } catch (e) { console.error("aviso diário falhou", e?.message || e); }
  }
  return n;
}

export async function dispatch(env, f = fetch) {
  const rows = (await rest(env, f, "POST", "rpc/lembretes_pendentes", {})) || [];
  let sent = 0, emails = 0, avisos = 0;
  if (rows.length) {
    const subs = await subsOf(env, f, [...new Set(rows.map((r) => r.user_id))]);
    for (const r of rows) {
      const mine = subs.filter((s) => s.user_id === r.user_id);
      const out = await deliver(env, f, mine, { title: "Lembrete", body: r.title || "Tarefa", id: String(r.doc_id).replace(/^tasks\//, ""), at: r.remind_at });
      sent += out.sent;
    }
    await rest(env, f, "POST", "push_sent", rows.map((r) => ({ user_id: r.user_id, doc_id: r.doc_id, remind_at: r.remind_at })),
      { Prefer: "resolution=ignore-duplicates,return=minimal" });
    try { emails = await lembretesPorEmail(env, f, rows); } catch (e) { console.error("lembretes por e-mail", e?.message || e); }
  }
  try { avisos = await avisosDiarios(env, f); } catch (e) { console.error("avisos diários", e?.message || e); }
  const old = new Date(Date.now() - 7 * 86400e3).toISOString();
  await rest(env, f, "DELETE", `push_sent?sent_at=lt.${encodeURIComponent(old)}`, undefined, { Prefer: "return=minimal" });
  return { due: rows.length, sent, emails, avisos };
}

async function userFromToken(env, f, token) {
  const res = await f(`${env.SUPABASE_URL}/auth/v1/user`, { headers: { apikey: env.SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${token}` } });
  if (!res.ok) return null;
  const u = await res.json();
  return u && u.id ? u : null;
}
const safeEq = (a, b) => {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
};
const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { ...CORS, "Content-Type": "application/json" } });

export async function handle(req, env, f = fetch) {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
  if (!env.VAPID_PUBLIC_KEY || !env.VAPID_PRIVATE_KEY) return json({ error: "Segredos VAPID não configurados." }, 500);
  if (req.method === "GET") return json({ publicKey: env.VAPID_PUBLIC_KEY });
  if (req.method !== "POST") return json({ error: "Método não permitido." }, 405);
  try {
    const cron = req.headers.get("x-cron-secret");
    if (cron) {
      if (!env.CRON_SECRET || !safeEq(cron, env.CRON_SECRET)) return json({ error: "Não autorizado." }, 401);
      return json(await dispatch(env, f));
    }
    const auth = req.headers.get("authorization") || "";
    const token = auth.replace(/^Bearer\s+/i, "");
    const user = token ? await userFromToken(env, f, token) : null;
    if (!user) return json({ error: "Entre na sua conta para testar." }, 401);
    let body = {}; try { body = await req.json(); } catch { /* vazio */ }
    if (body.action === "test-email") {   // v34: e-mail de teste
      if (!emailConfigurado(env)) return json({ error: "Envio por e-mail não configurado no servidor (segredos GAS_URL e GAS_SECRET; guia ENVIO-EMAIL)." }, 500);
      if (!user.email || !permitidos(env).includes(String(user.email).toLowerCase())) return json({ error: "Esta conta não está autorizada a receber e-mails (segredo ENVIO_USUARIOS)." }, 403);
      const perfis = await perfisDe(env, f, [user.id]);
      const para = await destinoDe(env, f, user.id, perfis[user.id] || {});
      if (!para) return json({ error: "Não foi possível achar o e-mail da conta." }, 400);
      try {
        await enviarEmail(env, f, para, "Teste: lembretes por e-mail da Agenda", "Os lembretes e avisos por e-mail da Agenda de Tarefas estão funcionando.",
          `<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px">Os lembretes e avisos por e-mail da <b>Agenda de Tarefas</b> estão funcionando.</div>`);
      } catch (e) { return json({ error: String(e?.message || e) }, 502); }
      return json({ ok: true, para });
    }
    if (body.action !== "test") return json({ error: "Ação desconhecida." }, 400);
    const subs = await subsOf(env, f, [user.id]);
    const out = await deliver(env, f, subs, { title: "Lembrete de teste", body: "As notificações da Agenda estão funcionando neste aparelho.", id: "" });
    return json({ devices: subs.length, ...out });
  } catch (e) {
    console.error(e);
    return json({ error: "Falha ao processar os lembretes." }, 500);
  }
}

if (typeof Deno !== "undefined") {
  Deno.serve((req) => handle(req, Deno.env.toObject()));
}

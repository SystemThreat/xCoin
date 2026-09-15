// Shared helpers for NerdMiner MD (popup + background + options).
const real = (typeof browser !== 'undefined' && browser.storage) ? browser : (typeof chrome !== 'undefined' && chrome.storage) ? chrome : null;
// Outside an extension (demo/QA page) fall back to localStorage + window.open so the popup still renders.
export const B = real || {
  storage: { local: { get: async (k) => { const o = {}; (Array.isArray(k) ? k : [k]).forEach(x => { const v = localStorage.getItem('md.' + x); if (v != null) o[x] = JSON.parse(v); }); return o; }, set: async (o) => { for (const k in o) localStorage.setItem('md.' + k, JSON.stringify(o[k])); } } },
  tabs: { create: ({ url }) => window.open(url, '_blank') }, runtime: { sendMessage: async () => {}, openOptionsPage: () => window.open('options.html', '_blank') }, alarms: { create() {}, onAlarm: { addListener() {} } }, notifications: { create() {} }, action: {},
};
// pool: the rehearsal stratum endpoint NerdMiner connects to; the popup's start hint is built from it. Switch to the mainnet pool once genesis is mined.
export const DEFAULTS = { site: 'https://minedifferent.com', cliUrl: 'http://127.0.0.1:47475', token: '', pool: '172.96.186.49:3335' };
export const TOKEN_FILE = '~/Library/Application Support/NerdMiner/companion-token';
// The companion token is exactly 32 hex characters (StatsServer generates and compares the bare token).
export const TOKEN_RE = /^[0-9a-fA-F]{32}$/;
// Accepts "127.0.0.1:47475", "http://127.0.0.1:47475/" etc. The stats server routes by exact path, so no trailing slash.
export function normalizeUrl(u, def) {
  u = String(u || '').trim(); if (!u) return def;
  if (!/^https?:\/\//i.test(u)) u = (/^https:/i.test(def) ? 'https://' : 'http://') + u;
  return u.replace(/\/+$/, '');
}

export async function getCfg() {
  const s = await B.storage.local.get(['site', 'cliUrl', 'token']);
  return { site: normalizeUrl(s.site, DEFAULTS.site), cliUrl: normalizeUrl(s.cliUrl, DEFAULTS.cliUrl), token: String(s.token || '').trim() };
}
export async function cliStats(cfg) {
  // The extension needs no token: NerdMiner 4.1 admits the X-NerdMiner-MD mark, which a web
  // page can never send (the miner's CORS preflight does not allow it). A token, if one is
  // pasted, rides along for older miners that still require it.
  const headers = { 'X-NerdMiner-MD': '1' };
  if (cfg.token) {
    if (!TOKEN_RE.test(cfg.token)) throw new Error('bad token');
    headers.Authorization = 'Bearer ' + cfg.token;
  }
  const r = await fetch(cfg.cliUrl + '/stats', { headers, cache: 'no-store' });
  if (r.status === 401) throw new Error(cfg.token ? 'bad token' : 'old miner');
  if (!r.ok) throw new Error('cli ' + r.status);
  return r.json();
}
export async function site(cfg, path, opts = {}) {
  // No custom headers: a non-safelisted header would force a CORS preflight the Worker does not answer. Presence passes ?via=extension instead.
  const signal = (typeof AbortSignal !== 'undefined' && AbortSignal.timeout) ? AbortSignal.timeout(8000) : undefined;
  const r = await fetch(cfg.site + path, { credentials: real ? 'include' : 'omit', cache: 'no-store', signal, ...opts });
  const ct = r.headers.get('content-type') || '';
  return { status: r.status, body: ct.includes('json') ? await r.json() : await r.text() };
}
export function fmtHash(h) {
  if (!h || h <= 0) return '0 H/s';
  const u = ['H/s', 'kH/s', 'MH/s', 'GH/s']; let i = 0; while (h >= 1000 && i < u.length - 1) { h /= 1000; i++; }
  return (h >= 100 ? h.toFixed(0) : h >= 10 ? h.toFixed(1) : h.toFixed(2)) + ' ' + u[i];
}
export function fmtUptime(s) { s = Math.max(0, s | 0); const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60); return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m ${s % 60}s`; }
// Binary units with the IEC suffix, matching the miner's own "4.00 GiB" format.
export function fmtBytes(b) { if (!b) return '—'; const u = ['B', 'KiB', 'MiB', 'GiB']; let i = 0; while (b >= 1024 && i < 3) { b /= 1024; i++; } return b.toFixed(i >= 3 ? 2 : 0) + ' ' + u[i]; }

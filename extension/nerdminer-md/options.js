// NerdMiner MD — options page. Lives in its own file: the MV3 extension_pages CSP (script-src 'self') never runs an inline script.
import { B, getCfg, cliStats, DEFAULTS, TOKEN_FILE, normalizeUrl, fmtHash } from './common.js';
const $ = id => document.getElementById(id);
// The token is 32 hex characters. A paste of the whole "Companion token: …" line is fine, only the token is kept; an empty field clears it.
const readToken = () => { const raw = $('token').value.trim(); if (!raw) return ''; const m = raw.match(/[0-9a-fA-F]{32}/); if (!m) throw new Error('not a token · it is 32 hex characters, kept in ' + TOKEN_FILE); return m[0]; };
const cliUrlField = () => normalizeUrl($('cliUrl').value, DEFAULTS.cliUrl);
const siteField = () => normalizeUrl($('site').value, DEFAULTS.site);
const wake = () => { try { Promise.resolve(B.runtime.sendMessage({ type: 'tick' })).catch(() => {}); } catch {} };
(async () => { const c = await getCfg(); $('token').value = c.token; $('cliUrl').value = c.cliUrl; $('site').value = c.site; })();
$('save').onclick = async () => {
  let token; try { token = readToken(); } catch (e) { $('state').textContent = e.message; return; }
  const cliUrl = cliUrlField(), site = siteField();
  $('token').value = token; $('cliUrl').value = cliUrl; $('site').value = site; // show exactly what was stored
  await B.storage.local.set({ token, cliUrl, site });
  $('state').textContent = 'saved'; wake();
};
$('test').onclick = async () => {
  let token; try { token = readToken(); } catch (e) { $('state').textContent = 'failed: ' + e.message; return; }
  const cliUrl = cliUrlField(); $('cliUrl').value = cliUrl;
  $('state').textContent = 'testing…';
  try {
    const s = await cliStats({ token, cliUrl });
    $('state').textContent = `ok · NerdMiner ${s.version}${s.worker ? ' · ' + s.worker : ''} · ${fmtHash(s.hashrate_hps)}`;
  } catch (e) {
    // A TypeError here means nothing answered (connection refused), not a bad reply.
    $('state').textContent = (e instanceof TypeError)
      ? `failed: nothing answering at ${cliUrl} · is NerdMiner running, and not with --no-stats? It prints "Companion stats: http://127.0.0.1:<port>/stats" at startup; that port must match the stats URL above.`
      : 'failed: ' + (e.message || e);
  }
};

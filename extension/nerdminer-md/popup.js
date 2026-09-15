import { B, getCfg, cliStats, site, fmtHash, fmtUptime, fmtBytes, DEFAULTS, TOKEN_FILE } from './common.js';
const $ = id => document.getElementById(id);
const demo = new URLSearchParams(location.search).get('demo') === '1';
let cfg, me = null, lastId = 0, hist = [], blocksSeen = null, chatOk = false, chatStarted = false;
// /stats reports the machine id of the chain; show it the way the site does.
const NET = { 'testnet-a': 'testnet A rehearsal', mainnet: 'mainnet', regtest: 'regtest' };
const netName = n => NET[n] || n || '';
const START_CMD = `./NerdMiner txa1r… --pool ${DEFAULTS.pool} --worker mymac`;

function esc(s) { return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function open(url) { B.tabs.create({ url }); }
function spark() {
  const c = $('spark'), x = c.getContext('2d'); x.clearRect(0, 0, c.width, c.height);
  if (hist.length < 2) return; const max = Math.max(...hist, 1);
  x.fillStyle = '#c7ff2e'; const w = c.width / 60;
  hist.slice(-60).forEach((v, i) => { const h = Math.max(2, v / max * (c.height - 4)); x.fillRect(i * w, c.height - h, Math.max(1, w - 1), h); });
}
function renderStats(s) {
  const h = s.hashrate_hps || 0; hist.push(h); if (hist.length > 60) hist.shift(); spark();
  $('hr').textContent = fmtHash(h); $('hr').className = 'hr' + (h > 0 ? '' : ' off');
  $('eyebrow').textContent = (s.worker ? s.worker + ' · ' : '') + netName(s.network) + (s.mode ? ' · ' + s.mode : '');
  $('sub').textContent = `${s.gpu || ''}${s.dag_traffic_gbs ? ' · ' + s.dag_traffic_gbs.toFixed(1) + ' GB/s DAG traffic' : ''}`; $('sub').title = '';
  $('blocks').textContent = s.blocks_found ?? '—'; $('blocksub').textContent = s.last_block_height ? 'last height ' + s.last_block_height : 'this run';
  $('acc').textContent = s.accepted ?? '—'; $('rej').textContent = s.rejected ?? '—'; $('diff').textContent = s.difficulty != null ? Number(s.difficulty).toPrecision(3) : '—';
  $('up').textContent = fmtUptime(s.uptime_s); $('dag').textContent = (s.dag_bytes ? fmtBytes(s.dag_bytes) : '—') + (s.dag_epoch != null ? ' · ep ' + s.dag_epoch : '');
  $('best').textContent = s.best_share_bits != null ? s.best_share_bits + ' bits' : '—';
  $('meta').classList.remove('cmd'); $('meta').title = ''; $('meta').textContent = `${s.pool || ''} · ${s.last_event || ''}`;
  if (blocksSeen != null && s.blocks_found > blocksSeen) { $('blocks').style.background = '#fff'; setTimeout(() => $('blocks').style.background = '', 1500); }
  blocksSeen = s.blocks_found;
}
// Each failure names its own cause: no token yet, a rejected token, an HTTP error from the stats server, or nothing listening.
// .sub stays one line (the hero is fixed-height); the longer hint goes in the .meta line and the tooltips.
function renderNoMiner(err) {
  const http = /^cli (\d+)$/.exec(err || '');
  const host = cfg.cliUrl.replace(/^https?:\/\//, '');
  const tokenErr = err === 'old miner' || err === 'bad token';
  $('hr').textContent = err === 'old miner' ? 'UPDATE' : err === 'bad token' ? 'BAD TOKEN' : http ? 'HTTP ' + http[1] : 'OFFLINE';
  $('hr').className = 'hr off'; $('eyebrow').textContent = 'YOUR RIG';
  $('sub').textContent = err === 'old miner' ? 'this NerdMiner wants a token · update it, or paste the token in Options'
    : err === 'bad token' ? 'token rejected · clear it or check Options'
    : http ? `${host} answered ${http[1]}`
    : `nothing answering at ${host}`;
  $('sub').title = (tokenErr || http) ? '' : 'NerdMiner is not running, was started with --no-stats, or listens on another --stats-port (set it in Options)';
  const m = $('meta'); m.classList.add('cmd');
  if (tokenErr) { m.textContent = 'token: ' + TOKEN_FILE; m.title = 'NerdMiner 4.1 needs no token for this extension. An older miner prints one at startup and keeps it in this file: cat ' + TOKEN_FILE.replace(' ', '\\ '); }
  else if (http) { m.textContent = 'check the stats URL in Options'; m.title = ''; }
  else { m.textContent = START_CMD; m.title = `testnet A rehearsal: ./NerdMiner <your txa1r… address> --pool ${DEFAULTS.pool} --worker mymac (xpa1r… and the mainnet pool once genesis is mined)`; }
}
async function pollStats() {
  if (demo) { const t = Date.now() / 1000; renderStats({ hashrate_hps: 1.0e3 + Math.sin(t) * 1e2, worker: 'demo', network: 'demo', mode: 'solo', gpu: 'demo rig (sample numbers)', dag_traffic_gbs: 0, blocks_found: 0, last_block_height: 0, accepted: 12, rejected: 0, difficulty: 0.001, uptime_s: 600, dag_bytes: 4294967296, dag_epoch: 0, best_share_bits: 20, pool: 'demo', last_event: 'share accepted' }); return; }
  try { renderStats(await cliStats(cfg)); } catch (e) { renderNoMiner(e.message); }
}
function line(m) {
  const t = new Date(m.ts * 1000), hh = String(t.getHours()).padStart(2, '0') + ':' + String(t.getMinutes()).padStart(2, '0');
  return `<div class="cl"><span class="ct">${hh}</span><a class="cn${m.role === 'founder' ? ' founder' : ''}" href="${cfg.site}/u/${m.address}" target="_blank">${esc(m.name)}</a>${m.badge ? `<span class="pill">${m.badge}</span>` : ''}<span class="cb">${esc(m.body)}</span></div>`;
}
// online = signed-in members seen in the last 2 minutes (site, chat, or this extension); rigs_mining comes from the explorer.
function counts(d) {
  const rm = d.rigs_mining, rigs = rm == null ? '— rigs' : rm + (rm === 1 ? ' rig' : ' rigs');
  $('who').textContent = `${rigs} mining · ${d.online ?? 0} in chat`; $('onl').textContent = `${d.online ?? '—'} in chat`; $('onl').classList.toggle('live', (d.online || 0) > 0);
}
async function pollChat() {
  if (demo) { $('log').innerHTML = [{ ts: Date.now() / 1000, name: '@demo', role: 'miner', badge: '', body: 'sample message (demo mode)' }, { ts: Date.now() / 1000, name: '@demo2', role: 'miner', badge: '', body: 'sample message (demo mode)' }].map(line).join(''); counts({ online: 2, rigs_mining: 2 }); return; }
  try {
    // The room is readable everywhere: signed-out users get the public feed, posting still needs a session.
    const authed = !!(me && me.signed_in);
    const r = await site(cfg, (authed ? '/api/chat' : '/api/chat/public') + '?since=' + lastId);
    if (r.status === 401) {
      if (!authed) return;
      me = null; applyMe(); // session ended mid-popup: read-only, never a wall over messages already shown
      return pollChat();
    }
    if (r.status !== 200) return;
    const d = r.body; if (d.messages && d.messages.length) { if ($('log').querySelector('p')) $('log').innerHTML = ''; const bottom = $('log').scrollHeight - $('log').scrollTop - $('log').clientHeight < 40; d.messages.forEach(m => { $('log').insertAdjacentHTML('beforeend', line(m)); lastId = Math.max(lastId, m.id); }); if (bottom) $('log').scrollTop = $('log').scrollHeight; }
    else if (!lastId && $('log').querySelector('p')) $('log').innerHTML = '<p class="muted">Quiet in here. Say something.</p>';
    counts(d);
  } catch {}
}
function applyMe() {
  const signed = !!(me && me.signed_in); chatOk = !!(signed && me.chat && me.chat.post);
  $('openLogin').textContent = signed ? me.name : 'Sign in'; $('openLogin').href = signed ? `${cfg.site}/u/${me.address}` : `${cfg.site}/login`;
  $('msg').disabled = !chatOk; $('say').querySelector('button').disabled = !chatOk;
  $('msg').placeholder = !signed ? 'sign in to chat' : chatOk ? (me.chat.links ? 'say something (280 max)' : 'say something · links unlock with a badge') : 'chat locked';
  // why chat is locked can be a long sentence; it gets its own line rather than a placeholder that clips
  showWhy(signed && !chatOk && me.chat ? me.chat.why : '');
}
function showWhy(t) { $('why').textContent = t || ''; $('why').hidden = !t; }
async function loadMe() {
  if (demo) { me = { signed_in: true, name: '@david', chat: { post: true, links: true } }; }
  else { try { const r = await site(cfg, '/api/me'); me = r.status === 200 ? r.body : null; } catch { me = null; } }
  applyMe();
}
function startChat() { if (chatStarted) return; chatStarted = true; loadMe().then(() => { pollChat(); setInterval(pollChat, 3000); }); }
// Without the host permission (revoked, or set to "on click") every site call fails silently; offer the grant instead of a blank log.
async function siteGranted() {
  try { return !B.permissions || !B.permissions.contains ? true : await B.permissions.contains({ origins: [cfg.site + '/*'] }); } catch { return true; }
}
$('say').addEventListener('submit', async e => {
  e.preventDefault(); const v = $('msg').value.trim(); if (!v || !chatOk) return;
  let r; try { r = await site(cfg, '/api/chat', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ body: v }) }); }
  catch { r = { status: 0, body: { error: 'MineDifferent unreachable · try again' } }; }
  if (r.status === 200) { $('msg').value = ''; showWhy(''); pollChat(); }
  else showWhy((r.body && r.body.error) || 'error'); // keep the text: slow mode, limits and the link gate are worth a resend or an edit
});
$('msg').addEventListener('input', () => { if (!$('why').hidden && chatOk) showWhy(''); });
(async () => {
  cfg = await getCfg();
  $('brandLink').onclick = $('openSite').onclick = e => { e.preventDefault(); open(cfg.site); };
  $('openLogin').onclick = e => { e.preventDefault(); open($('openLogin').href); };
  $('openOpts').onclick = e => { e.preventDefault(); B.runtime.openOptionsPage(); };
  // Local stats first and on their own clock; the site round-trip never gates them.
  pollStats(); setInterval(pollStats, 2000);
  if (demo || await siteGranted()) startChat();
  else {
    $('log').innerHTML = `<p class="muted">This extension needs access to ${esc(cfg.site.replace(/^https?:\/\//, ''))} for the room and presence. <button class="btn" id="grant" type="button">Grant access</button></p>`;
    $('grant').onclick = async () => { try { if (await B.permissions.request({ origins: [cfg.site + '/*'] })) { $('log').innerHTML = '<p class="muted">loading…</p>'; startChat(); } } catch {} };
  }
  try { Promise.resolve(B.runtime.sendMessage({ type: 'tick' })).catch(() => {}); } catch {}
})();

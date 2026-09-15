// NerdMiner MD — background: badge, block notifications, presence heartbeat.
import { B, getCfg, cliStats, site, fmtHash } from './common.js';

const ALARM = 'md-tick';
B.runtime.onInstalled.addListener(() => { B.alarms.create(ALARM, { periodInMinutes: 0.5 }); tick(); });
B.runtime.onStartup.addListener(() => { B.alarms.create(ALARM, { periodInMinutes: 0.5 }); tick(); });
B.alarms.onAlarm.addListener(a => { if (a.name === ALARM) tick(); });
B.runtime.onMessage.addListener((msg, _s, reply) => { if (msg && msg.type === 'tick') { tick().then(() => reply({ ok: true })); return true; } });

// Badge text never exceeds 4 characters (the browser clips longer text); thresholds sit at the rounding points so toFixed cannot spill into a fifth.
function badgeHash(h) {
  if (!(h > 0)) return '…';
  if (h < 999.5) return h.toFixed(0);                        // "999"
  if (h < 999_500) return (h / 1e3).toFixed(0) + 'k';        // "999k"
  if (h < 9_950_000) return (h / 1e6).toFixed(1) + 'M';      // "9.9M"
  if (h < 999_500_000) return (h / 1e6).toFixed(0) + 'M';    // "999M"
  if (h < 9_950_000_000) return (h / 1e9).toFixed(1) + 'G';  // "9.9G"
  return (h / 1e9).toFixed(0) + 'G';                         // "999G"
}
// `online` is signed-in members seen in the last 2 minutes (site, chat, or this extension); `rigs_mining` comes from the explorer.
function roomLine(o) { const rm = o.rigs_mining; const rigs = rm == null ? '? rigs' : rm + (rm === 1 ? ' rig' : ' rigs'); return `${rigs} mining · ${o.online ?? 0} in chat`; }

async function tick() {
  const cfg = await getCfg();
  let badge = '', color = '#c7ff2e', title = 'NerdMiner MD';
  // 1. miner
  try {
    const s = await cliStats(cfg);
    const last = await B.storage.local.get(['lastBlocks', 'lastUptime', 'lastRunStart']);
    let prev = last.lastBlocks;
    // blocks_found counts this NerdMiner process only. ts - uptime_s identifies the run (60 s tolerance: uptime_s is refreshed
    // from inside the mining loop, so it can drift a few seconds during a stall), so a restart resets the notification baseline.
    const runStart = (typeof s.ts === 'number' && typeof s.uptime_s === 'number') ? s.ts - s.uptime_s : null;
    const restarted = (typeof last.lastUptime === 'number' && s.uptime_s < last.lastUptime)
      || (runStart != null && typeof last.lastRunStart === 'number' && runStart - last.lastRunStart > 60)
      || (typeof prev === 'number' && s.blocks_found < prev);
    if (restarted) prev = 0;
    if (typeof prev === 'number' && s.blocks_found > prev) {
      B.notifications.create('block-' + Date.now(), { type: 'basic', iconUrl: 'icons/icon128.png', title: 'BLOCK FOUND', message: `${s.worker || 'your rig'} sealed block ${s.last_block_height ?? ''} · ${s.blocks_found} this run`, priority: 2 });
    }
    await B.storage.local.set({ lastBlocks: s.blocks_found, lastUptime: s.uptime_s, lastRunStart: runStart, lastStats: s, lastStatsAt: Date.now() });
    const h = s.hashrate_hps || 0;
    badge = badgeHash(h);
    title = `NerdMiner ${fmtHash(h)} · ${s.accepted} accepted · ${s.blocks_found} blocks`;
  } catch (e) {
    const err = String(e.message || e);
    await B.storage.local.set({ lastStats: null, lastStatsErr: err, lastStatsAt: Date.now() });
    color = '#111111';
    if (err === 'old miner') { badge = '!'; title = 'NerdMiner MD · this NerdMiner wants a token · update it or paste the token in Options'; }
    else if (err === 'bad token') { badge = '!'; title = 'NerdMiner MD · token rejected · check Options'; }
    else if (/^cli \d+$/.test(err)) { badge = 'off'; title = `NerdMiner MD · stats server answered HTTP ${err.slice(4)} · check the stats URL in Options`; }
    else { badge = 'off'; title = `NerdMiner MD · rig offline · nothing answering at ${cfg.cliUrl.replace(/^https?:\/\//, '')}`; }
  }
  // 2. site presence (only if signed in); the room counts go in the hover title when no miner is reachable, never on the badge
  try {
    const me = await site(cfg, '/api/me');
    const signedIn = me.status === 200 && me.body && me.body.signed_in;
    await B.storage.local.set({ me: signedIn ? me.body : null });
    const o = signedIn ? await site(cfg, '/api/presence?via=extension', { method: 'POST' }) : await site(cfg, '/api/online');
    if (o.status === 200 && o.body) {
      await B.storage.local.set({ online: o.body });
      if (badge === 'off') title = `NerdMiner MD · rig offline · ${roomLine(o.body)}`;
    }
  } catch {}
  try { await B.action.setBadgeText({ text: badge }); await B.action.setBadgeBackgroundColor({ color }); await B.action.setBadgeTextColor?.({ color: color === '#111111' ? '#ffffff' : '#101600' }); await B.action.setTitle({ title }); } catch {}
}

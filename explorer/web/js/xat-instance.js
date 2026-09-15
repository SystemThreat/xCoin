/* xat-instance.js — SingleInstanceManager for the xCoin acid-lime sites.
   Shared across the xCoin sites; edit the canonical copy and fan it out

   One active instance per browser profile per origin.
     Layer 1  Web Locks      navigator.locks "APP_SINGLE_INSTANCE"  — the authority (atomic, released on unload/crash)
     Layer 2  BroadcastChannel "APP_INSTANCE_CHANNEL"               — PRIMARY_ALIVE / DUPLICATE_OPENED / FOCUS_PRIMARY / PRIMARY_FOCUSED …
     Layer 3  Service worker   /xat-sw.js                            — WindowClient.focus() for the "Return to Open App" button
     Fallback (no Web Locks) BroadcastChannel claim + localStorage heartbeat with stale-primary detection.

   Configure on the script tag:
     <script src="/xat-instance.js" data-site="xat_miner" data-title="xCoinMiner" data-mode="strict"></script>
       data-mode="strict"  — duplicate tab does NOT initialize the app; it shows the duplicate screen (miner).
       data-mode="focus"   — (default) page renders everywhere, but the live services (chat, polling, presence) run in
                             exactly one tab: the visible one. A visible tab asks a hidden primary to yield.

   API (window.XATInstance):
     .ready                       Promise<"primary"|"duplicate"|"dormant">
     .status / .id / .site / .mode
     .whenPrimary(fn)             run fn now if primary, and every time this tab (re)becomes primary
     .onRelease(fn)               run fn when this tab stops being primary (services must stop here)
     .onChange(fn) → unsubscribe  every transition
     .focusPrimary() → Promise<boolean>
     .takeover() → Promise<boolean>   make THIS tab primary (the other tab releases, stops its services)
     .loadScript(src)             append a <script> (used to defer the chat widget until primary)
*/
(function () {
  'use strict';
  if (window.XATInstance) return;

  var LOCK = 'APP_SINGLE_INSTANCE';
  var CHANNEL = 'APP_INSTANCE_CHANNEL';
  var LS_PRIMARY = 'xat.instance.primary';    // fallback heartbeat  {id, ts}
  var LS_CLAIM = 'xat.instance.claim';        // fallback tie-break
  var HEARTBEAT_MS = 5000;                    // fallback only
  var STALE_MS = HEARTBEAT_MS * 2.5;
  var RETRY_MS = 3000;                        // waiting duplicate re-tries the lock (covers crashed primary)
  var REFRESH_GRACE_MS = 1500;                // after PRIMARY_RELEASED, give a refreshing primary time to reclaim

  var tag = document.currentScript || document.querySelector('script[data-site]');
  var ds = (tag && tag.dataset) || {};
  var SITE = ds.site || 'xat_app';
  var TITLE = ds.title || document.title || 'this app';
  var MODE = ds.mode === 'strict' ? 'strict' : 'focus';
  var DEBUG = false;
  try { DEBUG = localStorage.getItem('xat.debug') === '1' || /[?&]xatdebug/.test(location.search); } catch (e) {}

  var ID = (function () {
    try { return crypto.randomUUID().slice(0, 8); } catch (e) {}
    return Math.random().toString(36).slice(2, 10);
  })();

  function info() { try { console.info.apply(console, ['[xat-instance ' + ID + ']'].concat([].slice.call(arguments))); } catch (e) {} }
  function dbg() { if (!DEBUG) return; try { console.debug.apply(console, ['[xat-instance ' + ID + ']'].concat([].slice.call(arguments))); } catch (e) {} }

  var hasLocks = !!(navigator.locks && navigator.locks.request);
  var hasBC = typeof BroadcastChannel === 'function';
  var hasSW = ('serviceWorker' in navigator) && (location.protocol === 'https:' || location.hostname === 'localhost');

  // ───────────────────────────── state
  var M = {
    id: ID, site: SITE, mode: MODE, title: TITLE,
    status: 'pending',          // pending | primary | duplicate | dormant
    primaryId: null,            // last known primary instance id (from PRIMARY_ALIVE)
    everPrimary: false,
    fallback: !hasLocks
  };
  var listeners = [], primaryFns = [], releaseFns = [];
  var releaseHold = null;       // resolve → releases the Web Lock
  var retryTimer = null, graceTimer = null, hbTimer = null;
  var resolveReady;
  M.ready = new Promise(function (r) { resolveReady = r; });

  function setStatus(s, why) {
    if (M.status === s) return;
    var prev = M.status; M.status = s;
    document.documentElement.setAttribute('data-xat', s);
    if (s === 'primary') info('primary acquired' + (why ? ' (' + why + ')' : '') + (M.fallback ? ' [fallback mode]' : ''));
    else if (s === 'duplicate') info('duplicate detected — another tab is primary');
    else if (s === 'dormant') info('dormant — live services run in another tab' + (why ? ' (' + why + ')' : ''));
    listeners.slice().forEach(function (fn) { try { fn(s, prev); } catch (e) { dbg('listener error', e); } });
    if (s === 'primary') {
      if (M.everPrimary && MODE === 'strict' && prev !== 'pending') { location.reload(); return; }
      M.everPrimary = true;
      primaryFns.slice().forEach(function (fn) { try { fn(); } catch (e) { dbg('primary fn error', e); } });
    }
    if (prev === 'primary') releaseFns.slice().forEach(function (fn) { try { fn(why); } catch (e) { dbg('release fn error', e); } });
  }

  // ───────────────────────────── broadcast channel
  var bc = null;
  function send(type, extra) {
    if (!bc) return;
    var m = { type: type, from: ID, site: SITE, status: M.status, ts: Date.now() };
    if (extra) for (var k in extra) m[k] = extra[k];
    try { bc.postMessage(m); } catch (e) {}
  }
  if (hasBC) {
    try { bc = new BroadcastChannel(CHANNEL); } catch (e) { bc = null; }
  }
  if (bc) bc.onmessage = function (ev) {
    var m = ev.data || {}; if (!m.type || m.from === ID) return;
    dbg('←', m.type, 'from', m.from);
    switch (m.type) {
      case 'PRIMARY_ALIVE':
        M.primaryId = m.from;
        if (M.status === 'primary' && m.from !== ID) {
          // Two primaries can only happen in fallback mode; lowest id keeps it.
          if (M.fallback && m.from < ID) { info('fallback: conflicting primary, yielding'); release('conflict'); }
        }
        break;
      case 'DUPLICATE_OPENED':
        if (M.status === 'primary') { send('PRIMARY_ALIVE'); tryWindowFocus(); }
        break;
      case 'FOCUS_PRIMARY':
        if (M.status === 'primary') {
          info('focus requested by', m.from);
          tryWindowFocus();
          setTimeout(function () { send('PRIMARY_FOCUSED', { to: m.from, ok: document.hasFocus() }); }, 60);
        }
        break;
      case 'PRIMARY_FOCUSED':
        if (m.to === ID && focusWaiter) focusWaiter(!!m.ok);
        break;
      case 'YIELD_REQUEST':                       // focus mode: a visible tab wants the services
        if (M.status === 'primary') {
          if (document.visibilityState === 'hidden') release('yield');
          else send('PRIMARY_ALIVE');
        }
        break;
      case 'TAKEOVER':                            // explicit user action in another tab
        if (M.status === 'primary') release('takeover');
        break;
      case 'PRIMARY_RELEASED':
        M.primaryId = null;
        if (M.status === 'duplicate' || M.status === 'dormant') {
          var wait = m.reason === 'yield' || m.reason === 'takeover' ? 30 : REFRESH_GRACE_MS;
          if (MODE === 'focus' && document.visibilityState === 'hidden' && m.reason !== 'takeover') break; // hidden tabs don't need the services
          clearTimeout(graceTimer); graceTimer = setTimeout(function () { tryAcquire('primary released'); }, wait);
        }
        break;
      case 'WHO_IS_PRIMARY':
        if (M.status === 'primary') send('PRIMARY_ALIVE');
        break;
    }
  };

  function tryWindowFocus() { try { window.focus(); } catch (e) {} }

  // ───────────────────────────── service worker (layer 3)
  var swReg = null;
  function swActive() {
    if (!hasSW) return Promise.resolve(null);
    return navigator.serviceWorker.ready.then(function (reg) { return reg.active || null; }).catch(function () { return null; });
  }
  function swHello() {
    if (M.status !== 'primary') return;
    swActive().then(function (sw) { if (sw) try { sw.postMessage({ type: 'PRIMARY_HELLO', id: ID, site: SITE }); } catch (e) {} });
  }
  if (hasSW) {
    try {
      navigator.serviceWorker.register('/xat-sw.js', { scope: '/' }).then(function (reg) { swReg = reg; dbg('sw registered'); swHello(); }).catch(function (e) { dbg('sw register failed', e); });
      navigator.serviceWorker.addEventListener('controllerchange', swHello);
      navigator.serviceWorker.addEventListener('message', function (ev) {
        var m = ev.data || {};
        if (m.type === 'WHO_IS_PRIMARY' && M.status === 'primary') swHello();
        if (m.type === 'FOCUS_RESULT' && swFocusWaiter) swFocusWaiter(m);
      });
    } catch (e) {}
  }

  // ───────────────────────────── acquisition
  function acquireWithLocks(reason) {
    return new Promise(function (resolve) {
      var granted = false;
      navigator.locks.request(LOCK, { ifAvailable: true }, function (lock) {
        if (!lock) { resolve(false); return; }
        granted = true;
        resolve(true);
        // hold the lock for the life of the page (or until release())
        return new Promise(function (r) { releaseHold = r; }).then(function () { dbg('lock released'); });
      }).catch(function (e) { dbg('locks.request failed', e); if (!granted) resolve(null); });
    });
  }

  // Fallback: BroadcastChannel liveness probe + localStorage heartbeat with stale detection.
  function acquireFallback() {
    return new Promise(function (resolve) {
      var alive = false, ls = null;
      try { ls = JSON.parse(localStorage.getItem(LS_PRIMARY) || 'null'); } catch (e) {}
      var fresh = ls && ls.id !== ID && (Date.now() - ls.ts) < STALE_MS;
      var off = bc ? function (ev) { if (ev.data && ev.data.type === 'PRIMARY_ALIVE' && ev.data.from !== ID) alive = true; } : null;
      if (bc) bc.addEventListener('message', off);
      send('WHO_IS_PRIMARY');
      setTimeout(function () {
        if (bc) bc.removeEventListener('message', off);
        if (alive) return resolve(false);
        if (fresh && bc) return resolve(false);        // heartbeat says alive but nobody answered? trust the channel
        if (fresh && !bc) return resolve(false);       // no channel: trust the heartbeat until stale
        // nobody alive → claim with a tie-break so simultaneous tabs pick one
        try {
          var c = null; try { c = JSON.parse(localStorage.getItem(LS_CLAIM) || 'null'); } catch (e) {}
          if (!c || Date.now() - c.ts > 2000) localStorage.setItem(LS_CLAIM, JSON.stringify({ id: ID, ts: Date.now() }));
          setTimeout(function () {
            var w = null; try { w = JSON.parse(localStorage.getItem(LS_CLAIM) || 'null'); } catch (e) {}
            resolve(!w || w.id === ID);
          }, 150);
        } catch (e) { resolve(true); }                 // no storage at all: fail open
      }, 300);
    });
  }
  function heartbeat() { try { localStorage.setItem(LS_PRIMARY, JSON.stringify({ id: ID, ts: Date.now() })); } catch (e) {} }
  function startHeartbeat() { heartbeat(); clearInterval(hbTimer); hbTimer = setInterval(heartbeat, HEARTBEAT_MS); }
  function stopHeartbeat() {
    clearInterval(hbTimer); hbTimer = null;
    try { var ls = JSON.parse(localStorage.getItem(LS_PRIMARY) || 'null'); if (ls && ls.id === ID) localStorage.removeItem(LS_PRIMARY); } catch (e) {}
  }

  var acquiring = false;
  function tryAcquire(reason) {
    if (M.status === 'primary' || acquiring) return Promise.resolve(M.status === 'primary');
    acquiring = true;
    var p = hasLocks ? acquireWithLocks(reason) : acquireFallback();
    return p.then(function (ok) {
      acquiring = false;
      if (ok === null) { M.fallback = true; info('Web Locks failed, using fallback'); return acquireFallback().then(function (ok2) { return finish(ok2, reason); }); }
      return finish(ok, reason);
    });
  }
  function finish(ok, reason) {
    if (ok) {
      clearInterval(retryTimer); retryTimer = null; clearTimeout(graceTimer);
      if (M.fallback) startHeartbeat();
      hideDuplicateScreen();
      setStatus('primary', reason);
      send('PRIMARY_ALIVE');
      swHello();
      return true;
    }
    if (M.status === 'pending' || M.status === 'primary') {
      setStatus(MODE === 'strict' ? 'duplicate' : 'dormant', reason);
      send('DUPLICATE_OPENED');
      if (MODE === 'strict') showDuplicateScreen();
      else if (document.visibilityState === 'visible') send('YIELD_REQUEST');
    }
    scheduleRetry();
    return false;
  }
  function scheduleRetry() {
    clearInterval(retryTimer); retryTimer = null;
    // strict duplicates always wait for the primary to go away; focus-mode tabs only while visible
    if (MODE === 'strict' || document.visibilityState === 'visible') retryTimer = setInterval(function () { tryAcquire('retry'); }, RETRY_MS);
  }

  function release(why) {
    if (M.status !== 'primary') return;
    if (M.fallback) stopHeartbeat();
    if (releaseHold) { releaseHold(); releaseHold = null; }
    setStatus(MODE === 'strict' ? 'duplicate' : 'dormant', why);
    info('primary released (' + why + ')');
    send('PRIMARY_RELEASED', { reason: why });
    if (why === 'unload') return;
    if (MODE === 'strict') showDuplicateScreen(why === 'takeover' ? 'You moved ' + TITLE + ' to another tab.' : null);
    scheduleRetry();
  }

  // ───────────────────────────── focus + takeover (user activation lives in the click)
  var focusWaiter = null, swFocusWaiter = null;
  function focusPrimary() {
    info('focus requested');
    var viaChannel = new Promise(function (r) {
      focusWaiter = r; send('FOCUS_PRIMARY'); setTimeout(function () { r(false); }, 400);
    });
    var viaSW = swActive().then(function (sw) {
      if (!sw) return false;
      return new Promise(function (r) {
        swFocusWaiter = function (m) { r(!!m.ok); };
        try { sw.postMessage({ type: 'FOCUS_PRIMARY', requester: ID, primary: M.primaryId, site: SITE }); } catch (e) { r(false); }
        setTimeout(function () { r(false); }, 1500);
      });
    });
    return Promise.all([viaChannel, viaSW]).then(function (rs) {
      var ok = rs[0] || rs[1];
      info('focus ' + (ok ? 'succeeded' : 'not confirmed') + ' (channel=' + rs[0] + ', sw=' + rs[1] + ')');
      focusWaiter = swFocusWaiter = null;
      if (ok && M.status !== 'primary') { try { window.close(); } catch (e) {} }   // only works for script-opened tabs; harmless otherwise
      return ok;
    });
  }
  function takeover() {
    if (M.status === 'primary') return Promise.resolve(true);
    info('takeover requested');
    send('TAKEOVER');
    return new Promise(function (r) { setTimeout(r, 120); }).then(function () { return tryAcquire('takeover'); })
      .then(function (ok) { if (!ok) return new Promise(function (r) { setTimeout(r, 400); }).then(function () { return tryAcquire('takeover'); }); return ok; });
  }

  // ───────────────────────────── duplicate screen (strict mode) — acid-lime, no implementation details
  var CSS = 'html[data-xat="pending"][data-xat-mode="strict"] body{visibility:hidden}' +
    'html[data-xat="duplicate"] body>:not(#xat-dup){display:none!important}' +
    '#xat-dup{position:fixed;inset:0;z-index:2147483600;display:grid;place-items:center;background:#fff;color:#0a0a0a;font-family:"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace;padding:20px}' +
    '#xat-dup .card{max-width:640px;width:100%;border:2px solid #111;background:#fff;padding:clamp(24px,4vw,44px);box-shadow:8px 8px 0 #c7ff2e}' +
    '#xat-dup .eyebrow{margin:0 0 14px;color:#101600;background:#c7ff2e;display:inline-block;padding:2px 8px;border:1px solid #111;font-size:.72rem;font-weight:900;letter-spacing:.12em;text-transform:uppercase}' +
    '#xat-dup h1{margin:0 0 14px;font-size:clamp(1.6rem,4.5vw,2.6rem);line-height:.95;letter-spacing:-.06em;text-transform:uppercase;font-weight:900}' +
    '#xat-dup p{margin:0 0 10px;line-height:1.5}#xat-dup .muted{color:#626262;font-size:.85rem}' +
    '#xat-dup .row{display:flex;gap:10px;flex-wrap:wrap;margin-top:22px}' +
    '#xat-dup button{min-height:48px;border:2px solid #111;border-radius:0;padding:10px 18px;background:#fff;color:#0a0a0a;font:inherit;font-weight:900;text-transform:uppercase;letter-spacing:.04em;cursor:pointer}' +
    '#xat-dup button.primary{background:#c7ff2e;color:#101600}#xat-dup button:hover{box-shadow:6px 6px 0 #c7ff2e}#xat-dup button.primary:hover{box-shadow:6px 6px 0 #111}' +
    '#xat-dup .hint{margin-top:16px;min-height:1.4em;font-size:.85rem;font-weight:900;text-transform:uppercase;letter-spacing:.04em}';
  var styleEl = document.createElement('style'); styleEl.textContent = CSS;
  (document.head || document.documentElement).appendChild(styleEl);
  document.documentElement.setAttribute('data-xat', 'pending');
  document.documentElement.setAttribute('data-xat-mode', MODE);

  function esc(s) { return String(s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function showDuplicateScreen(note) {
    function render() {
      var el = document.getElementById('xat-dup');
      if (!el) { el = document.createElement('div'); el.id = 'xat-dup'; document.body.appendChild(el); }
      el.innerHTML = '<div class="card"><p class="eyebrow">' + esc(TITLE) + '</p><h1>Application already open</h1>' +
        '<p>' + esc(TITLE) + ' is already running in another tab.</p>' +
        (note ? '<p>' + esc(note) + '</p>' : '') +
        '<p class="muted">Only one active instance is allowed at a time.</p>' +
        '<div class="row"><button class="primary" id="xat-return">Return to Open App</button><button id="xat-here">Continue here instead</button></div>' +
        '<div class="hint" id="xat-hint"></div></div>';
      var hint = document.getElementById('xat-hint');
      document.getElementById('xat-return').onclick = function () {
        hint.textContent = 'switching…';
        focusPrimary().then(function (ok) {
          hint.textContent = ok ? 'switched — you can close this tab' : 'your browser did not allow switching tabs automatically. look for the tab named ' + TITLE + ', or continue here.';
        });
      };
      document.getElementById('xat-here').onclick = function () {
        hint.textContent = 'taking over…';
        takeover().then(function (ok) { if (!ok) hint.textContent = 'the other tab did not hand over. try again.'; });
      };
    }
    if (document.body) render(); else document.addEventListener('DOMContentLoaded', render, { once: true });
  }
  function hideDuplicateScreen() { var el = document.getElementById('xat-dup'); if (el) el.remove(); }

  // ───────────────────────────── lifecycle
  window.addEventListener('pagehide', function () {
    if (M.status === 'primary') release('unload');
    clearInterval(retryTimer); clearTimeout(graceTimer); clearInterval(hbTimer);
  });
  window.addEventListener('pageshow', function (ev) { if (ev.persisted) tryAcquire('bfcache restore'); });   // back-forward cache: lock was released on pagehide
  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState !== 'visible') { if (MODE === 'focus' && M.status !== 'primary') { clearInterval(retryTimer); retryTimer = null; } return; }
    if (M.status === 'primary') return;
    tryAcquire('became visible').then(function (ok) { if (!ok && MODE === 'focus') send('YIELD_REQUEST'); });
  });
  // A backgrounded primary stays primary: visibility/blur never release the lock.

  // Safety valve: if the decision somehow never lands (broken API), reveal the page and run as primary.
  var safety = setTimeout(function () { if (M.status === 'pending') { M.fallback = true; info('decision timed out, running as primary [fallback mode]'); finish(true, 'timeout'); } }, 2500);

  // ───────────────────────────── public API
  M.whenPrimary = function (fn) { primaryFns.push(fn); if (M.status === 'primary') { try { fn(); } catch (e) { dbg(e); } } return function () { var i = primaryFns.indexOf(fn); if (i >= 0) primaryFns.splice(i, 1); }; };
  M.onRelease = function (fn) { releaseFns.push(fn); return function () { var i = releaseFns.indexOf(fn); if (i >= 0) releaseFns.splice(i, 1); }; };
  M.onChange = function (fn) { listeners.push(fn); return function () { var i = listeners.indexOf(fn); if (i >= 0) listeners.splice(i, 1); }; };
  M.focusPrimary = focusPrimary;
  M.takeover = takeover;
  M.release = function (why) { release(why || 'manual'); };
  M.loadScript = function (src, attrs) { var s = document.createElement('script'); s.src = src; s.defer = true; if (attrs) for (var k in attrs) s.setAttribute(k, attrs[k]); (document.body || document.head).appendChild(s); return s; };
  M.isPrimary = function () { return M.status === 'primary'; };
  window.XATInstance = M;

  // decide before anything expensive runs
  tryAcquire('page load').then(function () { clearTimeout(safety); resolveReady(M.status); });
  M.ready.then(function (s) { dbg('ready:', s, 'locks=' + hasLocks, 'bc=' + !!bc, 'sw=' + hasSW); });
})();

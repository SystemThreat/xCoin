/* xat-sw.js — minimal service worker for the xCoin sites (single-instance focus helper).
   Shared across the xCoin sites; edit the canonical copy and fan it out
   No fetch handler, no caching: it never changes what the site serves.
   Its one job: on FOCUS_PRIMARY from a duplicate tab, find the primary WindowClient and focus() it. */
var primary = { id: null, client: null, ts: 0 };   // in-memory; the SW may be stopped, so pages re-HELLO on controllerchange

self.addEventListener('install', function (e) { self.skipWaiting(); });
self.addEventListener('activate', function (e) { e.waitUntil(self.clients.claim()); });

function windows() { return self.clients.matchAll({ type: 'window', includeUncontrolled: true }); }

function findPrimary(msg) {
  return windows().then(function (cs) {
    if (!cs.length) return null;
    // 1) the client that last said PRIMARY_HELLO
    var hit = null;
    if (primary.client) cs.forEach(function (c) { if (c.id === primary.client) hit = c; });
    if (hit) return hit;
    // 2) ask every window who is primary, wait briefly for a HELLO
    cs.forEach(function (c) { if (c.id !== msg.requesterClient) try { c.postMessage({ type: 'WHO_IS_PRIMARY' }); } catch (e) {} });
    return new Promise(function (resolve) {
      var t0 = Date.now();
      (function poll() {
        if (primary.client && Date.now() - primary.ts < 5000) {
          return windows().then(function (cs2) { var h = null; cs2.forEach(function (c) { if (c.id === primary.client) h = c; }); resolve(h); });
        }
        if (Date.now() - t0 > 600) return resolve(null);
        setTimeout(poll, 60);
      })();
    });
  });
}

self.addEventListener('message', function (e) {
  var m = e.data || {}; var src = e.source;
  if (m.type === 'PRIMARY_HELLO') { primary = { id: m.id, client: src && src.id, ts: Date.now() }; return; }
  if (m.type === 'STATE') {   // diagnostics for the debug console
    e.waitUntil(windows().then(function (cs) { try { src.postMessage({ type: 'STATE', primary: primary, me: src.id, windows: cs.map(function (c) { return { id: c.id, url: c.url, focused: c.focused, visibility: c.visibilityState }; }) }); } catch (e2) {} }));
    return;
  }
  if (m.type === 'FOCUS_PRIMARY') {
    m.requesterClient = src && src.id;
    e.waitUntil(findPrimary(m).then(function (c) {
      if (!c) return { ok: false, reason: 'no-primary' };
      if (c.id === m.requesterClient) return { ok: false, reason: 'self' };
      return c.focus().then(function (fc) { return { ok: !!(fc && fc.focused), reason: 'focused' }; })
        .catch(function (err) { return { ok: false, reason: String(err && err.name || err) }; });
    }).then(function (res) {
      try { src.postMessage({ type: 'FOCUS_RESULT', ok: res.ok, reason: res.reason }); } catch (e2) {}
    }));
  }
});

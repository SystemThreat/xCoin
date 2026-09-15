// Live overview: poll /api/stats, update the stat cards, draw the difficulty chart.
(function () {
  const $ = (s) => document.querySelector(s);
  function fmt(n) { return Number(n).toLocaleString(); }

  function drawChart(series) {
    const cv = $('#diffChart');
    if (!cv || !series || series.length < 2) return;
    const ctx = cv.getContext('2d');
    const w = cv.width = cv.clientWidth * 2;
    const h = cv.height = cv.clientHeight * 2;
    ctx.clearRect(0, 0, w, h);
    const ds = series.map(p => p.d);
    const mn = Math.min(...ds), mx = Math.max(...ds) || 1;
    const X = i => i / (series.length - 1) * w;
    const Y = v => (h - 10) - (mx === mn ? (h - 20) / 2 : ((v - mn) / (mx - mn)) * (h - 20));
    // area fill
    ctx.beginPath(); ctx.moveTo(0, h);
    series.forEach((p, i) => ctx.lineTo(X(i), Y(p.d)));
    ctx.lineTo(w, h); ctx.closePath();
    const g = ctx.createLinearGradient(0, 0, 0, h);
    g.addColorStop(0, 'rgba(255,26,60,.30)'); g.addColorStop(1, 'rgba(255,26,60,0)');
    ctx.fillStyle = g; ctx.fill();
    // glowing line
    ctx.beginPath();
    series.forEach((p, i) => i ? ctx.lineTo(X(i), Y(p.d)) : ctx.moveTo(X(i), Y(p.d)));
    ctx.lineWidth = 3; ctx.strokeStyle = '#ff2a46';
    ctx.shadowColor = '#ff1a3c'; ctx.shadowBlur = 18; ctx.stroke();
    ctx.shadowBlur = 0;
    // last point pip
    const lx = X(series.length - 1), ly = Y(ds[ds.length - 1]);
    ctx.fillStyle = '#fff'; ctx.beginPath(); ctx.arc(lx, ly, 4, 0, 7); ctx.fill();
  }

  let lastSeries = null;
  async function tick() {
    try {
      const d = await (await fetch('/api/stats', { cache: 'no-store' })).json();
      const set = (k, v) => { const e = document.querySelector(`[data-s="${k}"]`); if (e) e.textContent = v; };
      set('height', fmt(d.height));
      set('supply', fmt(Math.round(d.supply)));
      set('difficulty', d.difficulty < 1000 ? Number(d.difficulty).toFixed(4) : fmt(Math.round(d.difficulty)));
      set('hashrate', (d.hashrate / 1e9).toFixed(2));
      set('mempool', fmt(d.mempool));
      const dot = $('#liveDot'); if (dot) { dot.style.opacity = 1; setTimeout(() => dot.style.opacity = .3, 400); }
      lastSeries = d.series;
      drawChart(lastSeries);
    } catch (e) { /* keep last render */ }
  }

  if ($('#diffChart') || document.querySelector('[data-s]')) {
    tick();
    // Pause polling while the tab is hidden; resume (and refresh) on return.
    let timer = setInterval(tick, 8000);
    document.addEventListener('visibilitychange', () => {
      clearInterval(timer);
      if (!document.hidden) { tick(); timer = setInterval(tick, 8000); }
    });
    // Resize only redraws the existing chart (debounced) — no re-fetch.
    let rz;
    window.addEventListener('resize', () => {
      clearTimeout(rz);
      rz = setTimeout(() => { if (lastSeries) drawChart(lastSeries); }, 150);
    });
  }
})();

// ── Baseline : ce qui est appris (v12.68.0) ──────────────────────────────────
// Vue lecture seule : resume par cle (vhost / pays) puis grille 7 x 24 du profil
// appris (mediane par creneau, seuil d'alerte au survol). Rendu par textContent.
let bvState = { type: 'vhost', key: null };
const BV_DAYS = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'];

function bvEl(tag, text, cls) {
  const e = document.createElement(tag);
  if (text != null) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

function bvSlotLabel(how) {
  return t('baselineView.day.' + BV_DAYS[Math.floor(how / 24)]) + ' ' + String(how % 24).padStart(2, '0') + 'h';
}

async function baselineViewOpen(type) {
  bvState = { type, key: null };
  document.getElementById('bv-overlay').style.display = '';
  document.getElementById('bv-title').textContent = t(type === 'country' ? 'baselineView.titleCountry' : 'baselineView.titleVhost');
  document.getElementById('bv-th-key').textContent = t(type === 'country' ? 'baselineView.col.country' : 'baselineView.col.vhost');
  document.getElementById('bv-profile').textContent = '';
  const s = await api('/analyzer/baseline' + (type === 'country' ? '/country' : '')).catch(() => null);
  const note = document.getElementById('bv-note');
  note.textContent = '';
  if (s && s.reachable !== false) {
    ['baselineView.note.always', 'baselineView.note.slots', 'baselineView.note.alert'].forEach(k => {
      note.appendChild(bvEl('div', t(k, { min: 3, days: s.daysRequired })));
    });
    note.appendChild(bvEl('div', t('baselineView.note.since', {
      since: s.startedAt ? new Date(s.startedAt).toLocaleString() : '—',
      tracked: s.vhostsTracked, sporadic: s.sporadicKeys == null ? 0 : s.sporadicKeys }), 'ct-sub'));
  }
  const d = await api('/analyzer/baseline/keys?type=' + type).catch(() => null);
  const body = document.getElementById('bv-keys');
  body.textContent = '';
  if (!d || d.reachable === false) { note.appendChild(bvEl('div', t('baselineView.unreachable'))); return; }
  if (!d.keys.length) {
    const tr = bvEl('tr'); const td = bvEl('td', t('baselineView.empty')); td.colSpan = 5; tr.appendChild(td); body.appendChild(tr);
    return;
  }
  d.keys.forEach(k => {
    const tr = bvEl('tr'); tr.style.cursor = 'pointer';
    if (!k.relevant) tr.style.opacity = '.55';
    tr.appendChild(bvEl('td', k.key, 'ct-mono'));
    tr.appendChild(bvEl('td', k.weeklyEstimate.toLocaleString()));
    tr.appendChild(bvEl('td', k.peakPerHour.toLocaleString() + ' / h — ' + bvSlotLabel(k.peakHow)));
    tr.appendChild(bvEl('td', k.usableSlots + ' / 168'));
    tr.appendChild(bvEl('td', String(k.samples) + (k.relevant ? '' : ' ' + t('baselineView.sporadic'))));
    tr.addEventListener('click', () => baselineViewProfile(k.key));
    body.appendChild(tr);
  });
  baselineViewProfile(d.keys[0].key);
}

async function baselineViewProfile(key) {
  bvState.key = key;
  const box = document.getElementById('bv-profile');
  box.textContent = '';
  const p = await api('/analyzer/baseline/profile?type=' + bvState.type + '&key=' + encodeURIComponent(key)).catch(() => null);
  if (!p || p.reachable === false || !p.slots) { box.textContent = t('baselineView.unreachable'); return; }
  box.appendChild(bvEl('div', t('baselineView.profileOf', { key }), 'ctitle'));
  const max = Math.max(1, ...p.slots.filter(s => s.usable).map(s => s.median));
  const grid = bvEl('div'); grid.style.cssText = 'display:grid;grid-template-columns:34px repeat(24,1fr);gap:2px;margin-top:6px;font-size:10px';
  grid.appendChild(bvEl('div'));
  for (let h = 0; h < 24; h++) { const c = bvEl('div', h % 3 === 0 ? String(h) : '', 'ct-sub'); c.style.textAlign = 'center'; grid.appendChild(c); }
  for (let d = 0; d < 7; d++) {
    grid.appendChild(bvEl('div', t('baselineView.day.' + BV_DAYS[d]), 'ct-sub'));
    for (let h = 0; h < 24; h++) {
      const s = p.slots[d * 24 + h];
      const c = bvEl('div'); c.style.cssText = 'height:18px;border-radius:2px;background:var(--border)';
      if (s.samples > 0 && s.usable) {
        c.style.background = 'var(--blue, #3b82f6)';
        c.style.opacity = String(Math.max(0.15, s.median / max).toFixed(2));
        c.title = bvSlotLabel(d * 24 + h) + ' — ' + t('baselineView.tip.usable', { median: s.median, threshold: s.threshold, n: s.samples });
      } else if (s.samples > 0) {
        c.style.background = 'repeating-linear-gradient(45deg,var(--border),var(--border) 3px,transparent 3px,transparent 6px)';
        c.title = bvSlotLabel(d * 24 + h) + ' — ' + t('baselineView.tip.learning', { n: s.samples, min: p.minSamples });
      } else {
        c.title = bvSlotLabel(d * 24 + h) + ' — ' + t('baselineView.tip.none');
      }
      grid.appendChild(c);
    }
  }
  box.appendChild(grid);
  box.appendChild(bvEl('div', t('baselineView.legend', { sigma: p.sigma, min: p.minAbsoluteRequests }), 'ct-sub'));
}

function baselineViewClose() { document.getElementById('bv-overlay').style.display = 'none'; }

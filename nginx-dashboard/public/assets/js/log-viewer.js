'use strict';
/**
 * Page "Logs" (LOG VIEWER) — streaming SSE des fichiers de logs Nginx
 * (access/error/stream), filtrage, stats live, et ses fonctions utilitaires
 * (LOG HELPERS : drapeaux pays, raccourci User-Agent, popover géo-IP).
 * Extrait de public/index.html (voir CHANGELOG.md). countryFlag() est
 * également utilisée par analyzer.js (même scope global).
 *
 * pullGoAccessImage() vivait par erreur ici (sous le commentaire d'extraction
 * LOG HELPERS) alors qu'elle appartient à la fonctionnalité GoAccess —
 * rapatriée dans public/assets/js/goaccess.js (audit refactoring, voir
 * CHANGELOG.md).
 */
let activeSSE = null;
let logBuffer = [];       // all received lines (raw objects)
let logPaused = false;
let logStats = {s2:0, s3:0, s4:0, s5:0, total:0};
const MAX_BUFFER = 5000;
const MAX_RENDERED = 500; // DOM lines cap

let logFileMap = {}; let logFileIndex = 0;
async function loadLogFiles() {
  logFileMap = {}; logFileIndex = 0;
  const d = await api('/nginx-logs').catch(()=>null);
  const el = document.getElementById('log-file-list');
  if (!d || !d.files) {
    el.innerHTML = '<div style="padding:20px;color:var(--red);font-family:\'JetBrains Mono\',monospace;font-size:12px">Erreur — volume logs monté ?</div>';
    return;
  }
  document.getElementById('logv-count').textContent = d.files.length;
  if (!d.files.length) {
    el.innerHTML = '<div style="padding:20px;color:var(--text3);font-family:\'JetBrains Mono\',monospace;font-size:12px">Aucun fichier .log trouvé dans ' + h(d.dir) + '</div>';
    return;
  }

  // Group by type
  const byType = {};
  d.files.forEach(f => { if (!byType[f.type]) byType[f.type] = []; byType[f.type].push(f); });
  const typeLabel = { access: 'Accès', error: 'Erreur', stream: 'Stream' };
  const typeColor = { access: 'var(--green)', error: 'var(--red)', stream: 'var(--blue)' };

  el.innerHTML = Object.entries(byType).map(([type, files]) => `
    <div class="log-file-section">${typeLabel[type] || type}</div>
    ${files.map(f => `
      <div class="log-file-item" id="lfi-${(()=>{const i=logFileIndex++;logFileMap[i]=f;return i;})()}" onclick="openLogFile(this.id.slice(4))">
        <div class="lf-dot" style="background:${typeColor[f.type]||'var(--text3)'}"></div>
        <span class="lf-name" title="${h(f.path)}">${h(f.name)}</span>
        <span class="lf-size">${fmtB(f.size)}</span>
      </div>`).join('')}
  `).join('');
}

async function openLogFile(idxStr) {
  const idx = parseInt(idxStr);
  const f = logFileMap[idx];
  if (!f) return;
  const filePath = f.path, name = f.name;
  // Highlight selected item
  document.querySelectorAll('.log-file-item').forEach(el => el.classList.remove('active'));
  document.getElementById('lfi-'+idx)?.classList.add('active');

  // Stop previous SSE
  if (activeSSE) { activeSSE.close(); activeSSE = null; }
  logBuffer = [];
  logStats = {s2:0, s3:0, s4:0, s5:0, total:0};
  logPaused = false;

  document.getElementById('lv-title').textContent = name;
  document.getElementById('log-placeholder').style.display = 'none';
  document.getElementById('log-lines').style.display = 'flex';
  document.getElementById('log-lines').innerHTML = '';
  document.getElementById('btn-pause').disabled = false;
  document.getElementById('btn-pause').textContent = '⏸ Pause';
  setStreamStatus('connecting', 'Connexion…');
  updateStats();

  // Connect SSE — same-origin EventSource sends the session cookie
  // automatically (fix v12.21.1, SEC-06): no token needed in the URL, and
  // the dashboard no longer exposes one to fetch.
  const url = `/api/nginx-logs/stream?path=${encodeURIComponent(filePath)}&lines=150`;
  const es = new EventSource(url);
  activeSSE = es;

  es.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    if (msg.type === 'ready') {
      setStreamStatus('live', `Live — ${h(msg.file)}`);
    } else if (msg.type === 'rotated') {
      setStreamStatus('live', `Rotation détectée — ${h(msg.file)}`);
      appendSystemLine('⟳ Fichier roté / tronqué');
    } else if (msg.type === 'error') {
      setStreamStatus('paused', 'Erreur: ' + msg.message);
    } else if (msg.type === 'line') {
      ingestLine(msg);
    }
  };
  es.onerror = () => setStreamStatus('paused', 'Déconnecté — reconnexion…');
}

function ingestLine(line) {
  // Buffer management
  if (logBuffer.length >= MAX_BUFFER) logBuffer.shift();
  logBuffer.push(line);

  // Stats
  if (line.status) {
    const sc = String(line.status)[0];
    if (sc === '2') logStats.s2++;
    else if (sc === '3') logStats.s3++;
    else if (sc === '4') logStats.s4++;
    else if (sc === '5') logStats.s5++;
    logStats.total++;
  } else { logStats.total++; }

  if (!logPaused) {
    const filter = getFilter();
    if (!filter || matchesFilter(line, filter)) {
      appendLineDOM(line);
      if (document.getElementById('lv-autoscroll').checked) scrollBottom();
    }
  }
  updateStats();
}

function getFilter() {
  return {
    status: document.getElementById('lv-filter-status').value,
    text: document.getElementById('lv-filter-text').value.toLowerCase().trim()
  };
}

function matchesFilter(line, filter) {
  if (filter.status && line.status && !String(line.status).startsWith(filter.status)) return false;
  if (filter.text) {
    const raw = (line.raw || '').toLowerCase();
    if (!raw.includes(filter.text)) return false;
  }
  return true;
}

function appendLineDOM(line) {
  const container = document.getElementById('log-lines');
  // Cap DOM
  while (container.children.length >= MAX_RENDERED) container.removeChild(container.firstChild);

  const idx = logBuffer.length;
  const sc = line.status ? String(line.status)[0] : null;
  const cls = sc ? `ll-${sc}xx` : '';
  const scClass = sc ? `s${sc}` : '';

  let inner;
  if (line.request) {
    const parts = (line.request || '').split(' ');
    const method = parts[0] || '';
    const reqPath = parts[1] || '';
    inner = `
      <span class="ll-idx">${idx}</span>
      <span class="ll-time">${h(line.time||'')}</span>
      <span class="ll-status ${scClass}">${line.status||'?'}</span>
      ${line.vhost ? `<span class="ll-vhost" title="${h(line.vhost)}">${h(line.vhost)}</span>` : ''}
      <span class="ll-ip" title="${buildGeoTip(line)}">${h(line.ip||'')}${line.geo?.country?' '+countryFlag(line.geo.country):''}</span>
      <span class="ll-method">${h(method)}</span>
      <span class="ll-path" title="${h(reqPath)}">${h(reqPath)}</span>
      <span class="ll-bytes">${fmtB(line.bytes)}</span>
      ${line.ua && line.ua !== '-' ? `<span class="log-ua" title="${h(line.ua)}" onclick="showUaPopover(this,event)">${h(shortUA(line.ua))}</span>` : ''}`;
  } else {
    inner = `<span class="ll-idx">${idx}</span><span class="ll-raw">${h(line.raw||'')}</span>`;
  }

  const el = document.createElement('div');
  el.className = `log-line ${cls}`;
  el.innerHTML = inner;
  container.appendChild(el);
}

function appendSystemLine(msg) {
  const container = document.getElementById('log-lines');
  const el = document.createElement('div');
  el.className = 'log-line';
  el.innerHTML = `<span class="ll-idx">—</span><span class="ll-raw" style="color:var(--amber)">${h(msg)}</span>`;
  container.appendChild(el);
}

function scrollBottom() {
  const body = document.getElementById('log-stream-body');
  if (body) body.scrollTop = body.scrollHeight;
}

function applyFilters() {
  const container = document.getElementById('log-lines');
  container.innerHTML = '';
  const filter = getFilter();
  logBuffer.filter(l => !filter.status && !filter.text ? true : matchesFilter(l, filter))
    .slice(-MAX_RENDERED)
    .forEach(l => appendLineDOM(l));
  if (document.getElementById('lv-autoscroll').checked) scrollBottom();
}

function togglePause() {
  logPaused = !logPaused;
  const btn = document.getElementById('btn-pause');
  const body = document.getElementById('log-stream-body');
  btn.textContent = logPaused ? '▶ Reprendre' : '⏸ Pause';
  body.classList.toggle('paused', logPaused);
  const dot = document.getElementById('stream-dot');
  dot.className = 'stream-dot ' + (logPaused ? 'paused' : 'live');
  if (!logPaused) {
    applyFilters();
    if (document.getElementById('lv-autoscroll').checked) scrollBottom();
  }
}

function clearLogView() {
  logBuffer = [];
  logStats = {s2:0, s3:0, s4:0, s5:0, total:0};
  document.getElementById('log-lines').innerHTML = '';
  updateStats();
}

function setStreamStatus(state, txt) {
  const dot = document.getElementById('stream-dot');
  const stxt = document.getElementById('stream-status-txt');
  dot.className = 'stream-dot ' + (state === 'live' ? 'live' : state === 'connecting' ? '' : 'paused');
  stxt.textContent = txt;
}

function updateStats() {
  document.getElementById('lsb-2xx').textContent = logStats.s2;
  document.getElementById('lsb-3xx').textContent = logStats.s3;
  document.getElementById('lsb-4xx').textContent = logStats.s4;
  document.getElementById('lsb-5xx').textContent = logStats.s5;
  document.getElementById('lsb-total').textContent = logStats.total;
  document.getElementById('lsb-buf').textContent = logBuffer.length;
  document.getElementById('lv-linecount').textContent = logBuffer.length + ' lignes';
}

function countryFlag(iso) {
  if (!iso || iso.length !== 2) return '';
  const cp = [...iso.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65);
  return String.fromCodePoint(...cp);
}

function shortUA(ua) {
  if (!ua) return '';
  // Extract browser/bot name
  const m = ua.match(/(Chrome|Firefox|Safari|Edge|curl|python|bot|crawler|Go-http)/i);
  return m ? m[1] + '…' : ua.slice(0, 30) + (ua.length > 30 ? '…' : '');
}

// Click-to-expand for the truncated User-Agent column: a fixed-width slot
// (see .log-ua) still truncates a long UA string, and a native `title`
// tooltip is slow to appear, easy to miss and unusable on touch — this shows
// the full string in a small on-screen popover instead, with a one-click
// copy, positioned near whichever line was clicked and dismissed on the
// next click anywhere else.
let uaPopoverCloseHandler = null;
function showUaPopover(el, evt) {
  evt.stopPropagation();
  const full = el.getAttribute('title') || '';
  const pop  = document.getElementById('ua-popover');
  if (!pop) return;

  pop.textContent = '';
  const text = document.createElement('div');
  text.textContent = full;
  pop.appendChild(text);
  const copyLink = document.createElement('span');
  copyLink.className = 'uap-copy';
  copyLink.textContent = 'Copier';
  copyLink.onclick = (e) => {
    e.stopPropagation();
    // Fix (retour utilisateur v12.44.0) : `navigator.clipboard?.writeText(...)`
    // ne protege que l acces a `.writeText` — si `navigator.clipboard` est
    // absent (HTTP simple, hors contexte securise), l expression entiere vaut
    // `undefined`, et le `.then()` qui suit leve quand meme une TypeError
    // synchrone (jamais interceptee par le `.catch()` final). Voir
    // copyToClipboard() plus haut pour le detail et le repli execCommand.
    copyToClipboard(full).then((ok) => {
      if (!ok) return;
      copyLink.textContent = 'Copié ✓';
      setTimeout(() => { copyLink.textContent = 'Copier'; }, 1200);
    });
  };
  pop.appendChild(copyLink);

  const r = el.getBoundingClientRect();
  pop.style.display = 'block';
  // Measure after display:block so offsetWidth/Height are accurate, then
  // clamp so the popover never renders off the right or bottom edge.
  const pw = pop.offsetWidth, ph = pop.offsetHeight;
  let left = Math.min(r.left, window.innerWidth - pw - 12);
  let top  = r.bottom + 6;
  if (top + ph > window.innerHeight) top = Math.max(8, r.top - ph - 6);
  pop.style.left = Math.max(8, left) + 'px';
  pop.style.top  = top + 'px';

  if (uaPopoverCloseHandler) document.removeEventListener('click', uaPopoverCloseHandler);
  uaPopoverCloseHandler = () => { pop.style.display = 'none'; document.removeEventListener('click', uaPopoverCloseHandler); uaPopoverCloseHandler = null; };
  // Deferred so the click that opened the popover doesn't also close it.
  setTimeout(() => document.addEventListener('click', uaPopoverCloseHandler), 0);
}

function buildGeoTip(line) {
  const g = line.geo;
  if (!g) return h(line.ip || '');
  const parts = [line.ip];
  if (g.country) parts.push('Country: ' + g.country);
  if (g.city)    parts.push('City:    ' + g.city);
  if (g.asn)     parts.push('ASN:     ' + g.asn);
  if (g.org)     parts.push('Org:     ' + g.org);
  return parts.join('&#10;'); // \n in tooltip
}

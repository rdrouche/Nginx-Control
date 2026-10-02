// ── Administration > Conteneurs (v12.67.0) ───────────────────────────────────
// Liste + actions + logs en direct (SSE) des conteneurs du perimetre du
// dashboard. Tout le rendu passe par textContent (aucune donnee Docker n est
// injectee en HTML).
let ctState = { list: [], timer: null, es: null, logId: null, paused: false, lines: 0 };
const CT_MAX_LINES = 2000;

function ctEl(tag, text, cls) {
  const e = document.createElement(tag);
  if (text != null) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

function ctUptime(iso) {
  if (!iso || iso.startsWith('0001')) return '—';
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  const d = Math.floor(s / 86400), hh = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  if (d) return d + 'j ' + hh + 'h';
  if (hh) return hh + 'h ' + m + 'm';
  if (m) return m + 'm';
  return s + 's';
}

function ctBytes(n) {
  if (n == null) return '—';
  const u = ['B', 'KB', 'MB', 'GB']; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(i ? 1 : 0) + ' ' + u[i];
}

function ctSetMsg(text, isErr) {
  const m = document.getElementById('ct-msg');
  if (!m) return;
  m.textContent = text || '';
  m.style.color = isErr ? 'var(--red)' : 'var(--green)';
}

async function containersLoad() {
  await ctRefresh();
  if (ctState.timer) clearInterval(ctState.timer);
  ctState.timer = setInterval(() => {
    const page = document.getElementById('page-containers');
    if (!page || !page.classList.contains('active')) { ctStop(); return; }
    ctRefresh();
  }, 10000);
}

function ctStop() {
  if (ctState.timer) { clearInterval(ctState.timer); ctState.timer = null; }
  ctLogsClose();
}

async function ctRefresh() {
  const d = await api('/containers').catch(() => null);
  const body = document.getElementById('ct-tbody');
  if (!body) return;
  body.textContent = '';
  if (!d || !d.containers) {
    const tr = ctEl('tr'); const td = ctEl('td', t('containers.unavailable'));
    td.colSpan = 7; td.style.color = 'var(--amber)'; tr.appendChild(td); body.appendChild(tr);
    return;
  }
  ctState.list = d.containers;
  for (const c of d.containers) body.appendChild(ctRow(c));
}

function ctBtn(label, title, fn, danger) {
  const b = ctEl('button', label, 'btn sm' + (danger ? ' danger' : ''));
  b.title = title; b.style.marginRight = '4px';
  b.addEventListener('click', fn);
  return b;
}

function ctRow(c) {
  const tr = ctEl('tr');
  const name = ctEl('td');
  name.appendChild(ctEl('b', c.name));
  name.appendChild(ctEl('div', t('containers.role.' + c.role) + ' · ' + c.id, 'ct-sub'));
  tr.appendChild(name);
  tr.appendChild(ctEl('td', c.image, 'ct-mono'));
  const st = ctEl('td');
  const badge = ctEl('span', c.state + (c.health ? ' / ' + c.health : ''), 'badge ' + (c.running ? 'gn' : 'rd'));
  st.appendChild(badge);
  if (c.restartCount) st.appendChild(ctEl('div', t('containers.restarts', { n: c.restartCount }), 'ct-sub'));
  tr.appendChild(st);
  tr.appendChild(ctEl('td', c.running ? ctUptime(c.startedAt) : '—'));
  tr.appendChild(ctEl('td', c.stats && c.stats.cpuPercent != null ? c.stats.cpuPercent.toFixed(1) + ' %' : '—'));
  const mem = c.stats && c.stats.memUsedBytes != null ? ctBytes(c.stats.memUsedBytes) + (c.stats.memPercent != null ? " (" + c.stats.memPercent + " %)" : "") : '—';
  tr.appendChild(ctEl('td', mem));
  const act = ctEl('td');
  if (!c.running) act.appendChild(ctBtn('▶', t('containers.start'), () => ctAction(c, 'start')));
  if (c.running && c.canStop) act.appendChild(ctBtn('■', t('containers.stop'), () => ctAction(c, 'stop', true), true));
  act.appendChild(ctBtn('↻', t('containers.restart'), () => ctAction(c, 'restart', true)));
  act.appendChild(ctBtn('⬇', t('containers.update'), () => ctAction(c, 'update')));
  if (c.canRebuild) act.appendChild(ctBtn('⚒', t('containers.rebuild'), () => ctAction(c, 'rebuild', true), true));
  act.appendChild(ctBtn('☰', t('containers.logs'), () => ctLogsOpen(c)));
  tr.appendChild(act);
  return tr;
}

async function ctAction(c, action, confirmFirst) {
  if (confirmFirst && !confirm(t('containers.confirm.' + action, { name: c.name }))) return;
  ctSetMsg(t('containers.working', { action: t('containers.' + action), name: c.name }));
  const r = await api('/containers/action', { method: 'POST', body: JSON.stringify({ id: c.fullId, action }) }).catch(() => null);
  if (!r || !r.ok) { ctSetMsg((r && r.error) || t('common.error'), true); return; }
  let msg = t('containers.done', { action: t('containers.' + action), name: c.name });
  if (action === 'update') {
    msg = r.updated ? (r.recreated ? t('containers.updatedRecreated') : t('containers.updatedManual')) : t('containers.upToDate');
  }
  ctSetMsg(msg);
  setTimeout(ctRefresh, 1500);
}

// ── Logs en direct ───────────────────────────────────────────────────────────
function ctLogsOpen(c) {
  ctLogsClose();
  ctState.logId = c.fullId; ctState.paused = false; ctState.lines = 0;
  const panel = document.getElementById('ct-logs');
  panel.style.display = '';
  document.getElementById('ct-logs-title').textContent = c.name;
  document.getElementById('ct-logs-out').textContent = '';
  document.getElementById('ct-pause').textContent = t('containers.pause');
  const tail = parseInt(document.getElementById('ct-tail').value, 10) || 200;
  const es = new EventSource('/api/containers/logs/stream?id=' + encodeURIComponent(c.fullId) + '&tail=' + tail);
  ctState.es = es;
  es.onmessage = (ev) => {
    let m; try { m = JSON.parse(ev.data); } catch { return; }
    if (m.type === 'line') ctAppendLine(m.s, m.t);
    else if (m.type === 'end') { ctAppendLine('err', t('containers.streamEnded')); es.close(); }
    else if (m.type === 'error') { ctAppendLine('err', m.message); es.close(); }
  };
  es.onerror = () => { /* EventSource retente seul ; on ferme si le panneau est ferme */ };
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function ctAppendLine(stream, text) {
  if (ctState.paused) return;
  const out = document.getElementById('ct-logs-out');
  const filter = (document.getElementById('ct-filter').value || '').toLowerCase();
  const stick = out.scrollTop + out.clientHeight >= out.scrollHeight - 30;
  const div = ctEl('div', text, stream === 'err' ? 'ct-l ct-err' : 'ct-l');
  if (filter && !text.toLowerCase().includes(filter)) div.style.display = 'none';
  out.appendChild(div);
  if (++ctState.lines > CT_MAX_LINES) { out.removeChild(out.firstChild); ctState.lines--; }
  if (stick) out.scrollTop = out.scrollHeight;
}

function ctApplyFilter() {
  const f = (document.getElementById('ct-filter').value || '').toLowerCase();
  document.querySelectorAll('#ct-logs-out .ct-l').forEach(d => {
    d.style.display = !f || d.textContent.toLowerCase().includes(f) ? '' : 'none';
  });
}

function ctTogglePause() {
  ctState.paused = !ctState.paused;
  document.getElementById('ct-pause').textContent = t(ctState.paused ? 'containers.resume' : 'containers.pause');
}

function ctLogsClear() { document.getElementById('ct-logs-out').textContent = ''; ctState.lines = 0; }

function ctLogsClose() {
  if (ctState.es) { ctState.es.close(); ctState.es = null; }
  const p = document.getElementById('ct-logs');
  if (p) p.style.display = 'none';
}

function ctLogsReopen() {
  const c = ctState.list.find(x => x.fullId === ctState.logId);
  if (c) ctLogsOpen(c);
}

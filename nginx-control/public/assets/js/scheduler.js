// ── SCHEDULER (taches planifiees, formulaire visuel) ──────────────────────────
// Script global classique (comme les autres pages) : utilise api(), t(), h(),
// LANG du script principal. Les types de taches et leurs parametres viennent
// de GET /api/scheduler/types : ajouter un type cote serveur
// (lib/scheduler-tasks.js) suffit, aucun changement ici.

const SCHED = { tasks: [], types: [], tz: '', minuteSteps: [], hourSteps: [], editing: null, previewTimer: null, canWrite: true };
const SCHED_DAYS = [1, 2, 3, 4, 5, 6, 0]; // lundi -> dimanche

function schedL(o) { return o && typeof o === 'object' ? (o[LANG] || o.en || o.fr || '') : (o || ''); }
function schedLocale() { return LANG === 'fr' ? 'fr-FR' : 'en-GB'; }
function schedFmt(ts) { return ts ? new Date(ts).toLocaleString(schedLocale(), { dateStyle: 'short', timeStyle: 'short' }) : '—'; }
function schedDayName(d) { return new Date(2024, 0, 7 + d).toLocaleDateString(schedLocale(), { weekday: 'short' }); }
function schedType(id) { return SCHED.types.find(x => x.id === id); }
function schedMsg(d, fb) { return (d && (d.error || d.message)) || fb || t('common.error'); }

async function initScheduler() {
  schedLoadNotif();
  const [ty, ta] = await Promise.all([
    api('/scheduler/types?lang=' + LANG),
    api('/scheduler/tasks?lang=' + LANG),
  ]);
  const box = document.getElementById('sched-tasks');
  if (!ty || !ta) { if (box) box.innerHTML = '<div style="color:var(--red)">' + h(t('scheduler.loadError')) + '</div>'; return; }
  SCHED.types = ty.types; SCHED.minuteSteps = ty.minuteSteps; SCHED.hourSteps = ty.hourSteps;
  SCHED.tasks = ta.tasks; SCHED.tz = ta.timezone || ty.timezone || '';
  const tz = document.getElementById('sched-tz');
  if (tz) tz.textContent = t('scheduler.timezone') + ' : ' + SCHED.tz;
  schedRender();
}

function schedRender() {
  const box = document.getElementById('sched-tasks');
  if (!box) return;
  if (!SCHED.tasks.length) { box.innerHTML = '<div style="color:var(--text3);padding:12px 0">' + h(t('scheduler.empty')) + '</div>'; return; }
  const rows = SCHED.tasks.map(k => {
    const ty = schedType(k.type);
    const st = k.running ? '<span class="badge">' + h(t('scheduler.running')) + '</span>'
      : !k.lastRunAt ? '<span style="color:var(--text3)">—</span>'
      : '<span style="color:var(--' + (k.lastStatus === 'ok' ? 'green' : k.lastStatus === 'error' ? 'red' : 'amber') + ')">' + h(k.lastStatus) + '</span>';
    const lastTxt = k.lastRunAt ? schedFmt(k.lastRunAt) + (k.lastDurationMs != null ? ' · ' + (k.lastDurationMs / 1000).toFixed(1) + ' s' : '') : '';
    return '<tr>' +
      '<td><label class="sched-switch"><input type="checkbox" ' + (k.enabled ? 'checked' : '') + ' onchange="schedToggle(' + k.id + ', this.checked)"></label></td>' +
      '<td><b>' + h(k.name) + '</b><div class="sched-sub">' + h(ty ? schedL(ty.label) : k.type) + '</div></td>' +
      '<td>' + h(k.scheduleText) + '<div class="sched-sub"><code>' + h(k.cron) + '</code></div></td>' +
      '<td>' + (k.enabled ? h(schedFmt(k.nextRun)) : '<span style="color:var(--text3)">' + h(t('scheduler.disabled')) + '</span>') + '</td>' +
      '<td>' + st + '<div class="sched-sub" title="' + h(k.lastMessage || '') + '">' + h(lastTxt) + '</div></td>' +
      '<td class="sched-actions">' +
        '<button class="btn sm" onclick="schedRunNow(' + k.id + ')">&#9654; ' + h(t('scheduler.runNow')) + '</button> ' +
        '<button class="btn sm" onclick="schedHistory(' + k.id + ')">' + h(t('scheduler.history')) + '</button> ' +
        '<button class="btn sm" onclick="schedEdit(' + k.id + ')">' + h(t('scheduler.edit')) + '</button> ' +
        '<button class="btn sm danger" onclick="schedDelete(' + k.id + ')">&#10005;</button>' +
      '</td></tr>';
  }).join('');
  box.innerHTML = '<table class="sched-table"><thead><tr><th></th><th>' + h(t('scheduler.col.task')) + '</th><th>' + h(t('scheduler.col.schedule')) +
    '</th><th>' + h(t('scheduler.col.next')) + '</th><th>' + h(t('scheduler.col.last')) + '</th><th></th></tr></thead><tbody>' + rows + '</tbody></table>';
}

function schedFlash(msg, ok) {
  const el = document.getElementById('sched-flash');
  if (!el) return;
  el.textContent = msg; el.style.color = ok ? 'var(--green)' : 'var(--red)';
  clearTimeout(schedFlash.t); schedFlash.t = setTimeout(() => { el.textContent = ''; }, 8000);
}

async function schedToggle(id, enabled) {
  const d = await api('/scheduler/tasks/toggle', { method: 'POST', body: JSON.stringify({ id, enabled }) });
  if (!d || !d.ok) schedFlash(schedMsg(d), false);
  initScheduler();
}

async function schedDelete(id) {
  const k = SCHED.tasks.find(x => x.id === id);
  if (!k || !confirm(t('scheduler.confirmDelete', { name: k.name }))) return;
  const d = await api('/scheduler/tasks/delete', { method: 'POST', body: JSON.stringify({ id }) });
  schedFlash(d && d.ok ? t('scheduler.deleted') : schedMsg(d), !!(d && d.ok));
  initScheduler();
}

async function schedRunNow(id) {
  const k = SCHED.tasks.find(x => x.id === id);
  if (!k) return;
  schedFlash(t('scheduler.runningNow', { name: k.name }), true);
  const d = await api('/scheduler/tasks/run', { method: 'POST', body: JSON.stringify({ id }) });
  if (d && d.status) schedFlash(k.name + ' : ' + d.status + (d.message ? ' — ' + d.message : ''), d.status !== 'error');
  else schedFlash(schedMsg(d), false);
  initScheduler();
}

// ── Historique ───────────────────────────────────────────────────────────────
async function schedHistory(id) {
  const k = SCHED.tasks.find(x => x.id === id);
  const d = await api('/scheduler/runs?id=' + encodeURIComponent(id) + '&limit=30');
  const body = document.getElementById('sched-hist-body');
  document.getElementById('sched-hist-title').textContent = t('scheduler.history') + ' — ' + (k ? k.name : id);
  const runs = d && d.runs || [];
  body.innerHTML = !runs.length ? '<div style="color:var(--text3)">' + h(t('scheduler.noRuns')) + '</div>'
    : '<table class="sched-table"><thead><tr><th>' + h(t('scheduler.col.date')) + '</th><th>' + h(t('scheduler.col.status')) + '</th><th>' + h(t('scheduler.col.duration')) +
      '</th><th>' + h(t('scheduler.col.result')) + '</th></tr></thead><tbody>' + runs.map(r =>
      '<tr><td>' + h(schedFmt(r.startedAt || r.started_at)) + '</td><td style="color:var(--' + (r.status === 'ok' ? 'green' : r.status === 'error' ? 'red' : 'amber') + ')">' + h(r.status) +
      '</td><td>' + h(((r.durationMs ?? r.duration_ms ?? 0) / 1000).toFixed(1)) + ' s</td><td style="word-break:break-word">' + h(r.message || '') + '</td></tr>').join('') + '</tbody></table>';
  document.getElementById('sched-hist-modal').style.display = 'flex';
}
function schedCloseHistory() { document.getElementById('sched-hist-modal').style.display = 'none'; }

// ── Formulaire ───────────────────────────────────────────────────────────────
function schedNew() { schedOpen(null); }
function schedEdit(id) { schedOpen(SCHED.tasks.find(x => x.id === id) || null); }

function schedOpen(task) {
  if (!SCHED.types.length) return;
  SCHED.editing = task ? task.id : null;
  document.getElementById('sched-form-title').textContent = t(task ? 'scheduler.editTask' : 'scheduler.newTask');
  document.getElementById('sf-name').value = task ? task.name : '';
  const sel = document.getElementById('sf-type');
  sel.innerHTML = SCHED.types.map(x => '<option value="' + h(x.id) + '">' + h(schedL(x.label)) + '</option>').join('');
  sel.value = task ? task.type : SCHED.types[0].id;
  sel.disabled = !!task;
  document.getElementById('sf-enabled').checked = task ? !!task.enabled : true;
  schedBuildDays();
  const sc = task && task.schedule && task.schedule.mode ? task.schedule : { mode: 'daily', time: '03:00' };
  schedFillSchedule(sc);
  schedRenderParams(task ? task.params : {});
  document.getElementById('sf-notify').checked = task ? !!task.notify : false;
  document.getElementById('sf-error').textContent = '';
  document.getElementById('sched-form-modal').style.display = 'flex';
  schedTypeChanged(true);
  schedPreview();
}
function schedCloseForm() { document.getElementById('sched-form-modal').style.display = 'none'; }

function schedBuildDays() {
  document.getElementById('sf-days').innerHTML = SCHED_DAYS.map(d =>
    '<label class="sched-day"><input type="checkbox" value="' + d + '" onchange="schedPreview()"> ' + h(schedDayName(d)) + '</label>').join('');
  document.getElementById('sf-minstep').innerHTML = SCHED.minuteSteps.map(v => '<option value="' + v + '">' + v + '</option>').join('');
  document.getElementById('sf-hourstep').innerHTML = SCHED.hourSteps.map(v => '<option value="' + v + '">' + v + '</option>').join('');
}

function schedFillSchedule(s) {
  document.getElementById('sf-mode').value = s.mode;
  if (s.mode === 'interval') {
    document.getElementById('sf-unit').value = s.unit;
    document.getElementById('sf-minstep').value = s.unit === 'minutes' ? s.every : SCHED.minuteSteps[0];
    document.getElementById('sf-hourstep').value = s.unit === 'hours' ? s.every : SCHED.hourSteps[0];
    document.getElementById('sf-minute').value = s.minute || 0;
  }
  if (s.time) document.getElementById('sf-time').value = s.time;
  if (s.mode === 'weekly') document.querySelectorAll('#sf-days input').forEach(c => { c.checked = (s.days || []).includes(Number(c.value)); });
  if (s.mode === 'monthly') document.getElementById('sf-dom').value = s.day;
  if (s.mode === 'cron') document.getElementById('sf-cron').value = s.cron;
  schedModeChanged();
}

function schedModeChanged() {
  const mode = document.getElementById('sf-mode').value;
  const unit = document.getElementById('sf-unit').value;
  const show = (id, on) => { document.getElementById(id).style.display = on ? '' : 'none'; };
  show('sf-row-interval', mode === 'interval');
  show('sf-row-minstep', mode === 'interval' && unit === 'minutes');
  show('sf-row-hourstep', mode === 'interval' && unit === 'hours');
  show('sf-row-minute', mode === 'interval' && unit === 'hours');
  show('sf-row-time', mode === 'daily' || mode === 'weekly' || mode === 'monthly');
  show('sf-row-days', mode === 'weekly');
  show('sf-row-dom', mode === 'monthly');
  show('sf-row-cron', mode === 'cron');
  schedPreview();
}

function schedReadSchedule() {
  const mode = document.getElementById('sf-mode').value;
  const time = document.getElementById('sf-time').value || '03:00';
  if (mode === 'interval') {
    const unit = document.getElementById('sf-unit').value;
    return unit === 'minutes'
      ? { mode, unit, every: Number(document.getElementById('sf-minstep').value) }
      : { mode, unit, every: Number(document.getElementById('sf-hourstep').value), minute: Number(document.getElementById('sf-minute').value || 0) };
  }
  if (mode === 'daily') return { mode, time };
  if (mode === 'weekly') return { mode, time, days: [...document.querySelectorAll('#sf-days input:checked')].map(c => Number(c.value)) };
  if (mode === 'monthly') return { mode, time, day: Number(document.getElementById('sf-dom').value || 1) };
  return { mode: 'cron', cron: document.getElementById('sf-cron').value.trim() };
}

function schedPreview() {
  clearTimeout(SCHED.previewTimer);
  SCHED.previewTimer = setTimeout(async () => {
    const box = document.getElementById('sf-preview');
    if (!box) return;
    const d = await api('/scheduler/preview?lang=' + LANG, { method: 'POST', body: JSON.stringify({ schedule: schedReadSchedule() }) });
    if (!d) { box.innerHTML = ''; return; }
    if (!d.ok) { box.innerHTML = '<span style="color:var(--amber)">' + h(d.error) + '</span>'; return; }
    box.innerHTML = '<div><b>' + h(d.text) + '</b> <code>' + h(d.cron) + '</code></div>' +
      '<div class="sched-sub">' + h(t('scheduler.nextRuns')) + ' (' + h(d.timezone) + ') :</div><ul>' +
      d.next.map(ts => '<li>' + h(schedFmt(ts)) + '</li>').join('') + '</ul>';
  }, 150);
}

function schedTypeChanged(keepParams) {
  const ty = schedType(document.getElementById('sf-type').value);
  if (!ty) return;
  document.getElementById('sf-type-desc').textContent = schedL(ty.description);
  if (!keepParams) schedRenderParams({});
  const nl = schedL(ty.notifyLabel);
  document.getElementById('sf-row-notify').style.display = nl ? '' : 'none';
  document.getElementById('sf-notify-label').textContent = nl;
}

function schedRenderParams(values) {
  const ty = schedType(document.getElementById('sf-type').value);
  const box = document.getElementById('sf-params');
  if (!ty) { box.innerHTML = ''; return; }
  box.innerHTML = ty.params.map(p => {
    const v = values && values[p.key] !== undefined ? values[p.key] : p.default;
    const id = 'sp-' + p.key;
    const lab = h(schedL(p.label)) + (p.unit ? ' <span class="sched-sub">(' + h(schedL(p.unit)) + ')</span>' : '');
    let input = '';
    if (p.type === 'number') input = '<input type="number" id="' + id + '" min="' + p.min + '" max="' + p.max + '" value="' + h(v) + '" class="sched-narrow">';
    else if (p.type === 'boolean') input = '<label><input type="checkbox" id="' + id + '" ' + (v ? 'checked' : '') + ' class="sched-chk"> ' + lab + '</label>';
    else if (p.type === 'select') input = '<select id="' + id + '">' + (p.options || []).map(o => '<option value="' + h(o.value) + '"' + (o.value === v ? ' selected' : '') + '>' + h(schedL(o.label)) + '</option>').join('') + '</select>';
    else if (p.type === 'emails') input = '<input type="text" id="' + id + '" value="' + h((v || []).join(', ')) + '" placeholder="a@example.com, b@example.com">';
    else if (p.type === 'multiselect') {
      const cur = Array.isArray(v) ? v : [];
      input = !(p.options || []).length ? '<div class="sched-sub">' + h(t('scheduler.noOptions')) + '</div>'
        : '<div id="' + id + '" class="sched-multi">' + p.options.map(o => '<label><input type="checkbox" value="' + h(o.value) + '"' + (cur.includes(o.value) ? ' checked' : '') + '> ' + h(schedL(o.label)) + '</label>').join('') + '</div>';
    }
    return '<div class="sched-field">' + (p.type === 'boolean' ? '' : '<label class="sched-lbl">' + lab + '</label>') + input +
      (p.help ? '<div class="sched-sub">' + h(schedL(p.help)) + '</div>' : '') + '</div>';
  }).join('');
}

function schedReadParams() {
  const ty = schedType(document.getElementById('sf-type').value);
  const out = {};
  for (const p of ty ? ty.params : []) {
    const el = document.getElementById('sp-' + p.key);
    if (!el) continue;
    if (p.type === 'number') out[p.key] = el.value === '' ? undefined : Number(el.value);
    else if (p.type === 'boolean') out[p.key] = el.checked;
    else if (p.type === 'emails') out[p.key] = el.value.split(/[\s,;]+/).filter(Boolean);
    else if (p.type === 'multiselect') out[p.key] = [...el.querySelectorAll('input:checked')].map(c => c.value);
    else out[p.key] = el.value;
  }
  return out;
}

async function schedSaveTask() {
  const err = document.getElementById('sf-error');
  err.textContent = '';
  const body = {
    name: document.getElementById('sf-name').value.trim(),
    type: document.getElementById('sf-type').value,
    enabled: document.getElementById('sf-enabled').checked,
    schedule: schedReadSchedule(),
    params: schedReadParams(),
    notify: document.getElementById('sf-notify').checked,
  };
  if (SCHED.editing !== null) body.id = SCHED.editing;
  const d = await api('/scheduler/tasks/save', { method: 'POST', body: JSON.stringify(body) });
  if (!d || !d.ok) { err.textContent = schedMsg(d); return; }
  schedCloseForm();
  schedFlash(t('scheduler.saved'), true);
  initScheduler();
}

// ── Fichier tache (export / import) ──────────────────────────────────────────
function schedExport() { window.location.href = '/api/scheduler/export'; }

function schedImportPick() { document.getElementById('sched-import-file').click(); }

async function schedImportFile(input) {
  const f = input.files && input.files[0];
  input.value = '';
  if (!f) return;
  if (f.size > 1024 * 1024) { schedFlash(t('scheduler.fileTooBig'), false); return; }
  const content = await f.text();
  const replace = confirm(t('scheduler.importReplaceAsk'));
  const d = await api('/scheduler/import', { method: 'POST', body: JSON.stringify({ content, mode: replace ? 'replace' : 'merge' }) });
  if (d && d.ok) schedFlash(t('scheduler.imported', { added: d.added, skipped: d.skipped }), true);
  else schedFlash(schedMsg(d), false);
  initScheduler();
}

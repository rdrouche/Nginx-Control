'use strict';
/**
 * Page "WAF" (evenements ModSecurity) — extrait de public/index.html dans le
 * cadre du decoupage JS + traduction (voir CHANGELOG.md). Charge apres le
 * script inline principal : partage le meme scope global (api(), t(),
 * hasPerm(), ...), pas un module ES.
 */
let wafWindowHours = 24;
let wafTabCurrent  = 'events';

async function initWaf() { await wafLoad(); }

function wafRenderFormatWarning(warnings) {
  const box = document.getElementById('waf-format-warning');
  if (!box) return;
  if (!warnings || !warnings.length) { box.style.display = 'none'; box.innerHTML = ''; return; }

  box.style.display = '';
  box.innerHTML = '';
  const card = document.createElement('div');
  card.className = 'card';
  card.style.cssText = 'border-left:3px solid var(--amber);background:var(--bg3)';

  const title = document.createElement('div');
  title.style.cssText = 'color:var(--amber);font-weight:500;margin-bottom:6px';
  title.textContent = t('waf.formatWarningTitle');
  card.appendChild(title);

  const body = document.createElement('div');
  body.style.cssText = 'font-family:monospace;font-size:12px;color:var(--text2);line-height:1.6';
  const intro = document.createElement('div');
  intro.style.marginBottom = '8px';
  intro.textContent = t('waf.formatWarningIntro');
  body.appendChild(intro);
  for (const w of warnings) {
    const line = document.createElement('div');
    line.textContent = t('waf.formatWarningLine', { vhost: w.vhost || w.file, dropped: w.dropped, lines: w.lines, file: w.file });
    body.appendChild(line);
  }
  card.appendChild(body);
  box.appendChild(card);
}

async function wafLoad() {
  const cfg = await api('/analyzer/config').catch(() => null);
  const disabled = document.getElementById('waf-disabled');
  const main     = document.getElementById('waf-main');
  if (!cfg || !cfg.configured || !cfg.enabled) {
    disabled.style.display = '';
    main.style.display = 'none';
    return;
  }
  const status = await api('/analyzer/status').catch(() => null);
  const wafFiles = status?.agent?.wafTail?.files || 0;
  if (!wafFiles) {
    disabled.style.display = '';
    main.style.display = 'none';
    return;
  }
  disabled.style.display = 'none';
  main.style.display = 'flex';
  document.getElementById('waf-files').textContent = wafFiles;
  const clearBtn = document.getElementById('waf-clear-btn');
  if (clearBtn) clearBtn.style.display = hasPerm('manage_users') ? '' : 'none';

  // Un journal qui avance sans que rien n en soit tire ressemble exactement a
  // une absence d attaque : ce bandeau est ce qui evite de croire a tort que
  // tout va bien.
  wafRenderFormatWarning(status?.agent?.wafWarnings || []);

  await wafRender();
}

function wafSetWindow(hours) { wafWindowHours = hours; wafRender(); }

function wafTab(tab) {
  wafTabCurrent = tab;
  for (const tb of ['events', 'rules', 'ips']) {
    const b = document.getElementById('waf-tab-' + tb);
    if (b) b.classList.toggle('active', tb === tab);
  }
  const filters = document.getElementById('waf-filters');
  if (filters) filters.style.display = tab === 'events' ? 'flex' : 'none';
  wafRender();
}

async function wafRender() {
  const label = document.getElementById('waf-window-label');
  if (label) label.textContent = wafWindowHours >= 168 ? t('common.window.last7d')
                                : wafWindowHours >= 24 ? t('common.window.last24h') : t('common.window.lastHour');

  const series = await api(`/analyzer/waf/series?hours=${wafWindowHours}`).catch(() => null);
  if (series && series.reachable !== false) {
    const total   = (series.series || []).reduce((a, s) => a + (s.count || 0), 0);
    const blocked = (series.series || []).reduce((a, s) => a + (s.blocked || 0), 0);
    document.getElementById('waf-total').textContent    = total.toLocaleString('fr-FR');
    document.getElementById('waf-blocked').textContent  = blocked.toLocaleString('fr-FR');
    document.getElementById('waf-detected').textContent = (total - blocked).toLocaleString('fr-FR');
  }

  if (wafTabCurrent === 'events') return wafLoadEvents();
  if (wafTabCurrent === 'rules')  return wafLoadTopRules();
  if (wafTabCurrent === 'ips')    return wafLoadTopIps();
}

const WAF_SEV_BADGE = { critical: 'rd', error: 'rd', warning: 'am', notice: 'gy', info: 'gy', unknown: 'gy' };
const WAF_SEV_LABEL = () => ({
  critical: t('waf.sev.critical'), error: t('waf.sev.error'), warning: t('waf.sev.warning'),
  notice: t('waf.sev.notice'), info: t('waf.sev.info'), unknown: '—',
});

const WAF_PAGE_SIZE = 25;
let wafEventsOffset = 0;
let wafEventsTotal  = 0;

function wafResetPage() { wafEventsOffset = 0; wafRender(); }

function wafPage(dir) {
  const next = wafEventsOffset + dir * WAF_PAGE_SIZE;
  if (next < 0 || next >= wafEventsTotal) return;
  wafEventsOffset = next;
  wafLoadEvents();
  document.getElementById('waf-table-body').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

async function wafLoadEvents() {
  const head = document.getElementById('waf-table-head');
  const body = document.getElementById('waf-table-body');
  const pager = document.getElementById('waf-pager');
  if (!head || !body) return;

  const sev     = document.getElementById('waf-filter-sev').value;
  const blocked = document.getElementById('waf-filter-blocked').value;
  const qs = new URLSearchParams({ limit: String(WAF_PAGE_SIZE), offset: String(wafEventsOffset) });
  if (sev) qs.set('severity', sev);
  if (blocked !== '') qs.set('blocked', blocked);

  const d = await api('/analyzer/waf/events?' + qs.toString()).catch(() => null);
  head.innerHTML = ''; body.innerHTML = '';
  const sevLabel = WAF_SEV_LABEL();
  for (const cname of [t('waf.col.time'), t('analyzer.col.vhost'), t('waf.col.address'), t('waf.col.methodUri'), t('waf.col.rules'), t('waf.col.severity'), t('waf.col.state'), '']) {
    const th = document.createElement('th'); th.textContent = cname; head.appendChild(th);
  }

  wafEventsTotal = d && d.reachable !== false ? (d.total || 0) : 0;

  if (!d || d.reachable === false || !d.events || !d.events.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 8; td.style.cssText = 'color:var(--text3);padding:12px';
    td.textContent = d && d.reachable === false ? t('analyzer.agentUnreachable')
                    : wafEventsOffset > 0 ? t('analyzer.endOfList') : t('waf.noEvents');
    tr.appendChild(td); body.appendChild(tr);
    if (pager) pager.style.display = wafEventsOffset > 0 ? 'flex' : 'none';
    return;
  }

  for (const e of d.events) {
    const tr = document.createElement('tr');

    const c1 = document.createElement('td');
    c1.style.fontFamily = 'monospace'; c1.style.fontSize = '11px';
    c1.textContent = new Date(e.ts).toLocaleString('fr-FR');
    tr.appendChild(c1);

    const c2 = document.createElement('td'); c2.textContent = e.vhost || '—'; tr.appendChild(c2);

    const c3 = document.createElement('td');
    c3.style.fontFamily = 'monospace'; c3.textContent = e.ip || '—';
    tr.appendChild(c3);

    const c4 = document.createElement('td');
    c4.style.cssText = 'font-family:monospace;font-size:11px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap';
    c4.title = (e.method || '') + ' ' + (e.uri || '');
    c4.textContent = (e.method || '') + ' ' + (e.uri || '');
    tr.appendChild(c4);

    const c5 = document.createElement('td');
    c5.style.fontFamily = 'monospace'; c5.style.fontSize = '11px';
    c5.textContent = (e.ruleIds || []).slice(0, 3).join(', ') + ((e.ruleIds || []).length > 3 ? '…' : '');
    if (e.messages && e.messages.length) c5.title = e.messages.map(m => m.message).filter(Boolean).join(' | ');
    tr.appendChild(c5);

    const c6 = document.createElement('td');
    const badge = document.createElement('span');
    badge.className = 'badge ' + (WAF_SEV_BADGE[e.severity] || 'gy');
    badge.textContent = sevLabel[e.severity] || e.severity || '—';
    c6.appendChild(badge);
    tr.appendChild(c6);

    const c7 = document.createElement('td');
    const stateBadge = document.createElement('span');
    stateBadge.className = 'badge ' + (e.blocked ? 'rd' : 'am');
    stateBadge.textContent = e.blocked ? t('waf.blocked') : t('waf.detected');
    c7.appendChild(stateBadge);
    tr.appendChild(c7);

    const c8 = document.createElement('td');
    const detailBtn = document.createElement('button');
    detailBtn.className = 'btn sm';
    detailBtn.textContent = t('waf.detail');
    detailBtn.addEventListener('click', (function (id) {
      return () => wafOpenDetail(id);
    })(e.id));
    c8.appendChild(detailBtn);
    tr.appendChild(c8);

    body.appendChild(tr);
  }

  const from = wafEventsTotal === 0 ? 0 : wafEventsOffset + 1;
  const to   = Math.min(wafEventsOffset + WAF_PAGE_SIZE, wafEventsTotal);
  const info = document.getElementById('waf-pageinfo');
  if (info) info.textContent = t('analyzer.pageRange', { from, to, total: wafEventsTotal });
  const prev = document.getElementById('waf-prev');
  const next = document.getElementById('waf-next');
  if (prev) prev.disabled = wafEventsOffset === 0;
  if (next) next.disabled = wafEventsOffset + WAF_PAGE_SIZE >= wafEventsTotal;
  if (pager) pager.style.display = wafEventsTotal > WAF_PAGE_SIZE ? 'flex' : 'none';
}

// ── Modal de detail ──────────────────────────────────────────────────────────
const WAF_ENGINE_LABEL = () => ({
  DetectionOnly: t('waf.engine.detectionOnly'),
  On: t('waf.engine.on'),
});

async function wafOpenDetail(id) {
  const overlay = document.getElementById('waf-modal-overlay');
  const box = document.getElementById('waf-modal-body');
  if (!overlay || !box) return;
  overlay.style.display = 'flex';
  box.innerHTML = '';
  const loading = document.createElement('div');
  loading.style.color = 'var(--text3)';
  loading.textContent = t('common.loading');
  box.appendChild(loading);

  const d = await api(`/analyzer/waf/events/${id}`).catch(() => null);
  box.innerHTML = '';
  if (!d || d.reachable === false) {
    const err = document.createElement('div');
    err.style.color = 'var(--red)';
    err.textContent = t('waf.agentOrEventNotFound');
    box.appendChild(err);
    return;
  }

  // Resume
  const summary = document.createElement('div');
  summary.style.cssText = 'display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:16px;color:var(--text2)';
  const rows = [
    ['Date', new Date(d.ts).toLocaleString('fr-FR')],
    [t('analyzer.col.vhost'), d.vhost || '—'],
    [t('waf.col.address'), d.ip || '—'],
    [t('waf.modal.method'), d.method || '—'],
    [t('waf.modal.httpStatus'), d.status != null ? String(d.status) : '—'],
    [t('waf.col.state'), d.blocked ? t('waf.blocked') : t('waf.detected')],
  ];
  for (const [label, val] of rows) {
    const l = document.createElement('div'); l.style.color = 'var(--text3)'; l.textContent = label; summary.appendChild(l);
    const v = document.createElement('div'); v.textContent = val; summary.appendChild(v);
  }
  box.appendChild(summary);

  const uriBlock = document.createElement('div');
  uriBlock.style.cssText = 'margin-bottom:16px;padding:8px 10px;background:var(--bg);border-radius:var(--r);word-break:break-all';
  uriBlock.textContent = (d.method || '') + ' ' + (d.uri || '');
  box.appendChild(uriBlock);

  // Contexte du moteur : explique un evenement non bloque malgre une regle critique
  if (d.engine) {
    const engineBox = document.createElement('div');
    engineBox.className = 'an-expl';
    engineBox.style.marginBottom = '16px';
    const line = document.createElement('div');
    const b = document.createElement('b'); b.textContent = t('waf.engineLabel', { engine: d.engine });
    line.appendChild(b);
    line.appendChild(document.createTextNode(WAF_ENGINE_LABEL()[d.engine] || ''));
    engineBox.appendChild(line);
    box.appendChild(engineBox);
  }

  // Regles declenchees : categorie, explication, lien externe
  const rulesTitle = document.createElement('div');
  rulesTitle.style.cssText = 'font-weight:500;color:var(--text);margin-bottom:8px';
  rulesTitle.textContent = t('waf.rulesTriggered');
  box.appendChild(rulesTitle);

  for (const r of (d.rules || [])) {
    const card = document.createElement('div');
    card.className = 'an-expl';
    card.style.marginBottom = '10px';

    const head = document.createElement('div');
    head.style.cssText = 'display:flex;align-items:center;gap:8px;margin-bottom:6px';
    const idSpan = document.createElement('span');
    idSpan.style.cssText = 'font-weight:500;color:var(--text)';
    idSpan.textContent = r.ruleId;
    head.appendChild(idSpan);
    const catBadge = document.createElement('span');
    catBadge.className = 'badge gy';
    catBadge.textContent = r.category;
    head.appendChild(catBadge);
    card.appendChild(head);

    const why = document.createElement('div');
    why.textContent = r.why;
    card.appendChild(why);

    const msg = (d.messages || []).find(m => m.ruleId === r.ruleId);
    if (msg && msg.message) {
      const msgLine = document.createElement('div');
      msgLine.style.cssText = 'margin-top:6px;color:var(--text3)';
      msgLine.textContent = t('waf.modsecMessage', { msg: msg.message });
      card.appendChild(msgLine);
    }

    if (r.referenceUrl) {
      const link = document.createElement('a');
      link.href = r.referenceUrl;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      link.style.cssText = 'display:inline-block;margin-top:8px;color:var(--blue)';
      link.textContent = t('waf.ruleDefinitionLink');
      card.appendChild(link);
    }

    box.appendChild(card);
  }

  // Ligne JSON complete, repliee par defaut
  const toggle = document.createElement('button');
  toggle.className = 'btn sm';
  toggle.style.marginTop = '10px';
  toggle.textContent = t('waf.viewRawJson');
  const pre = document.createElement('pre');
  pre.style.cssText = 'display:none;margin-top:8px;padding:12px;background:var(--bg);border:1px solid var(--border);border-radius:var(--r);white-space:pre-wrap;word-break:break-all;max-height:400px;overflow:auto;font-size:11px;color:var(--text2)';
  let pretty = d.raw || '';
  try { pretty = JSON.stringify(JSON.parse(d.raw), null, 2); } catch { /* garde le texte brut */ }
  pre.textContent = pretty;
  toggle.addEventListener('click', () => {
    pre.style.display = pre.style.display === 'none' ? 'block' : 'none';
  });
  box.appendChild(toggle);
  box.appendChild(pre);
}

function wafCloseDetail() {
  const overlay = document.getElementById('waf-modal-overlay');
  if (overlay) overlay.style.display = 'none';
}

async function wafLoadTopRules() {
  const head = document.getElementById('waf-table-head');
  const body = document.getElementById('waf-table-body');
  if (!head || !body) return;
  const d = await api(`/analyzer/waf/top-rules?hours=${wafWindowHours}`).catch(() => null);
  head.innerHTML = ''; body.innerHTML = '';
  for (const cname of [t('waf.col.rule'), 'Occurrences', t('waf.col.exampleMessage')]) {
    const th = document.createElement('th'); th.textContent = cname; head.appendChild(th);
  }
  const rules = d && d.reachable !== false ? (d.rules || []) : [];
  if (!rules.length) {
    const tr = document.createElement('tr'); const td = document.createElement('td');
    td.colSpan = 3; td.style.cssText = 'color:var(--text3);padding:12px';
    td.textContent = d && d.reachable === false ? t('analyzer.agentUnreachable') : t('waf.noRulesPeriod');
    tr.appendChild(td); body.appendChild(tr); return;
  }
  for (const r of rules) {
    const tr = document.createElement('tr');
    const c1 = document.createElement('td'); c1.style.fontFamily = 'monospace'; c1.textContent = r.ruleId; tr.appendChild(c1);
    const c2 = document.createElement('td'); c2.textContent = r.count.toLocaleString('fr-FR'); tr.appendChild(c2);
    const c3 = document.createElement('td'); c3.style.cssText = 'color:var(--text3);font-size:12px'; c3.textContent = r.example || '—'; tr.appendChild(c3);
    body.appendChild(tr);
  }
}

async function wafLoadTopIps() {
  const head = document.getElementById('waf-table-head');
  const body = document.getElementById('waf-table-body');
  if (!head || !body) return;
  const d = await api(`/analyzer/waf/top-ips?hours=${wafWindowHours}`).catch(() => null);
  head.innerHTML = ''; body.innerHTML = '';
  for (const cname of [t('waf.col.address'), t('waf.col.events'), t('waf.blockedPlural')]) {
    const th = document.createElement('th'); th.textContent = cname; head.appendChild(th);
  }
  const ips = d && d.reachable !== false ? (d.ips || []) : [];
  if (!ips.length) {
    const tr = document.createElement('tr'); const td = document.createElement('td');
    td.colSpan = 3; td.style.cssText = 'color:var(--text3);padding:12px';
    td.textContent = d && d.reachable === false ? t('analyzer.agentUnreachable') : t('waf.noAddressesPeriod');
    tr.appendChild(td); body.appendChild(tr); return;
  }
  for (const ip of ips) {
    const tr = document.createElement('tr');
    const c1 = document.createElement('td'); c1.style.fontFamily = 'monospace'; c1.textContent = ip.ip; tr.appendChild(c1);
    const c2 = document.createElement('td'); c2.textContent = ip.count.toLocaleString('fr-FR'); tr.appendChild(c2);
    const c3 = document.createElement('td'); c3.style.color = ip.blocked > 0 ? 'var(--red)' : 'var(--text3)';
    c3.textContent = (ip.blocked || 0).toLocaleString('fr-FR'); tr.appendChild(c3);
    body.appendChild(tr);
  }
}

/** Filtres actuellement affiches sur l onglet Evenements, pour que la purge les respecte. */
function wafCurrentFilters() {
  const sev     = document.getElementById('waf-filter-sev').value;
  const blocked = document.getElementById('waf-filter-blocked').value;
  const f = {};
  if (sev) f.severity = sev;
  if (blocked !== '') f.blocked = blocked;
  return f;
}

async function wafClearEvents() {
  const f = wafCurrentFilters();
  const scope = (f.severity || f.blocked !== undefined)
    ? t('waf.scopeFiltered')
    : t('waf.scopeAll');
  if (!confirm(t('analyzer.clearAllConfirm', { scope }))) return;
  if (!confirm(t('analyzer.clearAllFinalConfirm'))) return;
  const d = await api('/analyzer/waf/clear', { method: 'POST', body: JSON.stringify(f) })
    .catch(e => ({ error: e.message }));
  if (d && d.error) { alert(t('common.error') + ' : ' + d.error); return; }
  await wafRender();
}

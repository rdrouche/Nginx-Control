'use strict';
/**
 * Page "Analyse des journaux" (analyseur de comportements + exceptions) —
 * extrait de public/index.html dans le cadre du decoupage JS + traduction
 * (voir CHANGELOG.md). Charge apres le script inline principal : partage le
 * meme scope global (api(), t(), svgEsc(), gmCategoryLabel(), countryFlag(),
 * hasPerm(), fmtB(), ...), pas un module ES.
 *
 * Tout ce qui affiche des donnees venues du serveur passe par l API DOM plutot
 * que par de l innerHTML avec interpolation : une adresse IP ou un agent
 * utilisateur contient des guillemets, et un onclick construit par concatenation
 * casse silencieusement.
 */
let anWindowHours = 24;
let anTabCurrent  = 'countries';

async function initAnalyzer() { await anLoad(); }

async function anLoad() {
  const cfg = await api('/analyzer/config').catch(() => null);
  const disabled = document.getElementById('an-disabled');
  const main     = document.getElementById('an-main');
  if (!cfg || !cfg.configured || !cfg.enabled) {
    disabled.style.display = '';
    main.style.display = 'none';
    return;
  }
  disabled.style.display = 'none';
  main.style.display = 'flex';
  const clearBtn = document.getElementById('an-clear-all');
  if (clearBtn) clearBtn.style.display = hasPerm('manage_users') ? '' : 'none';
  const imgName = document.getElementById('an-image-name');
  if (imgName) imgName.textContent = cfg.image || 'forge.rdr-it.com/dockerfiles/nginx-analyzer:latest';
  await anRefreshStatus();
  await anLoadAlerts();
  await anLoadExceptions();
  await anLoadTraffic();
  await anLoadBotStats();
}

/**
 * Repartition humains/robots, avec le detail par categorie au survol. Chiffres
 * reels issus de l agregation persistee (bot_traffic), independants de GeoIP —
 * contrairement a la carte, cette statistique fonctionne meme sans base
 * geographique configuree.
 */
async function anLoadBotStats() {
  const d = await api('/analyzer/traffic/bots?hours=24').catch(() => null);
  const humanEl = document.getElementById('an-bot-human');
  const botsEl  = document.getElementById('an-bot-bots');
  const totalEl = document.getElementById('an-bot-total');
  const tooltip = document.getElementById('an-bot-tooltip');
  if (!humanEl || !botsEl || !totalEl) return;

  if (!d || d.reachable === false || !d.total) {
    humanEl.textContent = '—'; botsEl.textContent = '—'; totalEl.textContent = '—';
    if (tooltip) tooltip.innerHTML = '';
    return;
  }

  humanEl.textContent = d.human.toLocaleString('fr-FR');
  botsEl.textContent  = d.bots.toLocaleString('fr-FR');
  totalEl.textContent = d.total.toLocaleString('fr-FR');

  // Infobulle construite via l API DOM : les libelles sont fixes (pas de
  // donnee utilisateur ici), mais on reste sur le meme reflexe que le reste
  // de la page plutot que de melanger les styles. Pourcentages calcules sur
  // le total des robots (pas sur le trafic global) : "42% des robots sont
  // des robots IA" a un sens, "3% du trafic total" en aurait peu.
  if (tooltip) {
    tooltip.innerHTML = '';
    const botRows = (d.byCategory || []).filter(r => r.category !== 'human');
    const botTotal = botRows.reduce((a, r) => a + r.requests, 0);

    const title = document.createElement('div');
    title.style.cssText = 'color:var(--text);font-weight:500;margin-bottom:6px;padding-bottom:6px;border-bottom:1px solid var(--border2)';
    title.textContent = t('analyzer.botDistribution', { total: botTotal.toLocaleString('fr-FR') });
    tooltip.appendChild(title);

    if (!botRows.length) {
      const p = document.createElement('div');
      p.style.color = 'var(--text3)';
      p.textContent = t('analyzer.noBotsPeriod');
      tooltip.appendChild(p);
    } else {
      for (const row of botRows.sort((a, b) => b.requests - a.requests)) {
        const pct = botTotal > 0 ? (row.requests / botTotal * 100) : 0;
        const line = document.createElement('div');
        line.style.cssText = 'display:flex;align-items:center;gap:8px;padding:3px 0';
        const dot = document.createElement('span');
        dot.className = 'gm-dot';
        dot.style.background = GM_CATEGORY_COLOR[row.category] || GM_CATEGORY_COLOR.unknown;
        line.appendChild(dot);
        const label = document.createElement('span');
        label.style.color = 'var(--text)';
        label.textContent = gmCategoryLabel(row.category);
        line.appendChild(label);
        const pctEl = document.createElement('span');
        pctEl.style.cssText = 'margin-left:auto;color:var(--text);font-weight:500';
        pctEl.textContent = pct.toFixed(1) + '%';
        line.appendChild(pctEl);
        const count = document.createElement('span');
        count.style.cssText = 'color:var(--text3);min-width:52px;text-align:right';
        count.textContent = '(' + row.requests.toLocaleString('fr-FR') + ')';
        line.appendChild(count);
        tooltip.appendChild(line);
      }
    }
  }
}

// Affichage/masquage de l infobulle : geres une seule fois, pas a chaque
// rechargement des donnees, pour ne pas empiler les ecouteurs. Les elements
// sont deja dans le DOM a ce stade du script (meme convention que le reste
// de ce fichier : pas besoin d attendre DOMContentLoaded).
(function initBotTooltip() {
  const card = document.getElementById('an-bot-card');
  const tooltip = document.getElementById('an-bot-tooltip');
  if (!card || !tooltip) return;
  card.addEventListener('mouseenter', () => { if (tooltip.innerHTML) tooltip.style.display = 'block'; });
  card.addEventListener('mouseleave', () => { tooltip.style.display = 'none'; });
})();

async function anRefreshStatus() {
  const d = await api('/analyzer/status').catch(() => null);
  const el = document.getElementById('an-status');
  const bStart = document.getElementById('an-btn-start');
  const bStop  = document.getElementById('an-btn-stop');
  const bImg   = document.getElementById('an-image-update');
  if (!d || !d.enabled || !el) return;
  if (bImg) bImg.style.display = '';

  const c = d.container || {};
  el.innerHTML = '';
  const dot = document.createElement('span');
  dot.className = 'cb-status-dot ' + (c.running ? 'running' : 'stopped');
  el.appendChild(dot);
  const txt = document.createElement('span');
  if (!c.exists)      txt.textContent = t('analyzer.containerAbsent');
  else if (c.running) txt.textContent = t('analyzer.running', { image: c.image || '' });
  else                txt.textContent = t('analyzer.stopped', { status: c.status || '' });
  el.appendChild(txt);

  if (c.dockerUnavailable) {
    const warn = document.createElement('span');
    warn.style.color = 'var(--amber)';
    warn.style.marginLeft = '10px';
    warn.textContent = t('analyzer.dockerUnreachable');
    el.appendChild(warn);
  } else if (c.running && !d.reachable) {
    const warn = document.createElement('span');
    warn.style.color = 'var(--amber)';
    warn.style.marginLeft = '10px';
    warn.textContent = t('analyzer.startedUnreachable');
    el.appendChild(warn);
  } else if (c.running && d.reachable && d.agent && (d.agent.tail.files || 0) === 0) {
    // Fix v12.22.x (audit finding ANA-02, avertissement complementaire) :
    // "aucun fichier suivi" et "aucun trafic" sont sinon indiscernables dans
    // l interface — le premier est un probleme de configuration
    // (LOG_PATTERN/logsDir), le second est normal sur un site calme.
    const warn = document.createElement('span');
    warn.style.color = 'var(--amber)';
    warn.style.marginLeft = '10px';
    warn.textContent = t('analyzer.noFilesFollowed');
    el.appendChild(warn);
  }

  bStart.style.display = c.running ? 'none' : '';
  bStop.style.display  = c.running ? '' : 'none';

  const a = d.agent;
  const set = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v; };
  set('an-parsed', a ? (a.tail.parsed || 0).toLocaleString('fr-FR') : '—');
  set('an-files',  a ? (a.tail.files || 0) : '—');
  set('an-mem',    a ? a.memoryMb + ' Mo' : '—');

  anRenderBaseline(a && a.baseline, 'an-baseline-card', 'an-baseline');
  anRenderBaseline(a && a.countryBaseline, 'an-baseline-country-card', 'an-baseline-country');
}

function anRenderBaseline(b, cardId, boxId) {
  const card = document.getElementById(cardId);
  const box  = document.getElementById(boxId);
  if (!b || !card) { if (card) card.style.display = 'none'; return; }
  card.style.display = '';
  box.innerHTML = '';

  if (b.learning) {
    const wrap = document.createElement('div');
    wrap.className = 'an-learn';
    const pct = Math.min(100, Math.round(100 * b.daysElapsed / b.daysRequired));
    const line = document.createElement('div');
    line.style.marginBottom = '8px';
    line.textContent = t('analyzer.learning', { elapsed: b.daysElapsed, required: b.daysRequired });
    wrap.appendChild(line);
    const bar = document.createElement('div');
    bar.className = 'an-bar';
    const fill = document.createElement('span');
    fill.style.width = pct + '%';
    bar.appendChild(fill);
    wrap.appendChild(bar);
    const note = document.createElement('div');
    note.style.marginTop = '8px';
    note.style.fontSize = '11px';
    // Dire pourquoi l attente, sinon elle passe pour une panne.
    note.textContent = t('analyzer.learningNote');
    wrap.appendChild(note);
    const cov = document.createElement('div');
    cov.style.marginTop = '6px';
    cov.style.fontSize = '11px';
    cov.textContent = t('analyzer.slotsUsable', { usable: b.bucketsUsable, total: b.totalSlots, coverage: b.coverage });
    wrap.appendChild(cov);
    box.appendChild(wrap);
    return;
  }

  const ok = document.createElement('div');
  ok.className = 'an-learn';
  ok.style.color = 'var(--green)';
  ok.textContent = t('analyzer.active', { usable: b.bucketsUsable, total: b.totalSlots, coverage: b.coverage });
  box.appendChild(ok);
}

async function anAction(action) {
  const el = document.getElementById('an-status');
  if (el) el.textContent = action === 'start' ? t('analyzer.starting') : t('analyzer.stopping');
  const d = await api('/analyzer/container/' + action, { method: 'POST' })
    .catch(e => ({ error: e.message }));
  if (d && d.error) {
    if (el) { el.textContent = t('common.error') + ' : ' + d.error; el.style.color = 'var(--red)'; }
    return;
  }
  setTimeout(() => anLoad(), 1500);
}

async function analyzerImageUpdate() {
  const btn = document.getElementById('an-image-update');
  if (btn) { btn.disabled = true; btn.textContent = t('analyzer.updateImage.checking'); }
  const d = await api('/analyzer/image/update', { method: 'POST' }).catch(e => ({ error: e.message }));
  if (btn) { btn.disabled = false; btn.textContent = '⬇ ' + t('analyzer.updateImage'); }
  if (!d || d.error || d.ok === false) { alert(t('common.error') + ' : ' + (d?.error || 'unknown')); return; }
  alert(d.updated
    ? t('analyzer.imageDownloaded') + (d.recreated ? t('analyzer.containerRecreated') : '.')
    : t('analyzer.imageUpToDate'));
  await anRefreshStatus();
}

const AN_TYPE_LABEL = () => ({
  bruteforce: t('analyzer.type.bruteforce'), scan: t('analyzer.type.scan'), flood: t('analyzer.type.flood'),
  scraping: t('analyzer.type.scraping'), volumetric: t('analyzer.type.volumetric'),
  country_traffic: t('analyzer.type.countryTraffic'),
});
const AN_SEV_BADGE = { high: 'rd', medium: 'am', low: 'gy' };

const AN_PAGE_SIZE = 25;
let anOffset = 0;
let anTotal  = 0;

function anResetPage() { anOffset = 0; anLoadAlerts(); }

function anPage(dir) {
  const next = anOffset + dir * AN_PAGE_SIZE;
  if (next < 0 || next >= anTotal) return;
  anOffset = next;
  anLoadAlerts();
  document.getElementById('an-alerts').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

async function anLoadAlerts() {
  const box = document.getElementById('an-alerts');
  if (!box) return;
  const sev   = document.getElementById('an-filter-sev').value;
  const type  = document.getElementById('an-filter-type').value;
  const acked = document.getElementById('an-filter-acked').value;

  const qs = new URLSearchParams({ limit: String(AN_PAGE_SIZE), offset: String(anOffset) });
  if (sev)   qs.set('severity', sev);
  if (type)  qs.set('type', type);
  if (acked !== '') qs.set('acked', acked);

  const d = await api('/analyzer/alerts?' + qs.toString()).catch(() => null);
  box.innerHTML = '';
  const badge = document.getElementById('an-count');
  const pager = document.getElementById('an-pager');

  if (!d || d.reachable === false) {
    box.appendChild(anEmpty(t('analyzer.agentUnreachable')));
    if (badge) badge.textContent = '';
    if (pager) pager.style.display = 'none';
    return;
  }

  const alerts = d.alerts || [];
  anTotal = d.total || 0;
  document.getElementById('an-alerts-count').textContent = anTotal;

  // Le badge du menu compte les alertes a traiter, tous filtres confondus.
  anRefreshBadge();

  if (!alerts.length) {
    box.appendChild(anEmpty(anOffset > 0
      ? t('analyzer.endOfList')
      : (acked === '0' ? t('analyzer.nothingToReview') : t('analyzer.noAlerts'))));
    if (pager) pager.style.display = anOffset > 0 ? 'flex' : 'none';
  } else {
    for (const a of alerts) box.appendChild(anAlertCard(a));
    if (pager) pager.style.display = anTotal > AN_PAGE_SIZE ? 'flex' : 'none';
  }

  const from = anTotal === 0 ? 0 : anOffset + 1;
  const to   = Math.min(anOffset + AN_PAGE_SIZE, anTotal);
  const info = document.getElementById('an-pageinfo');
  if (info) info.textContent = t('analyzer.pageRange', { from, to, total: anTotal });
  const prev = document.getElementById('an-prev');
  const next = document.getElementById('an-next');
  if (prev) prev.disabled = anOffset === 0;
  if (next) next.disabled = anOffset + AN_PAGE_SIZE >= anTotal;
}

/** Compteur du menu : uniquement les alertes non acquittees. */
async function anRefreshBadge() {
  const badge = document.getElementById('an-count');
  if (!badge) return;
  const d = await api('/analyzer/alerts?limit=1&acked=0').catch(() => null);
  const n = d && d.reachable !== false ? (d.total || 0) : 0;
  badge.textContent = n > 0 ? String(n) : '';
}

// ── Exceptions ───────────────────────────────────────────────────────────────
function anToggleExcForm() {
  const f = document.getElementById('an-exc-form');
  if (f) f.style.display = f.style.display === 'none' ? 'flex' : 'none';
}

async function anLoadExceptions() {
  const box = document.getElementById('an-exc-list');
  if (!box) return;
  const d = await api('/analyzer/exceptions').catch(() => null);
  box.innerHTML = '';
  if (!d || d.reachable === false) { box.appendChild(anEmpty(t('analyzer.agentUnreachable'))); return; }
  const list = d.exceptions || [];
  if (!list.length) { box.appendChild(anEmpty(t('analyzer.noException'))); return; }

  for (const e of list) {
    const row = document.createElement('div');
    row.className = 'an-exc-row';

    const vhost = document.createElement('span');
    vhost.style.minWidth = '190px';
    vhost.textContent = e.vhost;
    row.appendChild(vhost);

    const ip = document.createElement('span');
    ip.style.minWidth = '130px';
    ip.style.color = 'var(--text)';
    ip.textContent = e.ip;
    row.appendChild(ip);

    const reason = document.createElement('span');
    reason.style.cssText = 'flex:1;color:var(--text3)';
    reason.textContent = e.reason || '—';
    row.appendChild(reason);

    const meta = document.createElement('span');
    meta.style.cssText = 'color:var(--text3);font-size:10px';
    meta.textContent = (e.author ? e.author + ' · ' : '') + new Date(e.created).toLocaleDateString('fr-FR');
    row.appendChild(meta);

    const del = document.createElement('button');
    del.className = 'btn sm danger';
    del.textContent = t('analyzer.remove');
    del.addEventListener('click', (function (id) {
      return async function () {
        await api('/analyzer/exceptions/remove', { method: 'POST', body: JSON.stringify({ id }) })
          .catch(() => {});
        anLoadExceptions();
      };
    })(e.id));
    row.appendChild(del);

    box.appendChild(row);
  }
}

async function anAddException(prefill) {
  const vhost  = prefill ? prefill.vhost  : document.getElementById('an-exc-vhost').value.trim();
  const ip     = prefill ? prefill.ip     : document.getElementById('an-exc-ip').value.trim();
  const reason = prefill ? prefill.reason : document.getElementById('an-exc-reason').value.trim();
  if (!vhost || !ip) { alert(t('analyzer.vhostIpRequired')); return; }
  const d = await api('/analyzer/exceptions', {
    method: 'POST', body: JSON.stringify({ vhost, ip, reason }),
  }).catch(e => ({ error: e.message }));
  if (d && d.error) { alert(t('common.error') + ' : ' + d.error); return; }
  if (!prefill) {
    document.getElementById('an-exc-vhost').value = '';
    document.getElementById('an-exc-ip').value = '';
    document.getElementById('an-exc-reason').value = '';
    document.getElementById('an-exc-form').style.display = 'none';
  }
  anLoadExceptions();
  anLoadAlerts();
}

function anEmpty(text) {
  const d = document.createElement('div');
  d.style.cssText = 'color:var(--text3);font-family:monospace;font-size:12px;padding:10px';
  d.textContent = text;
  return d;
}

function anAlertCard(a) {
  const card = document.createElement('div');
  card.className = 'an-alert ' + (a.severity || 'low') + (a.acked ? ' acked' : '');

  const head = document.createElement('div');
  head.className = 'an-alert-head';

  const sev = document.createElement('span');
  sev.className = 'badge ' + (AN_SEV_BADGE[a.severity] || 'gy');
  sev.textContent = (a.severity || '').toUpperCase();
  head.appendChild(sev);

  const type = document.createElement('span');
  type.className = 'badge gy';
  type.textContent = AN_TYPE_LABEL()[a.type] || a.type;
  head.appendChild(type);

  const sum = document.createElement('span');
  sum.className = 'an-alert-sum';
  sum.textContent = a.summary;
  head.appendChild(sum);

  if (!a.acked) {
    const ack = document.createElement('button');
    ack.className = 'btn sm';
    ack.textContent = t('analyzer.ack');
    ack.addEventListener('click', (function (id) {
      return async function () {
        await api('/analyzer/alerts/ack', { method: 'POST', body: JSON.stringify({ id }) })
          .catch(() => {});
        anLoadAlerts();
      };
    })(a.id));
    head.appendChild(ack);
  }
  card.appendChild(head);

  const meta = document.createElement('div');
  meta.className = 'an-alert-meta';
  const parts = [new Date(a.ts).toLocaleString('fr-FR')];
  if (a.ip)    parts.push('IP ' + a.ip);
  if (a.vhost) parts.push(a.vhost);
  // country_traffic alerts have no ip/vhost of their own (they're a
  // per-country aggregate, not a per-address or per-vhost one) — the
  // country lives only in evidence, so it wouldn't otherwise appear here.
  if (!a.vhost && a.evidence?.country) parts.push(a.evidence.country + (countryFlag(a.evidence.country) ? ' ' + countryFlag(a.evidence.country) : ''));
  for (const p of parts) {
    const s = document.createElement('span');
    s.textContent = p;
    meta.appendChild(s);
  }
  card.appendChild(meta);

  // Pourquoi cette alerte : un verdict sans motif se fait ignorer, ou pire,
  // suivre aveuglement. L explication inclut les cas ou le constat est legitime.
  const expl = a.explanation || (a.evidence && a.evidence.explanation);
  if (expl) {
    const box = document.createElement('div');
    box.className = 'an-expl';
    for (const [labelKey, key] of [['analyzer.explanation.what', 'what'], ['analyzer.explanation.why', 'why'],
                                ['analyzer.explanation.legit', 'legit'], ['analyzer.explanation.action', 'action']]) {
      if (!expl[key]) continue;
      const line = document.createElement('div');
      const b = document.createElement('b');
      b.textContent = t(labelKey) + ' : ';
      line.appendChild(b);
      line.appendChild(document.createTextNode(expl[key]));
      box.appendChild(line);
    }
    card.appendChild(box);
  }

  // Raccourci : une adresse jugee legitime se met en exception pour ce vhost,
  // plutot que de baisser les seuils pour tout le monde.
  if (a.ip && a.vhost && !a.acked) {
    const exc = document.createElement('button');
    exc.className = 'btn sm';
    exc.style.marginTop = '8px';
    exc.style.marginRight = '6px';
    exc.textContent = t('analyzer.excludeIpOn', { vhost: a.vhost });
    exc.addEventListener('click', (function (vhost, ip, type) {
      return async function () {
        if (!confirm(t('analyzer.excludeConfirm', { ip, vhost }))) return;
        await anAddException({ vhost, ip, reason: t('analyzer.excludedFromAlert', { type }) });
      };
    })(a.vhost, a.ip, a.type));
    card.appendChild(exc);
  }

  // Les preuves sont ce qui permet de decider : repliees, mais presentes.
  if (a.evidence && Object.keys(a.evidence).length) {
    const toggle = document.createElement('button');
    toggle.className = 'btn sm';
    toggle.style.marginTop = '8px';
    toggle.textContent = t('analyzer.evidence');
    const pre = document.createElement('div');
    pre.className = 'an-evidence';
    pre.style.display = 'none';
    pre.textContent = JSON.stringify(a.evidence, null, 2);
    toggle.addEventListener('click', function () {
      pre.style.display = pre.style.display === 'none' ? '' : 'none';
    });
    card.appendChild(toggle);
    card.appendChild(pre);
  }
  return card;
}

/** Filtres actuellement affiches, pour que les actions groupees les respectent. */
function anCurrentFilters() {
  const sev  = document.getElementById('an-filter-sev').value;
  const type = document.getElementById('an-filter-type').value;
  const f = {};
  if (sev)  f.severity = sev;
  if (type) f.type = type;
  return f;
}

async function anAckAll() {
  const f = anCurrentFilters();
  const scope = (f.type || f.severity)
    ? t('analyzer.scopeFiltered')
    : t('analyzer.scopeAllToReview');
  if (!confirm(t('analyzer.ackAllConfirm', { scope }))) return;
  const d = await api('/analyzer/alerts/ack-all', { method: 'POST', body: JSON.stringify(f) })
    .catch(e => ({ error: e.message }));
  if (d && d.error) { alert(t('common.error') + ' : ' + d.error); return; }
  anResetPage();
}

async function anClearAll() {
  const f = anCurrentFilters();
  const scope = (f.type || f.severity)
    ? t('analyzer.scopeFiltered')
    : t('analyzer.scopeAllIncludingAcked');
  if (!confirm(t('analyzer.clearAllConfirm', { scope }))) return;
  if (!confirm(t('analyzer.clearAllFinalConfirm'))) return;
  const d = await api('/analyzer/alerts/clear', { method: 'POST', body: JSON.stringify(f) })
    .catch(e => ({ error: e.message }));
  if (d && d.error) { alert(t('common.error') + ' : ' + d.error); return; }
  anResetPage();
}

function anSetWindow(hours) {
  anWindowHours = hours;
  anLoadTraffic();
}

function anTab(tab) {
  anTabCurrent = tab;
  for (const t of ['countries', 'vhosts']) {
    const b = document.getElementById('an-tab-' + t);
    if (b) b.classList.toggle('active', t === tab);
  }
  anLoadTraffic();
}

/** Indicatif pays vers emoji drapeau, sans table de correspondance. */
function anFlag(cc) {
  if (!cc || cc.length !== 2 || !/^[A-Za-z]{2}$/.test(cc)) return '';
  return String.fromCodePoint(...[...cc.toUpperCase()].map(ch => 0x1F1E6 + ch.charCodeAt(0) - 65));
}

async function anLoadTraffic() {
  const head = document.getElementById('an-traffic-head');
  const body = document.getElementById('an-traffic-body');
  if (!head || !body) return;

  const label = document.getElementById('an-window-label');
  if (label) label.textContent = anWindowHours >= 168 ? t('common.window.last7d')
                               : anWindowHours >= 24 ? t('common.window.last24h')
                               : t('common.window.lastHour');

  // Chargees en parallele : la repartition bot/humain est une colonne en
  // plus sur le meme tableau, pas un second appel bloquant.
  const botKind = anTabCurrent === 'countries' ? 'bots/countries' : 'bots/vhosts';
  const [d, botData] = await Promise.all([
    api(`/analyzer/traffic/${anTabCurrent}?hours=${anWindowHours}`).catch(() => null),
    api(`/analyzer/traffic/${botKind}?hours=${anWindowHours}`).catch(() => null),
  ]);
  head.innerHTML = ''; body.innerHTML = '';

  const botKeyField = anTabCurrent === 'countries' ? 'country' : 'vhost';
  const botRows = botData && botData.reachable !== false ? (botData.countries || botData.vhosts || []) : [];
  const botByKey = new Map(botRows.map(r => [r[botKeyField], r]));

  const cols = anTabCurrent === 'countries'
    ? [t('analyzer.col.country'), t('analyzer.col.requests'), t('analyzer.col.traffic'), t('analyzer.col.errors'), t('analyzer.col.bots')]
    : [t('analyzer.col.vhost'), t('analyzer.col.requests'), t('analyzer.col.traffic'), t('analyzer.col.errors'), t('analyzer.col.bots')];
  for (const cname of cols) {
    const th = document.createElement('th');
    th.textContent = cname;
    head.appendChild(th);
  }

  const rows = d ? (d.countries || d.vhosts || []) : [];
  if (!rows.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 5;
    td.style.cssText = 'color:var(--text3);padding:12px';
    td.textContent = d && d.reachable === false
      ? t('analyzer.agentUnreachable')
      : t('analyzer.noDataPeriod');
    tr.appendChild(td); body.appendChild(tr);
    return;
  }

  for (const r of rows) {
    const tr = document.createElement('tr');

    const c1 = document.createElement('td');
    c1.style.fontFamily = 'monospace';
    if (anTabCurrent === 'countries') {
      const flag = document.createElement('span');
      flag.className = 'an-flag';
      flag.textContent = anFlag(r.country);
      c1.appendChild(flag);
      // '??' est le regroupement des adresses non resolues.
      c1.appendChild(document.createTextNode(r.country === '??' ? t('analyzer.unknownCountry') : (r.country || '')));
    } else {
      c1.textContent = r.vhost || '';
    }
    tr.appendChild(c1);

    const c2 = document.createElement('td');
    c2.textContent = (r.requests || 0).toLocaleString('fr-FR');
    tr.appendChild(c2);

    const c3 = document.createElement('td');
    c3.textContent = fmtB(r.bytes || 0);
    tr.appendChild(c3);

    const c4 = document.createElement('td');
    const errs = r.errors || 0;
    const ratio = r.requests ? Math.round(100 * errs / r.requests) : 0;
    c4.textContent = errs.toLocaleString('fr-FR') + (ratio > 0 ? ` (${ratio} %)` : '');
    if (ratio >= 30) c4.style.color = 'var(--red)';
    else if (ratio >= 10) c4.style.color = 'var(--amber)';
    tr.appendChild(c4);

    // Colonne robots : jointe par pays ou par vhost selon l onglet actif.
    // Absente (tiret) plutot qu a zero force quand l agent n a pas encore
    // de donnees pour cette ligne precise — un vrai zero et une donnee
    // manquante ne veulent pas dire la meme chose.
    const c5 = document.createElement('td');
    const botKey = anTabCurrent === 'countries' ? r.country : r.vhost;
    const botRow = botByKey.get(botKey);
    if (botRow && botRow.total > 0) {
      const botPct = Math.round(100 * botRow.bots / botRow.total);
      c5.textContent = botRow.bots.toLocaleString('fr-FR') + ` (${botPct} %)`;
      if (botPct >= 50) c5.style.color = 'var(--amber)';
    } else {
      c5.textContent = '—';
      c5.style.color = 'var(--text3)';
    }
    tr.appendChild(c5);

    body.appendChild(tr);
  }
}

// ── Modale "Regles" : catalogue integre + regles personnalisees YAML ───────
// Chargee a la demande (ouverture de la modale), pas au chargement de la
// page Analyse — ces donnees changent rarement et n ont pas besoin d etre
// tenues a jour par le cycle de rafraichissement de 5s du reste de la page.
const RULES_META = {
  bruteforce:      { name: () => t('analyzer.rules.name.bruteforce')      || 'Force brute',                 severity: 'high'  },
  scan:            { name: () => t('analyzer.rules.name.scan')            || 'Scan de chemins',              severity: 'medium'},
  flood:           { name: () => t('analyzer.rules.name.flood')           || 'Flood par adresse',            severity: 'high'  },
  scraping:        { name: () => t('analyzer.rules.name.scraping')        || 'Aspiration de contenu',        severity: 'low'   },
  volumetric:      { name: () => t('analyzer.rules.name.volumetric')      || 'Anomalie volumetrique (vhost)',severity: null    },
  country_traffic: { name: () => t('analyzer.rules.name.countryTraffic')  || 'Anomalie volumetrique (pays)', severity: null    },
};
const RULES_SEVERITY_LABEL = {
  high:   () => t('analyzer.rules.sevHigh')   || 'Haute',
  medium: () => t('analyzer.rules.sevMedium') || 'Moyenne',
  low:    () => t('analyzer.rules.sevLow')    || 'Basse',
};
const RULES_SEVERITY_COLOR = { high: 'var(--red)', medium: 'var(--amber)', low: 'var(--text3)' };

// Libelle + mise en forme de chaque champ de configuration reelle qu une
// regle integree peut exposer (voir lib/rules-manager.js#catalog() cote
// nginx-analyzer) — un seul endroit pour ne pas repeter le mapping cle/texte
// dans rulesRenderBuiltins().
const RULES_CONFIG_FIELD = {
  windowMinutes:           { label: () => t('analyzer.rules.cfg.window')       || 'Fenetre glissante',        fmt: v => `${v} min` },
  minRequests:             { label: () => t('analyzer.rules.cfg.minRequests')  || 'Seuil de requetes',        fmt: v => `${v}` },
  minDistinct:             { label: () => t('analyzer.rules.cfg.minDistinct')  || 'Chemins distincts min.',   fmt: v => `${v}` },
  minNotFoundRatioPercent: { label: () => t('analyzer.rules.cfg.notFoundRatio')|| 'Ratio 404 min.',           fmt: v => `${v}%` },
  minFailures:             { label: () => t('analyzer.rules.cfg.minFailures')  || 'Echecs min.',              fmt: v => `${v}` },
  maxDistinct:             { label: () => t('analyzer.rules.cfg.maxDistinct')  || 'Chemins distincts max.',   fmt: v => `${v}` },
  learningDays:            { label: () => t('analyzer.rules.cfg.learningDays') || 'Apprentissage',            fmt: v => `${v} j` },
  sigmaThreshold:          { label: () => t('analyzer.rules.cfg.sigma')        || 'Seuil (ecarts-type)',      fmt: v => `${v}` },
  minAbsoluteRequests:     { label: () => t('analyzer.rules.cfg.minAbsolute')  || 'Volume min. absolu',       fmt: v => `${v}` },
};

function rulesOpen() {
  document.getElementById('rules-modal-overlay').style.display = 'flex';
  rulesLoad();
}
function rulesClose() {
  document.getElementById('rules-modal-overlay').style.display = 'none';
}

async function rulesLoad() {
  const data = await api('/analyzer/rules');
  const unreachableEl = document.getElementById('rules-unreachable');
  const listEl = document.getElementById('rules-builtin-list');
  const customListEl = document.getElementById('rules-custom-list');
  const errEl = document.getElementById('rules-custom-errors');
  if (!data || data.reachable === false) {
    unreachableEl.style.display = '';
    listEl.innerHTML = '';
    customListEl.innerHTML = '';
    return;
  }
  unreachableEl.style.display = 'none';
  rulesRenderProcessing(document.getElementById('rules-processing'), data.processing);
  rulesRenderBuiltins(listEl, data.builtins || []);
  rulesRenderCustom(customListEl, data.custom || []);
  const yamlBox = document.getElementById('rules-custom-yaml');
  // Ne pas ecraser une saisie en cours si l operateur a deja commence a
  // modifier le texte (ex : rafraichissement declenche par un toggle) —
  // seulement au tout premier chargement de la modale.
  if (!yamlBox.dataset.touched) yamlBox.value = data.customYaml || '';
  if (data.customErrors && data.customErrors.length) {
    errEl.style.display = '';
    errEl.textContent = data.customErrors.join('\n');
  } else {
    errEl.style.display = 'none';
  }
}

// "Comment le moteur traite ces regles" : texte vivant renvoye par
// nginx-analyzer (lib/rules-manager.js#buildProcessingInfo()), pas une
// documentation figee cote dashboard — la fenetre reelle en minutes y est
// deja substituee cote serveur, jamais desynchronisee d une config qu on
// pourrait changer sans regarder ce fichier.
function rulesRenderProcessing(container, processing) {
  if (!container) return;
  container.innerHTML = '';
  if (!processing) { container.style.display = 'none'; return; }
  container.style.display = '';
  const ROWS = [
    ['analyzer.rules.proc.aggregation', 'Agregation', processing.aggregation],
    ['analyzer.rules.proc.edgeTriggered', 'Declenchement', processing.edgeTriggered],
    ['analyzer.rules.proc.vhostOptOut', 'Opt-out par vhost', processing.vhostOptOut],
    ['analyzer.rules.proc.customRules', 'Regles personnalisees', processing.customRules],
  ];
  for (const [key, fallbackLabel, text] of ROWS) {
    if (!text) continue;
    const line = document.createElement('div');
    line.style.cssText = 'margin-bottom:6px';
    const strong = document.createElement('strong');
    strong.style.color = 'var(--text)';
    strong.textContent = (t(key) || fallbackLabel) + ' : ';
    line.appendChild(strong);
    line.appendChild(document.createTextNode(text));
    container.appendChild(line);
  }
}

function rulesRenderBuiltins(container, builtins) {
  container.innerHTML = '';
  for (const r of builtins) {
    const meta = RULES_META[r.key] || { name: () => r.key, severity: null };
    const wrap = document.createElement('div');
    wrap.style.cssText = 'border:1px solid var(--border2);border-radius:var(--r);padding:10px 12px';

    const head = document.createElement('div');
    head.style.cssText = 'display:flex;align-items:center;justify-content:space-between;gap:10px';

    const left = document.createElement('div');
    left.style.cssText = 'display:flex;align-items:center;gap:8px';
    const idBadge = document.createElement('span');
    idBadge.textContent = '#' + r.id;
    idBadge.style.cssText = 'font-family:monospace;font-size:10px;color:var(--text3);background:var(--bg);border-radius:4px;padding:1px 5px';
    const nameEl = document.createElement('span');
    nameEl.style.fontWeight = '600';
    nameEl.textContent = meta.name();
    left.appendChild(idBadge);
    left.appendChild(nameEl);
    if (meta.severity) {
      const sev = document.createElement('span');
      sev.textContent = (RULES_SEVERITY_LABEL[meta.severity] && RULES_SEVERITY_LABEL[meta.severity]()) || meta.severity;
      sev.style.cssText = `font-size:10px;color:${RULES_SEVERITY_COLOR[meta.severity] || 'var(--text3)'}`;
      left.appendChild(sev);
    }

    const toggle = document.createElement('label');
    toggle.style.cssText = 'display:flex;align-items:center;gap:6px;cursor:pointer;font-size:12px;color:var(--text2)';
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.checked = r.enabled !== false;
    cb.addEventListener('change', () => rulesToggle(r.key, cb.checked));
    const cbLabel = document.createElement('span');
    cbLabel.textContent = r.enabled !== false ? (t('analyzer.rules.enabled') || 'Activee') : (t('analyzer.rules.disabled') || 'Desactivee');
    cb.addEventListener('change', () => { cbLabel.textContent = cb.checked ? (t('analyzer.rules.enabled') || 'Activee') : (t('analyzer.rules.disabled') || 'Desactivee'); });
    toggle.appendChild(cb);
    toggle.appendChild(cbLabel);

    head.appendChild(left);
    head.appendChild(toggle);
    wrap.appendChild(head);

    if (r.explanation) {
      const body = document.createElement('div');
      body.style.cssText = 'margin-top:8px;font-size:12px;color:var(--text2);display:flex;flex-direction:column;gap:4px';
      const rows = [
        ['analyzer.rules.what', 'Quoi', r.explanation.what],
        ['analyzer.rules.why', 'Pourquoi', r.explanation.why],
        ['analyzer.rules.legit', 'Faux positif possible', r.explanation.legit],
        ['analyzer.rules.action', 'Action recommandee', r.explanation.action],
      ];
      for (const [key, fallbackLabel, text] of rows) {
        if (!text) continue;
        const line = document.createElement('div');
        const strong = document.createElement('strong');
        strong.style.color = 'var(--text)';
        strong.textContent = (t(key) || fallbackLabel) + ' : ';
        line.appendChild(strong);
        line.appendChild(document.createTextNode(text));
        body.appendChild(line);
      }
      wrap.appendChild(body);
    }
    if (r.config) {
      const cfgWrap = document.createElement('div');
      cfgWrap.style.cssText = 'margin-top:8px;display:flex;flex-wrap:wrap;gap:6px';
      for (const [field, value] of Object.entries(r.config)) {
        const def = RULES_CONFIG_FIELD[field];
        if (!def || value === null || value === undefined) continue;
        const chip = document.createElement('span');
        chip.style.cssText = 'font-size:10px;color:var(--text2);background:var(--bg);border:1px solid var(--border2);border-radius:10px;padding:2px 8px';
        chip.textContent = `${def.label()} : ${def.fmt(value)}`;
        cfgWrap.appendChild(chip);
      }
      if (cfgWrap.childNodes.length) wrap.appendChild(cfgWrap);
    }
    container.appendChild(wrap);
  }
}

function rulesRenderCustom(container, custom) {
  container.innerHTML = '';
  if (!custom.length) return;
  for (const r of custom) {
    const row = document.createElement('div');
    row.style.cssText = 'display:flex;align-items:center;gap:8px;font-size:12px;padding:6px 8px;background:var(--bg);border-radius:6px';
    const idBadge = document.createElement('span');
    idBadge.textContent = '#' + r.id;
    idBadge.style.cssText = 'font-family:monospace;font-size:10px;color:var(--text3)';
    const nameEl = document.createElement('span');
    nameEl.style.fontWeight = '600';
    nameEl.textContent = r.name;
    const sev = document.createElement('span');
    sev.textContent = (RULES_SEVERITY_LABEL[r.severity] && RULES_SEVERITY_LABEL[r.severity]()) || r.severity;
    sev.style.cssText = `font-size:10px;color:${RULES_SEVERITY_COLOR[r.severity] || 'var(--text3)'}`;
    const state = document.createElement('span');
    state.style.cssText = 'margin-left:auto;font-size:10px;color:' + (r.enabled !== false ? 'var(--green)' : 'var(--text3)');
    state.textContent = r.enabled !== false ? (t('analyzer.rules.enabled') || 'Activee') : (t('analyzer.rules.disabled') || 'Desactivee');
    row.appendChild(idBadge);
    row.appendChild(nameEl);
    row.appendChild(sev);
    if (r.description) {
      const desc = document.createElement('span');
      desc.style.color = 'var(--text3)';
      desc.textContent = r.description;
      row.appendChild(desc);
    }
    row.appendChild(state);
    container.appendChild(row);
  }
}

async function rulesToggle(key, enable) {
  await api('/analyzer/rules/toggle', { method: 'POST', body: JSON.stringify({ key, enable }) });
  await rulesLoad();
}

async function rulesSaveCustom() {
  const yamlBox = document.getElementById('rules-custom-yaml');
  const errEl = document.getElementById('rules-custom-errors');
  const r = await api('/analyzer/rules/custom', { method: 'POST', body: JSON.stringify({ yaml: yamlBox.value }) });
  if (!r || !r.ok) {
    errEl.style.display = '';
    errEl.textContent = (r && r.errors && r.errors.join('\n')) || (t('analyzer.rules.saveError') || 'Erreur : agent injoignable');
    return;
  }
  errEl.style.display = 'none';
  delete yamlBox.dataset.touched;
  await rulesLoad();
}

function rulesResetTemplate() {
  const yamlBox = document.getElementById('rules-custom-yaml');
  yamlBox.value = [
    'rules:',
    '  - id: 100',
    '    name: exemple_admin_probe',
    '    enable: false',
    "    severity: medium",
    '    description: "Exemple desactive par defaut — dupliquez et adaptez"',
    '    window_minutes: 5',
    '    min_matches: 10',
    '    path_hint: "(wp-admin|phpmyadmin|\\.env)"',
    '    ua_hint: null',
    '    status_in: []',
    '    method_in: []',
    '',
  ].join('\n');
  yamlBox.dataset.touched = '1';
}

// ── Modale "Hotes & directives" : vue en lecture seule des commentaires
// magiques # nginx-control-... reellement presents dans sites/*.conf ────────
// Reutilise GET /api/backends (deja expose par features/backends.js, deja
// protege par view_configs, deja utilise par la page Backends) : chaque
// serverBlock y porte deja diagnosticEnabled/analyzeEnabled/
// analyzeIgnoreRuleIds/monitoring, extraits par lib/vhost-targets.js. Aucune
// nouvelle route backend necessaire pour cette fonctionnalite — uniquement
// de l'agregation/affichage cote client.
let directivesRuleNameCache = null; // id numerique -> libelle, construit a la demande

function directivesOpen() {
  document.getElementById('directives-modal-overlay').style.display = 'flex';
  directivesLoad();
}
function directivesClose() {
  document.getElementById('directives-modal-overlay').style.display = 'none';
}

async function directivesRuleNames() {
  if (directivesRuleNameCache) return directivesRuleNameCache;
  directivesRuleNameCache = {};
  try {
    const data = await api('/analyzer/rules');
    for (const r of (data && data.builtins) || []) {
      const meta = RULES_META[r.key];
      directivesRuleNameCache[r.id] = meta ? meta.name() : r.key;
    }
    for (const r of (data && data.custom) || []) {
      directivesRuleNameCache[r.id] = r.name;
    }
  } catch (e) { /* agent injoignable : on retombe sur les identifiants bruts */ }
  return directivesRuleNameCache;
}

async function directivesLoad() {
  const [backendsData, ruleNames] = await Promise.all([
    api('/backends'),
    directivesRuleNames(),
  ]);
  const emptyEl = document.getElementById('directives-empty');
  const wrapEl = document.getElementById('directives-wrap');
  const body = document.getElementById('directives-body');
  body.innerHTML = '';

  const vhosts = (backendsData && backendsData.vhosts) || [];
  // Un fichier sans aucun bloc server{} exploitable (upstream seul, snippet
  // inclus ailleurs...) n'a rien a montrer ici — filtre avant le test vide,
  // sinon une majorite de fichiers "vides" masquerait les quelques vhosts
  // qui comptent reellement.
  const rows = [];
  for (const v of vhosts) {
    for (const b of (v.serverBlocks || [])) rows.push({ vhost: v, block: b });
  }
  if (!rows.length) {
    emptyEl.style.display = '';
    wrapEl.style.display = 'none';
    return;
  }
  emptyEl.style.display = 'none';
  wrapEl.style.display = '';

  for (const { vhost, block } of rows) body.appendChild(directivesRenderRow(vhost, block, ruleNames));
}

function directivesBadge(on, onLabelKey, onLabelFallback, offLabelKey, offLabelFallback) {
  const span = document.createElement('span');
  span.className = 'badge ' + (on ? 'gn' : 'gy');
  span.textContent = on ? (t(onLabelKey) || onLabelFallback) : (t(offLabelKey) || offLabelFallback);
  return span;
}

function directivesRenderRow(vhost, block, ruleNames) {
  const tr = document.createElement('tr');
  if (!vhost.enabled) tr.style.opacity = '0.5'; // fichier <name>.conf.DISABLE

  const c1 = document.createElement('td');
  c1.style.fontFamily = 'monospace';
  c1.textContent = (block.serverNames && block.serverNames.length) ? block.serverNames.join(', ') : '—';
  tr.appendChild(c1);

  const c2 = document.createElement('td');
  c2.style.cssText = 'font-family:monospace;font-size:11px;color:var(--text3)';
  c2.textContent = vhost.name + (vhost.enabled ? '' : ' (' + (t('analyzer.directives.fileDisabled') || 'desactive') + ')');
  tr.appendChild(c2);

  // Diagnostic : le fichier ET le bloc doivent tous deux etre actifs — deux
  // portees distinctes (# nginx-control-diagnostic vs -diagnostic-vhost, voir
  // lib/vhost-targets.js), mais une seule colonne suffit ici : ce qui compte
  // pour l'operateur est le resultat final, pas laquelle des deux l'a coupe.
  const c3 = document.createElement('td');
  c3.appendChild(directivesBadge(
    vhost.diagnosticEnabled && block.diagnosticEnabled,
    'analyzer.directives.on', 'Actif', 'analyzer.directives.off', 'Coupe'
  ));
  tr.appendChild(c3);

  const c4 = document.createElement('td');
  c4.appendChild(directivesBadge(
    block.analyzeEnabled !== false,
    'analyzer.directives.on', 'Actif', 'analyzer.directives.off', 'Coupe'
  ));
  tr.appendChild(c4);

  const c5 = document.createElement('td');
  const ignored = block.analyzeIgnoreRuleIds || [];
  if (!ignored.length) {
    c5.textContent = '—';
    c5.style.color = 'var(--text3)';
  } else {
    c5.style.cssText = 'display:flex;flex-wrap:wrap;gap:4px';
    for (const id of ignored) {
      const chip = document.createElement('span');
      chip.style.cssText = 'font-size:10px;color:var(--text2);background:var(--bg);border:1px solid var(--border2);border-radius:10px;padding:2px 8px;white-space:nowrap';
      chip.textContent = '#' + id + (ruleNames[id] ? ' ' + ruleNames[id] : '');
      c5.appendChild(chip);
    }
  }
  tr.appendChild(c5);

  const c6 = document.createElement('td');
  const mon = block.monitoring || {};
  if (mon.enabled) {
    c6.style.fontSize = '11px';
    let txt = (t('analyzer.directives.on') || 'Actif') + ` (${mon.intervalSec}s)`;
    if (mon.validHttpCodes && mon.validHttpCodes.length) {
      txt += ' — ' + (t('analyzer.directives.validCodes') || 'codes valides') + ' : ' + mon.validHttpCodes.join(', ');
    }
    c6.textContent = txt;
  } else {
    c6.textContent = '—';
    c6.style.color = 'var(--text3)';
  }
  tr.appendChild(c6);

  return tr;
}

// Ce script est charge en fin de body (apres le HTML de la modale), donc le
// DOM est deja pret ici — un DOMContentLoaded ne se declencherait jamais
// (l evenement est deja passe a ce stade du chargement de la page).
(() => {
  const yamlBox = document.getElementById('rules-custom-yaml');
  if (yamlBox) yamlBox.addEventListener('input', () => { yamlBox.dataset.touched = '1'; });
})();

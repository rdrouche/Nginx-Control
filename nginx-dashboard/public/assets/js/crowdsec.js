// ── CROWDSEC ──────────────────────────────────────────────────────────────────
// Extrait de public/index.html (voir CHANGELOG.md).

async function loadCrowdSec() {
  const bodyEl     = document.getElementById('cs-body');
  const notCfgEl   = document.getElementById('cs-not-configured');
  const statsEl    = document.getElementById('cs-stats');
  bodyEl.style.display    = 'flex';
  notCfgEl.style.display  = 'none';
  statsEl.innerHTML = '<div style="color:var(--text3);font-family:monospace;font-size:12px">Loading...</div>';

  const d = await api('/crowdsec/status').catch(() => null);
  if (!d || !d.configured) {
    bodyEl.style.display   = 'none';
    notCfgEl.style.display = 'block';
    return;
  }
  csCheckMachineStatus();
  csLoadAllowlists();
  if (!d.ok && d.error && !d.summary) {
    statsEl.innerHTML = '<div style="color:var(--red);font-family:monospace;font-size:12px">Error: ' + h(d.error) + '</div>';
    return;
  }

  const s       = d.summary || {};
  const isProm  = d.mode === 'prometheus';
  const isLocal = d.localOnly;

  document.getElementById('cs-count').textContent = s.displayTotal || s.totalDecisions || 0;

  // ── Stat cards ─────────────────────────────────────────────────────────────
  if (isProm) {
    statsEl.innerHTML = [
      { label: t('crowdsec.stat.local.bans'),  val: s.localBans              || 0, cls: 're' },
      { label: t('crowdsec.stat.capi.bans'),   val: isLocal ? t('crowdsec.stat.hidden') : (s.capiDecisions || 0), cls: 'am' },
      { label: t('crowdsec.stat.alerts'),      val: Math.round(s.totalAlerts  || 0), cls: 'bl' },
      { label: t('crowdsec.stat.overflows'),   val: Math.round(s.bucketsOverflowed || 0), cls: '' },
    ].map(c => `<div class="sc ${c.cls}"><div class="sl">${c.label}</div><div class="sv" style="font-size:${typeof c.val==='string'&&isNaN(c.val)?'13px':'22px'}">${h(String(c.val))}</div></div>`).join('');
  } else {
    // Fix (retour utilisateur v12.41.0) : la tuile "BOUNCERS" a ete retiree —
    // la LAPI de CrowdSec n a aucun moyen de fournir cette valeur (voir
    // features/crowdsec.js, en-tete de module) ; elle n avait donc aucun
    // interet a s afficher, meme sous forme de "n/d" permanent.
    statsEl.innerHTML = [
      { label: t('crowdsec.stat.decisions'), val: s.totalDecisions || 0, cls: 're' },
      { label: t('crowdsec.stat.alerts'),    val: s.totalAlerts    || 0, cls: 'am' },
      { label: t('crowdsec.stat.types'),     val: Object.keys(s.byType || {}).join(', ') || '-', cls: '' },
    ].map(c => `<div class="sc ${c.cls}"><div class="sl">${c.label}</div><div class="sv" style="font-size:${typeof c.val==='string'&&isNaN(c.val)?'13px':'22px'}">${h(String(c.val))}</div></div>`).join('');
  }

  // ── Origin breakdown (Prometheus only) ────────────────────────────────────
  const originEl = document.getElementById('cs-origin');
  if (isProm && (d.decisionsByOrigin || []).length) {
    const maxO = Math.max(...d.decisionsByOrigin.map(o => o.count), 1);
    originEl.innerHTML = `<div class="ctitle">${t('crowdsec.origin.title')}</div>` +
      d.decisionsByOrigin.map(o => `<div class="scenario-bar" style="margin-bottom:8px">
        <span style="font-family:monospace;font-size:11px;min-width:100px;color:var(--text2)">${h(o.origin)}</span>
        <div class="sbar"><div class="sbar-fill" style="width:${Math.round(o.count/maxO*100)}%;background:var(--${o.origin==='CAPI'||o.origin==='crowdsec'?'amber':'blue'})"></div></div>
        <span class="badge ${o.origin==='CAPI'||o.origin==='crowdsec'?'am':'bl'}" style="min-width:48px;text-align:right">${Math.round(o.count)}</span>
      </div>`).join('');
    originEl.style.display = '';
  } else {
    originEl.style.display = 'none';
  }

  // ── Acquisition sources (Prometheus only) ─────────────────────────────────
  const acqEl = document.getElementById('cs-acquisition');
  if (isProm && (d.acquisition || []).length) {
    acqEl.innerHTML = `<div class="ctitle">${t('crowdsec.acq.title')}</div>
      <table class="cs-table"><thead><tr>
        <th>${t('crowdsec.acq.source')}</th><th>${t('crowdsec.acq.type')}</th><th>${t('crowdsec.acq.lines')}</th>
      </tr></thead><tbody>` +
      d.acquisition.map(a => `<tr>
        <td style="font-family:monospace;font-size:11px;color:var(--text)">${h(a.source)}</td>
        <td><span class="badge gy">${h(a.type||'?')}</span></td>
        <td style="font-family:monospace">${Math.round(a.lines).toLocaleString()}</td>
      </tr>`).join('') + '</tbody></table>';
    acqEl.style.display = '';
  } else {
    acqEl.style.display = 'none';
  }

  // ── Top scenarios ──────────────────────────────────────────────────────────
  const scenarios = d.topScenarios || (d.summary?.topScenarios) || [];
  const maxSc = Math.max(...scenarios.map(s => s.count), 1);
  document.getElementById('cs-scenarios').innerHTML = scenarios.length
    ? scenarios.map(s => `<div class="scenario-bar" style="margin-bottom:8px">
        <span style="font-family:monospace;font-size:11px;min-width:200px;color:var(--text2)">${h(s.name)}</span>
        <div class="sbar"><div class="sbar-fill" style="width:${Math.round(s.count/maxSc*100)}%"></div></div>
        <span class="badge rd" style="min-width:40px;text-align:right">${Math.round(s.count)}</span>
      </div>`).join('')
    : `<div style="color:var(--text3);font-family:monospace;font-size:12px">${t('crowdsec.scenarios.empty')}</div>`;

  // ── Decisions list (LAPI) ──────────────────────────────────────────────────
  const decisions = d.recentDecisions || d.decisions || [];
  csLapiUnavailable = !!d.lapiUnavailable;
  // Store all decisions for client-side filter
  csDecisionsAll = decisions;
  csDecisionsFilter = 'all';

  // Inject filter tabs above the table
  const decSection = document.getElementById('cs-decisions').closest('.card');
  if (decSection && !decSection.querySelector('.cs-filter-tabs')) {
    const origins = [...new Set(decisions.map(d => d.origin).filter(Boolean))].sort();
    const tabs = document.createElement('div');
    tabs.className = 'cs-filter-tabs';
    tabs.innerHTML = `<button class="cs-filter-tab active" data-origin="all" onclick="setCsFilter('all')">All (${decisions.length})</button>` +
      origins.map(o => `<button class="cs-filter-tab" data-origin="${h(o)}" onclick="setCsFilter('${h(o)}')">${h(csOriginBadge(o).label)} (${decisions.filter(d=>d.origin===o).length})</button>`).join('');
    const ctitle = decSection.querySelector('.ctitle');
    if (ctitle) ctitle.insertAdjacentElement('afterend', tabs);
  } else if (decSection) {
    const tabs = decSection.querySelector('.cs-filter-tabs');
    if (tabs) {
      const origins = [...new Set(decisions.map(d => d.origin).filter(Boolean))].sort();
      tabs.innerHTML = `<button class="cs-filter-tab active" data-origin="all" onclick="setCsFilter('all')">All (${decisions.length})</button>` +
        origins.map(o => `<button class="cs-filter-tab" data-origin="${h(o)}" onclick="setCsFilter('${h(o)}')">${h(csOriginBadge(o).label)} (${decisions.filter(d=>d.origin===o).length})</button>`).join('');
    }
  }

  renderCsDecisions();

  // ── Parser health (Prometheus only) ───────────────────────────────────────
  const parserEl = document.getElementById('cs-parser');
  if (isProm && (s.parserOk || s.parserKo)) {
    const total = (s.parserOk || 0) + (s.parserKo || 0);
    const pct   = total ? Math.round((s.parserOk / total) * 100) : 0;
    parserEl.innerHTML = `<div class="ctitle">${t('crowdsec.parser.title')}</div>
      <div style="display:flex;align-items:center;gap:16px;margin-top:8px">
        <div style="flex:1;background:var(--bg3);border-radius:4px;height:8px;overflow:hidden">
          <div style="height:100%;width:${pct}%;background:var(--green);border-radius:4px;transition:.3s"></div>
        </div>
        <span style="font-family:monospace;font-size:12px;color:var(--green)">${pct}% OK</span>
        <span style="font-family:monospace;font-size:11px;color:var(--text3)">${Math.round(s.parserOk||0).toLocaleString()} / ${Math.round(total).toLocaleString()}</span>
      </div>`;
    parserEl.style.display = '';
  } else {
    parserEl.style.display = 'none';
  }

  // Bouncers connectes : retire entierement (retour utilisateur v12.41.0) —
  // voir features/crowdsec.js, en-tete de module, pour le detail. Aucune
  // section #cs-bouncers a mettre a jour ici, elle n existe plus dans
  // index.html.
}

// ── CROWDSEC DECISIONS FILTER ─────────────────────────────────────────────────
let csDecisionsAll = [];
let csLapiUnavailable = false;
let csDecisionsFilter = 'all';

/**
 * "cscli" fell into the generic grey badge, same as any unrecognized origin
 * — indistinguishable from a bug or a stray value. It deserves its own
 * identity: it is exactly the origin this dashboard's own manual ban feature
 * writes, and what `cscli decisions add` writes when run directly on the
 * CrowdSec host — an operator-added decision, not one the engine raised
 * itself.
 */
function csOriginBadge(origin) {
  if (origin === 'CAPI')     return { cls: 'am', label: 'CAPI' };
  if (origin === 'crowdsec') return { cls: 'gn', label: 'crowdsec' };
  if (origin === 'cscli')    return { cls: 'bl', label: 'cscli (manuel)' };
  return { cls: 'gy', label: origin || '-' };
}

function renderCsDecisions() {
  const filtered = csDecisionsFilter === 'all'
    ? csDecisionsAll
    : csDecisionsAll.filter(d => d.origin === csDecisionsFilter);
  const tbody = document.getElementById('cs-decisions');
  if (!tbody) return;
  // Sans acces LAPI, aucune adresse ne peut etre listee — seuls les compteurs
  // Prometheus sont disponibles. Le dire explicitement evite de laisser croire
  // a un tableau simplement vide alors qu il est structurellement impossible
  // a remplir avec la configuration actuelle.
  const emptyMsg = csLapiUnavailable
    ? t('crowdsec.decisions.lapi.unavailable')
    : t('crowdsec.decisions.empty');
  tbody.innerHTML = filtered.length
    ? filtered.map(dec => `<tr>
        <td style="color:var(--text);font-family:monospace">${h(dec.value||'-')}</td>
        <td><span class="badge ${dec.type==='ban'?'rd':'am'}">${h(dec.type||'-')}</span></td>
        <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;font-size:11px">${h(dec.scenario||'-')}</td>
        <td><span class="badge ${csOriginBadge(dec.origin).cls}">${h(csOriginBadge(dec.origin).label)}</span></td>
        <td style="font-family:monospace;font-size:11px">${h(dec.duration||dec.until||'-')}</td>
        <td>${dec.type==='ban' && Number.isInteger(dec.id) ? `<button class="btn sm" onclick="csUnbanDecision(${dec.id})">${h(t('crowdsec.decisions.unban'))}</button>` : ''}</td>
      </tr>`).join('')
    : `<tr><td colspan="6" style="color:${csLapiUnavailable?'var(--amber)':'var(--text3)'};text-align:center;padding:16px">${h(emptyMsg)}</td></tr>`;
}

/** Retire un bannissement — necessite les identifiants machine, pas la cle bouncer. */
/**
 * Affiche l erreur complete d une action CrowdSec — pas seulement le message
 * generique. Le serveur renvoie {error, status, body}, ou `body` est la
 * reponse verbatim du LAPI. Un bug precedent n affichait que `error`,
 * jetant silencieusement le detail qui permet de diagnostiquer un ecart de
 * schema (voir POST /v1/alerts, dont la forme exacte reste une hypothese
 * documentee dans lib/crowdsec-lapi.js).
 */
function csShowError(r) {
  if (!r) { alert(t('crowdsec.error.invalid')); return; }
  const lines = [r.error || t('crowdsec.error.unknown')];
  if (r.status) lines[0] += ` (HTTP ${r.status})`;
  const detail = r.body ?? r.detail;
  if (detail) lines.push(typeof detail === 'string' ? detail : JSON.stringify(detail, null, 2));
  alert(lines.join('\n\n'));
}

async function csUnbanDecision(id) {
  const dec = csDecisionsAll.find(d => d.id === id);
  const label = dec ? (dec.value || id) : id;
  if (!confirm(t('crowdsec.decisions.unban.confirm', { label }))) return;
  const r = await api('/crowdsec/unban', { method: 'POST', body: JSON.stringify({ id }) })
    .catch(e => ({ error: e.message }));
  if (r && r.error) { csShowError(r); return; }
  loadCrowdSec();
}

/** Verifie si les identifiants machine sont configures, sans bloquer le reste de la page. */
async function csCheckMachineStatus() {
  const badge = document.getElementById('cs-machine-badge');
  const warn  = document.getElementById('cs-machine-warning');
  const d = await api('/crowdsec/machine-status').catch(() => null);
  const ok = d && d.configured && d.ok !== false;
  if (badge) {
    // Le machine_id est affiche a chaque fois qu il est connu : c est le
    // moyen le plus rapide de reperer un decalage avec `cscli machines list`
    // sur l hote CrowdSec, la cause la plus frequente d un 401.
    const idPart = d && d.machineId ? ` (${d.machineId})` : '';
    badge.textContent = !d || !d.configured ? 'non configure'
                       : d.ok === false ? `erreur : ${d.error || ''}${idPart}`
                       : `connecte${idPart}`;
    badge.style.color = ok ? 'var(--green)' : 'var(--amber)';
    badge.title = d && d.detail ? JSON.stringify(d.detail) : '';
  }
  if (warn) warn.style.display = ok ? 'none' : '';
}

async function csBanIp() {
  const ip       = document.getElementById('cs-ban-ip').value.trim();
  const duration = document.getElementById('cs-ban-duration').value;
  const reason   = document.getElementById('cs-ban-reason').value.trim();
  if (!ip) { alert(t('crowdsec.ban.ip.required')); return; }
  if (!confirm(t('crowdsec.ban.confirm', { ip, duration }))) return;
  const r = await api('/crowdsec/ban', { method: 'POST', body: JSON.stringify({ ip, duration, reason }) })
    .catch(e => ({ error: e.message }));
  if (r && r.error) { csShowError(r); return; }
  document.getElementById('cs-ban-ip').value = '';
  document.getElementById('cs-ban-reason').value = '';
  loadCrowdSec();
}

// ── Listes blanches centralisees (lecture seule — voir la note sur la page) ──
async function csCheckAllowlist() {
  const value = document.getElementById('cs-al-check').value.trim();
  const out = document.getElementById('cs-al-check-result');
  if (!value) return;
  out.textContent = t('crowdsec.allowlist.checking');
  out.style.color = 'var(--text3)';
  const d = await api('/crowdsec/allowlists/check?value=' + encodeURIComponent(value)).catch(() => null);
  if (!d || !d.configured) { out.textContent = t('crowdsec.allowlist.machine.not.configured'); out.style.color = 'var(--amber)'; return; }
  if (d.ok === false) { out.textContent = t('crowdsec.allowlist.error', { error: d.error || '' }); out.style.color = 'var(--amber)'; return; }
  if (d.allowlisted) {
    out.textContent = t('crowdsec.allowlist.covered') + (d.reason ? ' — ' + d.reason : '');
    out.style.color = 'var(--green)';
  } else {
    out.textContent = t('crowdsec.allowlist.not.covered');
    out.style.color = 'var(--text3)';
  }
}

/** Charge et affiche les listes blanches, via l API DOM — les valeurs viennent de l operateur. */
async function csLoadAllowlists() {
  const box = document.getElementById('cs-allowlists');
  if (!box) return;
  const d = await api('/crowdsec/allowlists').catch(() => null);
  box.innerHTML = '';

  if (!d || !d.configured) {
    const p = document.createElement('div');
    p.style.cssText = 'color:var(--text3);font-family:monospace;font-size:12px';
    p.textContent = t('crowdsec.allowlist.machine.not.configured');
    box.appendChild(p);
    return;
  }
  if (d.ok === false) {
    const p = document.createElement('div');
    p.style.cssText = 'color:var(--amber);font-family:monospace;font-size:12px';
    p.textContent = t('crowdsec.allowlist.crowdsec.error', { error: d.error || '' }) + (d.detail ? ' — ' + JSON.stringify(d.detail) : '');
    box.appendChild(p);
    return;
  }
  const lists = d.allowlists || [];
  if (!lists.length) {
    const p = document.createElement('div');
    p.style.cssText = 'color:var(--text3);font-family:monospace;font-size:12px';
    p.textContent = t('crowdsec.allowlist.empty');
    box.appendChild(p);
    return;
  }
  for (const al of lists) {
    const card = document.createElement('div');
    card.style.cssText = 'background:var(--bg3);border:1px solid var(--border2);border-radius:var(--r);padding:10px 12px;margin-bottom:8px';

    const head = document.createElement('div');
    head.style.cssText = 'display:flex;align-items:center;gap:8px;margin-bottom:6px';
    const name = document.createElement('span');
    name.style.fontWeight = '500';
    name.textContent = al.name;
    head.appendChild(name);
    if (al.description) {
      const desc = document.createElement('span');
      desc.style.color = 'var(--text3)';
      desc.style.fontSize = '12px';
      desc.textContent = al.description;
      head.appendChild(desc);
    }
    if (al.console_managed) {
      const badge = document.createElement('span');
      badge.className = 'badge bl';
      badge.style.marginLeft = 'auto';
      badge.textContent = t('crowdsec.allowlist.console');
      head.appendChild(badge);
    }
    card.appendChild(head);

    const items = al.items || [];
    if (!items.length) {
      const empty = document.createElement('div');
      empty.style.cssText = 'color:var(--text3);font-size:11px';
      empty.textContent = t('crowdsec.allowlist.no.entries');
      card.appendChild(empty);
    }
    for (const item of items) {
      const row = document.createElement('div');
      row.style.cssText = 'display:flex;align-items:center;gap:8px;font-family:monospace;font-size:12px;padding:4px 0';
      const val = document.createElement('span');
      val.style.color = 'var(--text)';
      val.textContent = item.value;
      row.appendChild(val);
      if (item.description) {
        const d2 = document.createElement('span');
        d2.style.color = 'var(--text3)';
        d2.textContent = item.description;
        row.appendChild(d2);
      }
      card.appendChild(row);
    }
    box.appendChild(card);
  }
}

function setCsFilter(origin) {
  csDecisionsFilter = origin;
  document.querySelectorAll('.cs-filter-tab').forEach(b => b.classList.toggle('active', b.dataset.origin === origin));
  renderCsDecisions();
}


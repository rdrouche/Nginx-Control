// ── Blocklists IP ────────────────────────────────────────────────────────────
// Extrait de public/index.html (voir CHANGELOG.md).
//
// Page de suivi + declenchement manuel pour features/blocklists.js : agrege
// des listes d IP externes (URL + nom, une ou plusieurs), fusionne/deduplique,
// et genere deux snippets nginx inclus au niveau http (table geo) et par
// vhost (blocage). La configuration des sources (URL, activation, cron,
// action de blocage) se fait via config/blocklists.yml, deja editable
// depuis la page Configurations grace a l entree "Blocklists IP" enregistree
// dans features/config-editor.js — cette page-ci est volontairement en
// lecture + un seul bouton d action (rafraichissement manuel), pas un
// second editeur de configuration.

let blocklistsBusy = false;

async function loadBlocklistsPage() {
  const kpiTotal    = document.getElementById('bl-kpi-total');
  const kpiEnabled  = document.getElementById('bl-kpi-enabled');
  const kpiInterval = document.getElementById('bl-kpi-interval');
  const kpiAction   = document.getElementById('bl-kpi-action');
  const sourcesBody = document.getElementById('blocklists-sources-body');
  const configBody  = document.getElementById('blocklists-config-body');
  const filesBody   = document.getElementById('blocklists-files-body');
  const navBadge    = document.getElementById('blocklists-count');

  const d = await api('/blocklists/status').catch(() => null);
  if (!d || d.error) {
    sourcesBody.innerHTML = `<tr><td colspan="4" style="color:var(--red)">${h(t('blocklists.error.api'))}${d?.error ? ' : ' + h(d.error) : ''}</td></tr>`;
    configBody.innerHTML  = `<div style="color:var(--red)">${h(t('blocklists.error.api'))}</div>`;
    filesBody.innerHTML   = '';
    return;
  }

  kpiTotal.textContent    = String(d.totalUniqueIps ?? 0);
  kpiEnabled.textContent  = d.enable ? t('blocklists.state.enabled') : t('blocklists.state.disabled');
  kpiEnabled.style.color  = d.enable ? 'var(--green)' : 'var(--text3)';
  kpiInterval.textContent = d.intervalCron || '—';
  kpiAction.textContent   = d.blockAction === 'drop_444'
    ? t('blocklists.action.drop444')
    : t('blocklists.action.deny403');

  if (navBadge) navBadge.textContent = d.enable ? String(d.totalUniqueIps ?? 0) : '';

  // ── Sources ──
  sourcesBody.innerHTML = '';
  const sources = d.sources || [];
  if (!sources.length) {
    sourcesBody.innerHTML = `<tr><td colspan="4" style="color:var(--text3)">${h(t('blocklists.sources.none'))}</td></tr>`;
  } else {
    for (const s of sources) {
      const tr = document.createElement('tr');

      const tdName = document.createElement('td');
      tdName.innerHTML = `${h(s.name)}${s.enable === false ? ` <span class="badge gy">${h(t('blocklists.sources.disabled'))}</span>` : ''}`;
      tr.appendChild(tdName);

      const tdCount = document.createElement('td');
      tdCount.textContent = String(s.count ?? 0);
      tr.appendChild(tdCount);

      const tdStatus = document.createElement('td');
      if (s.lastError) {
        tdStatus.innerHTML = `<span class="badge rd" title="${h(s.lastError)}">${h(t('blocklists.sources.error'))}</span>`;
      } else if (s.lastSuccessAt) {
        tdStatus.innerHTML = `<span class="badge gn">${h(t('blocklists.sources.ok'))}</span>`;
      } else {
        tdStatus.innerHTML = `<span class="badge gy">${h(t('blocklists.sources.pending'))}</span>`;
      }
      tr.appendChild(tdStatus);

      const tdLast = document.createElement('td');
      tdLast.style.fontFamily = 'monospace';
      tdLast.style.fontSize = '11px';
      tdLast.textContent = s.lastSuccessAt ? new Date(s.lastSuccessAt).toLocaleString('fr-FR') : '—';
      tr.appendChild(tdLast);

      sourcesBody.appendChild(tr);
    }
  }

  // ── Configuration (lecture seule — voir hint dans la carte) ──
  const errCount = (d.configErrors || []).length;
  configBody.innerHTML = [
    `<div>${h(t('blocklists.config.enabled'))} : <strong>${d.enable ? h(t('blocklists.state.enabled')) : h(t('blocklists.state.disabled'))}</strong></div>`,
    `<div>${h(t('blocklists.config.interval'))} : <strong>${h(d.intervalCron || '—')}</strong></div>`,
    `<div>${h(t('blocklists.config.action'))} : <strong>${h(d.blockAction || '—')}</strong></div>`,
    `<div>${h(t('blocklists.config.sourcecount'))} : <strong>${sources.length}</strong></div>`,
    errCount
      ? `<div style="color:var(--red)">${h(t('blocklists.config.errors', { n: errCount }))}</div>`
      : '',
  ].filter(Boolean).join('');

  // ── Fichiers generes ──
  const geo = d.geoFile || {};
  const enf = d.enforceFile || {};
  filesBody.innerHTML = [
    `<div>${h(geo.path || '')}${geo.exists ? ` — ${fmtB(geo.size || 0)}` : ` <span style="color:var(--red)">${h(t('blocklists.files.missing'))}</span>`}</div>`,
    `<div>${h(enf.path || '')}${enf.exists ? ` — ${fmtB(enf.size || 0)}` : ` <span style="color:var(--red)">${h(t('blocklists.files.missing'))}</span>`}</div>`,
  ].join('');

  // ── Efficacite (hits) — uniquement si la fonctionnalite est active ──
  const hitsCard = document.getElementById('blocklists-hits-card');
  if (d.enable) {
    await loadBlocklistHitStats();
    if (hitsCard) hitsCard.style.display = '';
  } else if (hitsCard) {
    hitsCard.style.display = 'none';
  }
}

async function loadBlocklistHitStats() {
  const totalEl  = document.getElementById('bl-hits-total');
  const uniqEl   = document.getElementById('bl-hits-uniqueips');
  const bySrcEl  = document.getElementById('bl-hits-bysource');
  const noteEl   = document.getElementById('bl-hits-note');
  if (!totalEl) return;

  const d = await api('/blocklists/hit-stats?hours=24').catch(() => null);
  if (!d || !d.available) {
    totalEl.textContent = '—';
    uniqEl.textContent  = '—';
    bySrcEl.innerHTML   = '';
    noteEl.textContent  = (d && d.hitLogging && !d.hitLogging.enable)
      ? t('blocklists.hits.disabled')
      : t('blocklists.hits.unavailable');
    return;
  }

  totalEl.textContent = String(d.totalHits ?? 0);
  uniqEl.textContent  = String(d.uniqueHitIps ?? 0);
  bySrcEl.innerHTML = (d.bySource || []).length
    ? d.bySource.map(s => `<div>${h(s.name)} : <strong>${s.hits}</strong></div>`).join('')
    : `<div style="color:var(--text3)">${h(t('blocklists.hits.none'))}</div>`;
  noteEl.textContent = d.hitLogging?.method === 'approx' ? t('blocklists.hits.approxnote') : '';
}

async function blocklistsSearchIp() {
  const input  = document.getElementById('bl-search-input');
  const result = document.getElementById('bl-search-result');
  const ip = (input?.value || '').trim();
  if (!ip) return;
  result.innerHTML = `<div style="color:var(--text3)">${h(t('common.loading'))}</div>`;

  const d = await api(`/blocklists/check?ip=${encodeURIComponent(ip)}`).catch(e => ({ error: e.message }));
  if (!d || d.error) {
    result.innerHTML = `<div style="color:var(--red)">${h(t('blocklists.search.invalid'))}</div>`;
    return;
  }
  if (d.blocked) {
    result.innerHTML = `<div style="color:var(--red)">${h(t('blocklists.search.found', { n: d.sources.length }))}</div>` +
      `<div>${d.sources.map(s => `<span class="badge rd">${h(s)}</span>`).join(' ')}</div>`;
  } else {
    result.innerHTML = `<div style="color:var(--green)">${h(t('blocklists.search.notfound'))}</div>`;
  }
}

async function blocklistsRefreshNow() {
  if (blocklistsBusy) return;
  if (!confirm(t('blocklists.confirm.refresh'))) return;
  blocklistsBusy = true;

  const btn = document.getElementById('btn-blocklists-refresh');
  const card = document.getElementById('blocklists-result-card');
  const body = document.getElementById('blocklists-result-body');
  const label = btn?.querySelector('span');
  const prevLabel = label ? label.textContent : '';
  if (btn) btn.disabled = true;
  if (label) label.textContent = t('blocklists.refreshing');

  const d = await api('/blocklists/refresh', { method: 'POST' }).catch(e => ({ error: e.message }));

  if (btn) btn.disabled = false;
  if (label) label.textContent = prevLabel;

  if (card) card.style.display = '';
  if (body) {
    if (!d || d.error) {
      body.innerHTML = `<div style="color:var(--red)">${h(t('blocklists.error.api'))}${d?.error ? ' : ' + h(d.error) : ''}</div>`;
    } else if (d.skipped) {
      body.innerHTML = `<div style="color:var(--text3)">${h(t('blocklists.result.skipped', { reason: d.reason }))}</div>`;
    } else if (d.testFailed) {
      body.innerHTML = `<div style="color:var(--red)">${h(t('blocklists.result.testfailed'))}</div><div style="color:var(--text3);white-space:pre-wrap">${h(d.stderr || d.error || '')}</div>`;
    } else if (!d.ok) {
      body.innerHTML = `<div style="color:var(--red)">${h(t('blocklists.result.reloadfailed'))}${d.error ? ' : ' + h(d.error) : ''}</div>`;
    } else if (d.reloaded) {
      body.innerHTML = `<div style="color:var(--green)">${h(t('blocklists.result.reloaded', { n: d.totalUniqueIps ?? 0 }))}</div>`;
    } else {
      body.innerHTML = `<div style="color:var(--text3)">${h(t('blocklists.result.nochange', { n: d.totalUniqueIps ?? 0 }))}</div>`;
    }
  }

  blocklistsBusy = false;
  await loadBlocklistsPage();
}

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
    sourcesBody.innerHTML = `<tr><td colspan="5" style="color:var(--red)">${h(t('blocklists.error.api'))}${d?.error ? ' : ' + h(d.error) : ''}</td></tr>`;
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
    sourcesBody.innerHTML = `<tr><td colspan="5" style="color:var(--text3)">${h(t('blocklists.sources.none'))}</td></tr>`;
  } else {
    for (const s of sources) {
      const tr = document.createElement('tr');
      const isAnalyzer = s.type === 'analyzer';

      const tdName = document.createElement('td');
      // Source "analyzer" (v12.49.4, redesign par regle v12.50.0) : liste
      // generee depuis les regles d Analyse plutot que recuperee par URL —
      // badges dedies pour la distinguer d une source tierce classique, et
      // pour rendre l etat remediation immediatement visible ("detectee" ne
      // veut pas dire "bloquee"). Le detail (seuil/fenetre/remediation) vit
      // maintenant par regle — voir byRule — plus sur la source elle-meme.
      let nameHtml = `${h(s.name)}${s.enable === false ? ` <span class="badge gy">${h(t('blocklists.sources.disabled'))}</span>` : ''}`;
      if (isAnalyzer) {
        const byRule = s.byRule || [];
        const ruleSummary = byRule.length
          ? byRule.map(r => `${r.name} (${r.detectedCount}${r.remediation ? ', bloque' : ''})`).join(', ')
          : t('blocklists.sources.analyzerNoRule');
        const hasRemediation = byRule.some(r => r.remediation && r.detectedCount > 0);
        nameHtml += ` <span class="badge bl" title="${h(ruleSummary)}">${h(t('blocklists.sources.analyzerBadge'))}</span>`;
        nameHtml += hasRemediation
          ? ` <span class="badge rd">${h(t('blocklists.sources.remediationOn'))}</span>`
          : ` <span class="badge gy" title="${h(t('blocklists.sources.remediationOffHelp'))}">${h(t('blocklists.sources.remediationOff'))}</span>`;
      }
      tdName.innerHTML = nameHtml;
      tr.appendChild(tdName);

      const tdCount = document.createElement('td');
      if (isAnalyzer && (s.count ?? 0) === 0 && (s.detectedCount ?? 0) > 0) {
        tdCount.innerHTML = `0 <span style="color:var(--text3)">(${h(t('blocklists.sources.detected', { n: s.detectedCount ?? 0 }))})</span>`;
      } else {
        tdCount.textContent = String(s.count ?? 0);
      }
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

      // Export (retour utilisateur) : une URL directe pour visualiser (le
      // lien ouvre le texte brut dans un nouvel onglet — le navigateur porte
      // la session en cours) ou telecharger (bouton dedie, force
      // l enregistrement via download=1) la liste de cette source. Pour une
      // source "analyzer", un second lien expose aussi le detail complet
      // ("detectees", y compris sans remediation active) quand il y en a.
      const tdExport = document.createElement('td');
      tdExport.style.whiteSpace = 'nowrap';
      const base = `/api/blocklists/export?source=${encodeURIComponent(s.name)}&format=txt`;
      let exportHtml = `<a href="${base}" target="_blank" rel="noopener" title="${h(t('blocklists.sources.exportView'))}">${h(t('blocklists.sources.exportView'))}</a>`;
      exportHtml += ` · <a href="${base}&download=1" title="${h(t('blocklists.sources.exportDownload'))}">${h(t('blocklists.sources.exportDownload'))}</a>`;
      if (isAnalyzer && (s.detectedCount ?? 0) > 0) {
        const detBase = `${base}&detected=1`;
        exportHtml += ` · <a href="${detBase}" target="_blank" rel="noopener" title="${h(t('blocklists.sources.exportDetected'))}">${h(t('blocklists.sources.exportDetected'))}</a>`;
      }
      tdExport.innerHTML = exportHtml;
      tr.appendChild(tdExport);

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
    (d.challenge ? `<div>${h(t('blocklists.challenge.label'))} : <strong>${d.challenge.enable ? h(t('blocklists.challenge.on', { engine: d.challenge.engine, n: d.challenge.ips })) : h(t('blocklists.challenge.off'))}</strong></div>`
      + `<div class="nf-hint"><a href="#" onclick="openPage('challenge');return false">${h(t('blocklists.challenge.open'))}</a></div>` : ''),
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
    d.challenge ? `<div>${h(d.challenge.httpFile || '')}</div><div>${h(d.challenge.gateFile || '')}</div>` : '',
  ].join('');


  // ── Efficacite (hits) — uniquement si la fonctionnalite est active ──
  const hitsCard = document.getElementById('blocklists-hits-card');
  if (d.enable) {
    await loadBlocklistHitStats();
    if (hitsCard) hitsCard.style.display = '';
  } else if (hitsCard) {
    hitsCard.style.display = 'none';
  }

  // ── Historique des ajouts/retraits de la source analyzer ──
  const histCard = document.getElementById('blocklists-history-card');
  const hasAnalyzer = (d.sources || []).some(s => s.type === 'analyzer');
  if (histCard) {
    histCard.style.display = (d.enable && hasAnalyzer) ? '' : 'none';
    if (d.enable && hasAnalyzer) loadBlocklistHistory(0);
  }
}

// ── Historique (lib/blocklist-history.js) ──
const BL_HIST_PAGE = 25;
let blHistOffset = 0, blHistTotal = 0;

function blHistQuery(offset, extra = '') {
  const action = document.getElementById('bl-hist-action')?.value || '';
  const hours  = Number(document.getElementById('bl-hist-period')?.value || 0);
  const ip     = (document.getElementById('bl-hist-ip')?.value || '').trim();
  const p = new URLSearchParams({ limit: String(BL_HIST_PAGE), offset: String(offset) });
  if (action) p.set('action', action);
  if (ip) p.set('ip', ip);
  if (hours > 0) p.set('since', String(Date.now() - hours * 3600_000));
  return p.toString() + extra;
}

async function loadBlocklistHistory(offset = 0) {
  const body = document.getElementById('bl-hist-body');
  if (!body) return;
  blHistOffset = Math.max(0, offset);
  const d = await api('/blocklists/history?' + blHistQuery(blHistOffset)).catch(() => null);
  if (!d || !Array.isArray(d.entries)) {
    body.innerHTML = `<tr><td colspan="5" style="color:var(--red)">${h(t('blocklists.history.error'))}</td></tr>`;
    return;
  }
  blHistTotal = d.total || 0;
  const badge = { added: 'rd', removed: 'gn', detected: 'gy' };
  body.innerHTML = d.entries.length ? d.entries.map(e => {
    const detail = e.action === 'added' && e.until ? t('blocklists.history.until', { d: new Date(e.until).toLocaleString() })
      : e.reason ? t('blocklists.history.reason.' + e.reason) : '';
    return `<tr><td>${h(new Date(e.ts).toLocaleString())}</td><td style="font-family:monospace">${h(e.ip)}</td>`
      + `<td><span class="badge ${badge[e.action] || 'gy'}">${h(t('blocklists.history.' + e.action))}</span></td>`
      + `<td>${h(e.rule || '—')}</td><td>${h(detail)}`
      + (e.action === 'added' ? ` <button class="sm" data-ip="${h(e.ip)}" onclick="blocklistsManageIp(this.dataset.ip)">${h(t('blocklists.unblock.manage'))}</button>` : '')
      + `</td></tr>`;
  }).join('') : `<tr><td colspan="5" style="color:var(--text3)">${h(t('blocklists.history.none'))}</td></tr>`;
  const from = blHistTotal ? blHistOffset + 1 : 0;
  const to = Math.min(blHistTotal, blHistOffset + BL_HIST_PAGE);
  document.getElementById('bl-hist-info').textContent = t('blocklists.history.range', { from, to, total: blHistTotal });
  document.getElementById('bl-hist-prev').disabled = blHistOffset <= 0;
  document.getElementById('bl-hist-next').disabled = blHistOffset + BL_HIST_PAGE >= blHistTotal;
}

function blocklistHistoryPage(dir) {
  loadBlocklistHistory(blHistOffset + dir * BL_HIST_PAGE);
}

// Export des lignes filtrees (500 max) : meme session que le reste du dashboard.
function blocklistHistoryCsv(ev) {
  ev.preventDefault();
  window.location.href = '/api/blocklists/history?' + blHistQuery(0, '&format=csv');
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
  } else if (d.challenged) {
    result.innerHTML = `<div style="color:var(--amber, #d98e04)">${h(t('blocklists.search.challenged'))}</div>`;
  } else {
    result.innerHTML = `<div style="color:var(--green)">${h(t('blocklists.search.notfound'))}</div>`;
  }
  // v12.54.0 : une IP bloquee par la source "analyzer" peut etre debloquee a la main.
  if (d.analyzerBlocked) {
    result.insertAdjacentHTML('beforeend',
      `<div class="bl-unblock">`
      + `<select id="bl-unblock-hours" class="bl-f-sel">`
      + `<option value="0">${h(t('blocklists.unblock.reset'))}</option>`
      + `<option value="1">${h(t('blocklists.unblock.exempt', { d: '1 h' }))}</option>`
      + `<option value="24">${h(t('blocklists.unblock.exempt', { d: '24 h' }))}</option>`
      + `<option value="168">${h(t('blocklists.unblock.exempt', { d: '7 j' }))}</option>`
      + `</select>`
      + `<button class="sm danger" id="bl-unblock-btn" data-ip="${h(d.ip)}" onclick="blocklistsUnblock(this.dataset.ip)">${h(t('blocklists.unblock.button'))}</button>`
      + `</div>`
      + `<div class="bl-unblock-help">${h(t('blocklists.unblock.help'))}</div>`);
  }
  if (d.unblocked) {
    const until = d.unblocked.until ? t('blocklists.unblock.untilNote', { d: new Date(d.unblocked.until).toLocaleString() }) : '';
    result.insertAdjacentHTML('beforeend',
      `<div class="bl-unblock-help">${h(t('blocklists.unblock.done', { d: new Date(d.unblocked.at).toLocaleString(), by: d.unblocked.by || '—' }))} ${h(until)}</div>`);
  }
}

async function blocklistsUnblock(ip) {
  if (!ip || blocklistsBusy) return;
  const hours = Number(document.getElementById('bl-unblock-hours')?.value || 0);
  if (!confirm(t('blocklists.unblock.confirm', { ip }))) return;
  blocklistsBusy = true;
  const btn = document.getElementById('bl-unblock-btn');
  if (btn) btn.disabled = true;
  const d = await api('/blocklists/unblock', { method: 'POST', body: JSON.stringify({ ip, hours }) }).catch(e => ({ error: e.message }));
  blocklistsBusy = false;
  const result = document.getElementById('bl-search-result');
  if (!d || d.error) {
    if (btn) btn.disabled = false;
    if (result) result.insertAdjacentHTML('beforeend', `<div style="color:var(--red);margin-top:6px">${h(t('blocklists.unblock.error'))}${d?.error ? ' : ' + h(d.error) : ''}</div>`);
    return;
  }
  // Relance la recherche : l'IP n'est plus listee ; recharge aussi l'historique.
  await blocklistsSearchIp();
  if (result && !d.refreshed) {
    result.insertAdjacentHTML('beforeend', `<div style="color:var(--amber);margin-top:6px">${h(t('blocklists.unblock.notrefreshed'))}</div>`);
  }
  loadBlocklistHistory(0);
}

// Depuis une ligne de l'historique : charge l'IP dans la recherche, ou se trouvent les controles.
function blocklistsManageIp(ip) {
  const input = document.getElementById('bl-search-input');
  if (!input) return;
  input.value = ip;
  blocklistsSearchIp();
  input.scrollIntoView({ behavior: 'smooth', block: 'center' });
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

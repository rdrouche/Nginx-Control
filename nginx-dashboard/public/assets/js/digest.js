// ── Resume periodique (digest) ────────────────────────────────────────────────
// Extrait de public/index.html (voir CHANGELOG.md).

async function loadDigest() {
  await digLoadHistory();
  const d = await api('/digest/latest').catch(() => null);
  digRender(d?.digest || null);
}

async function digLoadHistory() {
  const sel = document.getElementById('dig-history');
  if (!sel) return;
  const d = await api('/digest/history?limit=20').catch(() => null);
  sel.innerHTML = '<option value="">' + t('digest.selectLatest') + '</option>';
  for (const item of (d?.digests || [])) {
    const opt = document.createElement('option');
    opt.value = item.id;
    opt.textContent = new Date(item.generated_at).toLocaleString('fr-FR');
    sel.appendChild(opt);
  }
}

async function digShowSelected() {
  const id = document.getElementById('dig-history')?.value;
  const d = id ? await api('/digest/' + id).catch(() => null) : await api('/digest/latest').catch(() => null);
  digRender(d?.digest || null);
}

async function digGenerateNow() {
  const btn = document.getElementById('dig-gen-btn');
  if (btn) { btn.disabled = true; btn.textContent = t('digest.generating'); }
  const d = await api('/digest/generate', { method: 'POST' }).catch(e => ({ error: e.message }));
  if (btn) { btn.disabled = false; btn.textContent = t('digest.generateNow'); }
  if (d && d.error) { alert(t('common.error') + ' : ' + d.error); return; }
  await digLoadHistory();
  digRender(d.digest);
}

/** Supprime le résumé actuellement affiché (celui choisi dans la liste
 * déroulante, ou le dernier si "Dernier résumé" est sélectionné — digRender()
 * garde toujours l id du résumé affiché sur l objet courant via dig-id). */
async function digDeleteSelected() {
  const id = document.getElementById('dig-id')?.value;
  if (!id) return;
  const dateLabel = document.getElementById('dig-meta')?.textContent || `#${id}`;
  if (!confirm(t('digest.confirmDelete', { date: dateLabel }))) return;
  const btn = document.getElementById('dig-del-btn');
  if (btn) btn.disabled = true;
  const r = await api('/digest/remove', { method: 'POST', body: JSON.stringify({ id }) }).catch(e => ({ error: e.message }));
  if (btn) btn.disabled = false;
  if (!r || r.error || !r.ok) { alert(t('common.error') + ' : ' + (r?.error || t('digest.deleteError'))); return; }
  await digLoadHistory();
  const sel = document.getElementById('dig-history');
  if (sel) sel.value = '';
  const latest = await api('/digest/latest').catch(() => null);
  digRender(latest?.digest || null);
}

/** Rendu via l API DOM : aucune donnee ici ne vient d un utilisateur, mais on
 * reste sur le meme reflexe que le reste du dashboard plutot que de melanger
 * les styles. */
function digRender(d) {
  const empty = document.getElementById('dig-empty');
  const content = document.getElementById('dig-content');
  const delBtn = document.getElementById('dig-del-btn');
  if (!d) {
    empty.style.display = ''; content.style.display = 'none';
    if (delBtn) delBtn.style.display = 'none';
    return;
  }
  empty.style.display = 'none';
  content.style.display = 'flex';
  const idEl = document.getElementById('dig-id');
  if (idEl) idEl.value = d.id || '';
  if (delBtn) delBtn.style.display = d.id ? '' : 'none';

  const periodLabel = d.periodHours >= 168 ? t('digest.periodWeeks', { n: Math.round(d.periodHours / 168) }) : `${d.periodHours}h`;
  document.getElementById('dig-meta').textContent =
    t('digest.generatedMeta', { date: new Date(d.generatedAt).toLocaleString('fr-FR'), period: periodLabel });

  document.getElementById('dig-requests').textContent = d.traffic ? fmt(d.traffic.totalRequests) : '—';
  document.getElementById('dig-errors').textContent = d.traffic ? fmt(d.traffic.totalErrors) : '—';
  document.getElementById('dig-bytes').textContent = d.traffic ? fmtB(d.traffic.totalBytes) : '—';
  if (d.bots) {
    const pct = d.bots.total ? Math.round(100 * d.bots.bots / d.bots.total) : 0;
    document.getElementById('dig-bots').textContent = fmt(d.bots.bots) + ' (' + pct + '%)';
  } else {
    document.getElementById('dig-bots').textContent = '—';
  }

  const countriesEl = document.getElementById('dig-countries');
  countriesEl.innerHTML = '';
  if (!d.topCountries?.length) {
    const p = document.createElement('div'); p.style.color = 'var(--text3)'; p.textContent = t('analyzer.noDataPeriod');
    countriesEl.appendChild(p);
  } else {
    for (const c of d.topCountries) {
      const row = document.createElement('div');
      row.style.cssText = 'display:flex;gap:8px';
      const flag = document.createElement('span'); flag.className = 'an-flag'; flag.textContent = anFlag(c.country);
      row.appendChild(flag);
      const name = document.createElement('span'); name.style.color = 'var(--text)'; name.textContent = c.country || '??';
      row.appendChild(name);
      const n = document.createElement('span'); n.style.cssText = 'margin-left:auto;color:var(--text3)'; n.textContent = fmt(c.requests);
      row.appendChild(n);
      countriesEl.appendChild(row);
    }
  }

  const vhostsEl = document.getElementById('dig-vhosts');
  vhostsEl.innerHTML = '';
  for (const v of (d.traffic?.byVhost || [])) {
    const tr = document.createElement('tr');
    const cells = [v.vhost, fmt(v.requests), fmtB(v.bytes), fmt(v.errors)];
    for (const val of cells) {
      const td = document.createElement('td'); td.textContent = val; tr.appendChild(td);
    }
    vhostsEl.appendChild(tr);
  }

  const csCard = document.getElementById('dig-crowdsec-card');
  const csEl = document.getElementById('dig-crowdsec');
  if (d.crowdsec?.configured) {
    csCard.style.display = '';
    csEl.innerHTML = '';
    const total = document.createElement('div');
    total.textContent = t('digest.decisionsActive', { n: fmt(d.crowdsec.activeTotal) });
    csEl.appendChild(total);
    for (const [origin, n] of Object.entries(d.crowdsec.byOrigin || {})) {
      const row = document.createElement('div');
      row.style.cssText = 'color:var(--text3);padding-left:12px';
      row.textContent = origin + ' : ' + n;
      csEl.appendChild(row);
    }
  } else { csCard.style.display = 'none'; }

  const wafCard = document.getElementById('dig-waf-card');
  const wafEl = document.getElementById('dig-waf');
  if (d.waf?.configured) {
    wafCard.style.display = '';
    wafEl.textContent = t('digest.blockedRequests', { n: fmt(d.waf.blockedCount) });
  } else { wafCard.style.display = 'none'; }

  const certsCard = document.getElementById('dig-certs-card');
  const certsEl = document.getElementById('dig-certs');
  if (d.certs?.expiringSoon?.length) {
    certsCard.style.display = '';
    certsEl.innerHTML = '';
    for (const c of d.certs.expiringSoon) {
      const row = document.createElement('div');
      row.style.cssText = 'display:flex;gap:8px';
      const name = document.createElement('span'); name.style.color = 'var(--text)'; name.textContent = c.name;
      row.appendChild(name);
      const days = document.createElement('span');
      days.style.cssText = 'margin-left:auto;' + (c.daysLeft <= 7 ? 'color:var(--red)' : 'color:var(--amber)');
      days.textContent = t('digest.daysLeft', { n: c.daysLeft });
      row.appendChild(days);
      certsEl.appendChild(row);
    }
  } else { certsCard.style.display = 'none'; }

  const errCard = document.getElementById('dig-errors-card');
  if (d.errors?.length) {
    errCard.style.display = '';
    errCard.textContent = t('digest.sectionsUnavailable', { list: d.errors.join(' · ') });
  } else { errCard.style.display = 'none'; }
}

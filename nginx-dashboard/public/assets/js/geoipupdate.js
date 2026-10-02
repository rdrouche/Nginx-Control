// ── GeoIP (geoipupdate) ───────────────────────────────────────────────────────
// Extrait de public/index.html (voir CHANGELOG.md).

async function geoipupdateLoad() {
  const cfg = await api('/geoipupdate/config').catch(() => null);
  const disabled = document.getElementById('gi-disabled');
  const nokey    = document.getElementById('gi-nokey');
  const main     = document.getElementById('gi-main');
  if (!cfg?.enabled) {
    disabled.style.display = '';
    nokey.style.display = 'none';
    main.style.display = 'none';
    return;
  }
  disabled.style.display = 'none';
  if (!cfg.licenseKeySet) {
    nokey.style.display = '';
    main.style.display = 'none';
    return;
  }
  nokey.style.display = 'none';
  main.style.display = 'flex';
  document.getElementById('gi-frequency').textContent = (cfg.frequencyHours || 168) + 'h';
  document.getElementById('gi-image-name').textContent = cfg.image || 'maxmindinc/geoipupdate:latest';
  await geoipupdateRefreshStatus();
}

async function geoipupdateRefreshStatus() {
  const d = await api('/geoipupdate/status').catch(() => null);
  const el       = document.getElementById('gi-status');
  const btnStart = document.getElementById('gi-start');
  const btnStop  = document.getElementById('gi-stop');
  const btnNow   = document.getElementById('gi-update-now');
  const btnImg   = document.getElementById('gi-image-update');
  if (!d?.enabled || !el) return;
  const c = d.container;
  if (!c?.exists) {
    el.innerHTML = '<span class="cb-status-dot stopped"></span>' + t('godns.containerAbsent');
    btnStart.style.display = ''; btnStop.style.display = 'none'; btnNow.style.display = 'none'; btnImg.style.display = '';
  } else if (c.running) {
    el.innerHTML = '<span class="cb-status-dot running"></span>' + t('godns.running', { image: h(c.image) }) +
      (c.started ? t('geoip.startedAt', { date: new Date(c.started).toLocaleString('fr-FR') }) : '');
    btnStart.style.display = 'none'; btnStop.style.display = ''; btnNow.style.display = ''; btnImg.style.display = '';
  } else {
    el.innerHTML = '<span class="cb-status-dot stopped"></span>' + t('godns.stopped') + ' (' + h(c.status || '?') + ')';
    btnStart.style.display = ''; btnStop.style.display = 'none'; btnNow.style.display = ''; btnImg.style.display = '';
  }

  const tbody = document.getElementById('gi-databases');
  tbody.innerHTML = '';
  for (const db of (d.databases || [])) {
    const tr = document.createElement('tr');
    const tdEd = document.createElement('td'); tdEd.textContent = db.edition; tr.appendChild(tdEd);
    const tdSt = document.createElement('td');
    tdSt.innerHTML = db.exists ? '<span style="color:var(--green)">' + t('geoip.dbPresent') + '</span>' : '<span style="color:var(--text3)">' + t('geoip.dbAbsent') + '</span>';
    tr.appendChild(tdSt);
    const tdSz = document.createElement('td'); tdSz.textContent = db.exists ? fmtB(db.sizeBytes) : '—'; tr.appendChild(tdSz);
    const tdMt = document.createElement('td'); tdMt.textContent = db.mtime ? new Date(db.mtime).toLocaleString('fr-FR') : '—'; tr.appendChild(tdMt);
    tbody.appendChild(tr);
  }
}

async function geoipupdateStart() {
  document.getElementById('gi-status').innerHTML = '<span style="color:var(--text3)">' + t('geoip.starting') + '</span>';
  const d = await api('/geoipupdate/container/start', { method: 'POST' }).catch(e => ({ error: e.message }));
  if (d?.error) {
    document.getElementById('gi-status').innerHTML = '<span style="color:var(--red)">' + t('common.error') + ' : ' + h(d.error) + '</span>';
    return;
  }
  await geoipupdateRefreshStatus();
}

async function geoipupdateStop() {
  if (!confirm(t('geoip.confirmStop'))) return;
  await api('/geoipupdate/container/stop', { method: 'POST' }).catch(() => {});
  await geoipupdateRefreshStatus();
}

async function geoipupdateUpdateNow() {
  const btn = document.getElementById('gi-update-now');
  if (btn) { btn.disabled = true; btn.textContent = t('geoip.updatingNow'); }
  const d = await api('/geoipupdate/update-now', { method: 'POST' }).catch(e => ({ error: e.message }));
  if (btn) { btn.disabled = false; btn.textContent = '⟳ ' + t('geoip.updateNowBtn'); }
  if (d?.error) { alert(t('common.error') + ' : ' + d.error); return; }
  // Le conteneur redemarre puis telecharge en tache de fond ; l age des
  // fichiers ne bougera qu une fois le telechargement termine, pas tout de
  // suite — on rafraichit quand meme le statut du conteneur immediatement.
  await geoipupdateRefreshStatus();
}

async function geoipupdateImageUpdate() {
  const btn = document.getElementById('gi-image-update');
  if (btn) { btn.disabled = true; btn.textContent = t('geoip.checkingUpdate'); }
  const d = await api('/geoipupdate/image/update', { method: 'POST' }).catch(e => ({ error: e.message }));
  if (btn) { btn.disabled = false; btn.textContent = '⬇ ' + t('analyzer.updateImage'); }
  if (!d || d.error || d.ok === false) { alert(t('common.error') + ' : ' + (d?.error || t('geoip.updateImpossible'))); return; }
  alert(d.updated
    ? t('geoip.newImageDownloaded') + (d.recreated ? t('geoip.containerRecreated') : '.')
    : t('geoip.imageAlreadyUpToDate'));
  await geoipupdateRefreshStatus();
}

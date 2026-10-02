// ── Pages d'erreur (error-pages) ──────────────────────────────────────────────
// Extrait de public/index.html (voir CHANGELOG.md).

async function errorPagesLoad() {
  const cfg = await api('/error-pages/config').catch(() => null);
  const disabled = document.getElementById('ep-disabled');
  const main     = document.getElementById('ep-main');
  if (!cfg?.enabled) {
    disabled.style.display = '';
    main.style.display = 'none';
    return;
  }
  disabled.style.display = 'none';
  main.style.display = 'flex';
  document.getElementById('ep-template-cfg').textContent = cfg.templateName || 'connection';
  document.getElementById('ep-image-name').textContent = cfg.image || 'tarampampam/error-pages:latest';
  await errorPagesRefreshStatus();
}

async function errorPagesRefreshStatus() {
  const d = await api('/error-pages/status').catch(() => null);
  const el       = document.getElementById('ep-status');
  const btnStart = document.getElementById('ep-start');
  const btnStop  = document.getElementById('ep-stop');
  const btnImg   = document.getElementById('ep-image-update');
  if (!d?.enabled || !el) return;
  const c = d.container;
  const cfgTemplate = document.getElementById('ep-template-cfg').textContent;
  const activeTemplate = c?.templateName || null;
  document.getElementById('ep-template-active').textContent = activeTemplate || '—';
  const mismatch = document.getElementById('ep-template-mismatch');
  mismatch.style.display = (activeTemplate && activeTemplate !== cfgTemplate) ? '' : 'none';

  btnImg.style.display = '';
  if (!c?.exists) {
    el.innerHTML = '<span class="cb-status-dot stopped"></span>' + t('godns.containerAbsent');
    btnStart.style.display = ''; btnStop.style.display = 'none';
  } else if (c.running) {
    el.innerHTML = '<span class="cb-status-dot running"></span>' + t('godns.running', { image: h(c.image) }) +
      (c.started ? t('geoip.startedAt', { date: new Date(c.started).toLocaleString('fr-FR') }) : '');
    btnStart.style.display = ''; btnStop.style.display = '';
  } else {
    el.innerHTML = '<span class="cb-status-dot stopped"></span>' + t('godns.stopped') + ' (' + h(c.status || '?') + ')';
    btnStart.style.display = ''; btnStop.style.display = 'none';
  }
}

async function errorPagesStart() {
  document.getElementById('ep-status').innerHTML = '<span style="color:var(--text3)">' + t('geoip.starting') + '</span>';
  const d = await api('/error-pages/container/start', { method: 'POST' }).catch(e => ({ error: e.message }));
  if (d?.error) {
    document.getElementById('ep-status').innerHTML = '<span style="color:var(--red)">' + t('common.error') + ' : ' + h(d.error) + '</span>';
    return;
  }
  await errorPagesRefreshStatus();
}

async function errorPagesStop() {
  if (!confirm(t('errorPages.confirmStop'))) return;
  await api('/error-pages/container/stop', { method: 'POST' }).catch(() => {});
  await errorPagesRefreshStatus();
}

async function errorPagesImageUpdate() {
  const btn = document.getElementById('ep-image-update');
  if (btn) { btn.disabled = true; btn.textContent = t('geoip.checkingUpdate'); }
  const d = await api('/error-pages/image/update', { method: 'POST' }).catch(e => ({ error: e.message }));
  if (btn) { btn.disabled = false; btn.textContent = '⬇ ' + t('analyzer.updateImage'); }
  if (!d || d.error || d.ok === false) { alert(t('common.error') + ' : ' + (d?.error || t('geoip.updateImpossible'))); return; }
  alert(d.updated
    ? t('geoip.newImageDownloaded') + (d.recreated ? t('geoip.containerRecreated') : '.')
    : t('geoip.imageAlreadyUpToDate'));
  await errorPagesRefreshStatus();
}

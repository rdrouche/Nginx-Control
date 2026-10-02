'use strict';
/**
 * Page "Sync" — comparaison et application des fichiers de référence
 * (dépôt distant) vers l'instance locale, avec diff et pipeline de
 * déploiement. Extrait de public/index.html (voir CHANGELOG.md).
 */
let syncItems = [];

async function initSync() {
  const st = await api('/sync/status').catch(() => null);
  const infoEl = document.getElementById('sync-repo-info');
  if (!st?.configured) {
    document.getElementById('sync-not-configured').style.display = '';
    document.getElementById('sync-body').style.display = 'none';
    infoEl.style.display = 'none';
    return;
  }
  document.getElementById('sync-not-configured').style.display = 'none';
  document.getElementById('sync-body').style.display = 'flex';

  // Shows exactly which repo/path is active — the dashboard has several
  // layers that can set or override this (build-time ARG, .env, docker-compose
  // environment:), so displaying the resolved value here is the fastest way
  // to confirm which one actually won, rather than guessing from the outside.
  const parts = ['Dépôt : <a href="' + h(st.url) + '" target="_blank" rel="noopener">' + h(st.url) + '</a>'];
  parts.push('Sections : ' + h((st.sections || []).join(', ')));
  parts.push(st.pathPrefix ? ('Sous-dossier : ' + h(st.pathPrefix)) : 'Racine du dépôt (pas de sous-dossier)');
  infoEl.innerHTML = parts.join(' &nbsp;·&nbsp; ');
  infoEl.style.display = '';

  await syncCheck();
}

async function syncCheck() {
  document.getElementById('sync-stats').style.display = 'none';
  document.getElementById('sync-table-card').style.display = 'none';
  document.getElementById('sync-diff-card').style.display = 'none';
  document.getElementById('sync-apply-btn').style.display = 'none';
  document.getElementById('sync-table-body').innerHTML =
    '<tr><td colspan="8" style="color:var(--text3);font-family:monospace;padding:16px">Checking...</td></tr>';
  document.getElementById('sync-table-card').style.display = '';

  const d = await api('/sync/check').catch(() => null);
  if (!d?.configured) {
    document.getElementById('sync-table-body').innerHTML =
      '<tr><td colspan="8" style="color:var(--red)">Error — check SYNC_REF_URL</td></tr>';
    return;
  }
  if (d.error) {
    document.getElementById('sync-table-body').innerHTML =
      '<tr><td colspan="8" style="color:var(--red)">' + h(d.error) + '</td></tr>';
    return;
  }

  syncItems = d.items || [];
  document.getElementById('sync-cnt-update').textContent = d.summary?.update || 0;
  document.getElementById('sync-cnt-new').textContent    = d.summary?.new    || 0;
  document.getElementById('sync-cnt-ok').textContent     = d.summary?.ok     || 0;
  document.getElementById('sync-cnt-total').textContent  = d.summary?.total  || 0;
  document.getElementById('sync-stats').style.display    = '';

  const hasUpdates = (d.summary?.update || 0) + (d.summary?.new || 0) > 0;
  document.getElementById('sync-apply-btn').style.display = hasUpdates ? '' : 'none';
  const badge = document.getElementById('sync-mode-badge');
  if (badge) {
    const hasGit = !!(await api('/sync/status').catch(()=>({}))).url;
    // Detect from config: show mode hint
    api('/git/status').then(g => {
      if (g?.configured) {
        badge.textContent = 'mode: git — sync will commit + push';
        badge.style.color = 'var(--green)';
      } else {
        badge.textContent = 'mode: local — no Git repo';
        badge.style.color = 'var(--text3)';
      }
      badge.style.display = '';
    }).catch(() => { badge.style.display = 'none'; });
  }

  if (!syncItems.length) {
    document.getElementById('sync-table-body').innerHTML =
      '<tr><td colspan="8" style="color:var(--text3);text-align:center;padding:16px">' + t('sync.empty') + '</td></tr>';
    return;
  }

  document.getElementById('sync-table-body').innerHTML = syncItems.map((item, idx) => {
    const statusCls = item.status === 'new' ? 'bl' : item.status === 'update' ? 'rd' : 'gy';
    const statusLabel = t('sync.status.' + item.status);
    const stateLabel  = item.localExists ? (item.localDisabled ? 'DISABLE' : 'ACTIVE') : '—';
    const stateCls    = item.localDisabled ? 'am' : item.localExists ? 'gn' : 'gy';
    const canSelect   = item.status !== 'ok';
    return '<tr>' +
      '<td><input type="checkbox" data-idx="' + idx + '" ' + (canSelect ? 'checked' : 'disabled') + '></td>' +
      '<td><span class="badge gy">' + h(item.section) + '</span></td>' +
      '<td style="color:var(--text)">' + h(item.file) + '</td>' +
      '<td style="color:var(--text3)">' + h(item.localVersion || '—') + '</td>' +
      '<td style="color:var(--green)">' + h(item.remoteVersion || '—') + '</td>' +
      '<td><span class="badge ' + statusCls + '">' + statusLabel + '</span></td>' +
      '<td><span class="badge ' + stateCls + '">' + stateLabel + '</span></td>' +
      '<td><button class="btn sm" onclick="syncShowDiff(' + idx + ')">Diff</button></td>' +
      '</tr>';
  }).join('');
}

function syncSelectAll(checked) {
  document.querySelectorAll('#sync-table-body input[type=checkbox]:not(:disabled)')
    .forEach(cb => cb.checked = checked);
}

async function syncShowDiff(idx) {
  const item = syncItems[idx];
  if (!item) return;
  const card = document.getElementById('sync-diff-card');
  card.style.display = '';
  document.getElementById('sync-diff-title').textContent = item.section + '/' + item.file;
  document.getElementById('sync-diff-content').textContent = 'Loading...';

  const d = await api('/sync/preview', {
    method: 'POST',
    body: JSON.stringify({ files: [{ section: item.section, file: item.file }] })
  }).catch(() => null);

  if (!d?.items?.length) {
    document.getElementById('sync-diff-content').textContent = 'Error loading diff';
    return;
  }
  const prev = d.items[0];
  const diffEl = document.getElementById('sync-diff-content');

  if (!prev.localContent) {
    diffEl.innerHTML = '<span class="diff-meta">New file:</span>\n' +
      prev.remoteContent.split('\n').map(l => '<span class="diff-add">+' + h(l) + '</span>').join('\n');
    return;
  }

  // Simple line diff
  const localLines  = (prev.localContent  || '').split('\n');
  const remoteLines = (prev.remoteContent || '').split('\n');
  const html = [];
  const maxLen = Math.max(localLines.length, remoteLines.length);
  for (let i = 0; i < maxLen; i++) {
    const l = localLines[i];
    const r = remoteLines[i];
    if (l === r)       html.push('<span class="diff-meta"> ' + h(r || '') + '</span>');
    else if (l === undefined) html.push('<span class="diff-add">+' + h(r) + '</span>');
    else if (r === undefined) html.push('<span class="diff-del">-' + h(l) + '</span>');
    else {
      html.push('<span class="diff-del">-' + h(l) + '</span>');
      html.push('<span class="diff-add">+' + h(r) + '</span>');
    }
  }
  diffEl.innerHTML = html.join('\n');
  card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

async function syncApply() {
  const checked = [...document.querySelectorAll('#sync-table-body input[type=checkbox]:checked')]
    .map(cb => parseInt(cb.dataset.idx))
    .filter(idx => !isNaN(idx) && syncItems[idx]?.status !== 'ok');

  if (!checked.length) { alert('No files selected'); return; }

  const files = checked.map(idx => ({ section: syncItems[idx].section, file: syncItems[idx].file }));
  const names = files.map(f => f.section + '/' + f.file).join('\n');

  if (!confirm('Apply ' + files.length + ' file(s) and run deployment pipeline?\n\n' + names)) return;

  const pipelineLog = document.getElementById('sync-pipeline-log');
  const pipelineCard = document.getElementById('sync-pipeline-card');
  pipelineCard.style.display = '';
  pipelineLog.innerHTML = '<span style="color:var(--text3)">' + t('sync.applying') + '</span>\n';

  function log(msg, cls) {
    const line = document.createElement('div');
    line.style.color = cls === 'ok' ? 'var(--green)' : cls === 'err' ? 'var(--red)' : 'var(--text2)';
    line.textContent = msg;
    pipelineLog.appendChild(line);
    pipelineLog.scrollTop = pipelineLog.scrollHeight;
  }

  // Step 1: apply to git-work
  const applyRes = await api('/sync/apply', {
    method: 'POST',
    body: JSON.stringify({ files, deploy: true })
  }).catch(e => ({ error: e.message }));

  if (applyRes?.error) { log('Error: ' + applyRes.error, 'err'); return; }

  // Mode badge
  const modeLabel = applyRes.mode === 'git' ? '[git] ' : '[local] ';
  log(modeLabel + (applyRes.applied?.length || 0) + ' file(s) processed', 'ok');

  // Show full pipeline log from server
  (applyRes.log || []).forEach(line => {
    const isErr = /error|fail|ERR/i.test(line);
    const isOk  = /\[OK\]/i.test(line);
    log(line, isErr ? 'err' : isOk ? 'ok' : '');
  });

  log(applyRes.ok ? '[OK] ' + applyRes.message : '[ERR] ' + applyRes.message,
      applyRes.ok ? 'ok' : 'err');

  if (applyRes.ok) setTimeout(() => syncCheck(), 1500);
}

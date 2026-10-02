'use strict';
/**
 * Page "Cache Nginx" — zones de cache proxy, purge globale ou par zone.
 * Extrait de public/index.html (voir CHANGELOG.md).
 */
async function initCache() { await cacheLoad(); }

async function cacheLoad() {
  document.getElementById('cache-zones-card').style.display = 'none';
  document.getElementById('cache-not-configured').style.display = 'none';
  document.getElementById('cache-clear-all-btn').style.display = 'none';

  const d = await api('/cache/zones').catch(() => null);
  if (!d?.configured) {
    document.getElementById('cache-not-configured').style.display = '';
    return;
  }

  const zones = d.zones || [];
  document.getElementById('cache-zones-card').style.display = '';

  if (!zones.length) {
    document.getElementById('cache-zones-list').innerHTML =
      '<div style="color:var(--text3);font-family:monospace;font-size:12px;padding:8px">' + t('cache.empty') + '</div>';
    return;
  }

  document.getElementById('cache-clear-all-btn').style.display = '';

  let totalFiles = 0, totalBytes = 0;
  document.getElementById('cache-zones-list').innerHTML = zones.map(z => {
    totalFiles += z.files; totalBytes += z.bytes;
    return `<div class="cache-zone">
      <span class="cache-zone-name">📁 ${h(z.name)}</span>
      <span class="cache-zone-stats">${z.files} fichier(s) — ${fmtB(z.bytes)}</span>
      <button class="btn sm danger" onclick="cacheClearZone('${h(z.name)}')">
        🗑 <span data-i18n="cache.btn.clear">Clear</span>
      </button>
    </div>`;
  }).join('');

  document.getElementById('cache-total').textContent =
    'Total : ' + totalFiles + ' fichier(s) — ' + fmtB(totalBytes);
}

async function cacheClearAll() {
  if (!confirm(t('cache.confirm.all'))) return;
  await cacheDoClear(null);
}

async function cacheClearZone(zoneName) {
  if (!confirm(t('cache.confirm.one') + ' (' + zoneName + ')')) return;
  await cacheDoClear([zoneName]);
}

async function cacheDoClear(zones) {
  const resultCard = document.getElementById('cache-result-card');
  const resultLog  = document.getElementById('cache-result-log');
  resultCard.style.display = '';
  resultLog.innerHTML = '<span style="color:var(--text3)">' + t('cache.clearing') + '</span>';

  const d = await api('/cache/clear', {
    method: 'POST',
    body: JSON.stringify({ zones })
  }).catch(e => ({ error: e.message }));

  if (d?.error) {
    resultLog.innerHTML = '<span style="color:var(--red)">Erreur : ' + h(d.error) + '</span>';
    return;
  }

  const lines = [];
  (d.results || []).forEach(r => {
    lines.push('[OK] Zone <strong>' + h(r.zone) + '</strong> : ' + r.deleted + ' fichier(s) supprimé(s), ' + fmtB(r.freed) + ' libérés');
  });
  lines.push('');
  lines.push('<strong>Total : ' + d.totalDeleted + ' fichier(s), ' + fmtB(d.totalFreed) + ' libérés</strong>');
  (d.reloadLog || []).forEach(l => {
    const ok = l.includes('[OK]');
    lines.push('<span style="color:' + (ok ? 'var(--green)' : 'var(--amber)') + '">' + h(l) + '</span>');
  });
  resultLog.innerHTML = lines.join('<br>');

  // Refresh zones list
  setTimeout(() => cacheLoad(), 500);
}

'use strict';
/**
 * Badge de version (dashboard + Nginx) et vérification de mise à jour
 * (bandeau "Updates available"). Extrait de public/index.html (voir
 * CHANGELOG.md). Appelé depuis Boot (index.html) via initVersionBadge().
 */
let _versionChecked = false;

async function initVersionBadge() {
  // Use version injected by server at boot
  const v = window.DASHBOARD_VERSION || '?';
  const el = document.getElementById('dash-version');
  if (el) el.textContent = 'v' + v;

  // Auto-check updates once per session (non-blocking)
  if (!_versionChecked && window.UPDATE_CHECK_URL_CONFIGURED) {
    _versionChecked = true;
    setTimeout(() => checkUpdates(true), 3000);
  }
}

async function checkUpdates(silent) {
  const d = await api('/version?check=1').catch(() => null);
  if (!d) return;

  // Update nginx version badge
  const nv = document.getElementById('nginx-version');
  if (nv && d.nginx?.current) nv.textContent = d.nginx.current;
  if (nv && d.nginx?.image)   nv.title = 'Image: ' + d.nginx.image;

  // Update dashboard version badge
  const dv = document.getElementById('dash-version');
  if (dv) dv.textContent = 'v' + (d.dashboard?.current || '?');

  // Check if updates available
  const msgs = [];
  const dashCurrent = d.dashboard?.current || '';
  const dashLatest  = d.updates?.dashboard;
  // Normalize version — strip "nginx/" prefix, leading "v", and this
  // project's own build-variant suffix (-waf / -coraza). Without the last
  // part, an image tagged "1.30.5-waf" never equals the bare "1.30.5"
  // published by an update-check feed, so the badge flags an update as
  // available forever, even right after upgrading to the latest -waf build.
  // lib/docker.js's stripVariantSuffix() does the same on the server side
  // for its own callers; duplicated here (same regex) since this comparison
  // runs entirely client-side against the raw fields the API returns.
  const stripVer = v => (v || '').replace(/^nginx\//, '').replace(/^v/, '').replace(/-(waf|coraza)$/i, '').trim();
  const nginxCurrent = stripVer(d.nginx?.image || d.nginx?.current || '');
  const nginxLatest  = stripVer(d.updates?.nginx || '');

  // Don't flag non-semver versions (e.g. "vnightly", "dev", "manual-build") as outdated
  const isSemver = v => /^\d+\.\d+/.test(v);
  if (dv) dv.title = 'Current: ' + dashCurrent + (dashLatest ? ' | Latest: ' + dashLatest : '');
  if (nv) {
    const nginxVer  = d.nginx?.current || nginxCurrent || '';
    const nginxImg  = d.nginx?.image || '';
    nv.title = 'Running: ' + nginxVer + (nginxImg ? ' | Image: ' + nginxImg : '') + (nginxLatest ? ' | Latest: ' + nginxLatest : '');
  }
  if (dashLatest && isSemver(dashCurrent) && dashLatest !== dashCurrent && dashLatest !== '?') {
    msgs.push('Dashboard: ' + dashCurrent + ' → <strong>' + h(dashLatest) + '</strong>');
    if (dv) dv.classList.add('update');
  } else if (dv) {
    dv.classList.remove('update');
  }
  if (nginxLatest && nginxLatest && nginxLatest !== nginxCurrent) {
    msgs.push('Nginx: ' + h(nginxCurrent) + ' → <strong>' + h(nginxLatest) + '</strong>');
    if (nv) nv.classList.add('update');
  } else if (nv) {
    nv.classList.remove('update');
  }

  if (msgs.length && !silent) {
    const toast = document.getElementById('update-toast');
    document.getElementById('update-toast-content').innerHTML =
      '<div style="margin-bottom:6px;font-weight:500">Updates available</div>' +
      msgs.map(m => '<div style="color:var(--amber)">' + m + '</div>').join('');
    toast.style.display = 'block';
    setTimeout(() => { toast.style.display = 'none'; }, 10000);
  }
  if (!msgs.length && !silent) {
    alert('All components are up to date.');
  }
}

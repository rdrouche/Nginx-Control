// ── Page « Challenge HTTP » (v12.65.0) ─────────────────────────────────────────
// Vue complète du challenge navigateur, indépendante de la blocklist : état,
// conteneur (démarrer / arrêter / image), fichiers nginx générés (+ régénération),
// snippets à inclure dans un vhost, réglages effectifs, IP signalées.
// Aucun innerHTML avec des valeurs serveur : tout passe par textContent.

const CH_SNIPPETS = [
  ['challenge-gate.conf', 'challenge.snip.listed'],
  ['challenge-all.conf', 'challenge.snip.all'],
  ['challenge-all-allowbots.conf', 'challenge.snip.allbots'],
];

function chEl(tag, text, cls) {
  const e = document.createElement(tag);
  if (text != null) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}
function chSet(id, text, color) {
  const e = document.getElementById(id);
  if (!e) return;
  e.textContent = text;
  e.style.color = color || '';
}
function chRow(box, label, value, color) {
  const row = chEl('div');
  row.appendChild(chEl('span', label + ' : '));
  const v = chEl('strong', value);
  if (color) v.style.color = color;
  row.appendChild(v);
  box.appendChild(row);
}

async function challengeLoad() {
  const d = await api('/challenge/status').catch(() => null);
  if (!d) return;
  challengeStatsLoad();
  const green = 'var(--green)', red = 'var(--red)', amber = 'var(--amber, #d98e04)';
  document.getElementById('ch-off').style.display = d.challengeEnabled ? 'none' : '';

  chSet('ch-k-state', d.challengeEnabled ? t('challenge.on') : t('challenge.offShort'), d.challengeEnabled ? green : amber);
  chSet('ch-k-engine', d.engine + ' — ' + d.upstream);
  chSet('ch-errors', (d.errors || []).join(' ; '));
  const ips = d.ips || { count: 0, sample: [] };
  chSet('ch-k-ips', String(ips.count));

  // Conteneur
  const st = document.getElementById('ch-status');
  st.textContent = '';
  st.style.color = '';
  const btnStart = document.getElementById('ch-start'), btnStop = document.getElementById('ch-stop'), btnImg = document.getElementById('ch-image-update');
  if (!d.enabled) {
    chSet('ch-k-container', t('challenge.external'));
    st.appendChild(chEl('div', t('challenge.containerOff', { file: d.configFile || 'challenge.yml' })));
    btnStart.style.display = btnStop.style.display = btnImg.style.display = 'none';
  } else {
    const c = d.container || {};
    let msg, color;
    if (c.dockerUnavailable) { msg = t('challenge.dockerDown'); color = red; }
    else if (!c.exists) { msg = t('challenge.absent', { name: d.name }); color = amber; }
    else if (c.running) { msg = t('challenge.running', { name: d.name, image: c.image || d.image }); color = green; }
    else { msg = t('challenge.stopped', { name: d.name }) + ' (' + (c.status || '?') + ')'; color = red; }
    chSet('ch-k-container', c.running ? t('challenge.runningShort') : (c.exists ? t('challenge.stoppedShort') : t('challenge.absentShort')), color);
    chRow(st, t('challenge.container'), msg, color);
    chRow(st, t('challenge.image'), d.image);
    btnStart.style.display = ''; btnImg.style.display = '';
    btnStop.style.display = c.running ? '' : 'none';
  }

  // Fichiers nginx
  const files = document.getElementById('ch-files');
  files.textContent = '';
  let stale = false;
  (d.files || []).forEach(f => {
    const row = chEl('div');
    const badge = !f.exists ? [t('challenge.file.missing'), red] : (f.upToDate ? [t('challenge.file.ok'), green] : [t('challenge.file.stale'), amber]);
    if (!f.exists || !f.upToDate) stale = true;
    const b = chEl('strong', '● ' + badge[0]); b.style.color = badge[1];
    row.appendChild(b);
    row.appendChild(chEl('span', '  ' + f.name));
    files.appendChild(row);
  });
  document.getElementById('ch-apply').disabled = !stale;

  // Snippets
  const box = document.getElementById('ch-snippets');
  box.textContent = '';
  CH_SNIPPETS.forEach(([file, key]) => {
    const row = chEl('div'); row.style.cssText = 'display:flex;align-items:center;gap:8px;flex-wrap:wrap';
    row.appendChild(chEl('code', 'include snippets/' + file + ';'));
    const btn = chEl('button', t('common.copy') || 'Copier', 'btn sm');
    btn.addEventListener('click', () => copyToClipboard('include snippets/' + file + ';'));
    row.appendChild(btn);
    box.appendChild(row);
    const hint = chEl('div', t(key), 'nf-hint'); hint.style.margin = '0 0 6px 0';
    box.appendChild(hint);
  });

  // Profils par vhost : un snippet dédié chacun
  const profiles = (d.settings && d.settings.profiles) || [];
  if (profiles.length) {
    const ttl = chEl('div', t('challenge.profile.title'), 'ctitle');
    ttl.style.cssText = 'margin-top:10px;font-size:12px';
    box.appendChild(ttl);
    profiles.forEach(pr => {
      const row = chEl('div'); row.style.cssText = 'display:flex;align-items:center;gap:8px;flex-wrap:wrap';
      row.appendChild(chEl('code', 'include snippets/' + pr.file + ';'));
      const btn = chEl('button', t('common.copy') || 'Copier', 'btn sm');
      btn.addEventListener('click', () => copyToClipboard('include snippets/' + pr.file + ';'));
      row.appendChild(btn);
      box.appendChild(row);
      const hint = chEl('div', t('challenge.profile.desc', {
        name: pr.name, mode: t('challenge.mode.' + pr.mode),
        ua: pr.exemptUaRegex || '—', path: pr.exemptPathRegex || '—',
      }), 'nf-hint');
      hint.style.margin = '0 0 6px 0';
      box.appendChild(hint);
    });
  }

  // Réglages effectifs
  const s = d.settings || {};
  const set = document.getElementById('ch-settings');
  set.textContent = '';
  chRow(set, t('challenge.engine'), String(s.engine));
  chRow(set, t('challenge.upstream'), String(s.upstream));
  chRow(set, t('challenge.resolver'), String(s.resolver));
  chRow(set, t('challenge.exemptPath'), String(s.exemptPathRegex || '—'));
  chRow(set, t('challenge.exemptUa'), String(s.exemptUaRegex || '—'));
  if (d.engine === 'builtin') {
    chRow(set, t('challenge.difficulty'), String(s.difficultyBits));
    chRow(set, t('challenge.cookieHours'), String(s.cookieHours));
    chRow(set, t('challenge.goodbots'), s.goodbots ? t('challenge.yes') : t('challenge.no'));
    if (s.goodbotsExtra) chRow(set, t('challenge.goodbotsExtra'), s.goodbotsExtra);
  }

  // IP signalées
  document.getElementById('ch-ips').textContent = (ips.sample || []).join('  ') || '—';
  const note = !d.blocklistEnabled ? t('challenge.ipsNoBlocklist')
    : (ips.count > (ips.sample || []).length ? t('challenge.ipsMore', { n: ips.count - ips.sample.length }) : '');
  document.getElementById('ch-ips-note').textContent = note;
}

// ── Aide intégrée (modal, FR/EN via i18n) ──────────────────────────────────────
const CH_DOC_SECTIONS = [
  ['modes', null],
  ['snippets', 'include snippets/challenge-all-allowbots.conf;'],
  ['location', "server {\n    include snippets/challenge-location-support.conf;\n    location = /wp-login.php {\n        include snippets/challenge-location.conf;\n        # ... proxy_pass / fastcgi_pass habituel\n    }\n}"],
  ['profiles', "profiles:\n  - name: forgejo\n    mode: allbots\n    exempt_ua_regex: '^forgejo-runner/'"],
  ['exempt', "challenge_exempt_ua_regex: '^NginxControl$'\nchallenge_exempt_path_regex: '^/(api/|[.]well-known/)'"],
  ['bots', null],
  ['difficulty', null],
  ['apply', null],
];

function challengeDocOpen() {
  const body = document.getElementById('ch-doc-body');
  body.textContent = '';
  CH_DOC_SECTIONS.forEach(([id, code]) => {
    const h = chEl('div', t('challenge.doc.' + id + '.t'), 'ctitle');
    h.style.cssText = 'margin:14px 0 4px;font-size:12px';
    body.appendChild(h);
    t('challenge.doc.' + id + '.b').split('\n').forEach(par => {
      const p = chEl('div', par); p.style.margin = '0 0 4px';
      body.appendChild(p);
    });
    if (code) {
      const pre = chEl('pre', code);
      pre.style.cssText = 'margin:6px 0;padding:10px;background:var(--bg);border-radius:var(--r);color:var(--text2);overflow:auto';
      body.appendChild(pre);
    }
  });
  document.getElementById('ch-doc-overlay').style.display = 'flex';
}
function challengeDocClose() { document.getElementById('ch-doc-overlay').style.display = 'none'; }

async function challengeAction(path, confirmKey) {
  if (confirmKey && !confirm(t(confirmKey))) return;
  const st = document.getElementById('ch-status');
  st.textContent = t('geoip.starting');
  const d = await api(path, { method: 'POST' }).catch(e => ({ error: e.message }));
  if (d && (d.error || d.ok === false)) {
    st.textContent = t('common.error') + ' : ' + (d.error || '') + (d.stderr ? ' — ' + d.stderr : '');
    st.style.color = 'var(--red)';
    return;
  }
  await challengeLoad();
}
function challengeStart() { return challengeAction('/challenge/container/start'); }
function challengeStop() { return challengeAction('/challenge/container/stop', 'challenge.confirmStop'); }
function challengeImageUpdate() { return challengeAction('/challenge/image/update'); }
function challengeApply() { return challengeAction('/challenge/apply'); }


// ── Statistiques d'efficacite (v12.68.0) ─────────────────────────────────────
async function challengeStatsLoad() {
  const grid = document.getElementById('ch-stats-grid');
  const bars = document.getElementById('ch-stats-bars');
  const note = document.getElementById('ch-stats-note');
  if (!grid) return;
  const hours = document.getElementById('ch-stats-hours').value;
  const d = await api('/challenge/stats?hours=' + encodeURIComponent(hours)).catch(() => null);
  grid.textContent = ''; bars.textContent = '';
  if (!d || !d.available) {
    note.textContent = t('challenge.stats.na.' + ((d && d.reason) || 'unreachable'));
    return;
  }
  const c = d.total;
  const noJs = Math.max(0, c.pages - c.started);
  const rate = c.started ? Math.round(1000 * c.solved / c.started) / 10 : null;
  const tiles = [
    ['redirected', c.redirected, 'am'], ['pages', c.pages], ['noJs', noJs], ['started', c.started],
    ['solved', c.solved, 'gn'], ['failed', c.failed, c.failed ? 'rd' : ''],
    ['rateLimited', c.rateLimited], ['rate', rate == null ? '—' : rate + ' %'],
    ['passCookie', c.passCookie], ['passBot', c.passBot],
  ];
  tiles.forEach(([k, v, cls]) => {
    const sc = chEl('div', null, 'sc' + (cls ? ' ' + cls : ''));
    sc.appendChild(chEl('div', t('challenge.stats.' + k), 'sl'));
    sc.appendChild(chEl('div', String(v), 'sv'));
    sc.title = t('challenge.stats.' + k + '.tip');
    grid.appendChild(sc);
  });
  // Barres : defis resolus (vert) / echoues (rouge) par heure, sur la fenetre.
  const by = new Map((d.series || []).map(p => [p.hour, p]));
  const end = Math.floor(Date.now() / 3600000) * 3600;
  const n = Math.min(parseInt(hours, 10), 168);
  const pts = [];
  for (let i = n - 1; i >= 0; i--) pts.push(by.get(end - i * 3600) || { redirected: 0, solved: 0, failed: 0 });
  const max = Math.max(1, ...pts.map(p => p.redirected));
  pts.forEach(p => {
    const b = chEl('div'); b.style.cssText = 'flex:1;min-width:1px;background:var(--amber, #d98e04);opacity:.75;height:' + Math.max(p.redirected ? 2 : 0, Math.round(56 * p.redirected / max)) + 'px';
    b.title = t('challenge.stats.barTip', { r: p.redirected, s: p.solved, f: p.failed });
    bars.appendChild(b);
  });
  note.textContent = t('challenge.stats.note', { since: new Date(d.since * 1000).toLocaleString() });
}

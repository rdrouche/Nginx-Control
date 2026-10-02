// ── SYNCHRONISATION DE CERTIFICATS (page SSL, admin) ─────────────────────────
// Script global classique (api(), t(), h(), copyToClipboard() du script principal).
// Les routes sont reservees aux administrateurs : sur 403 la carte reste masquee.

const CS = { data: null, editing: null, tokenRaw: '' };

function csFmt(ts) { return ts ? new Date(ts).toLocaleString(LANG === 'fr' ? 'fr-FR' : 'en-GB', { dateStyle: 'short', timeStyle: 'short' }) : '—'; }
function csStatus(msg, ok) {
  const el = document.getElementById('cs-status');
  if (!el) return;
  el.textContent = msg || ''; el.style.color = ok === null ? 'var(--text3)' : ok ? 'var(--green)' : 'var(--red)';
}
function csErr(d) { return (d && (d.error || d.message)) || t('common.error'); }

async function csLoad() {
  const card = document.getElementById('certsync-card');
  if (!card) return;
  const d = await api('/certsync/overview');
  if (!d || !d.remotes) { card.style.display = 'none'; return; }
  CS.data = d;
  card.style.display = '';
  csRender();
}

function csTable(headers, rows, empty) {
  if (!rows.length) return '<div style="color:var(--text3);font-size:12px;padding:4px 0">' + h(empty) + '</div>';
  return '<table class="sched-table"><thead><tr>' + headers.map(x => '<th>' + h(x) + '</th>').join('') + '</tr></thead><tbody>' + rows.join('') + '</tbody></table>';
}

function csRender() {
  const d = CS.data;
  const dirLabel = x => t(x === 'push' ? 'certsync.dirPush' : 'certsync.dirPull');
  const tlsLabel = r => t('certsync.tls.short.' + r.tls.mode);
  document.getElementById('cs-remotes').innerHTML = csTable(
    ['', t('certsync.f.name'), t('certsync.f.direction'), t('certsync.col.certs'), t('certsync.col.last'), ''],
    d.remotes.map(r => '<tr>' +
      '<td>' + (r.enabled ? '' : '<span class="badge">' + h(t('certsync.disabled')) + '</span>') + '</td>' +
      '<td><b>' + h(r.name) + '</b><div class="sched-sub">' + h(r.url) + ' · ' + h(tlsLabel(r)) + '</div></td>' +
      '<td>' + h(dirLabel(r.direction)) + '</td>' +
      '<td>' + h(r.certs.map(c => c.remote === c.local ? c.remote : c.remote + ' → ' + c.local).join(', ')) + '</td>' +
      '<td>' + (r.lastSyncAt ? '<span style="color:var(--' + (r.lastStatus === 'ok' ? 'green' : 'red') + ')">' + h(r.lastStatus) + '</span> ' + h(csFmt(r.lastSyncAt)) +
        '<div class="sched-sub" title="' + h(r.lastMessage || '') + '">' + h((r.lastMessage || '').slice(0, 120)) + '</div>' : '—') + '</td>' +
      '<td class="sched-actions"><button class="btn sm" onclick="csTest(\'' + r.id + '\')">' + h(t('certsync.test')) + '</button> ' +
        '<button class="btn sm" onclick="csSync(\'' + r.id + '\', false)">&#9654; ' + h(t('certsync.syncNow')) + '</button> ' +
        '<button class="btn sm" title="' + h(t('certsync.forceHelp')) + '" onclick="csSync(\'' + r.id + '\', true)">' + h(t('certsync.force')) + '</button> ' +
        '<button class="btn sm" onclick="csRemoteOpen(\'' + r.id + '\')">' + h(t('scheduler.edit')) + '</button> ' +
        '<button class="btn sm danger" onclick="csRemoteDelete(\'' + r.id + '\')">&#10005;</button></td></tr>'),
    t('certsync.noRemotes'));
  document.getElementById('cs-tokens').innerHTML = csTable(
    [t('certsync.f.name'), t('certsync.col.scope'), t('certsync.col.certs'), t('certsync.col.used'), ''],
    d.tokens.map(k => '<tr><td><b>' + h(k.name) + '</b></td><td>' + h(t(k.scope === 'push' ? 'certsync.scopePushShort' : 'certsync.scopePullShort')) + '</td>' +
      '<td>' + h(k.certs.join(', ')) + '</td><td>' + h(csFmt(k.lastUsedAt)) + (k.lastUsedIp ? '<div class="sched-sub">' + h(k.lastUsedIp) + '</div>' : '') + '</td>' +
      '<td class="sched-actions"><button class="btn sm danger" onclick="csTokenRevoke(\'' + k.id + '\')">' + h(t('certsync.revoke')) + '</button></td></tr>'),
    t('certsync.noTokens'));
  document.getElementById('cs-synced').innerHTML = csTable(
    [t('certsync.f.name'), t('certsync.col.domains'), t('certsync.col.expires'), t('certsync.col.source'), t('certsync.col.nginx'), ''],
    d.synced.map(s => '<tr><td><b>' + h(s.name) + '</b></td><td>' + h((s.domains || []).join(', ')) + '</td>' +
      '<td style="color:var(--' + (s.daysLeft < 14 ? 'amber' : 'green') + ')">' + h(csFmt(s.notAfter)) + ' (' + s.daysLeft + ' j)</td>' +
      '<td>' + h(s.source || '') + '<div class="sched-sub">' + h(csFmt(s.receivedAt)) + '</div></td>' +
      '<td><code style="font-size:11px">' + h(d.nginxBase + '/' + s.name + '/fullchain.pem') + '<br>' + h(d.nginxBase + '/' + s.name + '/privkey.pem') + '</code></td>' +
      '<td class="sched-actions"><button class="btn sm danger" onclick="csSyncedDelete(\'' + h(s.name) + '\')">&#10005;</button></td></tr>'),
    t('certsync.noSynced'));
}

// ── Actions ──────────────────────────────────────────────────────────────────
function csShowResults(d) {
  if (!d || !d.remotes) { csStatus(csErr(d), false); return; }
  csStatus(d.message, d.ok);
}
async function csSync(id, force) {
  csStatus(t('certsync.syncing'), null);
  const d = await api('/certsync/remotes/sync', { method: 'POST', body: JSON.stringify({ id, force }) });
  csShowResults(d);
  csLoad();
  if (typeof loadSSL === 'function') loadSSL();
}
async function csSyncAll() { await csSync(undefined, false); }
async function csTest(id) {
  csStatus(t('certsync.testing'), null);
  const d = await api('/certsync/remotes/test', { method: 'POST', body: JSON.stringify({ id }) });
  if (!d || !d.ok) { csStatus(csErr(d), false); return; }
  const miss = d.missing && d.missing.length ? ' — ' + t('certsync.missing') + ' : ' + d.missing.join(', ') : '';
  csStatus(t('certsync.testOk', { n: d.visible.length }) + miss, !miss);
}
async function csRemoteDelete(id) {
  const r = CS.data.remotes.find(x => x.id === id);
  if (!r || !confirm(t('certsync.confirmDelete', { name: r.name }))) return;
  const d = await api('/certsync/remotes/delete', { method: 'POST', body: JSON.stringify({ id }) });
  if (!d || !d.ok) csStatus(csErr(d), false);
  csLoad();
}
async function csTokenRevoke(id) {
  const k = CS.data.tokens.find(x => x.id === id);
  if (!k || !confirm(t('certsync.confirmRevoke', { name: k.name }))) return;
  const d = await api('/certsync/tokens/delete', { method: 'POST', body: JSON.stringify({ id }) });
  if (!d || !d.ok) csStatus(csErr(d), false);
  csLoad();
}
async function csSyncedDelete(name) {
  if (!confirm(t('certsync.confirmDeleteSynced', { name }))) return;
  const d = await api('/certsync/synced/delete', { method: 'POST', body: JSON.stringify({ name }) });
  if (!d || !d.ok) csStatus(csErr(d), false);
  csLoad();
  if (typeof loadSSL === 'function') loadSSL();
}

// ── Formulaire source ────────────────────────────────────────────────────────
function csRemoteOpen(id) {
  const r = id ? CS.data.remotes.find(x => x.id === id) : null;
  CS.editing = r ? r.id : null;
  csLastDir = r ? r.direction : 'pull';
  document.getElementById('cs-remote-title').textContent = t(r ? 'certsync.editRemote' : 'certsync.addRemote');
  document.getElementById('csr-name').value = r ? r.name : '';
  document.getElementById('csr-direction').value = r ? r.direction : 'pull';
  document.getElementById('csr-url').value = r ? r.url : '';
  document.getElementById('csr-token').value = '';
  document.getElementById('csr-token-hint').textContent = r && r.tokenSet ? t('certsync.tokenKept') : '';
  document.getElementById('csr-tlsmode').value = r ? r.tls.mode : 'verify';
  document.getElementById('csr-pin').value = r ? r.tls.pin : '';
  document.getElementById('csr-ca').value = '';
  document.getElementById('csr-ca-hint').textContent = r && r.tls.caSet ? t('certsync.caKept') : '';
  document.getElementById('csr-probe-out').textContent = '';
  document.getElementById('csr-enabled').checked = r ? r.enabled : true;
  document.getElementById('csr-error').textContent = '';
  document.getElementById('csr-certs').innerHTML = '';
  (r ? r.certs : [{ remote: '', local: '' }]).forEach(c => csCertRow(c));
  csTlsChanged();
  document.getElementById('cs-remote-modal').style.display = 'flex';
}
function csRemoteClose() { document.getElementById('cs-remote-modal').style.display = 'none'; }

function csTlsChanged() {
  const m = document.getElementById('csr-tlsmode').value;
  document.getElementById('csr-pin-box').style.display = m === 'pin' ? '' : 'none';
  document.getElementById('csr-ca-box').style.display = m === 'ca' ? '' : 'none';
  document.getElementById('csr-insecure-warn').style.display = m === 'insecure' ? '' : 'none';
}

async function csProbe() {
  const out = document.getElementById('csr-probe-out');
  out.style.color = ''; out.textContent = t('certsync.probing');
  const d = await api('/certsync/remotes/probe', { method: 'POST', body: JSON.stringify({ url: document.getElementById('csr-url').value.trim() }) });
  if (!d || !d.ok) { out.style.color = 'var(--red)'; out.textContent = csErr(d); return; }
  document.getElementById('csr-pin').value = d.fingerprint256;
  out.textContent = t('certsync.probeOk', { subject: d.subject, issuer: d.issuer, fp: d.fingerprint256 });
}

function csCertRow(c) {
  const dir = document.getElementById('csr-direction').value;
  const row = document.createElement('div');
  row.className = 'cs-cert-row';
  row.style.cssText = 'display:flex;gap:6px;margin-bottom:6px;align-items:center';
  const live = (CS.data ? CS.data.live.map(x => x.name).concat(CS.data.synced.map(x => x.name)) : []);
  const listId = 'cs-live-list';
  if (!document.getElementById(listId)) {
    const dl = document.createElement('datalist'); dl.id = listId;
    dl.innerHTML = [...new Set(live)].map(n => '<option value="' + h(n) + '">').join('');
    document.body.appendChild(dl);
  }
  row.innerHTML = '<input type="text" class="cs-c-remote" list="' + listId + '" placeholder="' + h(t(dir === 'pull' ? 'certsync.nameThere' : 'certsync.nameHere')) + '" value="' + h(c ? (dir === 'pull' ? c.remote : c.local) : '') + '" spellcheck="false">' +
    '<span>&rarr;</span><input type="text" class="cs-c-local" placeholder="' + h(t(dir === 'pull' ? 'certsync.nameHere' : 'certsync.nameThere')) + '" value="' + h(c ? (dir === 'pull' ? c.local : c.remote) : '') + '" spellcheck="false">' +
    '<button class="btn sm danger" onclick="this.parentNode.remove()">&#10005;</button>';
  document.getElementById('csr-certs').appendChild(row);
  document.getElementById('csr-certs-hint').textContent = t(dir === 'pull' ? 'certsync.certsHintPull' : 'certsync.certsHintPush');
}

function csReadCerts() {
  const dir = document.getElementById('csr-direction').value;
  return [...document.querySelectorAll('#csr-certs .cs-cert-row')].map(r => {
    const a = r.querySelector('.cs-c-remote').value.trim(), b = r.querySelector('.cs-c-local').value.trim();
    // pull : (nom chez l'autre) -> (nom ici) ; push : (nom ici) -> (nom chez l'autre)
    return dir === 'pull' ? { remote: a, local: b || a } : { local: a, remote: b || a };
  }).filter(c => c.remote || c.local);
}

async function csRemoteSave() {
  const err = document.getElementById('csr-error');
  err.textContent = '';
  const body = {
    id: CS.editing || undefined,
    name: document.getElementById('csr-name').value.trim(),
    direction: document.getElementById('csr-direction').value,
    url: document.getElementById('csr-url').value.trim(),
    token: document.getElementById('csr-token').value.trim(),
    tlsMode: document.getElementById('csr-tlsmode').value,
    pin: document.getElementById('csr-pin').value.trim(),
    ca: document.getElementById('csr-ca').value.trim(),
    certs: csReadCerts(),
    enabled: document.getElementById('csr-enabled').checked,
  };
  const d = await api('/certsync/remotes/save', { method: 'POST', body: JSON.stringify(body) });
  if (!d || !d.ok) { err.textContent = csErr(d); return; }
  csRemoteClose();
  csStatus(t('certsync.saved'), true);
  csLoad();
}

// ── Jeton d'acces ────────────────────────────────────────────────────────────
function csTokenOpen() {
  document.getElementById('cst-form').style.display = '';
  document.getElementById('cst-result').style.display = 'none';
  document.getElementById('cst-name').value = '';
  document.getElementById('cst-scope').value = 'pull';
  document.getElementById('cst-extra').value = '';
  document.getElementById('cst-error').textContent = '';
  csTokenScope();
  document.getElementById('cs-token-modal').style.display = 'flex';
}
function csTokenClose() {
  document.getElementById('cs-token-modal').style.display = 'none';
  CS.tokenRaw = ''; document.getElementById('cst-token-value').textContent = '';
}
function csTokenScope() {
  const pull = document.getElementById('cst-scope').value === 'pull';
  const box = document.getElementById('cst-certs');
  const names = CS.data ? CS.data.live.map(x => x.name).concat(CS.data.synced.map(x => x.name)) : [];
  box.innerHTML = pull ? [...new Set(names)].map(n => '<label><input type="checkbox" value="' + h(n) + '"> ' + h(n) + '</label>').join('') || '<span class="sched-sub">' + h(t('certsync.noLive')) + '</span>' : '';
  document.getElementById('cst-extra').style.display = pull ? 'none' : '';
  document.getElementById('cst-hint').textContent = t(pull ? 'certsync.tokenHintPull' : 'certsync.tokenHintPush');
}
async function csTokenCreate() {
  const err = document.getElementById('cst-error');
  err.textContent = '';
  const pull = document.getElementById('cst-scope').value === 'pull';
  const certs = pull ? [...document.querySelectorAll('#cst-certs input:checked')].map(c => c.value)
    : document.getElementById('cst-extra').value.split(/[\s,;]+/).filter(Boolean);
  const d = await api('/certsync/tokens/create', { method: 'POST', body: JSON.stringify({ name: document.getElementById('cst-name').value.trim(), scope: document.getElementById('cst-scope').value, certs }) });
  if (!d || !d.ok) { err.textContent = csErr(d); return; }
  CS.tokenRaw = d.rawToken;
  document.getElementById('cst-token-value').textContent = d.rawToken;
  document.getElementById('cst-form').style.display = 'none';
  document.getElementById('cst-result').style.display = '';
  csLoad();
}
function csTokenCopy() { if (CS.tokenRaw) copyToClipboard(CS.tokenRaw).then(ok => copyFeedback('cst-copy', ok)); }

// Le sens change l'ordre des deux noms de chaque ligne : on swappe les valeurs pour garder la correspondance.
let csLastDir = 'pull';
function csDirChanged() {
  const dir = document.getElementById('csr-direction').value;
  if (dir === csLastDir) return;
  csLastDir = dir;
  document.querySelectorAll('#csr-certs .cs-cert-row').forEach(r => {
    const a = r.querySelector('.cs-c-remote'), b = r.querySelector('.cs-c-local');
    const tmp = a.value; a.value = b.value; b.value = tmp;
    a.placeholder = t(dir === 'pull' ? 'certsync.nameThere' : 'certsync.nameHere');
    b.placeholder = t(dir === 'pull' ? 'certsync.nameHere' : 'certsync.nameThere');
  });
  document.getElementById('csr-certs-hint').textContent = t(dir === 'pull' ? 'certsync.certsHintPull' : 'certsync.certsHintPush');
}

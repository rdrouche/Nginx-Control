'use strict';
/**
 * Pages "Certbot" (défi HTTP) et "Certbot — Défi DNS" (Cloudflare et autres
 * fournisseurs) : émission/révocation de certificats Let's Encrypt,
 * démarrage/arrêt des conteneurs dédiés, mise à jour d'image. Extrait de
 * public/index.html (voir CHANGELOG.md). Les deux défis partagent
 * certbotRefreshCerts() (liste commune des certificats).
 */
let cbDomains = [];

async function initCertbot() { await certbotLoad(); }

async function certbotLoad() {
  cbdnsLoad(); // independent sub-feature — loaded regardless of the HTTP challenge's own state
  await certbotRefreshCerts(); // liste commune HTTP+DNS — visible meme si le defi HTTP est desactive
  const cfg = await api('/certbot/config').catch(() => null);
  if (!cfg?.enabled) {
    document.getElementById('cb-disabled').style.display = '';
    document.getElementById('cb-main').style.display = 'none';
    return;
  }
  document.getElementById('cb-disabled').style.display = 'none';
  document.getElementById('cb-main').style.display = 'flex';

  // Staging checkbox
  const stgChk = document.getElementById('cb-staging');
  if (stgChk) stgChk.checked = !!cfg.staging;

  document.getElementById('cb-image-name').textContent = cfg.image || 'certbot/certbot:latest';

  await certbotRefreshStatus();
}

async function certbotRefreshStatus() {
  const d = await api('/certbot/status').catch(() => null);
  const el = document.getElementById('cb-container-status');
  const btnStart = document.getElementById('cb-container-start');
  const btnStop  = document.getElementById('cb-container-stop');
  const btnImg   = document.getElementById('cb-image-update');
  if (!d?.enabled || !el) return;
  const c = d.container;
  if (btnImg) btnImg.style.display = '';
  if (!c?.exists) {
    el.innerHTML = '<span class="cb-status-dot stopped"></span>Conteneur absent';
    btnStart.style.display = ''; btnStop.style.display = 'none';
  } else if (c.running) {
    el.innerHTML = '<span class="cb-status-dot running"></span>En cours — ' + h(c.image) + ' (démarré ' + new Date(c.started).toLocaleString() + ')';
    btnStart.style.display = 'none'; btnStop.style.display = '';
  } else {
    el.innerHTML = '<span class="cb-status-dot stopped"></span>Arrêté (' + h(c.status) + ')';
    btnStart.style.display = ''; btnStop.style.display = 'none';
  }
}

async function certbotContainerStart() {
  document.getElementById('cb-container-status').innerHTML = '<span style="color:var(--text3)">Démarrage…</span>';
  const d = await api('/certbot/container/start', { method: 'POST' }).catch(e => ({ error: e.message }));
  if (d?.error) {
    document.getElementById('cb-container-status').innerHTML = '<span style="color:var(--red)">Erreur : ' + h(d.error) + '</span>';
    return;
  }
  await certbotRefreshStatus();
}

async function certbotImageUpdate() {
  const btn = document.getElementById('cb-image-update');
  if (btn) { btn.disabled = true; btn.textContent = 'Vérification…'; }
  const d = await api('/certbot/image/update', { method: 'POST' }).catch(e => ({ error: e.message }));
  if (btn) { btn.disabled = false; btn.textContent = '⬇ Mettre à jour l\'image'; }
  if (!d || d.error || d.ok === false) { alert('Erreur : ' + (d?.error || 'mise à jour impossible')); return; }
  alert(d.updated
    ? 'Nouvelle image téléchargée' + (d.recreated ? ', conteneur recréé.' : '.')
    : 'Image déjà à jour.');
  await certbotRefreshStatus();
}

async function certbotContainerStop() {
  if (!confirm('Arrêter le conteneur de renouvellement certbot ?')) return;
  await api('/certbot/container/stop', { method: 'POST' }).catch(() => {});
  await certbotRefreshStatus();
}

async function certbotAddDomain() {
  const inp = document.getElementById('cb-domain-input');
  const val = inp.value.trim().toLowerCase();
  if (!val || cbDomains.includes(val)) { inp.value = ''; return; }
  cbDomains.push(val);
  inp.value = '';
  certbotRenderDomains();
  // Check conflict
  if (!document.getElementById('cb-staging').checked) {
    const c = await api('/certbot/check-conflict?domain=' + encodeURIComponent(val)).catch(() => null);
    if (c?.conflict) {
      document.getElementById('cb-conflict-warn').style.display = '';
      document.getElementById('cb-conflict-warn').textContent =
        '⚠ ' + val + ' est déjà couvert par le certificat "' + c.cert + '" (' + c.match + ', ' + c.type + ')';
    }
  }
}

function certbotRemoveDomain(d) {
  cbDomains = cbDomains.filter(x => x !== d);
  certbotRenderDomains();
  document.getElementById('cb-conflict-warn').style.display = 'none';
}

function certbotRenderDomains() {
  const el = document.getElementById('cb-domains-tags');
  el.innerHTML = '';
  cbDomains.forEach(function(d) {
    const span = document.createElement('span');
    span.className = 'cb-domain-tag';
    const txt = document.createTextNode(d);
    const btn = document.createElement('button');
    btn.textContent = 'x';
    btn.addEventListener('click', (function(name) {
      return function() { certbotRemoveDomain(name); };
    })(d));
    span.appendChild(txt);
    span.appendChild(btn);
    el.appendChild(span);
  });
}

async function certbotIssue(dryRun) {
  if (!cbDomains.length) { alert('Ajouter au moins un domaine'); return; }
  const label = dryRun ? 'Dry-run' : 'Génération';
  const resultCard  = document.getElementById('cb-result-card');
  const resultTitle = document.getElementById('cb-result-title');
  const resultBadge = document.getElementById('cb-result-badge');
  const logEl       = document.getElementById('cb-log');
  const snippetBlock = document.getElementById('cb-snippet-block');

  resultCard.style.display = '';
  resultTitle.textContent  = label + ' — ' + cbDomains.join(', ');
  resultBadge.textContent  = '...';
  resultBadge.className    = 'badge gy';
  logEl.textContent        = 'En cours…';
  snippetBlock.style.display = 'none';
  resultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  const staging = document.getElementById('cb-staging').checked;
  const d = await api('/certbot/issue', {
    method: 'POST',
    body: JSON.stringify({ domains: cbDomains, dryRun, staging })
  }).catch(e => ({ error: e.message, ok: false }));

  if (d?.error && !d?.logs) {
    logEl.textContent    = 'Erreur : ' + d.error;
    resultBadge.textContent = 'ERREUR';
    resultBadge.className   = 'badge rd';
    return;
  }

  logEl.textContent = (d.command ? '$ ' + d.command + '\n\n' : '') + (d.logs || '(pas de logs)');
  resultBadge.textContent = d.ok ? (dryRun ? 'DRY-RUN OK' : 'SUCCÈS') : 'ÉCHEC';
  resultBadge.className   = 'badge ' + (d.ok ? 'gn' : 'rd');

  if (d.snippet) {
    snippetBlock.style.display = '';
    document.getElementById('cb-snippet').textContent = d.snippet;
  }

  if (d.ok && !dryRun) await certbotRefreshCerts();
}

async function certbotRefreshCerts() {
  const d = await api('/certbot/certs').catch(() => null);
  const el = document.getElementById('cb-certs-list');
  if (!el) return;
  const certs = d && d.certs ? d.certs : [];
  if (!certs.length) {
    el.innerHTML = '<div style="color:var(--text3);font-family:monospace;font-size:12px">Aucun certificat dans /nginx/certs/live/</div>';
    return;
  }
  el.innerHTML = '';
  certs.forEach(function(c) {
    const daysLeft  = c.daysLeft;
    const cls       = daysLeft === null ? 'gy' : daysLeft < 0 ? 'rd' : daysLeft < 30 ? 'am' : 'gn';
    const exp       = c.notAfter ? new Date(c.notAfter).toLocaleDateString() : '?';
    const sans      = (c.domains || []).filter(function(dd) { return dd !== c.name; }).join(', ');
    const daysLabel = daysLeft === null ? '?' : daysLeft < 0 ? 'EXPIRE' : daysLeft + 'j';
    const card = document.createElement('div');
    card.className = 'cb-cert-card';
    const row = document.createElement('div');
    row.className = 'row';
    const info = document.createElement('div');
    info.innerHTML = '<div class="cb-cert-domain">' + h(c.name) + '</div>'
      + '<div class="cb-cert-meta">Expire : ' + h(exp)
      + ' <span class="badge ' + cls + '">' + h(daysLabel) + '</span></div>'
      + (sans ? '<div class="cb-cert-sans">SANs : ' + h(sans) + '</div>' : '');
    const btn = document.createElement('button');
    btn.className = 'btn sm danger';
    btn.textContent = 'Revoquer';
    btn.addEventListener('click', (function(name) {
      return function() { certbotRevoke(name); };
    })(c.name));
    row.appendChild(info);
    row.appendChild(btn);
    card.appendChild(row);
    el.appendChild(card);
  });
}

async function certbotRevoke(domain) {
  if (!confirm('Révoquer le certificat pour ' + domain + ' ?\nCette action est irréversible.')) return;
  const d = await api('/certbot/revoke', { method: 'POST', body: JSON.stringify({ domain }) }).catch(e => ({ error: e.message }));
  if (d?.error) { alert('Erreur : ' + d.error); return; }
  await certbotRefreshCerts();
}

async function cbdnsLoad() {
  const cfg = await api('/certbot-dns/config').catch(() => null);
  const disabled = document.getElementById('cbdns-disabled');
  const main     = document.getElementById('cbdns-main');
  if (!disabled || !main) return;
  if (!cfg?.enabled) {
    disabled.style.display = '';
    main.style.display = 'none';
    if (!cfg || cfg.configured === false) {
      const list = await api('/certbot-dns/providers').catch(() => null);
      const el = document.getElementById('cbdns-providers-list');
      if (el && list?.providers) {
        el.textContent = list.providers.filter(p => p.key !== 'custom').map(p => p.label).join(', ');
      }
    }
    return;
  }
  disabled.style.display = 'none';
  main.style.display = 'flex';
  document.getElementById('cbdns-provider-label').textContent = cfg.providerLabel || cfg.provider || '—';
  document.getElementById('cbdns-nocreds-warn').style.display =
    (cfg.provider !== 'custom' && !cfg.credentialsConfigured) ? '' : 'none';
  await cbdnsRefreshStatus();
}

async function cbdnsRefreshStatus() {
  const d = await api('/certbot-dns/status').catch(() => null);
  const el = document.getElementById('cbdns-container-status');
  const bStart = document.getElementById('cbdns-container-start');
  const bStop  = document.getElementById('cbdns-container-stop');
  const bImg   = document.getElementById('cbdns-image-update');
  if (!d?.enabled || !el) return;
  if (bImg) bImg.style.display = '';
  const c = d.container;
  if (!c?.exists) {
    el.innerHTML = '<span class="cb-status-dot stopped"></span>Conteneur absent';
    bStart.style.display = ''; bStop.style.display = 'none';
  } else if (c.running) {
    el.innerHTML = '<span class="cb-status-dot running"></span>En cours — ' + h(c.image) +
      (c.started ? ' (démarré ' + new Date(c.started).toLocaleString() + ')' : '');
    bStart.style.display = 'none'; bStop.style.display = '';
  } else {
    el.innerHTML = '<span class="cb-status-dot stopped"></span>Arrêté (' + h(c.status || '?') + ')';
    bStart.style.display = ''; bStop.style.display = 'none';
  }
}

async function cbdnsContainerStart() {
  document.getElementById('cbdns-container-status').innerHTML = '<span style="color:var(--text3)">Démarrage…</span>';
  const d = await api('/certbot-dns/container/start', { method: 'POST' }).catch(e => ({ error: e.message }));
  if (d?.error) {
    document.getElementById('cbdns-container-status').innerHTML = '<span style="color:var(--red)">Erreur : ' + h(d.error) + '</span>';
    return;
  }
  await cbdnsRefreshStatus();
}

async function cbdnsContainerStop() {
  if (!confirm('Arrêter le conteneur de renouvellement DNS ?')) return;
  await api('/certbot-dns/container/stop', { method: 'POST' }).catch(() => {});
  await cbdnsRefreshStatus();
}

async function cbdnsImageUpdate() {
  const btn = document.getElementById('cbdns-image-update');
  if (btn) { btn.disabled = true; btn.textContent = 'Vérification…'; }
  const d = await api('/certbot-dns/image/update', { method: 'POST' }).catch(e => ({ error: e.message }));
  if (btn) { btn.disabled = false; btn.textContent = '⬇ Mettre à jour l\'image'; }
  if (!d || d.error || d.ok === false) { alert('Erreur : ' + (d?.error || 'mise à jour impossible')); return; }
  alert(d.updated
    ? 'Nouvelle image téléchargée' + (d.recreated ? ', conteneur recréé.' : '.')
    : 'Image déjà à jour.');
  await cbdnsRefreshStatus();
}

/**
 * One line in the textarea = one certificate (one `certbot certonly` call),
 * run sequentially server-side — mirrors the shipped docker-compose.yml
 * example without requiring a static list in YAML.
 */
function cbdnsParseGroups() {
  const raw = document.getElementById('cbdns-groups').value || '';
  return raw.split('\n')
    .map(line => line.split(',').map(d => d.trim()).filter(Boolean))
    .filter(domains => domains.length);
}

async function cbdnsIssue() {
  const groups = cbdnsParseGroups();
  const warnEl = document.getElementById('cbdns-conflict-warn');
  warnEl.style.display = 'none';
  if (!groups.length) { alert('Renseignez au moins une ligne de domaines.'); return; }

  const btn = document.getElementById('cbdns-issue-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Génération…'; }
  const d = await api('/certbot-dns/issue', {
    method: 'POST',
    body: JSON.stringify({ certificates: groups.map(domains => ({ domains })) }),
  }).catch(e => ({ error: e.message }));
  if (btn) { btn.disabled = false; btn.textContent = '🔒 Générer'; }

  if (d?.error && d?.conflict) {
    warnEl.textContent = d.error;
    warnEl.style.display = '';
    return;
  }
  if (d?.error && !d?.results) { alert('Erreur : ' + d.error); return; }

  const card = document.getElementById('cbdns-result-card');
  const log  = document.getElementById('cbdns-log');
  card.style.display = '';
  log.innerHTML = '';
  for (const r of (d.results || [])) {
    const block = document.createElement('div');
    block.style.marginBottom = '10px';
    const title = document.createElement('div');
    title.style.fontWeight = 'bold';
    title.style.color = r.ok ? 'var(--green)' : 'var(--red)';
    title.textContent = (r.ok ? '✓ ' : '✗ ') + r.domains.join(', ');
    block.appendChild(title);
    const pre = document.createElement('pre');
    pre.style.whiteSpace = 'pre-wrap';
    pre.style.fontSize = '11px';
    pre.textContent = r.logs || '';
    block.appendChild(pre);
    log.appendChild(block);
  }
  if (d.ok) await certbotRefreshCerts();
}

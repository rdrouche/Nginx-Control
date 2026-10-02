// ── GODNS ─────────────────────────────────────────────────────────────────────
// Extrait de public/index.html (voir CHANGELOG.md).

let godnsCurrentFormat = 'yaml';

const GODNS_TPL = {
  yaml: 'provider: Cloudflare\nemail: admin@example.com\npassword: your-cloudflare-api-token\ndomains:\n  - domain_name: example.com\n    sub_domains:\n      - www\n      - test\nip_urls:\n  - https://api4.ipify.org\n  - https://api-ipv4.ip.sb/ip\nip_type: IPv4\ninterval: 600\nresolver: 1.1.1.1\nproxied: false\nweb_panel:\n  enabled: true\n  addr: 0.0.0.0:9000\n  username: admin\n  password: changeme',
  json: '{\n  "provider": "Cloudflare",\n  "email": "admin@example.com",\n  "password": "your-cloudflare-api-token",\n  "domains": [\n    {\n      "domain_name": "example.com",\n      "sub_domains": ["www", "test"]\n    }\n  ],\n  "ip_urls": ["https://api4.ipify.org", "https://api-ipv4.ip.sb/ip"],\n  "ip_type": "IPv4",\n  "interval": 600,\n  "resolver": "1.1.1.1",\n  "proxied": false,\n  "web_panel": {\n    "enabled": true,\n    "addr": "0.0.0.0:9000",\n    "username": "admin",\n    "password": "changeme"\n  }\n}'
};

function GODNS_ACTION_LABEL() {
  return { start: t('analyzer.start'), stop: t('analyzer.stop'), restart: t('godns.restart'), update: t('analyzer.updateImage') };
}

async function initGodns() { await godnsLoad(); }

async function godnsLoad() {
  const cfg = await api('/godns/config').catch(() => null);
  if (!cfg || !cfg.configured || !cfg.enabled) {
    document.getElementById('godns-disabled').style.display = '';
    document.getElementById('godns-main').style.display = 'none';
    return;
  }
  document.getElementById('godns-disabled').style.display = 'none';
  document.getElementById('godns-main').style.display = 'flex';
  godnsCurrentFormat = cfg.configFormat || 'yaml';
  document.getElementById('godns-fmt-yaml').classList.toggle('active', godnsCurrentFormat === 'yaml');
  document.getElementById('godns-fmt-json').classList.toggle('active', godnsCurrentFormat === 'json');
  await godnsRefreshStatus();
  await godnsLoadConfigFile();

  // Web panel button (v12.40.0) — embarque desormais via le proxy interne du
  // dashboard (/api/godns/panel, meme principe que le rapport GoAccess),
  // sans jamais avoir besoin de publier le port du panel sur l hote. Plus
  // besoin de web_panel_external_port pour l afficher, seulement que le
  // panel soit active dans godns.config.yaml (web_panel.enabled: true).
  // v12.41.0 : c est bien webPanelConfigured (lu depuis la vraie config
  // GoDNS) qui decide, pas webPanelEnabled (qui ne concerne que la
  // publication du port sur l hote, plus necessaire depuis le proxy interne).
  const btn = document.getElementById('godns-panel-btn');
  if (btn) btn.style.display = cfg.webPanelConfigured ? '' : 'none';

  // Show info tab by default
  godnsTab('info');
}

async function godnsRefreshStatus() {
  const d = await api('/godns/status').catch(() => null);
  const el = document.getElementById('godns-container-status');
  const btnStart   = document.getElementById('godns-btn-start');
  const btnStop    = document.getElementById('godns-btn-stop');
  const btnRestart = document.getElementById('godns-btn-restart');
  if (!d || !d.enabled || !el) return;
  const c = d.container;
  if (!c || !c.exists) {
    el.innerHTML = '<span class="cb-status-dot stopped"></span>' + t('godns.containerAbsent');
    btnStart.style.display = ''; btnStop.style.display = 'none'; btnRestart.style.display = 'none';
  } else if (c.running) {
    el.innerHTML = '<span class="cb-status-dot running"></span>' + t('godns.running', { image: h(c.image) })
      + ' &nbsp;<span class="badge gn">' + h(c.status) + '</span>';
    btnStart.style.display = 'none'; btnStop.style.display = ''; btnRestart.style.display = '';
  } else {
    el.innerHTML = '<span class="cb-status-dot stopped"></span>' + t('godns.stopped') + ' <span class="badge rd">' + h(c.status) + '</span>';
    btnStart.style.display = ''; btnStop.style.display = 'none'; btnRestart.style.display = '';
  }
}

async function godnsAction(action) {
  const statusEl = document.getElementById('godns-container-status');
  if (statusEl) statusEl.innerHTML = '<span style="color:var(--text3)">' + (GODNS_ACTION_LABEL()[action] || action) + '…</span>';
  const d = await api('/godns/container/' + action, { method: 'POST' }).catch(e => ({ error: e.message }));
  if (d && d.error) {
    if (statusEl) statusEl.innerHTML = '<span style="color:var(--red)">' + t('common.error') + ' : ' + h(d.error) + '</span>';
    return;
  }
  await godnsRefreshStatus();
}

let godnsRevealed = false;

async function godnsToggleReveal() {
  godnsRevealed = !godnsRevealed;
  await godnsLoadConfigFile();
}

async function godnsLoadConfigFile() {
  const d = await api('/godns/config-file' + (godnsRevealed ? '?reveal=1' : '')).catch(() => null);
  const editor = document.getElementById('godns-editor');
  if (!editor) return;
  if (!d || !d.exists) {
    editor.value = GODNS_TPL[godnsCurrentFormat] || '';
    document.getElementById('godns-save-status').textContent = t('godns.fileAbsentTemplate');
    return;
  }
  editor.value = d.content || '';
  const st = document.getElementById('godns-save-status');
  st.textContent = d.masked
    ? t('godns.configLoadedMasked', { format: d.format })
    : t('godns.configLoaded', { format: d.format });
  const rb = document.getElementById('godns-reveal-btn');
  if (rb) {
    rb.style.display = d.canReveal ? '' : 'none';
    rb.innerHTML = godnsRevealed ? '\u{1F648} ' + t('common.hide') : '\u{1F441} Secrets';
  }
}

async function godnsSaveConfig() {
  const editor  = document.getElementById('godns-editor');
  const content = editor ? editor.value : '';
  if (!content.trim()) { alert(t('godns.configEmpty')); return; }
  // Basic JSON validation
  if (godnsCurrentFormat === 'json') {
    try { JSON.parse(content); } catch(e) { alert(t('godns.jsonInvalid', { msg: e.message })); return; }
  }
  const status = document.getElementById('godns-save-status');
  status.textContent = t('godns.saving');
  const d = await api('/godns/config-file', {
    method: 'POST',
    body: JSON.stringify({ content, format: godnsCurrentFormat })
  }).catch(e => ({ error: e.message }));
  if (d && d.error) { status.textContent = t('common.error') + ' : ' + d.error; return; }
  status.textContent = t('godns.savedRestarting');
  await godnsAction('restart');
  status.textContent = t('godns.savedAndRestarted');
}

function godnsSetFormat(fmt) {
  godnsCurrentFormat = fmt;
  document.getElementById('godns-fmt-yaml').classList.toggle('active', fmt === 'yaml');
  document.getElementById('godns-fmt-json').classList.toggle('active', fmt === 'json');
}

function godnsLoadTemplate() {
  const editor = document.getElementById('godns-editor');
  if (!editor) return;
  if (editor.value.trim() && !confirm(t('godns.confirmReplaceTemplate'))) return;
  editor.value = GODNS_TPL[godnsCurrentFormat] || '';
}

async function godnsRefreshLogs() {
  const el = document.getElementById('godns-log');
  if (!el) return;
  el.textContent = t('common.loading');
  const d = await api('/godns/logs').catch(() => null);
  el.textContent = (d && d.logs) ? d.logs : t('godns.noLogs');
  el.scrollTop = el.scrollHeight;
}

function godnsTab(tab) {
  ['info','config','logs'].forEach(function(t) {
    const pane = document.getElementById('godns-pane-' + t);
    const btn  = document.getElementById('godns-tab-' + t);
    if (pane) pane.style.display = t === tab ? '' : 'none';
    if (btn)  btn.classList.toggle('active', t === tab);
  });
  if (tab === 'logs') godnsRefreshLogs();
  if (tab === 'info') godnsRefreshInfo();
}

async function godnsRefreshInfo() {
  const d = await api('/godns/info').catch(() => null);
  if (!d || !d.enabled) return;

  document.getElementById('godns-info-ip').textContent       = d.publicIP   || '—';
  document.getElementById('godns-info-provider').textContent = d.provider   || '—';
  document.getElementById('godns-info-errors').textContent   = d.errors?.length || '0';
  if (d.lastUpdate) {
    const dt = new Date(d.lastUpdate);
    document.getElementById('godns-info-update').textContent = dt.toLocaleString('fr-FR');
  }

  // Error highlight
  const errEl = document.getElementById('godns-info-errors');
  if (errEl) errEl.style.color = d.errors?.length > 0 ? 'var(--red)' : 'var(--green)';

  // v12.39.0 (retour utilisateur) : verification multi-source de l IP —
  // GoDNS peut rapporter l IP d un CDN place devant son ip_url plutot que
  // l IP reelle, sans jamais le detecter lui-meme. Voir lib/ip-check.js.
  const mismatchEl  = document.getElementById('godns-ip-mismatch');
  const mismatchDet = document.getElementById('godns-ip-mismatch-detail');
  if (mismatchEl) {
    if (d.ipCheck && d.ipCheck.mismatch) {
      mismatchEl.style.display = '';
      const sourcesTxt = (d.ipCheck.sources || [])
        .map(function(s) { return h(s.url) + ' → ' + (s.ip ? h(s.ip) : t('godns.ipCheckUnreachable')); })
        .join(' · ');
      mismatchDet.innerHTML = t('godns.ipMismatchDetail', { godnsIp: h(d.publicIP || '—'), consensusIp: h(d.ipCheck.consensusIp) })
        + '<div style="margin-top:4px;color:var(--text3)">' + sourcesTxt + '</div>';
    } else {
      mismatchEl.style.display = 'none';
    }
  }

  // Domains table
  const tbody = document.getElementById('godns-domains-body');
  const domains = d.domains || {};
  const keys = Object.keys(domains);
  if (!keys.length) {
    tbody.innerHTML = '<tr><td colspan="4" style="color:var(--text3);padding:12px">' + t('godns.noDomains') + '</td></tr>';
  } else {
    tbody.innerHTML = keys.map(function(dom) {
      const info = domains[dom];
      const cls  = info.status === 'ok' ? 'gn' : info.status === 'updating' ? 'am' : 'gy';
      const label = info.status === 'ok' ? 'OK' : info.status === 'updating' ? t('godns.domainUpdating') : info.status;
      const ip   = info.ip || info.newIP || '—';
      const time = info.time ? new Date(info.time).toLocaleTimeString('fr-FR') : '—';
      return '<tr>'
        + '<td style="font-family:monospace">' + h(dom) + '</td>'
        + '<td><span class="badge ' + cls + '">' + label + '</span></td>'
        + '<td style="font-family:monospace">' + h(ip) + '</td>'
        + '<td style="color:var(--text3)">' + h(time) + '</td>'
        + '</tr>';
    }).join('');
  }
}

// v12.40.0 (retirée en v12.43.0, retour utilisateur) : le panel s ouvrait
// dans un iframe embarque via un relais HTTP cote dashboard
// (/api/godns/panel, voir l ancien proxyGoDNS() dans features/godns.js).
// Abandonne : le panel GoDNS est une appli Next.js dont les requetes d
// assets relatives (_next/static/chunks/*.js/.css) ne survivent pas a un
// relai generique — elles reviennent en 404 ou en application/json, que le
// navigateur refuse d executer/appliquer ("Refused to execute script"/
// "Refused to apply style... strict MIME checking"). Plutot que d ecrire un
// vrai proxy conscient de Next.js pour un gain marginal, la modale explique
// desormais comment atteindre le panel directement via un vhost nginx
// normal — qui fonctionne nativement, sans ce genre de probleme, et sans
// aucun code cote dashboard.
async function godnsOpenPanel() {
  const cfg = await api('/godns/config').catch(() => null);
  const containerName = (cfg && cfg.containerName) || 'godns';
  const port = (cfg && cfg.port) || 9000;
  const body = document.getElementById('godns-panel-frame-wrap');
  if (body) {
    body.style.overflow = 'auto'; // ce wrapper (.ga-iframe-wrap, partage avec le rapport GoAccess) est overflow:hidden par defaut pour contenir un iframe plein cadre — ici c est du texte, donc on le laisse defiler si besoin
    body.innerHTML = `
      <div style="padding:20px;max-width:640px;margin:0 auto;font-size:13px;line-height:1.6;color:var(--text)">
        <p>${h(t('godns.panelHelp.intro'))}</p>
        <ol style="padding-left:20px;margin:12px 0">
          <li>${h(t('godns.panelHelp.step1'))}</li>
          <li>${h(t('godns.panelHelp.step2'))}
            <div style="font-family:monospace;font-size:12px;background:var(--bg3);border:1px solid var(--border2);border-radius:var(--r);padding:8px 12px;margin-top:6px">
              proxy_pass http://${h(containerName)}:${h(String(port))};
            </div>
          </li>
          <li>${h(t('godns.panelHelp.step3'))}</li>
          <li>${h(t('godns.panelHelp.step4'))}</li>
        </ol>
        <div style="display:flex;gap:8px;margin-top:16px">
          <button class="btn sm primary" onclick="godnsPanelClose(); openPage('vhostgen');">&#9881; <span data-i18n="godns.panelHelp.openVhg">Ouvrir le Générateur de VHost</span></button>
        </div>
      </div>`;
    applyTranslations();
  }
  document.getElementById('godns-panel-overlay').style.display = 'flex';
}

function godnsPanelClose() {
  document.getElementById('godns-panel-overlay').style.display = 'none';
}

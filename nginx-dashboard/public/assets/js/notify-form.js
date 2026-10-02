// ── NOTIFICATIONS : formulaires SMTP et alertes ──────────────────────────────
// Script global classique (api(), t(), h(), LANG du script principal).
// Les types d'alertes viennent de GET /api/notify/form (schema serveur :
// lib/notify-form.js) : ajouter une alerte cote serveur suffit.

const NF = { presets: [], schema: [], rules: [], unknown: [], passwordSet: false, maxRecipients: 20 };

function nfL(o) { return o && typeof o === 'object' ? (o[LANG] || o.en || o.fr || '') : (o || ''); }
function nfStatus(id, msg, ok) {
  const el = document.getElementById(id);
  if (el) { el.textContent = msg || ''; el.style.color = ok === null ? 'var(--text3)' : ok ? 'var(--green)' : 'var(--red)'; }
}

async function nfLoad() {
  const d = await api('/notify/form');
  if (!d) { nfStatus('notify-smtp-status', t('notifyForm.loadError'), false); return; }
  NF.presets = d.presets; NF.schema = d.schema; NF.rules = d.rules; NF.unknown = d.unknownSections || [];
  NF.maxRecipients = d.maxRecipients || 20;
  nfFillSmtp(d.smtp);
  nfRenderRules();
  nfWarnIfSmtpOff(d.smtp);
}

function nfFillSmtp(s) {
  const sel = document.getElementById('nf-preset');
  sel.innerHTML = '<option value="">' + h(t('notifyForm.presetCustom')) + '</option>' +
    NF.presets.map(p => '<option value="' + h(p.id) + '">' + h(p.label) + '</option>').join('');
  const match = NF.presets.find(p => p.host === s.host && p.port === s.port && p.security === s.security);
  sel.value = match ? match.id : '';
  document.getElementById('nf-enabled').checked = !!s.enabled;
  document.getElementById('nf-host').value = s.host;
  document.getElementById('nf-port').value = s.port;
  document.getElementById('nf-security').value = s.security;
  document.getElementById('nf-ignoressl').checked = !!s.ignoreSsl;
  document.getElementById('nf-from').value = s.from;
  document.getElementById('nf-fromname').value = s.fromName;
  document.getElementById('nf-username').value = s.username;
  document.getElementById('nf-password').value = '';
  document.getElementById('nf-clearpass').checked = false;
  NF.passwordSet = !!s.passwordSet;
  document.getElementById('nf-pass-hint').textContent = t(s.passwordSet ? 'notifyForm.passwordKept' : 'notifyForm.passwordNone');
  document.getElementById('nf-clear-row').style.display = s.passwordSet ? '' : 'none';
  nfSecurityHint();
}

function nfApplyPreset() {
  const p = NF.presets.find(x => x.id === document.getElementById('nf-preset').value);
  if (!p) return;
  document.getElementById('nf-host').value = p.host;
  document.getElementById('nf-port').value = p.port;
  document.getElementById('nf-security').value = p.security;
  nfSecurityHint();
}

function nfSecurityHint() {
  const sec = document.getElementById('nf-security').value;
  const el = document.getElementById('nf-smtp-hint');
  el.textContent = sec === 'plain' ? t('notifyForm.plainWarn') : '';
  el.style.color = sec === 'plain' ? 'var(--amber)' : '';
}

function nfReadSmtp() {
  return {
    enabled: document.getElementById('nf-enabled').checked,
    host: document.getElementById('nf-host').value.trim(),
    port: Number(document.getElementById('nf-port').value),
    security: document.getElementById('nf-security').value,
    ignoreSsl: document.getElementById('nf-ignoressl').checked,
    from: document.getElementById('nf-from').value.trim(),
    fromName: document.getElementById('nf-fromname').value.trim(),
    username: document.getElementById('nf-username').value.trim(),
    password: document.getElementById('nf-password').value,
    clearPassword: document.getElementById('nf-clearpass').checked,
  };
}

async function nfSaveSmtp() {
  nfStatus('notify-smtp-status', t('notifyForm.saving'), null);
  const d = await api('/notify/smtp-form', { method: 'POST', body: JSON.stringify(nfReadSmtp()) });
  if (!d || !d.ok) { nfStatus('notify-smtp-status', t('common.error') + ' : ' + ((d && d.error) || 'unknown'), false); return; }
  nfFillSmtp(d.smtp);
  nfWarnIfSmtpOff(d.smtp);
  nfStatus('notify-smtp-status', t('common.saveSuccess'), true);
}

async function notifyTestSmtp() {
  const to = document.getElementById('notify-test-addr').value.trim();
  const smtp = nfReadSmtp();
  nfStatus('notify-smtp-status', t('notify.sendingInProgress'), null);
  const d = await api('/notify/test', { method: 'POST', body: JSON.stringify({ to: to || smtp.from, smtp }) });
  if (d && d.ok) nfStatus('notify-smtp-status', t('notify.emailSentTo') + ' ' + (to || smtp.from) + (d.durationMs ? ' (' + (d.durationMs / 1000).toFixed(1) + ' s)' : ''), true);
  else nfStatus('notify-smtp-status', t('common.error') + ' : ' + ((d && (d.reason || d.error)) || 'unknown'), false);
}

function nfWarnIfSmtpOff(s) {
  const w = document.getElementById('nf-smtp-warn');
  if (w) w.style.display = s && s.enabled && s.host ? 'none' : '';
}

// ── Alertes ──────────────────────────────────────────────────────────────────
function nfRenderRules() {
  const box = document.getElementById('nf-rules');
  box.innerHTML = NF.schema.map(sc => {
    const r = NF.rules.find(x => x.id === sc.id) || { enabled: false, recipients: [], values: {} };
    const fields = sc.fields.map(f =>
      '<label class="nf-inline">' + h(nfL(f.label)) + ' <input type="number" data-rule="' + h(sc.id) + '" data-key="' + h(f.key) + '" min="' + f.min + '" max="' + f.max + '" value="' + h(r.values[f.key] ?? f.default) + '" class="nf-num"></label>').join('');
    return '<div class="nf-rule" data-id="' + h(sc.id) + '">' +
      '<label class="nf-check"><input type="checkbox" class="nf-r-en" ' + (r.enabled ? 'checked' : '') + '> <b>' + h(nfL(sc.label)) + '</b></label>' +
      '<div class="nf-hint">' + h(nfL(sc.description)) + '</div>' +
      '<input type="text" class="nf-r-rcpt" value="' + h(r.recipients.join(', ')) + '" placeholder="' + h(t('notifyForm.recipients')) + '" spellcheck="false">' +
      (fields ? '<div class="nf-fields">' + fields + '</div>' : '') + '</div>';
  }).join('') + (NF.unknown.length ? '<div class="nf-hint">' + h(t('notifyForm.unknown', { list: NF.unknown.join(', ') })) + '</div>' : '');
}

function nfReadRules() {
  return { rules: [...document.querySelectorAll('#nf-rules .nf-rule')].map(el => {
    const id = el.dataset.id, values = {};
    el.querySelectorAll('input[data-key]').forEach(i => { values[i.dataset.key] = i.value === '' ? undefined : Number(i.value); });
    return { id, enabled: el.querySelector('.nf-r-en').checked,
      recipients: el.querySelector('.nf-r-rcpt').value.split(/[\s,;]+/).filter(Boolean), values };
  }) };
}

async function nfSaveRules() {
  nfStatus('nf-rules-status', t('notifyForm.saving'), null);
  const d = await api('/notify/rules-form', { method: 'POST', body: JSON.stringify(nfReadRules()) });
  if (!d || !d.ok) { nfStatus('nf-rules-status', t('common.error') + ' : ' + ((d && d.error) || 'unknown'), false); return; }
  NF.rules = d.rules; NF.unknown = d.unknownSections || [];
  nfRenderRules();
  nfStatus('nf-rules-status', t('common.saveSuccess'), true);
}

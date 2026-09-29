// ── NOTIFICATIONS & SCHEDULER ─────────────────────────────────────────────────
// Extrait de index.html (voir CHANGELOG.md) — script global classique (pas
// un module ES), charge apres le script principal : partage sa portee
// globale (api(), t(), ...) exactement comme le code inline qu'il remplace.
//
// Les deux pages sont regroupees dans un seul fichier, pas un par page comme
// pour Configuration : elles pointent toutes les deux vers le meme fichier
// notifications.yml (page Notifications, onglet "Notifications" ; page
// Scheduler, onglet "Notifications" aussi — deux editeurs independants sur
// le meme fichier cote serveur) et partagent donc reellement les memes
// libelles ("Sauvegarder", "Sauvegarde OK", "Erreur : ...", "Règles de
// notification") plutot que de coincidences entre deux pages sans rapport.

async function initNotify() { await notifyLoad(); }

let notifyRevealed = false;

async function notifyLoad() {
  const q = notifyRevealed ? '?reveal=1' : '';
  const d = await api('/notify/config-files' + q).catch(() => null);
  if (!d) return;
  const smtpEl  = document.getElementById('notify-smtp-editor');
  const notifEl = document.getElementById('notify-notif-editor');
  const schedEl = document.getElementById('notify-sched-editor');
  if (smtpEl  && d.smtp?.content  !== undefined) smtpEl.value  = d.smtp.content;
  if (notifEl && d.notifications?.content !== undefined) notifEl.value = d.notifications.content;
  if (schedEl && d.scheduler?.content !== undefined) schedEl.value = d.scheduler.content;

  const btn = document.getElementById('notify-reveal-btn');
  if (btn) {
    btn.style.display = d.canReveal ? '' : 'none';
    btn.innerHTML = notifyRevealed ? '\u{1F648} ' + t('common.hide') : '\u{1F441} Secrets';
  }
  const st = document.getElementById('notify-smtp-status');
  if (st && d.smtp?.masked) {
    st.textContent = t('notify.statusMasked');
    st.style.color = 'var(--text3)';
  }
}

async function notifyToggleReveal() {
  notifyRevealed = !notifyRevealed;
  await notifyLoad();
}

function notifyTab(tab) {
  ['smtp','notif','sched'].forEach(function(t) {
    const pane = document.getElementById('notify-pane-' + t);
    const btn  = document.getElementById('notify-tab-' + t);
    if (pane) pane.style.display = t === tab ? '' : 'none';
    if (btn)  btn.classList.toggle('active', t === tab);
  });
}

async function notifySave(type) {
  const map    = { smtp: 'notify-smtp-editor', notif: 'notify-notif-editor', sched: 'notify-sched-editor' };
  const keyMap = { smtp: 'smtp', notif: 'notifications', sched: 'scheduler' };
  const el = document.getElementById(map[type]);
  if (!el) return;
  const body = {};
  body[keyMap[type]] = el.value;
  const d = await api('/notify/config-files', { method: 'POST', body: JSON.stringify(body) }).catch(e => ({ error: e.message }));
  const statusEl = document.getElementById('notify-smtp-status');
  if (d && d.ok) {
    if (statusEl && type === 'smtp') { statusEl.textContent = t('common.saveSuccess'); statusEl.style.color = 'var(--green)'; }
    else alert(t('common.saveSuccess'));
  } else {
    alert(t('common.error') + ' : ' + (d && d.error ? d.error : 'unknown'));
  }
}

async function notifyTestSmtp() {
  const to     = document.getElementById('notify-test-addr') && document.getElementById('notify-test-addr').value.trim();
  const status = document.getElementById('notify-smtp-status');
  if (!to) { if (status) { status.textContent = t('notify.enterEmail'); status.style.color = 'var(--amber)'; } return; }
  if (status) { status.textContent = t('notify.sendingInProgress'); status.style.color = 'var(--text3)'; }
  const d = await api('/notify/test', { method: 'POST', body: JSON.stringify({ to }) }).catch(e => ({ error: e.message }));
  if (status) {
    status.textContent = d && d.ok ? t('notify.emailSentTo') + ' ' + to : t('common.error') + ' : ' + (d && d.reason ? d.reason : d && d.error ? d.error : 'unknown');
    status.style.color = d && d.ok ? 'var(--green)' : 'var(--red)';
  }
}

function schedTab(tab) {
  ['sched','notif'].forEach(function(t) {
    var pane = document.getElementById('sched-pane-' + t);
    var btn  = document.getElementById('sched-tab-' + t);
    if (pane) pane.style.display = t === tab ? '' : 'none';
    if (btn)  btn.classList.toggle('active', t === tab);
  });
}

async function initScheduler() {
  const d = await api('/notify/config-files').catch(() => null);
  if (!d) return;
  var schedEl = document.getElementById('sched-sched-editor');
  var notifEl = document.getElementById('sched-notif-editor');
  if (schedEl && d.scheduler) schedEl.value = d.scheduler.content || '';
  if (notifEl && d.notifications) notifEl.value = d.notifications.content || '';
}

async function schedSave(type) {
  var map    = { sched: 'sched-sched-editor', notif: 'sched-notif-editor' };
  var keyMap = { sched: 'scheduler', notif: 'notifications' };
  var el = document.getElementById(map[type]);
  if (!el) return;
  var body = {};
  body[keyMap[type]] = el.value;
  var d = await api('/notify/config-files', { method: 'POST', body: JSON.stringify(body) }).catch(e => ({ error: e.message }));
  if (d && d.ok) alert(t('common.saveSuccess'));
  else alert(t('common.error') + ' : ' + (d && d.error ? d.error : 'unknown'));
}

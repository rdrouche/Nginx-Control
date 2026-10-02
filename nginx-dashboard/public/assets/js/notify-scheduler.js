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

async function initNotify() { await Promise.all([notifyLoad(), typeof nfLoad === 'function' ? nfLoad() : null]); }

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
}

async function notifyToggleReveal() {
  notifyRevealed = !notifyRevealed;
  await notifyLoad();
}

function notifyTab(tab) {
  ['smtp','notif','yaml'].forEach(function(t) {
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
  if (d && d.ok && typeof nfLoad === 'function') nfLoad();
  if (d && d.ok) {
    if (statusEl && type === 'smtp') { statusEl.textContent = t('common.saveSuccess'); statusEl.style.color = 'var(--green)'; }
    else alert(t('common.saveSuccess'));
  } else {
    alert(t('common.error') + ' : ' + (d && d.error ? d.error : 'unknown'));
  }
}

// notifyTestSmtp() : voir notify-form.js (test avec les valeurs du formulaire).

function schedTab(tab) {
  ['sched','notif'].forEach(function(t) {
    var pane = document.getElementById('sched-pane-' + t);
    var btn  = document.getElementById('sched-tab-' + t);
    if (pane) pane.style.display = t === tab ? '' : 'none';
    if (btn)  btn.classList.toggle('active', t === tab);
  });
}

// La page Scheduler (taches) est dans scheduler.js ; ici seul l'onglet
// "Notifications" de cette page reste un editeur de fichier.
async function schedLoadNotif() {
  const d = await api('/notify/config-files').catch(() => null);
  const notifEl = document.getElementById('sched-notif-editor');
  if (d && notifEl && d.notifications) notifEl.value = d.notifications.content || '';
}

async function schedSave(type) {
  if (type !== 'notif') return;
  const el = document.getElementById('sched-notif-editor');
  if (!el) return;
  const d = await api('/notify/config-files', { method: 'POST', body: JSON.stringify({ notifications: el.value }) }).catch(e => ({ error: e.message }));
  if (d && d.ok) alert(t('common.saveSuccess'));
  else alert(t('common.error') + ' : ' + (d && d.error ? d.error : 'unknown'));
}

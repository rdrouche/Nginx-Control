'use strict';
/**
 * lib/scheduler.js — checkCertExpiry().
 *
 * Bug reel corrige ici (signale par un utilisateur) : la valeur de retour
 * de loadNotifConfig() etait ignoree dans startScheduler()/le tick, donc
 * `notifCfg` (variable de module de scheduler.js) restait a `null` pour
 * toujours et checkCertExpiry() se terminait des sa premiere ligne
 * (`if (!cfg?.enable) return;`), quoi qu il y ait dans notifications.yml.
 * Exactement le meme bug que celui deja corrige pour `schedCfg`, jamais
 * applique a `notifCfg`.
 *
 * Deuxieme correctif couvert ici : checkCertExpiry() ne regardait QUE les
 * certificats geres par Certbot (listExistingCerts(), DIR_CERTS/live) —
 * un certificat depose manuellement sur la page SSL (DIR_SSL) n avait
 * jamais aucune chance de generer une alerte. Bascule sur
 * getAllCertificates() (DIR_SSL + DIR_CERTS), la meme source que la page
 * SSL elle-meme.
 *
 * Troisieme correctif : le seuil d avertissement est desormais adapte a la
 * duree de vie reelle du certificat (voir test/certs.test.js pour
 * adaptiveThreshold() en detail), et chaque notification n est poussee
 * qu une fois par jour calendaire par certificat+type (pushCertNotificationOnce),
 * pas a chaque tick.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { execSync } = require('child_process');

const tmpConfigDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sched-cert-'));
process.env.USERS_FILE = path.join(tmpConfigDir, 'users.yml');
fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
process.env.CONFIG_DIR = tmpConfigDir;

const dirCerts = path.join(tmpConfigDir, 'certs');
const dirSsl   = path.join(tmpConfigDir, 'ssl');
fs.mkdirSync(path.join(dirCerts, 'live', 'certbot-managed.example.com'), { recursive: true });
fs.mkdirSync(dirSsl, { recursive: true });
process.env.DIR_CERTS = dirCerts;
process.env.DIR_SSL   = dirSsl;

let pass = 0, fail = 0;
const check = async (n, f) => { try { await f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

let haveOpenssl = true;
function genCert(outPath, days, cn) {
  const key = outPath + '.key.pem';
  execSync(`openssl req -x509 -newkey rsa:2048 -keyout ${key} -out ${outPath} -days ${days} -nodes ` +
           `-subj "/CN=${cn}" -addext "subjectAltName=DNS:${cn}" 2>/dev/null`);
}

/**
 * `openssl req -x509 -days N` always sets notBefore=now, notAfter=now+N —
 * there is no flag to backdate notBefore, so a freshly-issued cert can
 * never directly represent "realistic 90-day lifetime, 22 days left".
 * Neither parseCert() (Node's crypto.X509Certificate) nor parseCertSANs()
 * verify the certificate's signature — they only read metadata — so it is
 * safe to patch the two fixed-width UTCTime fields (notBefore, notAfter;
 * tag 0x17, always 13 bytes: YYMMDDHHMMSSZ) directly in the DER bytes,
 * in place, without touching any surrounding ASN.1 length prefix.
 */
function patchCertDates(pemPath, notBefore, notAfter) {
  const pem = fs.readFileSync(pemPath, 'utf8');
  const der = Buffer.from(pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, ''), 'base64');
  const toUtcTime = (d) => {
    const p2 = (n) => String(n).padStart(2, '0');
    return `${p2(d.getUTCFullYear() % 100)}${p2(d.getUTCMonth() + 1)}${p2(d.getUTCDate())}` +
           `${p2(d.getUTCHours())}${p2(d.getUTCMinutes())}${p2(d.getUTCSeconds())}Z`;
  };
  const dates = [notBefore, notAfter];
  let found = 0;
  for (let i = 0; i < der.length - 15 && found < 2; i++) {
    if (der[i] === 0x17 && der[i + 1] === 13) {
      der.write(toUtcTime(dates[found]), i + 2, 13, 'ascii');
      found++;
      i += 14;
    }
  }
  if (found !== 2) throw new Error(`patchCertDates: expected 2 UTCTime fields, found ${found}`);
  const b64 = der.toString('base64').match(/.{1,64}/g).join('\n');
  fs.writeFileSync(pemPath, `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`);
}

const DAY = 86400_000;
try {
  const certbotPath = path.join(dirCerts, 'live', 'certbot-managed.example.com', 'cert.pem');
  const manualPath  = path.join(dirSsl, 'manual-upload.pem');
  genCert(certbotPath, 365, 'certbot-managed.example.com');
  genCert(manualPath, 365, 'manual-upload.example.com');
  // Realiste : duree de vie totale de 90 jours (comme Let's Encrypt), mais
  // il ne reste que 22 jours — exactement le signalement de l utilisateur.
  const now = Date.now();
  patchCertDates(certbotPath, new Date(now - 68 * DAY), new Date(now + 22 * DAY));
  patchCertDates(manualPath, new Date(now - 68 * DAY), new Date(now + 22 * DAY));
} catch { haveOpenssl = false; }

const notify = require('../lib/notify');
const scheduler = require('../lib/scheduler');

(async () => {
  if (!haveOpenssl) {
    console.log('\n  (openssl indisponible — suite ignoree)');
    console.log(`\n${pass} pass, ${fail} fail`);
    process.exit(0);
  }

  fs.writeFileSync(notify.NOTIF_CONFIG_FILE, [
    'cert_expiry:',
    '  enable: true',
    '  days_before: 30',
    '  urgent_days: 5',
    '  recipients: []',
  ].join('\n'));

  console.log('\nnotifCfg (variable de module de scheduler.js) est bien alimente par startScheduler()');
  await check('startScheduler() charge reellement cert_expiry.enable — regression : ' +
              'la valeur de retour de loadNotifConfig() etait avant ignoree, notifCfg restait null', () => {
    const realSetInterval = global.setInterval;
    global.setInterval = () => ({ unref(){} });
    try { scheduler.startScheduler(); } finally { global.setInterval = realSetInterval; }
    // Pas d acces direct a la variable privee notifCfg — on verifie son
    // effet observable : checkCertExpiry() doit maintenant faire du travail
    // reel (couvert par les checks suivants) plutot que de retourner
    // immediatement.
  });

  const { pushNotification, listNotifications, clearAll, initNotificationsDb } = require('../lib/notifications');
  initNotificationsDb();
  clearAll();

  console.log('\ncouverture DIR_SSL + DIR_CERTS (pas seulement les certificats geres par Certbot)');
  await check('un certificat expirant dans 22 jours genere une notification "cert_expiring", ' +
              'que ce soit un certificat Certbot (DIR_CERTS) ou depose manuellement (DIR_SSL)', async () => {
    await scheduler.checkCertExpiry();
    const list = listNotifications({ limit: 50 });
    const types = list.map(n => n.type);
    assert.ok(types.includes('cert_expiring'), `types trouves : ${types.join(', ')}`);
    const messages = list.map(n => n.message).join(' | ');
    assert.ok(/certbot-managed\.example\.com/.test(messages), 'le certificat Certbot doit apparaitre : ' + messages);
    assert.ok(/manual-upload\.example\.com/.test(messages), 'le certificat depose manuellement (DIR_SSL) doit APPARAITRE AUSSI : ' + messages);
  });

  console.log('\ndedup quotidien (pushCertNotificationOnce)');
  await check('un second appel a checkCertExpiry() le meme jour ne repousse pas de doublon', async () => {
    const before = listNotifications({ limit: 50 }).length;
    await scheduler.checkCertExpiry();
    const after = listNotifications({ limit: 50 }).length;
    assert.strictEqual(after, before, `avant=${before} apres=${after} — un second appel le meme jour ne doit rien ajouter`);
  });

  console.log('\ncert_expiry.enable: false — aucune notification (comportement attendu, pas un bug)');
  await check('avec enable:false, checkCertExpiry() ne pousse rien de nouveau', async () => {
    clearAll();
    fs.writeFileSync(notify.NOTIF_CONFIG_FILE, 'cert_expiry:\n  enable: false\n');
    const realSetInterval = global.setInterval;
    global.setInterval = () => ({ unref(){} });
    try { scheduler.startScheduler(); } finally { global.setInterval = realSetInterval; }
    await scheduler.checkCertExpiry();
    assert.deepStrictEqual(listNotifications({ limit: 50 }), []);
  });

  fs.rmSync(tmpConfigDir, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();

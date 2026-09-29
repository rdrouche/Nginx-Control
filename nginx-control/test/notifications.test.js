'use strict';
/**
 * lib/notifications.js — le centre de notification (stockage + pushNotification()).
 * Meme idiome SQLite que monitor-store.test.js / digest-storage.test.js.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
process.env.USERS_FILE = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'notifcenter-')), 'users.yml');
fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
const notifications = require('../lib/notifications');
let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

notifications.initNotificationsDb();
notifications.clearAll(); // repart d une base vide meme si un fichier .db residuel trainait

console.log('\npushNotification() — validation et valeurs par defaut');
check('type ou message manquant -> exception', () => {
  assert.throws(() => notifications.pushNotification({ message: 'x' }));
  assert.throws(() => notifications.pushNotification({ type: 'x' }));
  assert.throws(() => notifications.pushNotification());
});
check('level absent -> "info" par defaut', () => {
  const n = notifications.pushNotification({ type: 't1', message: 'm1' });
  assert.strictEqual(n.level, 'info');
  assert.strictEqual(n.read, false);
  assert.ok(n.id);
  assert.ok(n.ts);
});
check('level invalide -> repli silencieux sur "info", jamais une exception', () => {
  const n = notifications.pushNotification({ type: 't1', message: 'm2', level: 'not-a-level' });
  assert.strictEqual(n.level, 'info');
});
check('data est conserve et relu tel quel (aller-retour JSON)', () => {
  const n = notifications.pushNotification({ type: 't1', message: 'm3', level: 'warning', data: { a: 1, b: 'x' } });
  const found = notifications.listNotifications({ limit: 50 }).find(x => x.id === n.id);
  assert.deepStrictEqual(found.data, { a: 1, b: 'x' });
});

console.log('\nlistNotifications() / getUnreadCount()');
check('les plus recentes en premier', () => {
  const list = notifications.listNotifications({ limit: 50 });
  assert.ok(list.length >= 3);
  assert.ok(list[0].ts >= list[1].ts);
});
check('unreadOnly ne renvoie que les non lues', () => {
  const all = notifications.listNotifications({ limit: 50 });
  const unread = notifications.listNotifications({ limit: 50, unreadOnly: true });
  assert.strictEqual(unread.length, all.length); // tout est encore non lu a ce stade
  assert.ok(unread.every(n => n.read === false));
});
check('getUnreadCount() correspond au compte de listNotifications({unreadOnly:true})', () => {
  const unread = notifications.listNotifications({ limit: 200, unreadOnly: true });
  assert.strictEqual(notifications.getUnreadCount(), unread.length);
});

console.log('\nmarkRead() / markAllRead()');
check('markRead() sur un seul id -> celui-la seulement passe read:true', () => {
  const target = notifications.listNotifications({ limit: 1 })[0];
  notifications.markRead(target.id);
  const found = notifications.listNotifications({ limit: 50 }).find(n => n.id === target.id);
  assert.strictEqual(found.read, true);
});
check('markAllRead() -> unreadCount tombe a 0', () => {
  notifications.markAllRead();
  assert.strictEqual(notifications.getUnreadCount(), 0);
});

console.log('\ndeleteNotification() / clearRead() / clearAll()');
check('deleteNotification() retire une entree precise', () => {
  const before = notifications.listNotifications({ limit: 200 }).length;
  const target = notifications.listNotifications({ limit: 1 })[0];
  notifications.deleteNotification(target.id);
  const after = notifications.listNotifications({ limit: 200 });
  assert.strictEqual(after.length, before - 1);
  assert.ok(!after.some(n => n.id === target.id));
});
check('clearRead() ne touche pas les non lues', () => {
  notifications.clearAll();
  notifications.pushNotification({ type: 'a', message: 'unread-1' });
  const r = notifications.pushNotification({ type: 'b', message: 'read-1' });
  notifications.markRead(r.id);
  notifications.clearRead();
  const remaining = notifications.listNotifications({ limit: 50 });
  assert.strictEqual(remaining.length, 1);
  assert.strictEqual(remaining[0].message, 'unread-1');
});
check('clearAll() vide tout, lu ou non', () => {
  notifications.clearAll();
  assert.deepStrictEqual(notifications.listNotifications({ limit: 50 }), []);
  assert.strictEqual(notifications.getUnreadCount(), 0);
});

notifications.closeDb();
console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);

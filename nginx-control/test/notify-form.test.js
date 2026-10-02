'use strict';
/**
 * v12.57.0 — formulaires SMTP et alertes : validation, YAML genere relu a
 * l'identique par le chargeur, mot de passe jamais renvoye, API.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nf-'));
process.env.USERS_FILE = path.join(dir, 'users.yml');
fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
const events = require('../lib/events');
events.initEventsDb();
const notify = require('../lib/notify');
const F = require('../lib/notify-form');
const feature = require('../features/notifications');

let pass = 0, fail = 0;
const check = async (n, f) => { try { await f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const routes = {};
feature.register({ get: (p, h) => { routes['GET ' + p] = h; }, post: (p, h) => { routes['POST ' + p] = h; } });
const call = async (method, p, { role = 'admin', body = {} } = {}) => {
  let status = null, out = null;
  const res = { writeHead(s) { status = s; }, end(b) { try { out = JSON.parse(b); } catch { out = b; } }, setHeader() {} };
  const req = require('stream').Readable.from([JSON.stringify(body)]);
  await routes[method + ' ' + p]({ req, res, session: role ? { role, username: 'tester' } : null, url: new URL('http://x' + p) });
  return { status, body: out };
};

const good = { enabled: true, host: 'smtp.example.com', port: 587, security: 'tls', ignoreSsl: false,
  from: 'dash@example.com', fromName: 'Dash', username: 'u@example.com', password: 's3cret' };

(async () => {
  await check('validateSmtp : formulaire valide', () => {
    const r = F.validateSmtp(good, null);
    assert.ok(r.ok, r.error);
    assert.strictEqual(r.value.port, 587);
  });
  await check('validateSmtp : refus (hote, port, securite, expediteur, controle)', () => {
    for (const patch of [{ host: 'a b' }, { host: 'x;rm' }, { host: '' }, { port: 0 }, { port: 70000 }, { port: 'abc' }, { security: 'nope' },
      { from: 'pas-un-mail' }, { from: '' }, { fromName: 'a\nb' }, { username: 'a\nb' }, { password: 'a\nb' },
      { password: `a"b'c` }, { password: 'x'.repeat(300) }, { host: 'h'.repeat(300) }])
      assert.strictEqual(F.validateSmtp({ ...good, ...patch }, null).ok, false, JSON.stringify(patch));
  });
  await check('validateSmtp : desactive, hote et expediteur peuvent etre vides', () => {
    assert.ok(F.validateSmtp({ ...good, enabled: false, host: '', from: '' }, null).ok);
  });
  await check('mot de passe : vide = conserve, clearPassword = efface, nouveau = remplace', () => {
    assert.strictEqual(F.validateSmtp({ ...good, password: '' }, { password: 'old' }).value.password, 'old');
    assert.strictEqual(F.validateSmtp({ ...good, password: '', clearPassword: true }, { password: 'old' }).value.password, '');
    assert.strictEqual(F.validateSmtp({ ...good, password: 'new' }, { password: 'old' }).value.password, 'new');
  });
  await check('YAML genere : relu a l\'identique par le chargeur (mots de passe pieges)', () => {
    for (const pw of ['s3cret', '0123', '12345', 'true', 'a#b c', 'p"w', "p'w", 'x: y', '- z', 'é€ü']) {
      const v = F.validateSmtp({ ...good, password: pw, fromName: 'Nom # test', username: 'user name' }, null).value;
      const f = path.join(dir, 'rt.yml');
      fs.writeFileSync(f, F.smtpToYaml(v));
      const c = notify.parseYmlFlat(f);
      assert.strictEqual(c.password, pw === 'true' ? true : pw, `mot de passe ${pw}`);
      assert.strictEqual(typeof c.password, pw === 'true' ? 'boolean' : 'string');
      assert.strictEqual(c.from_name, 'Nom # test');
      assert.strictEqual(c.username, 'user name');
      assert.strictEqual(c.host, 'smtp.example.com');
      assert.strictEqual(c.port, 587);
      assert.strictEqual(c.enable, true);
      assert.deepStrictEqual(Object.keys(c).sort(), ['enable', 'from', 'from_name', 'host', 'ignore_ssl', 'password', 'port', 'security', 'username']);
    }
  });
  await check('smtpView ne contient jamais le mot de passe', () => {
    const v = F.smtpView({ enable: true, host: 'h', port: 25, password: 'topsecret' });
    assert.strictEqual(v.passwordSet, true);
    assert.ok(!JSON.stringify(v).includes('topsecret'));
  });

  const ruleBase = () => F.describeRules().map(r => ({ id: r.id, enabled: false, recipients: [], values: {} }));
  await check('validateRules : valide, activation exige un destinataire, adresses/bornes controlees', () => {
    const rs = ruleBase();
    rs[0] = { id: 'cert_expiry', enabled: true, recipients: ['a@x.fr', 'a@x.fr'], values: { days_before: 20, urgent_days: 3 } };
    const ok = F.validateRules({ rules: rs }, null);
    assert.ok(ok.ok, ok.error);
    assert.deepStrictEqual(ok.value.cert_expiry.recipients, ['a@x.fr']);
    const bad = patch => F.validateRules({ rules: [{ ...rs[0], ...patch }] }, null).ok;
    assert.strictEqual(bad({ recipients: [] }), false);
    assert.strictEqual(bad({ recipients: ['nope'] }), false);
    assert.strictEqual(bad({ recipients: ['a@x.fr\nb: c'] }), false);
    assert.strictEqual(bad({ values: { days_before: 0, urgent_days: 1 } }), false);
    assert.strictEqual(bad({ values: { days_before: 5, urgent_days: 10 } }), false);
    assert.strictEqual(F.validateRules({ rules: [{ id: 'inconnu' }] }, null).ok, false);
    assert.strictEqual(F.validateRules({ rules: [rs[1], rs[1]] }, null).ok, false);
    assert.strictEqual(F.validateRules({}, null).ok, false);
  });
  await check('rulesToYaml : relu par le chargeur, sections inconnues conservees', () => {
    const prev = { ma_regle: { enable: true, recipients: ['z@x.fr'], seuil: 7 } };
    const rs = ruleBase();
    rs[1] = { id: 'nginx_test_error', enabled: true, recipients: ['a@x.fr', 'b@x.fr'], values: {} };
    const v = F.validateRules({ rules: rs }, prev);
    const f = path.join(dir, 'rules.yml');
    fs.writeFileSync(f, F.rulesToYaml(v.value, prev));
    const c = notify.parseYmlFlat(f);
    assert.deepStrictEqual(c.nginx_test_error.recipients, ['a@x.fr', 'b@x.fr']);
    assert.strictEqual(c.nginx_test_error.enable, true);
    assert.strictEqual(c.cert_expiry.enable, false);
    assert.strictEqual(c.cert_expiry.days_before, 30);
    assert.deepStrictEqual(c.ma_regle.recipients, ['z@x.fr']);
    assert.strictEqual(c.ma_regle.seuil, 7);
    for (const r of F.describeRules()) assert.ok(c[r.id], r.id);
  });

  await check('API : permissions (viewer et anonyme refuses)', async () => {
    for (const [m, p] of [['GET', '/api/notify/form'], ['POST', '/api/notify/smtp-form'], ['POST', '/api/notify/rules-form'], ['POST', '/api/notify/test']]) {
      assert.strictEqual((await call(m, p, { role: 'viewer' })).status, 403, p);
      assert.strictEqual((await call(m, p, { role: null })).status, 403, p);
    }
  });
  await check('API : enregistrement SMTP, vue sans mot de passe, fichier 0600, conservation du mot de passe', async () => {
    const r = await call('POST', '/api/notify/smtp-form', { body: good });
    assert.strictEqual(r.status, 200, JSON.stringify(r.body));
    assert.strictEqual(r.body.smtp.passwordSet, true);
    assert.ok(!JSON.stringify(r.body).includes('s3cret'));
    const g = await call('GET', '/api/notify/form');
    assert.ok(!JSON.stringify(g.body).includes('s3cret'));
    assert.strictEqual(g.body.smtp.host, 'smtp.example.com');
    assert.ok(g.body.presets.length > 3 && g.body.schema.length >= 8);
    await call('POST', '/api/notify/smtp-form', { body: { ...good, password: '', host: 'smtp2.example.com' } });
    assert.strictEqual(notify.loadSmtpConfig().password, 's3cret');
    assert.strictEqual(notify.loadSmtpConfig().host, 'smtp2.example.com');
    if (process.platform !== 'win32') assert.strictEqual(fs.statSync(notify.SMTP_CONFIG_FILE).mode & 0o077, 0);
    assert.strictEqual((await call('POST', '/api/notify/smtp-form', { body: { ...good, port: 0 } })).status, 400);
  });
  await check('API : enregistrement des alertes et relecture', async () => {
    const rs = ruleBase();
    rs[0] = { id: 'cert_expiry', enabled: true, recipients: ['ops@x.fr'], values: { days_before: 14, urgent_days: 2 } };
    const r = await call('POST', '/api/notify/rules-form', { body: { rules: rs } });
    assert.strictEqual(r.status, 200, JSON.stringify(r.body));
    const g = await call('GET', '/api/notify/form');
    const c = g.body.rules.find(x => x.id === 'cert_expiry');
    assert.deepStrictEqual([c.enabled, c.recipients, c.values.days_before], [true, ['ops@x.fr'], 14]);
    assert.strictEqual((await call('POST', '/api/notify/rules-form', { body: { rules: [{ id: 'cert_expiry', enabled: true, recipients: [] }] } })).status, 400);
  });
  await check('API : test avec valeurs non enregistrees — erreurs de validation et adresse invalide sans connexion reseau', async () => {
    const a = await call('POST', '/api/notify/test', { body: { to: 'a@x.fr', smtp: { ...good, port: 0 } } });
    assert.strictEqual(a.body.ok, false);
    const b = await call('POST', '/api/notify/test', { body: { to: 'a@x.fr\r\nRCPT TO:<evil@x.fr>', smtp: good } });
    assert.strictEqual(b.body.ok, false);
    assert.ok(/invalide/i.test(b.body.reason));
  });

  await check('regression : `username:` vide et mot de passe « ******** » = pas d\'authentification', async () => {
    fs.writeFileSync(notify.SMTP_CONFIG_FILE, 'enable: true\nhost: smtp.example.com\nport: 587\nsecurity: tls\nfrom: a@example.com\nusername:\npassword: "********"\n');
    let v = F.smtpView(notify.loadSmtpConfig());
    assert.strictEqual(v.username, '');
    assert.strictEqual(v.passwordSet, false);
    fs.writeFileSync(notify.SMTP_CONFIG_FILE, 'enable: true\nhost: h.example.com\nport: 25\nsecurity: plain\nfrom: a@example.com\nusername: "[object Object]"\npassword:\n');
    v = F.smtpView(notify.loadSmtpConfig());
    assert.strictEqual(v.username, '');
    assert.strictEqual(v.passwordSet, false);
    // enregistrement par le formulaire avec identifiant et mot de passe vides
    const r = await call('POST', '/api/notify/smtp-form', { body: { ...good, username: '', password: '', security: 'plain', port: 25 } });
    assert.strictEqual(r.status, 200);
    const c = notify.loadSmtpConfig();
    assert.strictEqual(c.username, '');
    assert.strictEqual(c.password, '');
    assert.ok(/^username: ""$/m.test(fs.readFileSync(notify.SMTP_CONFIG_FILE, 'utf8')));
  });
  await check('regression : sauver l\'editeur YAML avec le masque sans mot de passe precedent ne cree pas de mot de passe', async () => {
    fs.writeFileSync(notify.SMTP_CONFIG_FILE, 'enable: false\nusername: ""\npassword: ""\n');
    const r = await call('POST', '/api/notify/config-files', { body: { smtp: 'enable: false\nusername: ""\npassword: "********"\n' } });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(notify.loadSmtpConfig().password, '');
    // avec un mot de passe existant, le masque restaure la vraie valeur
    fs.writeFileSync(notify.SMTP_CONFIG_FILE, 'enable: false\npassword: "vrai"\n');
    await call('POST', '/api/notify/config-files', { body: { smtp: 'enable: false\npassword: "********"\n' } });
    assert.strictEqual(notify.loadSmtpConfig().password, 'vrai');
  });

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();

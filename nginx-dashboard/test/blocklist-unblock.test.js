'use strict';
/**
 * v12.54.0 — deblocage manuel d'une IP de la source "analyzer".
 * Retour utilisateur : "ajouter une option pour debloquer une adresse IP dans la
 * blocklist analyzer".
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'blu-'));
  process.env.USERS_FILE   = path.join(dir, 'config', 'users.yml');
  fs.mkdirSync(path.dirname(process.env.USERS_FILE), { recursive: true });
  fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
  process.env.DIR_SNIPPETS = path.join(dir, 'snippets');
  process.env.DIR_CONF     = path.join(dir, 'conf');
  process.env.DIR_LOGS     = path.join(dir, 'logs');

  const docker = require('../lib/docker');
  const events = require('../lib/events');
  const cfg    = require('../lib/config');
  const H      = require('../lib/blocklist-history');
  const B      = require('../features/blocklists');
  events.initEventsDb();
  docker.execNginx = async (cmd) => ({ stdout: `${cmd} ok`, stderr: '' });
  fs.writeFileSync(cfg.BLOCKLIST_CONFIG_FILE, ['enable: true', 'sources:', '  - name: auto', '    type: analyzer'].join('\n'));
  B.ensureSnippetsAtBoot();

  const IP = '45.148.10.123';
  const rules = [{ id: 2, key: 'scan', name: 'scan', threshold: 1, windowMinutes: 5, remediation: true, remediationMinutes: 120 }];
  let alerts = [{ id: 1, ip: IP, type: 'scan', vhost: 'site.fr', ts: Date.now() }];
  B.setDeps({
    buildVhostRulesMap: () => ({}),
    analyzerApi: async (p) => p.startsWith('/api/rules/blocklist-config') ? { status: 200, data: { rules } }
      : p.startsWith('/api/alerts') ? { status: 200, data: { alerts } } : { status: 404, data: null },
  });
  const inList = () => fs.readFileSync(B.GEO_FILE, 'utf8').includes(IP);
  const cycle = () => B.refreshBlocklists({ manual: false, analyzerOnly: true });

  await B.refreshBlocklists({ manual: true, actor: 'test', analyzerOnly: true });
  check('point de depart : IP bloquee, checkIp la dit debloquable (analyzerBlocked)', () => {
    assert.ok(inList());
    const c = B.checkIp(IP);
    assert.strictEqual(c.blocked, true);
    assert.strictEqual(c.analyzerBlocked, true);
    assert.strictEqual(c.unblocked, null);
  });

  await sleep(5);
  const r = await B.unblockAnalyzerIp(IP, { hours: 0, actor: 'romain' });
  check('deblocage : retiree de la liste nginx immediatement, resultat explicite', () => {
    assert.deepStrictEqual([r.ok, r.wasBlocked, r.refreshed, r.until], [true, true, true, null]);
    assert.ok(!inList(), 'IP encore dans la table geo');
  });
  check('historique : removed / manual, une seule fois', () => {
    const e = H.query({ ip: IP, action: 'removed' });
    assert.strictEqual(e.total, 1);
    assert.strictEqual(e.entries[0].reason, 'manual');
  });
  check('evenement blocklists.unblock journalise avec l acteur', () => {
    const ev = events.queryEvents({ limit: 500 }).events.find(e => e.type === 'blocklists.unblock');
    assert.ok(ev, 'evenement absent');
    assert.ok(JSON.stringify(ev).includes('romain'));
  });

  await cycle();
  check('remise a zero : l ancienne alerte (toujours renvoyee par l analyzer) ne re-bloque pas', () => {
    assert.ok(!inList());
    assert.strictEqual(H.query({ ip: IP, action: 'removed' }).total, 1, 'pas de doublon dans l historique');
    assert.strictEqual(H.query({ ip: IP, action: 'added' }).total, 1);
  });

  await sleep(5);
  alerts = [...alerts, { id: 2, ip: IP, type: 'scan', vhost: 'site.fr', ts: Date.now() }];
  await cycle();
  check('une NOUVELLE alerte franchissant le seuil re-bloque l IP (hours=0)', () => {
    assert.ok(inList());
    assert.strictEqual(H.query({ ip: IP, action: 'added' }).total, 2);
  });

  await sleep(5);
  const r2 = await B.unblockAnalyzerIp(IP, { hours: 24, actor: 'romain' });
  check('exemption 24 h : retiree, echeance renvoyee, checkIp expose l exemption', () => {
    assert.ok(!inList());
    assert.ok(r2.until > Date.now() + 23 * 3600_000);
    const c = B.checkIp(IP);
    assert.ok(c.unblocked && c.unblocked.until > Date.now());
  });
  await sleep(5);
  alerts = [...alerts, { id: 3, ip: IP, type: 'scan', vhost: 'site.fr', ts: Date.now() }];
  await cycle();
  check('exemption 24 h : une nouvelle alerte ne re-bloque PAS', () => assert.ok(!inList()));

  const un = events.getState('blocklist_analyzer_unblocked');
  un[IP].until = Date.now() - 1000; events.setState('blocklist_analyzer_unblocked', un);
  await sleep(5);
  alerts = [...alerts, { id: 4, ip: IP, type: 'scan', vhost: 'site.fr', ts: Date.now() }];
  await cycle();
  check('exemption expiree : une alerte posterieure re-bloque', () => assert.ok(inList()));

  const rr = await B.unblockAnalyzerIp('203.0.113.99', { hours: 0, actor: 'romain' });
  check('IP qui n etait pas bloquee : ok, wasBlocked=false, aucune entree removed inventee', () => {
    assert.strictEqual(rr.wasBlocked, false);
    assert.strictEqual(H.query({ ip: '203.0.113.99' }).total, 0);
  });
  const rc = await B.unblockAnalyzerIp('203.0.113.98', { hours: 99999, actor: 'x' });
  check('heures plafonnees a 720', () => assert.ok(rc.until <= Date.now() + 720 * 3600_000 + 1000));

  // Concurrence : deux deblocages simultanes + un cycle ne corrompent pas l etat.
  await Promise.all([B.unblockAnalyzerIp('203.0.113.1'), B.unblockAnalyzerIp('203.0.113.2'), cycle()]);
  check('deblocages concurrents : les deux sont enregistres', () => {
    const s = events.getState('blocklist_analyzer_unblocked');
    assert.ok(s['203.0.113.1'] && s['203.0.113.2']);
  });

  fs.rmSync(dir, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();

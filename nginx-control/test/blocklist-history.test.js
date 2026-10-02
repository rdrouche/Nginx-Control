'use strict';
/**
 * v12.53.0 — historique des ajouts/retraits de la source "analyzer" et cadence
 * dediee. Retour utilisateur : "j'ai eu un declenchement d'alerte, par contre la
 * liste n'a pas ete mise a jour" (source recalculee seulement au cron general,
 * 6 h) et "possible d'avoir des logs pour savoir quand une IP est ajoutee /
 * retiree ?".
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'blh-'));
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
  const { parseAndValidate } = require('../lib/blocklist-yaml');
  events.initEventsDb();
  docker.execNginx = async (cmd) => ({ stdout: `${cmd} ok`, stderr: '' });
  const writeYaml = (t) => fs.writeFileSync(cfg.BLOCKLIST_CONFIG_FILE, t);
  B.ensureSnippetsAtBoot();

  console.log('\ndiffAnalyzer() — pur');
  const d1 = H.diffAnalyzer({
    source: 'auto', prevIps: ['1.1.1.1', '2.2.2.2'], newIps: ['2.2.2.2', '3.3.3.3'],
    prevDetected: ['1.1.1.1'], newDetected: ['3.3.3.3', '4.4.4.4'],
    ipRules: { '3.3.3.3': { rule: 'scan', until: 1234 } }, expired: ['1.1.1.1'],
  });
  check('IP nouvelle -> added avec regle et echeance', () => {
    const e = d1.find(x => x.ip === '3.3.3.3');
    assert.deepStrictEqual([e.action, e.rule, e.until], ['added', 'scan', 1234]);
  });
  check('IP disparue expiree -> removed/expired ; sinon no-longer-qualifies', () => {
    assert.strictEqual(d1.find(x => x.ip === '1.1.1.1').reason, 'expired');
    const d = H.diffAnalyzer({ source: 's', prevIps: ['9.9.9.9'], newIps: [] });
    assert.strictEqual(d[0].reason, 'no-longer-qualifies');
  });
  check('detectee non bloquee -> detected ; detectee ET bloquee -> pas de doublon', () => {
    const det = d1.filter(x => x.action === 'detected').map(x => x.ip);
    assert.deepStrictEqual(det, ['4.4.4.4']);
  });
  check('aucun changement -> aucune entree', () => {
    assert.deepStrictEqual(H.diffAnalyzer({ source: 's', prevIps: ['1.1.1.1'], newIps: ['1.1.1.1'], prevDetected: ['1.1.1.1'], newDetected: ['1.1.1.1'] }), []);
  });

  console.log('\nrecord()/query() — filtres, pagination, CSV');
  const t0 = Date.now() - 3 * 3600_000;
  H.record([{ ip: '10.0.0.1', action: 'added', source: 'a', rule: 'scan' }, { ip: '10.0.0.2', action: 'detected', source: 'a', rule: 'flood' }], t0);
  for (let i = 0; i < 120; i++) H.record([{ ip: `10.1.0.${i % 250}`, action: i % 2 ? 'removed' : 'added', source: 'a', rule: 'scan', reason: i % 2 ? 'expired' : null }], t0 + 1000 + i);
  check('plus de 100 entrees : pagination limit/offset sans perte', () => {
    const p1 = H.query({ limit: 100, offset: 0 }), p2 = H.query({ limit: 100, offset: 100 });
    assert.strictEqual(p1.total, 122);
    assert.strictEqual(p1.entries.length, 100);
    assert.strictEqual(p2.entries.length, 22);
    assert.strictEqual(new Set([...p1.entries, ...p2.entries].map(e => e.id)).size, 122);
  });
  check('tri : plus recent d abord', () => {
    const e = H.query({ limit: 500 }).entries;
    for (let i = 1; i < e.length; i++) assert.ok(e[i - 1].ts >= e[i].ts);
  });
  check('filtres action / ip (sous-chaine) / rule / periode', () => {
    assert.strictEqual(H.query({ action: 'detected' }).total, 1);
    assert.strictEqual(H.query({ ip: '10.0.0.' }).total, 2);
    assert.strictEqual(H.query({ rule: 'flood' }).total, 1);
    assert.strictEqual(H.query({ since: t0 + 500 }).total, 120);
  });
  check('limit borne (1..500), valeurs invalides ignorees, jamais toute la table', () => {
    assert.strictEqual(H.query({ limit: 99999 }).limit, 500);
    assert.strictEqual(H.query({ limit: -5 }).limit, 1);
    assert.strictEqual(H.query({ limit: 'abc' }).limit, 50);
    assert.strictEqual(H.query({ action: "x'; DROP TABLE blocklist_history;--" }).total, 122, 'action inconnue ignoree');
  });
  check('ip avec joker SQL (% _) traitee litteralement', () => {
    assert.strictEqual(H.query({ ip: '%' }).total, 0);
    assert.strictEqual(H.query({ ip: '_' }).total, 0);
  });
  check('action invalide a l enregistrement -> ignoree', () => {
    assert.strictEqual(H.record([{ ip: '1.2.3.4', action: 'hack' }, { action: 'added' }]), 0);
  });
  check('CSV : en-tete, protection injection de formule, guillemets', () => {
    const csv = H.toCsv([{ ts: 0, ip: '=1+1', action: 'added', source: 'a,b', rule: 'x"y', reason: null, until: null }]);
    assert.ok(csv.startsWith('date,ip,action,source,rule,reason,until\n'));
    assert.ok(csv.includes("'=1+1") && csv.includes('"a,b"') && csv.includes('"x""y"'));
  });

  console.log('\nrefreshBlocklists() — l historique suit les cycles de la source analyzer');
  let rules = [{ id: 2, key: 'scan', name: 'scan', threshold: 1, windowMinutes: 5, remediation: true, remediationMinutes: 120 }];
  let alerts = [{ id: 1, ip: '45.148.10.123', type: 'scan', vhost: 'access', ts: Date.now() }];
  B.setDeps({
    buildVhostRulesMap: () => ({}),
    analyzerApi: async (p) => p.startsWith('/api/rules/blocklist-config') ? { status: 200, data: { rules } }
      : p.startsWith('/api/alerts') ? { status: 200, data: { alerts } } : { status: 404, data: null },
  });
  writeYaml(['enable: true', 'sources:', '  - name: auto', '    type: analyzer'].join('\n'));
  const before = H.query({ ip: '45.148.10.123' }).total;
  const st = await B.refreshBlocklists({ manual: true, actor: 'test', analyzerOnly: true });
  check('alerte franchissant le seuil -> IP dans la liste ET entree added (regle + echeance)', () => {
    assert.strictEqual(st.totalUniqueIps, 1);
    assert.ok(fs.readFileSync(B.GEO_FILE, 'utf8').includes('45.148.10.123'));
    const e = H.query({ ip: '45.148.10.123' });
    assert.strictEqual(e.total, before + 1);
    assert.deepStrictEqual([e.entries[0].action, e.entries[0].rule], ['added', 'scan']);
    assert.ok(e.entries[0].until > Date.now() + 100 * 60_000, 'echeance ~ +120 min');
  });
  const beforeQuiet = events.queryEvents({ limit: 500 }).total;
  await B.refreshBlocklists({ manual: false, analyzerOnly: true });
  check('cycle frequent sans changement : aucune nouvelle entree d historique ni d evenement', () => {
    assert.strictEqual(H.query({ ip: '45.148.10.123' }).total, before + 1);
    assert.strictEqual(events.queryEvents({ limit: 500 }).total, beforeQuiet);
  });
  alerts = []; // l alerte sort de la fenetre ; la duree de 120 min doit etre tenue
  await B.refreshBlocklists({ manual: false, analyzerOnly: true });
  check('duree de remediation tenue : IP toujours bloquee, pas de removed premature', () => {
    assert.ok(fs.readFileSync(B.GEO_FILE, 'utf8').includes('45.148.10.123'));
    assert.strictEqual(H.query({ ip: '45.148.10.123', action: 'removed' }).total, 0);
  });
  // Force l expiration de l etat persiste.
  const stKey = 'blocklist_analyzer_remediation_state';
  const state = events.getState(stKey); state['45.148.10.123'].blockedUntil = Date.now() - 1000; events.setState(stKey, state);
  await B.refreshBlocklists({ manual: false, analyzerOnly: true });
  check('expiration -> IP retiree de la liste ET entree removed/expired', () => {
    assert.ok(!fs.readFileSync(B.GEO_FILE, 'utf8').includes('45.148.10.123'));
    const r = H.query({ ip: '45.148.10.123', action: 'removed' });
    assert.strictEqual(r.total, 1);
    assert.strictEqual(r.entries[0].reason, 'expired');
  });
  rules = [{ id: 2, key: 'scan', name: 'scan', threshold: 1, windowMinutes: 5, remediation: false, remediationMinutes: null }];
  alerts = [{ id: 2, ip: '198.51.100.7', type: 'scan', vhost: 'access', ts: Date.now() }];
  await B.refreshBlocklists({ manual: false, analyzerOnly: true });
  check('regle sans remediation : IP detected (observation seule), jamais dans la liste', () => {
    assert.ok(!fs.readFileSync(B.GEO_FILE, 'utf8').includes('198.51.100.7'));
    const r = H.query({ ip: '198.51.100.7' });
    assert.deepStrictEqual([r.total, r.entries[0].action, r.entries[0].reason], [1, 'detected', 'observation-only']);
  });

  console.log('\nanalyzerOnly — les autres sources ne sont pas retelechargees');
  let hits = 0;
  const http = require('http');
  const srv = http.createServer((q, r) => { hits++; r.writeHead(200); r.end('7.7.7.7\n'); });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  writeYaml(['enable: true', 'sources:', '  - name: ext', `    url: "http://127.0.0.1:${port}/l.txt"`, '    enable: true', '  - name: auto', '    type: analyzer'].join('\n'));
  await B.refreshBlocklists({ manual: true, actor: 'test' });
  const h1 = hits;
  await B.refreshBlocklists({ manual: false, analyzerOnly: true });
  check('cycle analyzerOnly : 0 telechargement, source ext toujours fusionnee depuis son cache', () => {
    assert.strictEqual(hits, h1);
    assert.ok(fs.readFileSync(B.GEO_FILE, 'utf8').includes('7.7.7.7'));
  });
  srv.close();

  console.log('\nreglages — analyzer_interval_cron');
  check('defaut : chaque minute', () => {
    assert.strictEqual(parseAndValidate('enable: true\n').settings.analyzerIntervalCron, '* * * * *');
  });
  check('valeur personnalisee reellement lue ; vide -> defaut', () => {
    assert.strictEqual(parseAndValidate('analyzer_interval_cron: "*/5 * * * *"\n').settings.analyzerIntervalCron, '*/5 * * * *');
    assert.strictEqual(parseAndValidate('analyzer_interval_cron: ""\n').settings.analyzerIntervalCron, '* * * * *');
  });
  check('interval_cron general inchange : defaut 6 h, et valeur explicite respectee', () => {
    assert.strictEqual(parseAndValidate('enable: true\n').settings.intervalCron, '0 */6 * * *');
    assert.strictEqual(parseAndValidate('interval_cron: "0 3 * * *"\n').settings.intervalCron, '0 3 * * *');
  });

  fs.rmSync(dir, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();

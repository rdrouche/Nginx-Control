'use strict';
/**
 * Verifie que le decoupage ne perd aucune route : l ensemble des chemins
 * declares dans server.js plus ceux enregistres par les features doit rester
 * identique a la reference prise avant le refactor.
 */
const assert=require('assert'), fs=require('fs'), path=require('path');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

const root = path.join(__dirname,'..');
const src  = fs.readFileSync(path.join(root,'server.js'),'utf8');

// Chemins encore dans la chaine historique
const inline = new Set();
for (const m of src.matchAll(/pathname\s*(?:===|\.startsWith\()\s*'([^']+)'/g)) inline.add(m[1]);

// Chemins enregistres par les features
const { Router } = require('../lib/http');
const router = new Router();
const featureDir = path.join(root,'features');
const features = fs.existsSync(featureDir)
  ? fs.readdirSync(featureDir).filter(f=>f.endsWith('.js'))
  : [];
for (const f of features) require(path.join(featureDir,f)).register(router);
const registered = new Set(router.list().map(r => r.split(' ')[1].replace(/\*$/,'')));

console.log('\nfeatures chargees : ' + (features.join(', ') || 'aucune'));

const all = new Set([...inline, ...registered]);
const expectedFile = path.join(root,'routes-before.txt');

check('la reference existe', ()=>assert.ok(fs.existsSync(expectedFile)));
check('aucune route perdue', ()=>{
  const expected = fs.readFileSync(expectedFile,'utf8').split('\n').map(s=>s.trim()).filter(Boolean);
  const missing  = expected.filter(r => !all.has(r));
  assert.deepStrictEqual(missing, [], `manquantes : ${missing.join(', ')}`);
});
check('aucune route inventee hors nouveautes declarees', ()=>{
  // La reference fige l etat d avant refactor. Les routes ajoutees depuis sont
  // listees ici explicitement : le test protege contre une route qui apparait
  // par accident, pas contre l evolution du produit.
  const added = new Set([
    '/api/analyzer/config', '/api/analyzer/status', '/api/analyzer/alerts',
    '/api/analyzer/alerts/ack', '/api/analyzer/baseline',
    '/api/analyzer/baseline/exclude', '/api/analyzer/container/start',
    '/api/analyzer/container/stop', '/api/analyzer/traffic/series',
    '/api/analyzer/traffic/countries', '/api/analyzer/traffic/vhosts',
    '/api/analyzer/exceptions', '/api/analyzer/exceptions/remove',
    '/api/analyzer/alerts/ack-all', '/api/analyzer/alerts/clear',
    '/api/analyzer/waf/events', '/api/analyzer/waf/top-rules',
    '/api/analyzer/waf/top-ips', '/api/analyzer/waf/series', '/api/analyzer/waf/clear',
    '/api/analyzer/waf/events/',
    '/api/nginx/restart-container', '/api/nginx/stats',
    '/api/crowdsec/machine-status', '/api/crowdsec/ban', '/api/crowdsec/unban',
    '/api/crowdsec/allowlists', '/api/crowdsec/allowlists/items',
    '/api/crowdsec/allowlists/items/remove', '/api/crowdsec/allowlists/check',
    '/api/metrics/rate', '/api/analyzer/traffic/recent', '/api/analyzer/traffic/bots',
    '/api/analyzer/traffic/bots/vhosts', '/api/analyzer/traffic/bots/countries',
    '/api/digest/latest', '/api/digest/history', '/api/digest/generate', '/api/digest/', '/api/digest/remove',
    '/api/geoipupdate/config', '/api/geoipupdate/status', '/api/geoipupdate/container/start',
    '/api/geoipupdate/container/stop', '/api/geoipupdate/update-now',
    '/api/error-pages/config', '/api/error-pages/status',
    '/api/error-pages/container/start', '/api/error-pages/container/stop',
    '/api/geoipupdate/image/update', '/api/certbot/image/update', '/api/error-pages/image/update',
    '/api/analyzer/image/update',
    '/api/analyzer/baseline/country', '/api/analyzer/baseline/country/exclude',
    '/api/certbot-dns/providers', '/api/certbot-dns/config', '/api/certbot-dns/status',
    '/api/certbot-dns/certs', '/api/certbot-dns/check-conflict',
    '/api/certbot-dns/container/start', '/api/certbot-dns/container/stop',
    '/api/certbot-dns/image/update', '/api/certbot-dns/issue', '/api/certbot-dns/revoke',
    '/api/config-editor/files', '/api/config-editor/file',
    '/api/configs/save', '/api/configs/create', '/api/configs/create-status',
    '/api/backends', '/api/backends/check',
    '/api/audit', '/api/audit/headers',
    '/api/monitor', '/api/monitor/history', '/api/monitor/check-now',
    '/api/system-info',
    '/api/notifications', '/api/notifications/', '/api/notifications/unread-count',
    '/api/notifications/read-all', '/api/notifications/clear-read', '/api/notifications/clear',
    '/api/analyzer/rules', '/api/analyzer/rules/toggle', '/api/analyzer/rules/custom',
    '/api/blocklists/status', '/api/blocklists/refresh',
    '/api/blocklists/check', '/api/blocklists/hit-stats',
    '/api/docker-autoconfig/status', '/api/docker-autoconfig/rescan',
    '/api/docker-autoconfig/approve', '/api/docker-autoconfig/reject',
    '/api/agents', '/api/agents/', '/api/agent/manifest', '/api/agent/enroll',
    '/api/system-info/generate-api-token', '/api/system-info/revoke-api-token',
    '/api/system-info/generate-webhook-secret', '/api/system-info/revoke-webhook-secret',
    '/api/docker-autoconfig/pause', '/api/docker-autoconfig/resume',
    '/api/docker-autoconfig/decisions/remove',
    '/api/menu-visibility',
    '/api/changelog',
    '/api/alerting/unread', '/api/alerting/history', '/api/alerting/refresh',
    '/assets/',
  ]);
  const expected = new Set(fs.readFileSync(expectedFile,'utf8').split('\n').map(s=>s.trim()).filter(Boolean));
  const extra = [...all].filter(r => !expected.has(r) && !added.has(r));
  assert.deepStrictEqual(extra, [], `inattendues : ${extra.join(', ')}`);
});
check('aucun doublon entre features et chaine historique', ()=>{
  const dup = [...registered].filter(r => inline.has(r));
  assert.deepStrictEqual(dup, [], `servies deux fois : ${dup.join(', ')}`);
});
check('chaque feature expose register()', ()=>{
  for (const f of features) {
    const mod = require(path.join(featureDir,f));
    assert.strictEqual(typeof mod.register, 'function', `${f} n expose pas register()`);
  }
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail?1:0);

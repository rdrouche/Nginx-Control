'use strict';
/**
 * Fix (audit report, Basse/Divers dashboard, "CrowdSec en mode LAPI seul :
 * /v1/alerts est appele avec la cle bouncer et /v1/watchers n'existe pas,
 * donc les alertes sont toujours vides ou en 500") : getCrowdSecMetrics()
 * (le chemin pris quand seul CROWDSEC_URL/CROWDSEC_API_KEY est configure,
 * sans CROWDSEC_PROMETHEUS_URL) est ici exerce contre un vrai petit serveur
 * HTTP local qui simule le LAPI, pour verifier que /v1/alerts est bien
 * appele avec le jeton machine (JAMAIS la cle bouncer) quand des identifiants
 * machine sont configures, et qu aucune requete n est faite du tout vers
 * /v1/watchers (qui n existe pas dans le vrai LAPI).
 */
const assert = require('assert');
const http = require('http');

let pass = 0, fail = 0;
const check = async (n, f) => {
  try { await f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; }
};

function freshCrowdsecModule() {
  for (const m of ['../lib/config', '../lib/crowdsec-cfg', '../lib/crowdsec-lapi', '../features/crowdsec']) {
    delete require.cache[require.resolve(m)];
  }
  return require('../features/crowdsec');
}

(async () => {

console.log('\ngetCrowdSecMetrics() en mode LAPI seul (bouncer + machine configures)');
await check('/v1/alerts est appele avec le jeton machine, jamais la cle bouncer ; /v1/watchers jamais appele', async () => {
  const requestsSeen = [];
  const srv = http.createServer((req, res) => {
    requestsSeen.push({ method: req.method, url: req.url, headers: req.headers });
    let body = ''; req.on('data', d => body += d);
    req.on('end', () => {
      if (req.method === 'POST' && req.url === '/v1/watchers/login') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ token: 'machine-jwt-abc', expire: new Date(Date.now() + 3600_000).toISOString() }));
      }
      if (req.method === 'GET' && req.url.startsWith('/v1/alerts')) {
        // Le vrai LAPI exige l authentification MACHINE (JWT) pour /v1/alerts,
        // pas la cle bouncer : ce faux serveur reproduit cette regle.
        if (req.headers.authorization !== 'Bearer machine-jwt-abc') {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ message: 'access forbidden for bouncer credentials on this route' }));
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify([{ id: 1, scenario: 'crowdsecurity/ssh-bf', source: { ip: '198.51.100.9' }, created_at: '2026-01-01T00:00:00Z', decisions: [{ scenario: 'crowdsecurity/ssh-bf' }] }]));
      }
      if (req.method === 'GET' && req.url.startsWith('/v1/decisions')) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify([{ id: 1, type: 'ban', value: '203.0.113.9', origin: 'crowdsec', scenario: 'crowdsecurity/ssh-bf' }]));
      }
      if (req.method === 'GET' && req.url.startsWith('/v1/watchers')) {
        // Ne devrait plus jamais etre appele — 404 si jamais c est le cas,
        // exactement comme le vrai LAPI.
        res.writeHead(404, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ message: 'not found' }));
      }
      res.writeHead(404); res.end();
    });
  });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;

  process.env.CROWDSEC_URL = `http://127.0.0.1:${port}`;
  process.env.CROWDSEC_API_KEY = 'bouncer-key-xyz';
  process.env.CROWDSEC_MACHINE_ID = 'nginx-dashboard';
  process.env.CROWDSEC_MACHINE_PASSWORD = 'secret';
  delete process.env.CROWDSEC_PROMETHEUS_URL;
  const CS = freshCrowdsecModule();

  try {
    const result = await CS.getCrowdSecMetrics();

    assert.strictEqual(result.alertsUnavailable, false, 'alertsUnavailable doit etre faux : des identifiants machine sont configures');
    assert.strictEqual(result.summary.totalAlerts, 1, `/v1/alerts aurait du renvoyer 1 alerte, alertsUnavailable=${result.alertsUnavailable}`);
    assert.strictEqual(result.recentAlerts.length, 1);
    assert.strictEqual(result.recentAlerts[0].source_ip, '198.51.100.9');

    const watchersCalls = requestsSeen.filter(r => r.url.startsWith('/v1/watchers') && r.method === 'GET');
    assert.strictEqual(watchersCalls.length, 0, 'GET /v1/watchers ne doit plus jamais etre appele (endpoint inexistant dans le vrai LAPI)');

    const alertsCalls = requestsSeen.filter(r => r.url.startsWith('/v1/alerts'));
    assert.ok(alertsCalls.length >= 1, '/v1/alerts aurait du etre appele');
    assert.ok(alertsCalls.every(c => c.headers.authorization === 'Bearer machine-jwt-abc'),
      '/v1/alerts doit toujours etre appele avec le jeton MACHINE, jamais X-Api-Key (bouncer)');
    assert.ok(alertsCalls.every(c => !c.headers['x-api-key']),
      '/v1/alerts ne doit pas porter la cle bouncer du tout');
  } finally {
    srv.close();
  }
});

console.log('\ngetCrowdSecMetrics() sans identifiants machine (bouncer seul)');
await check('/v1/alerts n est jamais tente sans identifiants machine ; alertsUnavailable=true', async () => {
  const requestsSeen = [];
  const srv = http.createServer((req, res) => {
    requestsSeen.push({ method: req.method, url: req.url });
    if (req.method === 'GET' && req.url.startsWith('/v1/decisions')) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify([]));
    }
    // Toute autre route (alerts, watchers/login) : le bouncer seul ne doit
    // meme pas essayer de les appeler.
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ message: 'should not be called' }));
  });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;

  process.env.CROWDSEC_URL = `http://127.0.0.1:${port}`;
  process.env.CROWDSEC_API_KEY = 'bouncer-key-xyz';
  delete process.env.CROWDSEC_MACHINE_ID;
  delete process.env.CROWDSEC_MACHINE_PASSWORD;
  delete process.env.CROWDSEC_PROMETHEUS_URL;
  const CS = freshCrowdsecModule();

  try {
    const result = await CS.getCrowdSecMetrics();
    assert.strictEqual(result.alertsUnavailable, true);
    assert.strictEqual(result.summary.totalAlerts, 0);
    assert.strictEqual(result.recentAlerts.length, 0);
    const alertsOrLoginCalls = requestsSeen.filter(r => r.url.startsWith('/v1/alerts') || r.url.startsWith('/v1/watchers'));
    assert.strictEqual(alertsOrLoginCalls.length, 0, 'ni /v1/alerts ni /v1/watchers/login ne doivent etre appeles sans identifiants machine');
  } finally {
    srv.close();
    delete process.env.CROWDSEC_MACHINE_ID;
    delete process.env.CROWDSEC_MACHINE_PASSWORD;
  }
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
})();

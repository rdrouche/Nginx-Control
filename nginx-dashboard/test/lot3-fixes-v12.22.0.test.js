'use strict';
/**
 * Lot 3 (v12.22.0) de l'audit rapport-bugs-v12.21.0.md — couverture des
 * correctifs cote dashboard qui n'ont pas deja leur propre test dedie
 * ailleurs (AGT-02/AGT-03/AGT-04 primaire ont deja les leurs dans
 * test/agent-tunnel.test.js et test/agents-store.test.js) :
 *
 *   - AGT-04 (partie 1) : rejet des adresses IP litterales comme serverName.
 *   - AGT-04 (partie 2) : le scan de conflit de server_name couvre desormais
 *     DIR_CONF en plus de DIR_SITES.
 *   - AGT-06 : enrolement — limite de debit par IP, plafond de "pending",
 *     expiration des entrees pending trop anciennes.
 *
 * Meme isolation CONFIG_DIR/DIR_SITES/DIR_CONF/initEventsDb() que les autres
 * fichiers de test de ce module.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { Readable } = require('stream');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lot3-fixes-'));
process.env.USERS_FILE = path.join(tmp, 'config', 'users.yml');
process.env.CONFIG_DIR = path.join(tmp, 'config');
process.env.DIR_SITES = path.join(tmp, 'sites');
process.env.DIR_CONF = path.join(tmp, 'conf');
for (const d of [process.env.CONFIG_DIR, process.env.DIR_SITES, process.env.DIR_CONF]) fs.mkdirSync(d, { recursive: true });
fs.writeFileSync(process.env.USERS_FILE, 'users: []\n');
fs.writeFileSync(path.join(process.env.CONFIG_DIR, 'agents.yml'), 'enable: true\n');

const events = require('../lib/events');
events.initEventsDb();

const { validateManifestVhost } = require('../lib/agent-manifest');
const agentsFeature = require('../features/agents');
const agentsStore = require('../lib/agents-store');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

function fakeRes() {
  const headers = {};
  return {
    headers, status: null, body: null,
    setHeader(k, v) { headers[k] = v; },
    writeHead(status, hdrs) { this.status = status; Object.assign(headers, hdrs || {}); },
    end(body) { this.body = body; },
  };
}
function fakeReqWithJSON(obj) {
  return Readable.from([Buffer.from(JSON.stringify(obj))]);
}
function resJSON(res) { try { return JSON.parse(res.body); } catch { return res.body; } }

console.log('\nAGT-04 (partie 1) : une adresse IP litterale n est pas un serverName valide');
check('IPv4 seule -> rejetee', () => {
  const r = validateManifestVhost({ serverName: '192.168.1.10', locations: [{ path: '/', target: 'http://127.0.0.1:80' }] });
  assert.strictEqual(r.valid, false);
  assert.ok(r.errors.some(e => /litterale/.test(e)), r.errors.join('; '));
});
check('un octet hors plage (999.999.999.999) n est pas une IPv4 valide -> pas reconnue par le garde-fou, mais reste sans consequence (jamais une IP routable)', () => {
  const r = validateManifestVhost({ serverName: '999.999.999.999', locations: [{ path: '/', target: 'http://127.0.0.1:80' }] });
  // isIPv4Literal() n identifie a dessein que des octets 0-255 : ce label
  // n est ni un hostname "reel" utile ni une adresse IP exploitable pour
  // le scenario AGT-04 (elle ne correspond a aucune interface reseau
  // existante), donc le laisser passer la validation de forme ne
  // reintroduit pas le probleme corrige.
  assert.strictEqual(r.valid, true, (r.errors || []).join('; '));
});
check('wildcard sur une IP litterale (*.192.168.1.10) -> egalement rejetee', () => {
  const r = validateManifestVhost({ serverName: '*.192.168.1.10', locations: [{ path: '/', target: 'http://127.0.0.1:80' }] });
  assert.strictEqual(r.valid, false);
});
check('un vrai nom d hote (meme avec des chiffres) reste accepte', () => {
  const r = validateManifestVhost({ serverName: 'app2.example.com', locations: [{ path: '/', target: 'http://127.0.0.1:80' }] });
  assert.strictEqual(r.valid, true, (r.errors || []).join('; '));
});

console.log('\nAGT-04 (partie 2) : le scan de conflit couvre DIR_CONF en plus de DIR_SITES');
(async () => {
  fs.writeFileSync(path.join(process.env.DIR_CONF, 'manual-vhost.conf'),
    'server {\n    listen 80;\n    server_name claimed-in-confd.example.com;\n}\n');
  const enrolled = agentsStore.enroll({ hostnameProposed: 'vps-conf', fingerprint: '' });
  const { rawToken } = agentsStore.approve(enrolled.id, 'test');
  void rawToken;
  const result = await agentsFeature.applyManifestForAgent(enrolled, {
    protocolVersion: 1,
    vhosts: [{ serverName: 'claimed-in-confd.example.com', locations: [{ path: '/', target: 'http://127.0.0.1:81' }] }],
  });
  check('un serverName deja pris dans DIR_CONF (conf.d) est refuse, pas seulement DIR_SITES', () => {
    assert.strictEqual(result.vhosts[0].ok, false);
    assert.ok(/conflit de server_name/.test(result.vhosts[0].errors[0]), JSON.stringify(result.vhosts[0]));
  });

  console.log('\nAGT-06 : enrolement — limite de debit par IP');
  {
    const ip = '203.0.113.50';
    let last429 = null;
    for (let i = 0; i < 15; i++) {
      const res = fakeRes();
      await agentsFeature.handleEnroll(fakeReqWithJSON({ hostname: `bulk-host-${i}` }), res, ip);
      if (res.status === 429) { last429 = i; break; }
    }
    check('au-dela de ENROLL_MAX_PER_IP_PER_HOUR tentatives depuis la meme IP -> 429', () => {
      assert.ok(last429 !== null, '15 enrolements consecutifs depuis la meme IP n ont jamais declenche de 429');
    });
  }
  {
    const otherIp = '203.0.113.99';
    const res = fakeRes();
    await agentsFeature.handleEnroll(fakeReqWithJSON({ hostname: 'depuis-une-autre-ip' }), res, otherIp);
    check('une IP DIFFERENTE n est pas affectee par la limite de la precedente (bucket par IP)', () => {
      assert.strictEqual(res.status, 200, JSON.stringify(resJSON(res)));
    });
  }

  console.log('\nAGT-06 : enrolement — plafond du nombre de "pending"');
  {
    events.setState(agentsStore.STATE_KEY, { agents: {} }); // table rase
    for (let i = 0; i < 50; i++) agentsStore.enroll({ hostnameProposed: `pending-${i}`, fingerprint: '' });
    const res = fakeRes();
    await agentsFeature.handleEnroll(fakeReqWithJSON({ hostname: 'de-trop' }), res, '198.51.100.1');
    check('MAX_PENDING_AGENTS deja atteint -> nouvel enrolement refuse (429)', () => {
      assert.strictEqual(res.status, 429, JSON.stringify(resJSON(res)));
    });
  }

  console.log('\nAGT-06 : expiration automatique des "pending" trop anciens');
  {
    events.setState(agentsStore.STATE_KEY, { agents: {} });
    const stale = agentsStore.enroll({ hostnameProposed: 'stale-agent', fingerprint: '' });
    // Recule artificiellement sa date de creation de 31 jours (> PENDING_AGENT_TTL_MS).
    const state = agentsStore.loadState();
    state.agents[stale.id].createdAt = Date.now() - 31 * 24 * 60 * 60 * 1000;
    agentsStore.saveState(state);

    const res = fakeRes();
    await agentsFeature.handleEnroll(fakeReqWithJSON({ hostname: 'fresh-agent' }), res, '198.51.100.2');
    check('un nouvel enrolement declenche l expiration silencieuse des pending perimes', () => {
      const refreshed = agentsStore.getAgent(stale.id);
      assert.strictEqual(refreshed.status, 'rejected');
      assert.strictEqual(refreshed.decidedBy, 'system:expired');
    });
    check('le nouvel enrolement lui-meme reussit normalement (200)', () => {
      assert.strictEqual(res.status, 200, JSON.stringify(resJSON(res)));
    });
  }

  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();

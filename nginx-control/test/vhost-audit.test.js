'use strict';
/**
 * lib/vhost-audit.js en isolation — pas de reseau, pas de fichiers : on
 * construit directement les objets { ssl, redirectsToHttps, locations }
 * que produirait lib/vhost-targets.js et on verifie les findings.
 */
const assert = require('assert');
let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const { auditServerBlock, auditVhosts, auditHeaderProbe } = require('../lib/vhost-audit');

console.log('\nauditServerBlock() — vhost HTTP sans SSL');
check('http sans redirection -> warning http-no-redirect', () => {
  const findings = auditServerBlock({ ssl: false, redirectsToHttps: false, locations: [] });
  assert.ok(findings.some(f => f.code === 'http-no-redirect' && f.level === 'warning'));
});
check('http qui redirige vers https -> info, pas warning', () => {
  const findings = auditServerBlock({ ssl: false, redirectsToHttps: true, locations: [] });
  assert.ok(findings.some(f => f.code === 'http-redirect' && f.level === 'info'));
  assert.ok(!findings.some(f => f.code === 'http-no-redirect'));
});

console.log('\nauditServerBlock() — vhost HTTPS, posture du backend');
check('https vhost + backend http -> decharge SSL (info), mentionne proxy_ssl_verify', () => {
  const findings = auditServerBlock({ ssl: true, redirectsToHttps: false, locations: [
    { path: '/', kind: 'direct', targets: [{ scheme: 'http', host: '10.0.0.1', port: 8080 }], sslVerifyOff: false },
  ] });
  const f = findings.find(f => f.code === 'ssl-offload');
  assert.ok(f && f.level === 'info');
  assert.ok(/proxy_ssl_verify off/.test(f.message));
});
check('https vhost + backend https -> full-ssl (ok)', () => {
  const findings = auditServerBlock({ ssl: true, redirectsToHttps: false, locations: [
    { path: '/', kind: 'direct', targets: [{ scheme: 'https', host: '10.0.0.1', port: 443 }], sslVerifyOff: false },
  ] });
  const f = findings.find(f => f.code === 'full-ssl');
  assert.ok(f && f.level === 'ok');
  assert.ok(!/proxy_ssl_verify/.test(f.message));
});
check('https vhost + backend https + proxy_ssl_verify off -> full-ssl mentionne le certificat auto-signe', () => {
  const findings = auditServerBlock({ ssl: true, redirectsToHttps: false, locations: [
    { path: '/', kind: 'direct', targets: [{ scheme: 'https', host: '10.0.0.1', port: 443 }], sslVerifyOff: true },
  ] });
  const f = findings.find(f => f.code === 'full-ssl');
  assert.ok(f && /auto-signe/.test(f.message));
});
check('http vhost + backend https -> info http-vhost-https-backend', () => {
  const findings = auditServerBlock({ ssl: false, redirectsToHttps: false, locations: [
    { path: '/', kind: 'direct', targets: [{ scheme: 'https', host: '10.0.0.1', port: 443 }], sslVerifyOff: false },
  ] });
  assert.ok(findings.some(f => f.code === 'http-vhost-https-backend' && f.level === 'info'));
});

console.log('\nauditServerBlock() — cible non resolue');
check('location kind unresolved -> warning, pas de posture SSL calculee dessus', () => {
  const findings = auditServerBlock({ ssl: true, redirectsToHttps: false, locations: [
    { path: '/api', kind: 'unresolved', targets: [], sslVerifyOff: false },
  ] });
  assert.ok(findings.some(f => f.code === 'unresolved-target' && f.level === 'warning'));
  assert.ok(!findings.some(f => f.code === 'ssl-offload' || f.code === 'full-ssl'));
});

console.log('\nauditVhosts() — decore chaque server block sans toucher au reste');
check('chaque server block recoit bien un tableau findings, la structure d origine est preservee', () => {
  const vhosts = [{
    file: '/x/a.conf', name: 'a.conf', enabled: true,
    serverBlocks: [{ ssl: false, redirectsToHttps: false, serverNames: ['a.example.com'], locations: [] }],
  }];
  const audited = auditVhosts(vhosts);
  assert.strictEqual(audited[0].name, 'a.conf');
  assert.strictEqual(audited[0].serverBlocks[0].serverNames[0], 'a.example.com');
  assert.ok(Array.isArray(audited[0].serverBlocks[0].findings));
  assert.ok(audited[0].serverBlocks[0].findings.length > 0);
});

console.log('\nauditHeaderProbe() — proxy injoignable');
check('proxy inaccessible -> seul le finding proxy-unreachable, rien d autre (pas de faux "absent")', () => {
  const findings = auditHeaderProbe({ ssl: true, proxyHeaders: {}, backendHeaders: {}, proxyOk: false, backendOk: false });
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].code, 'proxy-unreachable');
  assert.strictEqual(findings[0].level, 'warning');
});

console.log('\nauditHeaderProbe() — HSTS (uniquement pertinent en HTTPS)');
check('https sans HSTS -> warning', () => {
  const findings = auditHeaderProbe({ ssl: true, proxyHeaders: {}, backendHeaders: {}, proxyOk: true, backendOk: false });
  assert.ok(findings.some(f => f.code === 'missing-hsts' && f.level === 'warning'));
});
check('https avec HSTS court -> info, mentionne la duree', () => {
  const findings = auditHeaderProbe({ ssl: true, proxyHeaders: { 'strict-transport-security': 'max-age=3600' }, backendHeaders: {}, proxyOk: true, backendOk: false });
  const f = findings.find(f => f.code === 'hsts-short');
  assert.ok(f && /3600/.test(f.message));
});
check('https avec HSTS long -> ok', () => {
  const findings = auditHeaderProbe({ ssl: true, proxyHeaders: { 'strict-transport-security': 'max-age=31536000; includeSubDomains' }, backendHeaders: {}, proxyOk: true, backendOk: false });
  assert.ok(findings.some(f => f.code === 'hsts-ok' && f.level === 'ok'));
});
check('http (pas ssl) -> aucun finding HSTS, pertinent seulement en https', () => {
  const findings = auditHeaderProbe({ ssl: false, proxyHeaders: {}, backendHeaders: {}, proxyOk: true, backendOk: false });
  assert.ok(!findings.some(f => f.code.startsWith('hsts') || f.code === 'missing-hsts'));
});

console.log('\nauditHeaderProbe() — en-tetes qui fuitent de l information');
check('Server avec un numero de version -> warning server-version-leak', () => {
  const findings = auditHeaderProbe({ ssl: false, proxyHeaders: { server: 'nginx/1.25.3' }, backendHeaders: {}, proxyOk: true, backendOk: false });
  assert.ok(findings.some(f => f.code === 'server-version-leak' && f.level === 'warning'));
});
check('Server generique sans chiffre -> ok, pas de warning', () => {
  const findings = auditHeaderProbe({ ssl: false, proxyHeaders: { server: 'nginx' }, backendHeaders: {}, proxyOk: true, backendOk: false });
  assert.ok(findings.some(f => f.code === 'server-generic' && f.level === 'ok'));
  assert.ok(!findings.some(f => f.code === 'server-version-leak'));
});
check('X-Powered-By present -> warning', () => {
  const findings = auditHeaderProbe({ ssl: false, proxyHeaders: { 'x-powered-by': 'Express' }, backendHeaders: {}, proxyOk: true, backendOk: false });
  assert.ok(findings.some(f => f.code === 'x-powered-by-leak' && /Express/.test(f.message)));
});
check('meme Server (avec version) cote proxy et cote backend -> warning backend-header-passthrough', () => {
  const findings = auditHeaderProbe({
    ssl: false,
    proxyHeaders: { server: 'Apache/2.4.41' }, backendHeaders: { server: 'Apache/2.4.41' },
    proxyOk: true, backendOk: true,
  });
  assert.ok(findings.some(f => f.code === 'backend-header-passthrough'));
});
check('Server different entre proxy et backend -> pas de passthrough signale', () => {
  const findings = auditHeaderProbe({
    ssl: false,
    proxyHeaders: { server: 'nginx' }, backendHeaders: { server: 'Apache/2.4.41' },
    proxyOk: true, backendOk: true,
  });
  assert.ok(!findings.some(f => f.code === 'backend-header-passthrough'));
});

console.log('\nauditHeaderProbe() — en-tetes de securite manquants (informationnel)');
check('aucun des quatre en-tetes courants -> quatre findings info', () => {
  const findings = auditHeaderProbe({ ssl: false, proxyHeaders: {}, backendHeaders: {}, proxyOk: true, backendOk: false });
  for (const code of ['missing-nosniff', 'missing-frame-options', 'missing-referrer-policy', 'missing-csp']) {
    assert.ok(findings.some(f => f.code === code && f.level === 'info'), `manque ${code}`);
  }
});
check('tous presents -> aucun des quatre findings "missing-*"', () => {
  const findings = auditHeaderProbe({
    ssl: false,
    proxyHeaders: {
      'x-content-type-options': 'nosniff', 'x-frame-options': 'SAMEORIGIN',
      'referrer-policy': 'strict-origin-when-cross-origin', 'content-security-policy': "default-src 'self'",
    },
    backendHeaders: {}, proxyOk: true, backendOk: false,
  });
  for (const code of ['missing-nosniff', 'missing-frame-options', 'missing-referrer-policy', 'missing-csp']) {
    assert.ok(!findings.some(f => f.code === code));
  }
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);

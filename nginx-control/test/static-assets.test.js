'use strict';
/**
 * GET /assets/* (server.js) — premier pas du decoupage de public/index.html
 * (voir CHANGELOG.md) : le CSS vit desormais dans public/assets/style.css,
 * servi par une route statique generique. Contre un vrai serveur, comme les
 * autres *-routes.test.js. Point central a verifier : la route ne doit
 * jamais servir un fichier hors de public/assets/ (tentative de traversee),
 * ni un fichier dont l extension n est pas explicitement autorisee.
 */
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const root = path.join(__dirname, '..');
const appDir = fs.mkdtempSync(path.join(os.tmpdir(), 'staticassets-app-'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'staticassets-data-'));
fs.cpSync(path.join(root, 'lib'), path.join(appDir, 'lib'), { recursive: true });
fs.cpSync(path.join(root, 'features'), path.join(appDir, 'features'), { recursive: true });
fs.cpSync(path.join(root, 'public'), path.join(appDir, 'public'), { recursive: true });
fs.copyFileSync(path.join(root, 'server.js'), path.join(appDir, 'server.js'));

// Un fichier "secret" hors de public/assets/, pour verifier qu aucune
// traversee ne peut l atteindre depuis la route.
fs.writeFileSync(path.join(appDir, 'server.js.secret-marker'), 'should never be served');
// Un fichier dans public/ mais PAS dans public/assets/ — meme risque, chemin plus court.
fs.writeFileSync(path.join(appDir, 'public', 'outside-assets.css'), 'body{color:red}');
// Une extension non autorisee a l interieur meme de public/assets/.
fs.writeFileSync(path.join(appDir, 'public', 'assets', 'notes.txt'), 'not css or js');

for (const d of ['config', 'sites', 'conf', 'snippets', 'streams', 'logs', 'backups', 'goaccess', 'gitwork', 'ssl', 'certs', 'cache', 'geoip'])
  fs.mkdirSync(path.join(tmp, d), { recursive: true });
fs.writeFileSync(path.join(tmp, 'config', 'users.yml'),
  'users:\n  - username: admin\n    password: admin123\n    role: admin\n    name: A\n    enabled: true\n');

const PORT = 3914;
const env = { ...process.env, PORT: String(PORT),
  USERS_FILE: path.join(tmp, 'config', 'users.yml'), CONFIG_DIR: path.join(tmp, 'config'),
  DIR_SITES: path.join(tmp, 'sites'), DIR_CONF: path.join(tmp, 'conf'),
  DIR_SNIPPETS: path.join(tmp, 'snippets'), DIR_STREAMS: path.join(tmp, 'streams'),
  DIR_LOGS: path.join(tmp, 'logs'), DIR_BACKUPS: path.join(tmp, 'backups'),
  DIR_GOACCESS: path.join(tmp, 'goaccess'), DIR_GIT_WORK: path.join(tmp, 'gitwork'),
  DIR_SSL: path.join(tmp, 'ssl'), DIR_CERTS: path.join(tmp, 'certs'),
  DIR_CACHE: path.join(tmp, 'cache'), DIR_GEOIP: path.join(tmp, 'geoip') };

function get(p) {
  return new Promise(resolve => {
    const r = http.get({ host: '127.0.0.1', port: PORT, path: p, timeout: 5000 }, res => {
      let b = ''; res.on('data', d => b += d);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: b }));
    });
    r.on('error', e => resolve({ status: 0, body: e.message }));
    r.on('timeout', () => { r.destroy(); resolve({ status: 0, body: 'timeout' }); });
  });
}

(async () => {
  const srv = spawn('node', ['server.js'], { env, cwd: appDir, stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise(r => setTimeout(r, 2000));

  console.log('\nGET /assets/* — assets statiques, contre un vrai serveur');

  const css = await get('/assets/style.css');
  check('style.css -> 200, sans authentification, Content-Type text/css', () => {
    assert.strictEqual(css.status, 200);
    assert.ok(/text\/css/.test(css.headers['content-type']));
    assert.ok(css.body.length > 1000);
  });

  const cfgEditorJs = await get('/assets/js/config-editor.js');
  check('js/config-editor.js -> 200, Content-Type JS, contient bien ses fonctions', () => {
    assert.strictEqual(cfgEditorJs.status, 200);
    assert.ok(/javascript/.test(cfgEditorJs.headers['content-type']));
    assert.ok(cfgEditorJs.body.includes('function initConfigEditor'));
    assert.ok(cfgEditorJs.body.includes('function cfgEditorSave'));
  });

  const notifySchedJs = await get('/assets/js/notify-scheduler.js');
  check('js/notify-scheduler.js -> 200, Content-Type JS, contient les fonctions des deux pages', () => {
    assert.strictEqual(notifySchedJs.status, 200);
    assert.ok(/javascript/.test(notifySchedJs.headers['content-type']));
    assert.ok(notifySchedJs.body.includes('function notifySave'));
    assert.ok(notifySchedJs.body.includes('function schedSave'));
    assert.ok(notifySchedJs.body.includes('function schedLoadNotif'));
  });

  const notifyFormJs = await get('/assets/js/notify-form.js');
  check('js/notify-form.js -> 200, Content-Type JS, contient les formulaires SMTP/alertes', () => {
    assert.strictEqual(notifyFormJs.status, 200);
    assert.ok(/javascript/.test(notifyFormJs.headers['content-type']));
    assert.ok(notifyFormJs.body.includes('function nfSaveSmtp'));
    assert.ok(notifyFormJs.body.includes('function nfSaveRules'));
    assert.ok(notifyFormJs.body.includes('function notifyTestSmtp'));
  });

  const schedJs = await get('/assets/js/scheduler.js');
  check('js/scheduler.js -> 200, Content-Type JS, contient le formulaire de taches', () => {
    assert.strictEqual(schedJs.status, 200);
    assert.ok(/javascript/.test(schedJs.headers['content-type']));
    assert.ok(schedJs.body.includes('function initScheduler'));
    assert.ok(schedJs.body.includes('function schedSaveTask'));
    assert.ok(schedJs.body.includes('function schedImportFile'));
  });

  const csJs = await get('/assets/js/certsync.js');
  check('js/certsync.js -> 200, Content-Type JS, contient la synchro de certificats', () => {
    assert.strictEqual(csJs.status, 200);
    assert.ok(/javascript/.test(csJs.headers['content-type']));
    assert.ok(csJs.body.includes('function csLoad'));
    assert.ok(csJs.body.includes('function csRemoteSave'));
    assert.ok(csJs.body.includes('function csTokenCreate'));
  });

  const rbJs = await get('/assets/js/rules-builder.js');
  check('js/rules-builder.js -> 200, Content-Type JS, contient le formulaire de regles', () => {
    assert.strictEqual(rbJs.status, 200);
    assert.ok(/javascript/.test(rbJs.headers['content-type']));
    assert.ok(rbJs.body.includes('function rbSetData'));
    assert.ok(rbJs.body.includes('function rbSave'));
    assert.ok(rbJs.body.includes('function rulesTab'));
  });

  const campJs = await get('/assets/js/analyzer-campaign.js');
  check('js/analyzer-campaign.js -> 200, Content-Type JS, contient le panneau de campagne', () => {
    assert.strictEqual(campJs.status, 200);
    assert.ok(/javascript/.test(campJs.headers['content-type']));
    assert.ok(campJs.body.includes('function anCampaignPanel'));
    assert.ok(campJs.body.includes('function anCampaignRaw'));
  });

  const analyzerJs = await get('/assets/js/analyzer.js');
  check('js/analyzer.js -> 200, Content-Type JS, contient bien ses fonctions', () => {
    assert.strictEqual(analyzerJs.status, 200);
    assert.ok(/javascript/.test(analyzerJs.headers['content-type']));
    assert.ok(analyzerJs.body.includes('function anLoad'));
    assert.ok(analyzerJs.body.includes('function anLoadExceptions'));
    assert.ok(analyzerJs.body.includes('function anAlertCard'));
  });

  const wafJs = await get('/assets/js/waf.js');
  check('js/waf.js -> 200, Content-Type JS, contient bien ses fonctions', () => {
    assert.strictEqual(wafJs.status, 200);
    assert.ok(/javascript/.test(wafJs.headers['content-type']));
    assert.ok(wafJs.body.includes('function wafLoad'));
    assert.ok(wafJs.body.includes('function wafOpenDetail'));
    assert.ok(wafJs.body.includes('function wafClearEvents'));
  });

  const sysInfoJs = await get('/assets/js/system-info.js');
  check('js/system-info.js -> 200, Content-Type JS, contient bien ses fonctions', () => {
    assert.strictEqual(sysInfoJs.status, 200);
    assert.ok(/javascript/.test(sysInfoJs.headers['content-type']));
    assert.ok(sysInfoJs.body.includes('function loadSystemInfo'));
    assert.ok(sysInfoJs.body.includes('function sysinfoValueText'));
  });

  const geomapJs = await get('/assets/js/geomap.js');
  check('js/geomap.js -> 200, Content-Type JS, contient bien ses fonctions', () => {
    assert.strictEqual(geomapJs.status, 200);
    assert.ok(/javascript/.test(geomapJs.headers['content-type']));
    assert.ok(geomapJs.body.includes('function loadGeomap'));
    assert.ok(geomapJs.body.includes('function gmPoll'));
    assert.ok(geomapJs.body.includes('function gmPulse'));
  });

  const gitJs = await get('/assets/js/git.js');
  check('js/git.js -> 200, Content-Type JS, contient bien ses fonctions', () => {
    assert.strictEqual(gitJs.status, 200);
    assert.ok(/javascript/.test(gitJs.headers['content-type']));
    assert.ok(gitJs.body.includes('function loadDeployPage'));
    assert.ok(gitJs.body.includes('function gitDeploy'));
    assert.ok(gitJs.body.includes('function gitTestConn'));
  });

  const digestJs = await get('/assets/js/digest.js');
  check('js/digest.js -> 200, Content-Type JS, contient bien ses fonctions', () => {
    assert.strictEqual(digestJs.status, 200);
    assert.ok(/javascript/.test(digestJs.headers['content-type']));
    assert.ok(digestJs.body.includes('function loadDigest'));
    assert.ok(digestJs.body.includes('function digRender'));
    assert.ok(digestJs.body.includes('function digDeleteSelected'));
  });

  const godnsJs = await get('/assets/js/godns.js');
  check('js/godns.js -> 200, Content-Type JS, contient bien ses fonctions', () => {
    assert.strictEqual(godnsJs.status, 200);
    assert.ok(/javascript/.test(godnsJs.headers['content-type']));
    assert.ok(godnsJs.body.includes('function godnsLoad'));
    assert.ok(godnsJs.body.includes('function godnsRefreshInfo'));
    assert.ok(godnsJs.body.includes('function godnsSaveConfig'));
  });

  const geoipJs = await get('/assets/js/geoipupdate.js');
  check('js/geoipupdate.js -> 200, Content-Type JS, contient bien ses fonctions', () => {
    assert.strictEqual(geoipJs.status, 200);
    assert.ok(/javascript/.test(geoipJs.headers['content-type']));
    assert.ok(geoipJs.body.includes('function geoipupdateLoad'));
    assert.ok(geoipJs.body.includes('function geoipupdateRefreshStatus'));
    assert.ok(geoipJs.body.includes('function geoipupdateImageUpdate'));
  });

  const errorPagesJs = await get('/assets/js/error-pages.js');
  check('js/error-pages.js -> 200, Content-Type JS, contient bien ses fonctions', () => {
    assert.strictEqual(errorPagesJs.status, 200);
    assert.ok(/javascript/.test(errorPagesJs.headers['content-type']));
    assert.ok(errorPagesJs.body.includes('function errorPagesLoad'));
    assert.ok(errorPagesJs.body.includes('function errorPagesRefreshStatus'));
    assert.ok(errorPagesJs.body.includes('function errorPagesImageUpdate'));
  });

  const challengeJs = await get('/assets/js/challenge.js');
  check('js/challenge.js -> 200, Content-Type JS, contient bien ses fonctions', () => {
    assert.strictEqual(challengeJs.status, 200);
    assert.ok(/javascript/.test(challengeJs.headers['content-type']));
    assert.ok(challengeJs.body.includes('function challengeLoad'));
    assert.ok(challengeJs.body.includes('function challengeStart'));
    assert.ok(challengeJs.body.includes('function challengeApply'));
    assert.ok(challengeJs.body.includes('function challengeImageUpdate'));
  });

  const ctJs = await get('/assets/js/containers.js');
  check('js/containers.js -> 200, contient ses fonctions', () => {
    assert.strictEqual(ctJs.status, 200);
    assert.ok(/javascript/.test(ctJs.headers['content-type']));
    assert.ok(ctJs.body.includes('function containersLoad'));
    assert.ok(ctJs.body.includes('function ctLogsOpen'));
  });

  const bvJs = await get('/assets/js/baseline-view.js');
  check('js/baseline-view.js -> 200, contient ses fonctions', () => {
    assert.strictEqual(bvJs.status, 200);
    assert.ok(bvJs.body.includes('function baselineViewOpen'));
    assert.ok(bvJs.body.includes('function baselineViewProfile'));
  });

  const gsJs = await get('/assets/js/global-search.js');
  check('js/global-search.js -> 200, Content-Type JS, contient bien ses fonctions', () => {
    assert.strictEqual(gsJs.status, 200);
    assert.ok(/javascript/.test(gsJs.headers['content-type']));
    assert.ok(gsJs.body.includes('function gsSearch'));
    assert.ok(gsJs.body.includes('function gsGo'));
  });

  const blocklistsJs = await get('/assets/js/blocklists.js');
  check('js/blocklists.js -> 200, Content-Type JS, contient bien ses fonctions', () => {
    assert.strictEqual(blocklistsJs.status, 200);
    assert.ok(/javascript/.test(blocklistsJs.headers['content-type']));
    assert.ok(blocklistsJs.body.includes('function loadBlocklistsPage'));
    assert.ok(blocklistsJs.body.includes('function blocklistsRefreshNow'));
  });

  const crowdsecJs = await get('/assets/js/crowdsec.js');
  check('js/crowdsec.js -> 200, Content-Type JS, contient bien ses fonctions', () => {
    assert.strictEqual(crowdsecJs.status, 200);
    assert.ok(/javascript/.test(crowdsecJs.headers['content-type']));
    assert.ok(crowdsecJs.body.includes('function loadCrowdSec'));
    assert.ok(crowdsecJs.body.includes('function csBanIp'));
    assert.ok(crowdsecJs.body.includes('function csLoadAllowlists'));
  });

  const vhgJs = await get('/assets/js/vhost-generator.js');
  check('js/vhost-generator.js -> 200, Content-Type JS, contient bien ses fonctions', () => {
    assert.strictEqual(vhgJs.status, 200);
    assert.ok(/javascript/.test(vhgJs.headers['content-type']));
    assert.ok(vhgJs.body.includes('function initVhostGen'));
    assert.ok(vhgJs.body.includes('function vhgPreview'));
    assert.ok(vhgJs.body.includes('function copyVhgOutput'));
  });

  const apiDocJs = await get('/assets/js/api-doc.js');
  check('js/api-doc.js -> 200, Content-Type JS, contient bien ses fonctions', () => {
    assert.strictEqual(apiDocJs.status, 200);
    assert.ok(/javascript/.test(apiDocJs.headers['content-type']));
    assert.ok(apiDocJs.body.includes('function renderApiDoc'));
    assert.ok(apiDocJs.body.includes('function tryEP'));
  });

  const en = await get('/assets/lang/en.json');
  const fr = await get('/assets/lang/fr.json');
  check('lang/en.json et lang/fr.json -> 200, JSON valide, memes cles des deux cotes', () => {
    assert.strictEqual(en.status, 200);
    assert.strictEqual(fr.status, 200);
    assert.ok(/application\/json/.test(en.headers['content-type']));
    const enDict = JSON.parse(en.body), frDict = JSON.parse(fr.body);
    assert.ok(Object.keys(enDict).length > 100);
    assert.deepStrictEqual(Object.keys(enDict).sort(), Object.keys(frDict).sort());
  });

  const missing = await get('/assets/does-not-exist.css');
  check('fichier absent -> 404', () => assert.strictEqual(missing.status, 404));

  const wrongExt = await get('/assets/notes.txt');
  check('extension non autorisee (meme dans public/assets/) -> 404', () => assert.strictEqual(wrongExt.status, 404));

  const traversalParent = await get('/assets/../server.js');
  check('traversee vers server.js (racine de l app) -> 404, jamais servi', () => {
    assert.strictEqual(traversalParent.status, 404);
    assert.ok(!traversalParent.body.includes('handleRequest'));
  });

  const traversalSecret = await get('/assets/../server.js.secret-marker');
  check('traversee vers un fichier hors de public/ -> 404', () => assert.strictEqual(traversalSecret.status, 404));

  const outsideAssets = await get('/assets/../outside-assets.css');
  check('traversee vers un fichier dans public/ mais hors de public/assets/ -> 404', () => assert.strictEqual(outsideAssets.status, 404));

  const encodedTraversal = await get('/assets/%2e%2e/server.js');
  check('traversee encodee (%2e%2e) -> 404 (Node decode l URL avant path.join, meme garde-fou)', () => assert.strictEqual(encodedTraversal.status, 404));

  const nestedTraversal = await get('/assets/lang/../../server.js');
  check('traversee depuis un sous-repertoire (lang/) -> 404, meme garde-fou a toute profondeur', () => assert.strictEqual(nestedTraversal.status, 404));

  const dashboardStillLoadsLink = await (async () => {
    // Pas de session ici : on verifie juste que le HTML pointe bien vers le
    // nouveau fichier plutot que d avoir garde un <style> inline dupliquant
    // le contenu (ce qui romprait le decoupage sans le signaler).
    const html = fs.readFileSync(path.join(appDir, 'public', 'index.html'), 'utf8');
    return html;
  })();
  check('index.html reference bien /assets/style.css, plus de <style> inline', () => {
    assert.ok(dashboardStillLoadsLink.includes('href="/assets/style.css"'));
    assert.ok(!/<style>/.test(dashboardStillLoadsLink));
  });
  check('index.html charge les traductions via loadTranslations(), plus de dictionnaire inline', () => {
    assert.ok(dashboardStillLoadsLink.includes("fetch('/assets/lang/en.json')"));
    assert.ok(dashboardStillLoadsLink.includes("fetch('/assets/lang/fr.json')"));
    assert.ok(dashboardStillLoadsLink.includes('const TRANSLATIONS = { en: {}, fr: {} };'),
      'TRANSLATIONS doit demarrer vide, rempli au demarrage par loadTranslations()');
    assert.ok(!dashboardStillLoadsLink.includes("'nav.section.monitoring':"),
      'le dictionnaire ne doit plus etre defini inline dans index.html');
  });

  srv.kill();
  fs.rmSync(appDir, { recursive: true, force: true });
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();

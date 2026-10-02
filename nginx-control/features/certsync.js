'use strict';
/**
 * Synchronisation de certificats entre instances Nginx Control (v12.59.0).
 *
 * Un nœud qui obtient ses certificats (certbot HTTP/DNS) peut les partager ;
 * les autres les installent dans `<DIR_CERTS>/synced/<nom>/` au lieu de les
 * redemander. Deux sens, au choix de chaque source configurée :
 *   pull : CE nœud va chercher des certificats chez un autre (tâche planifiée
 *          quotidienne ou bouton « Synchroniser maintenant ») ;
 *   push : CE nœud envoie ses certificats à un autre.
 *
 * Routes d'administration (permission `manage_users` : on manipule des clés
 * privées) :
 *   GET  /api/certsync/overview            jetons émis, sources, certificats locaux et synchronisés
 *   POST /api/certsync/tokens/create       { name, scope: pull|push, certs: [...] } -> jeton (affiché une fois)
 *   POST /api/certsync/tokens/delete       { id }
 *   POST /api/certsync/remotes/save        { id?, name, url, direction, token, tlsMode, ca, pin, certs:[{remote,local}], enabled }
 *   POST /api/certsync/remotes/delete      { id }
 *   POST /api/certsync/remotes/probe       { url } -> empreinte du certificat présenté (mode « empreinte »)
 *   POST /api/certsync/remotes/test        { id } -> contact + certificats visibles
 *   POST /api/certsync/remotes/sync        { id?, force? } -> synchronise (une source ou toutes)
 *   POST /api/certsync/synced/delete       { name }
 * Routes appelées PAR un autre nœud, authentifiées par jeton certsync
 * (server.js : CERTSYNC_TOKEN_ROUTES — liste fixe, comme pour les agents) :
 *   GET  /api/certsync/list                certificats autorisés + empreintes
 *   GET  /api/certsync/pull?name=&have=    certificat + clé (si l'empreinte a changé)
 *   POST /api/certsync/push                { name, fullchain, privkey } -> installé ici
 */
const cfg     = require('../lib/config');
const httpLib = require('../lib/http');
const auth    = require('../lib/auth');
const docker  = require('../lib/docker');
const events  = require('../lib/events');
const notify  = require('../lib/notify');
const { pushNotification } = require('../lib/notifications');
const { withLock } = require('../lib/nginx-write-lock');
const core    = require('../lib/certsync-core');
const store   = require('../lib/certsync-store');
const client  = require('../lib/certsync-http');

const { PERMS, hasPerm } = auth;
const { send, parseBody } = httpLib;
const { logEvent } = events;
const DIR_CERTS = cfg.DIR_CERTS;
const NGINX_SYNCED_BASE = '/etc/letsencrypt/synced';
const WARN_DAYS = 14;

/** Injectables pour les tests (le test/reload nginx passe par lib/docker). */
const deps = {
  nginxTest: () => docker.execNginx('nginx -t'),
  nginxReload: () => docker.execNginx('nginx -s reload'),
};
function setDeps(o) { Object.assign(deps, o); }

const errText = e => (e && (e.error || e.stderr || e.message)) ? String(e.error || e.stderr || e.message).slice(0, 400) : String(e);

/** `nginx -t` puis reload, sous le verrou commun des écritures de configuration. */
function applyNginx() {
  return withLock(async () => {
    try { await deps.nginxTest(); } catch (e) { return { ok: false, stage: 'test', error: errText(e) }; }
    try { await deps.nginxReload(); } catch (e) { return { ok: false, stage: 'reload', error: errText(e) }; }
    return { ok: true };
  });
}

// ─── Installation commune (push reçu, pull effectué) ─────────────────────────
/** Installe, teste nginx, recharge ; annule si `nginx -t` échoue. */
async function installAndReload(name, bundle, { force = false } = {}) {
  const r = core.installSynced(DIR_CERTS, name, bundle, { force });
  if (!r.ok) return r;
  if (!r.changed) return { ok: true, changed: false, info: r.info };
  const a = await applyNginx();
  if (!a.ok && a.stage === 'test') {
    core.rollbackSynced(DIR_CERTS, name, !!r.previous);
    return { ok: false, error: `nginx -t a échoué, certificat non installé : ${a.error}` };
  }
  return { ok: true, changed: true, info: r.info, reloadError: a.ok ? null : a.error };
}

// ─── Synchronisation sortante (pull / push) ──────────────────────────────────
const running = new Set();

async function syncRemote(remote, { force = false } = {}) {
  const results = [];
  const lastPushed = {};
  let changedAny = false;
  const pending = []; // pull : installés, rechargement groupé à la fin

  for (const m of remote.certs) {
    try {
      if (remote.direction === 'pull') {
        const have = (core.readSyncedMeta(DIR_CERTS, m.local) || {}).fingerprint256 || '';
        const res = await client.request(remote, 'GET', `/api/certsync/pull?name=${encodeURIComponent(m.remote)}${have && !force ? `&have=${have}` : ''}`);
        if (res.status !== 200 || !res.json) { results.push({ ...m, status: 'error', message: remoteError(res) }); continue; }
        if (res.json.changed === false) { results.push({ ...m, status: 'unchanged', message: 'à jour' }); continue; }
        const inst = core.installSynced(DIR_CERTS, m.local, { fullchain: res.json.fullchain, privkey: res.json.privkey, source: `${remote.name} : ${m.remote}` }, { force });
        if (!inst.ok) { results.push({ ...m, status: 'error', message: inst.error }); continue; }
        if (!inst.changed) { results.push({ ...m, status: 'unchanged', message: 'à jour', notAfter: inst.info.notAfter }); continue; }
        pending.push({ m, inst });
        results.push({ ...m, status: 'updated', message: `installé (expire le ${new Date(inst.info.notAfter).toISOString().slice(0, 10)})`, notAfter: inst.info.notAfter });
      } else {
        const local = core.readLocalBundle(DIR_CERTS, m.local);
        if (!local) { results.push({ ...m, status: 'error', message: 'certificat local introuvable (live/ ou synced/)' }); continue; }
        if (!local.ok) { results.push({ ...m, status: 'error', message: `certificat local invalide : ${local.error}` }); continue; }
        const fp = local.info.fingerprint256;
        if (!force && remote.lastPushed && remote.lastPushed[m.local] === fp) { results.push({ ...m, status: 'unchanged', message: 'déjà envoyé', notAfter: local.info.notAfter }); continue; }
        const res = await client.request(remote, 'POST', '/api/certsync/push', { name: m.remote, fullchain: local.fullchain, privkey: local.privkey });
        if (res.status !== 200 || !res.json || res.json.ok === false) { results.push({ ...m, status: 'error', message: remoteError(res) }); continue; }
        lastPushed[m.local] = fp;
        results.push({ ...m, status: res.json.changed ? 'pushed' : 'unchanged', message: res.json.changed ? 'envoyé et installé' : 'déjà à jour chez le destinataire', notAfter: local.info.notAfter });
        if (res.json.reloadError) results[results.length - 1].message += ` (rechargement nginx distant en échec : ${res.json.reloadError})`;
      }
    } catch (e) { results.push({ ...m, status: 'error', message: errText(e) }); }
  }

  if (pending.length) {
    const a = await applyNginx();
    if (!a.ok && a.stage === 'test') {
      for (const { m, inst } of pending) {
        core.rollbackSynced(DIR_CERTS, m.local, !!inst.previous);
        const r = results.find(x => x.local === m.local && x.status === 'updated');
        if (r) { r.status = 'error'; r.message = `nginx -t a échoué, retour à la version précédente : ${a.error}`; }
      }
    } else {
      changedAny = true;
      if (!a.ok) for (const r of results) if (r.status === 'updated') r.message += ` (rechargement nginx en échec : ${a.error})`;
    }
  }
  return { results, lastPushed, changedAny };
}

function remoteError(res) {
  if (res.status === 401) return 'jeton refusé par l\'autre Nginx Control';
  if (res.status === 403) return (res.json && res.json.error) || 'accès refusé (certificat non autorisé pour ce jeton ?)';
  if (res.status === 404) return (res.json && res.json.error) || 'certificat introuvable chez l\'autre nœud';
  return (res.json && res.json.error) || `réponse HTTP ${res.status}`;
}

/**
 * Synchronise une ou plusieurs sources (toutes celles activées si `ids` est vide).
 * @returns {{ok:boolean, status:string, message:string, remotes:object[]}}
 */
async function runSync({ ids = [], force = false, by = 'scheduler' } = {}) {
  const all = ids.length ? ids.map(id => store.getRemote(id)).filter(Boolean)
    : store.listRemotes().filter(r => r.enabled).map(r => store.getRemote(r.id));
  const out = [];
  for (const remote of all) {
    if (!ids.length && !remote.enabled) continue;
    if (running.has(remote.id)) { out.push({ id: remote.id, name: remote.name, status: 'busy', message: 'synchronisation déjà en cours', results: [] }); continue; }
    running.add(remote.id);
    try {
      const { results, lastPushed } = await syncRemote(remote, { force });
      const errors = results.filter(r => r.status === 'error');
      const changed = results.filter(r => r.status === 'updated' || r.status === 'pushed').length;
      const status = errors.length ? 'error' : 'ok';
      const message = `${changed} mis à jour, ${results.length - changed - errors.length} inchangé(s)${errors.length ? `, ${errors.length} erreur(s) : ${errors.map(e => `${e.remote} (${e.message})`).join(' ; ')}` : ''}`.slice(0, 500);
      store.recordSync(remote.id, { status, message, results, lastPushed });
      logEvent('certsync.sync', { remote: remote.name, direction: remote.direction, status, changed, errors: errors.length, by }, 'api');
      if (errors.length) {
        pushNotification({ type: 'certsync_failed', level: 'error', message: `Synchro certificats « ${remote.name} » : ${errors.length} erreur(s) — ${errors[0].message}` });
        await notify.sendNotification('certsync_failed', '[Nginx Dashboard] Certificate sync FAILED', `Source "${remote.name}" (${remote.direction}) :\n${errors.map(e => `- ${e.remote}: ${e.message}`).join('\n')}`).catch(() => {});
        if (remote.direction === 'pull') for (const e of errors) {
          const meta = core.readSyncedMeta(DIR_CERTS, e.local);
          if (meta && meta.daysLeft < WARN_DAYS) pushNotification({ type: 'certsync_expiring', level: 'warning', message: `Certificat synchronisé « ${e.local} » expire dans ${meta.daysLeft} jour(s) et la source « ${remote.name} » est en erreur` });
        }
      } else if (changed) {
        pushNotification({ type: 'certsync_updated', level: 'success', message: `Synchro certificats « ${remote.name} » : ${changed} certificat(s) mis à jour` });
      }
      out.push({ id: remote.id, name: remote.name, status, message, results });
    } catch (e) {
      store.recordSync(remote.id, { status: 'error', message: errText(e), results: [] });
      out.push({ id: remote.id, name: remote.name, status: 'error', message: errText(e), results: [] });
    } finally { running.delete(remote.id); }
  }
  const bad = out.filter(r => r.status === 'error');
  return { ok: !bad.length, status: bad.length ? 'error' : 'ok',
    message: out.length ? out.map(r => `${r.name} : ${r.message}`).join(' | ') : 'aucune source activée', remotes: out };
}

const listRemotesForScheduler = () => store.listRemotes().map(r => ({ value: r.id, label: `${r.name} (${r.direction})` }));

// ─── Routes ──────────────────────────────────────────────────────────────────
function tokenSession(session) {
  if (!session || !session.certsyncScope || !session.certsyncTokenId) return null;
  return store.getToken(session.certsyncTokenId);
}

function register(router) {
  const admin = (session) => hasPerm(session, PERMS.MANAGE_USERS);

  router.get('/api/certsync/overview', async ({ res, session }) => {
    if (!admin(session)) return httpLib.forbidden(res);
    let live = [];
    try {
      const fsx = require('fs'), path = require('path');
      live = fsx.readdirSync(path.join(DIR_CERTS, 'live')).filter(core.validName).map(n => {
        const b = core.readLocalBundle(DIR_CERTS, n);
        return b && b.source === 'live' ? { name: n, ok: b.ok, error: b.error, domains: b.info ? b.info.domains : [], notAfter: b.info ? b.info.notAfter : null, daysLeft: b.info ? b.info.daysLeft : null } : null;
      }).filter(Boolean);
    } catch { /* pas de live/ */ }
    return send(res, 200, { tokens: store.listTokens(), remotes: store.listRemotes(), live, synced: core.listSynced(DIR_CERTS), nginxBase: NGINX_SYNCED_BASE, running: [...running] });
  });

  router.post('/api/certsync/tokens/create', async ({ req, res, session }) => {
    if (!admin(session)) return httpLib.forbidden(res);
    const v = core.validateTokenInput(await parseBody(req));
    if (!v.ok) return httpLib.badRequest(res, v.error);
    const r = store.createToken(v.value, session.username);
    if (!r.ok) return httpLib.badRequest(res, r.error);
    logEvent('certsync.token.create', { id: r.token.id, name: r.token.name, scope: r.token.scope, certs: r.token.certs, by: session.username }, 'api');
    return send(res, 200, { ok: true, token: r.token, rawToken: r.rawToken });
  });

  router.post('/api/certsync/tokens/delete', async ({ req, res, session }) => {
    if (!admin(session)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    if (!store.revokeToken(String(body.id || ''))) return httpLib.notFound(res, 'Jeton introuvable');
    logEvent('certsync.token.revoke', { id: body.id, by: session.username }, 'api');
    return send(res, 200, { ok: true });
  });

  router.post('/api/certsync/remotes/save', async ({ req, res, session }) => {
    if (!admin(session)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    const id = body.id ? String(body.id) : null;
    const prev = id ? store.getRemote(id) : null;
    if (id && !prev) return httpLib.notFound(res, 'Source introuvable');
    const v = core.validateRemote(body, prev);
    if (!v.ok) return httpLib.badRequest(res, v.error);
    const r = store.saveRemote(id, v.value, session.username);
    if (!r.ok) return send(res, r.status || 400, { ok: false, error: r.error });
    logEvent('certsync.remote.save', { id: r.remote.id, name: r.remote.name, direction: r.remote.direction, url: r.remote.url, tls: r.remote.tls.mode, by: session.username }, 'api');
    return send(res, 200, { ok: true, remote: store.listRemotes().find(x => x.id === r.remote.id) });
  });

  router.post('/api/certsync/remotes/delete', async ({ req, res, session }) => {
    if (!admin(session)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    if (!store.deleteRemote(String(body.id || ''))) return httpLib.notFound(res, 'Source introuvable');
    logEvent('certsync.remote.delete', { id: body.id, by: session.username }, 'api');
    return send(res, 200, { ok: true });
  });

  router.post('/api/certsync/remotes/probe', async ({ req, res, session }) => {
    if (!admin(session)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    const u = core.validateRemoteUrl(body.url);
    if (!u.ok) return send(res, 200, { ok: false, error: u.error });
    try { return send(res, 200, { ok: true, ...(await client.probeServerCert(u.value)) }); }
    catch (e) { return send(res, 200, { ok: false, error: errText(e) }); }
  });

  router.post('/api/certsync/remotes/test', async ({ req, res, session }) => {
    if (!admin(session)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    const remote = store.getRemote(String(body.id || ''));
    if (!remote) return httpLib.notFound(res, 'Source introuvable');
    try {
      const r = await client.request(remote, 'GET', '/api/certsync/list');
      if (r.status !== 200 || !r.json) return send(res, 200, { ok: false, error: remoteError(r) });
      const names = (r.json.certs || []).map(c => c.name);
      const missing = remote.certs.filter(m => !names.includes(m.remote)).map(m => m.remote);
      return send(res, 200, { ok: true, scope: r.json.scope, visible: r.json.certs || [], missing });
    } catch (e) { return send(res, 200, { ok: false, error: errText(e) }); }
  });

  router.post('/api/certsync/remotes/sync', async ({ req, res, session }) => {
    if (!admin(session)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    const ids = body.id ? [String(body.id)] : [];
    if (ids.length && !store.getRemote(ids[0])) return httpLib.notFound(res, 'Source introuvable');
    try { return send(res, 200, await runSync({ ids, force: body.force === true, by: session.username })); }
    catch (e) { return send(res, 500, { ok: false, error: errText(e) }); }
  });

  router.post('/api/certsync/synced/delete', async ({ req, res, session }) => {
    if (!admin(session)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    if (!core.validName(body.name) || !core.readSyncedMeta(DIR_CERTS, body.name)) return httpLib.notFound(res, 'Certificat synchronisé introuvable');
    core.removeSynced(DIR_CERTS, body.name);
    logEvent('certsync.synced.delete', { name: body.name, by: session.username }, 'api');
    return send(res, 200, { ok: true });
  });

  // ── Appelées par un autre nœud (jeton certsync) ───────────────────────────
  router.get('/api/certsync/list', async ({ res, session }) => {
    const t = tokenSession(session);
    if (!t) return httpLib.forbidden(res, 'Jeton de synchronisation requis');
    store.touchToken(t.id, session.ip);
    const certs = t.certs.map(name => {
      if (t.scope === 'pull') {
        const b = core.readLocalBundle(DIR_CERTS, name);
        return b && b.ok ? { name, source: b.source, fingerprint256: b.info.fingerprint256, notAfter: b.info.notAfter, domains: b.info.domains } : null;
      }
      const m = core.readSyncedMeta(DIR_CERTS, name);
      return m ? { name, source: 'synced', fingerprint256: m.fingerprint256, notAfter: m.notAfter, domains: m.domains || [] } : { name, source: null, fingerprint256: null };
    }).filter(Boolean);
    return send(res, 200, { scope: t.scope, certs });
  });

  router.get('/api/certsync/pull', async ({ res, session, url }) => {
    const t = tokenSession(session);
    if (!t) return httpLib.forbidden(res, 'Jeton de synchronisation requis');
    if (t.scope !== 'pull') return httpLib.forbidden(res, 'Ce jeton ne permet pas de lire des certificats');
    const name = url.searchParams.get('name') || '';
    if (!core.validName(name) || !t.certs.includes(name)) return httpLib.forbidden(res, 'Certificat non autorisé pour ce jeton');
    const b = core.readLocalBundle(DIR_CERTS, name);
    if (!b) return httpLib.notFound(res, 'Certificat introuvable sur ce nœud');
    if (!b.ok) return send(res, 409, { error: `Certificat local invalide : ${b.error}` });
    store.touchToken(t.id, session.ip);
    const have = core.normFingerprint(url.searchParams.get('have'));
    res.setHeader && res.setHeader('Cache-Control', 'no-store');
    if (have && have === b.info.fingerprint256) return send(res, 200, { name, changed: false, fingerprint256: have });
    logEvent('certsync.pull.served', { name, token: t.name, tokenId: t.id, ip: session.ip }, 'api');
    return send(res, 200, { name, changed: true, fingerprint256: b.info.fingerprint256, notAfter: b.info.notAfter, domains: b.info.domains, fullchain: b.fullchain, privkey: b.privkey });
  });

  router.post('/api/certsync/push', async ({ req, res, session }) => {
    const t = tokenSession(session);
    if (!t) return httpLib.forbidden(res, 'Jeton de synchronisation requis');
    if (t.scope !== 'push') return httpLib.forbidden(res, 'Ce jeton ne permet pas d\'envoyer des certificats');
    const body = await parseBody(req);
    if (!core.validName(body.name) || !t.certs.includes(body.name)) return httpLib.forbidden(res, 'Certificat non autorisé pour ce jeton');
    store.touchToken(t.id, session.ip);
    try {
      const r = await installAndReload(body.name, { fullchain: body.fullchain, privkey: body.privkey, source: `push : ${t.name}` });
      if (!r.ok) {
        logEvent('certsync.push.rejected', { name: body.name, token: t.name, error: r.error, ip: session.ip }, 'api');
        return send(res, 422, { ok: false, error: r.error });
      }
      if (r.changed) {
        logEvent('certsync.push.installed', { name: body.name, token: t.name, notAfter: r.info.notAfter, ip: session.ip }, 'api');
        pushNotification({ type: 'certsync_updated', level: 'success', message: `Certificat « ${body.name} » reçu de « ${t.name} » et installé` });
      }
      return send(res, 200, { ok: true, changed: r.changed, notAfter: r.info.notAfter, reloadError: r.reloadError || null });
    } catch (e) { return send(res, 500, { ok: false, error: errText(e) }); }
  });
}

module.exports = { register, setDeps, runSync, syncRemote, installAndReload, listRemotesForScheduler, NGINX_SYNCED_BASE };

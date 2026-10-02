'use strict';
/**
 * Utilitaires purs (sans I/O) pour la page Conteneurs (v12.67.0) :
 *  - createLogParser : decoupe en lignes un flux `docker logs --follow`
 *    recu par morceaux (trames multiplexees 8 octets d en-tete, ou flux brut
 *    pour un conteneur TTY) — une trame ou une ligne peut etre coupee entre
 *    deux chunks, c est le piege que demuxStream() (reponse complete) ignore.
 *  - buildRecreateBody : corps `POST /containers/create` reconstruit depuis un
 *    `inspect`, pour le "rebuild" d un conteneur gere.
 */

const MAX_LINE = 16 * 1024; // une ligne sans \n plus longue est coupee (anti-memoire)

function createLogParser({ tty = false } = {}) {
  let frameBuf = Buffer.alloc(0);
  const partial = { out: '', err: '' };

  function feedText(stream, text, out) {
    let s = partial[stream] + text;
    let idx;
    while ((idx = s.indexOf('\n')) !== -1) {
      out.push({ stream, line: s.slice(0, idx).replace(/\r$/, '') });
      s = s.slice(idx + 1);
    }
    if (s.length > MAX_LINE) { out.push({ stream, line: s }); s = ''; }
    partial[stream] = s;
  }

  function push(chunk) {
    const out = [];
    if (tty) { feedText('out', chunk.toString('utf8'), out); return out; }
    frameBuf = frameBuf.length ? Buffer.concat([frameBuf, chunk]) : chunk;
    while (frameBuf.length >= 8) {
      const size = frameBuf.readUInt32BE(4);
      if (frameBuf.length < 8 + size) break;
      const type = frameBuf[0];
      feedText(type === 2 ? 'err' : 'out', frameBuf.slice(8, 8 + size).toString('utf8'), out);
      frameBuf = frameBuf.slice(8 + size);
    }
    return out;
  }

  function flush() {
    const out = [];
    for (const k of ['out', 'err']) if (partial[k]) { out.push({ stream: k, line: partial[k] }); partial[k] = ''; }
    return out;
  }
  return { push, flush };
}

/**
 * Reconstruit le corps de creation a partir d un `docker inspect`.
 * Les reseaux sont reattaches avec leurs alias (hors alias auto = id court)
 * et leur IPAM statique eventuel ; en mode host/none/container: aucun
 * NetworkingConfig n est envoye (Docker le refuserait).
 */
function buildRecreateBody(info) {
  const cfgIn = info.Config || {};
  const host = info.HostConfig || {};
  const body = { ...cfgIn, HostConfig: host };
  delete body.Hostname; // regenere par Docker (id court) sauf si defini par l utilisateur
  const autoHost = typeof cfgIn.Hostname === 'string' && /^[a-f0-9]{12}$/.test(cfgIn.Hostname);
  if (cfgIn.Hostname && !autoHost) body.Hostname = cfgIn.Hostname;
  const mode = host.NetworkMode || 'default';
  if (!/^(host|none|container:)/.test(mode)) {
    const nets = (info.NetworkSettings && info.NetworkSettings.Networks) || {};
    const endpoints = {};
    for (const [name, n] of Object.entries(nets)) {
      const ep = {};
      const aliases = (n.Aliases || []).filter(a => !/^[a-f0-9]{12}$/.test(a));
      if (aliases.length) ep.Aliases = aliases;
      if (n.IPAMConfig) ep.IPAMConfig = n.IPAMConfig;
      endpoints[name] = ep;
    }
    if (Object.keys(endpoints).length) body.NetworkingConfig = { EndpointsConfig: endpoints };
  }
  return body;
}

module.exports = { createLogParser, buildRecreateBody, MAX_LINE };

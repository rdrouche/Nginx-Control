'use strict';
/**
 * GeoIP lookup endpoint. The database reading itself lives in lib/geoip.js,
 * shared with access-log enrichment.
 */

const fs = require('fs');

const http  = require('../lib/http');
const auth  = require('../lib/auth');
const geoip = require('../lib/geoip');

const { PERMS, hasPerm } = auth;
const { send } = http;

function register(router) {
  router.get('/api/geoip/lookup', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return http.forbidden(res);
    const ip = url.searchParams.get('ip');
    if (!ip) return http.badRequest(res, 'ip required');
    return send(res, 200, {
      ip,
      geo: geoip.geoipCached(ip),
      dbs: {
        city:    fs.existsSync(geoip.GEOIP_CITY_DB),
        country: fs.existsSync(geoip.GEOIP_COUNTRY_DB),
        asn:     fs.existsSync(geoip.GEOIP_ASN_DB),
      },
    });
  });
}

module.exports = { register };

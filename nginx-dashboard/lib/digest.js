'use strict';
/**
 * A periodic operational summary — traffic, bot/human split, top countries,
 * CrowdSec activity, WAF activity, upcoming certificate expiries — composed
 * from data this project already computes elsewhere. No new log parsing, no
 * new aggregation engine: this is assembly of existing pieces (the
 * analyzer's traffic/bot aggregates, CrowdSec's decision list, the WAF event
 * store, the certificate lister), sent by email and shown in the dashboard.
 *
 * A CrowdSec Decision, per its own published schema, carries no creation
 * timestamp — only `duration` (a Go duration string) and `until` (an expiry
 * date). There is no honest way to ask "how many bans are new since the last
 * digest" from that shape alone, so this reports a snapshot instead — how
 * many are active right now, broken down by origin — rather than fabricate
 * a "new since X" figure the API cannot actually support.
 */

const certsLib = require('./certs');

// Injectable, defaulting to no-ops that report "unavailable" rather than
// throwing — a digest should degrade gracefully (a missing analyzer or
// unconfigured CrowdSec shows as absent in the digest, not a hard failure),
// the same tolerance this project already applies everywhere else data
// crosses a network boundary.
const deps = {
  analyzerApi: null,
  crowdsecGet: null,
  crowdsecConfigured: () => false,
  listExistingCerts: certsLib.listExistingCerts,
  // features/blocklists.js's getHitStats(), injected — returns
  // { available, hitLogging, totalUniqueIps?, totalHits, uniqueHitIps,
  //   topIps, bySource }. null when unset (mirrors every other dep here).
  getBlocklistStats: null,
};

function configure(overrides) { Object.assign(deps, overrides); }

async function generateDigest(periodHours = 24) {
  const to = Date.now();
  const from = to - periodHours * 3_600_000;

  const digest = {
    generatedAt: to,
    periodHours,
    traffic: null,
    bots: null,
    topCountries: [],
    crowdsec: { configured: false },
    waf: { configured: false },
    blocklists: { enable: false },
    certs: { expiringSoon: [] },
    errors: [],
  };

  if (deps.analyzerApi) {
    // Promise.allSettled, not Promise.all: these three calls are independent
    // — a timeout on one (bots) must not discard the other two that already
    // succeeded. Promise.all rejects the whole batch the instant any single
    // promise rejects, which silently wiped out traffic and topCountries
    // here even when only the bots call had actually failed.
    const [botsRes, countriesRes, vhostsRes] = await Promise.allSettled([
      deps.analyzerApi(`/api/traffic/bots?hours=${periodHours}`),
      deps.analyzerApi(`/api/traffic/countries?hours=${periodHours}`),
      deps.analyzerApi(`/api/traffic/vhosts?hours=${periodHours}`),
    ]);

    if (botsRes.status === 'fulfilled' && botsRes.value?.data) {
      const data = botsRes.value.data;
      digest.bots = {
        total: data.total || 0,
        human: data.human || 0,
        bots:  data.bots || 0,
        byCategory: data.byCategory || [],
      };
    } else if (botsRes.status === 'rejected') {
      digest.errors.push(`traffic (bots): ${botsRes.reason?.message || botsRes.reason}`);
    }

    if (countriesRes.status === 'fulfilled' && Array.isArray(countriesRes.value?.data?.countries)) {
      digest.topCountries = countriesRes.value.data.countries
        .slice().sort((a, b) => (b.requests || 0) - (a.requests || 0)).slice(0, 5);
    } else if (countriesRes.status === 'rejected') {
      digest.errors.push(`traffic (countries): ${countriesRes.reason?.message || countriesRes.reason}`);
    }

    if (vhostsRes.status === 'fulfilled' && Array.isArray(vhostsRes.value?.data?.vhosts)) {
      const vhosts = vhostsRes.value.data.vhosts;
      digest.traffic = {
        totalRequests: vhosts.reduce((s, v) => s + (v.requests || 0), 0),
        totalBytes:    vhosts.reduce((s, v) => s + (v.bytes || 0), 0),
        totalErrors:   vhosts.reduce((s, v) => s + (v.errors || 0), 0),
        byVhost: vhosts.slice().sort((a, b) => (b.requests || 0) - (a.requests || 0)),
      };
    } else if (vhostsRes.status === 'rejected') {
      digest.errors.push(`traffic (vhosts): ${vhostsRes.reason?.message || vhostsRes.reason}`);
    }

    try {
      const wafRes = await deps.analyzerApi(`/api/waf/events?since=${from}&blocked=1&limit=1`);
      if (wafRes?.data) {
        digest.waf = { configured: true, blockedCount: wafRes.data.total || 0 };
      }
    } catch (e) { digest.errors.push(`waf: ${e.message}`); }
  }

  if (deps.crowdsecConfigured()) {
    // Fix (audit finding MISC-07): `activeTotal`/`byOrigin` used to be set
    // ONLY inside the try block below — a CrowdSec that is "configured" per
    // crowdsecConfigured() (e.g. only a Prometheus scrape target set, no
    // reachable LAPI) makes the /v1/decisions call fail, the catch records
    // the error but leaves both fields undefined, and formatDigest() below
    // unconditionally calls `.toLocaleString()` on activeTotal whenever
    // `configured` is true — an uncaught exception there aborted the WHOLE
    // digest, silently, for every period, not just the CrowdSec section.
    // Defaults set here up front mean a failed fetch degrades to "0 active
    // decisions" (visible, alongside the logged error) rather than crashing
    // digest generation entirely.
    digest.crowdsec.configured = true;
    digest.crowdsec.activeTotal = 0;
    digest.crowdsec.byOrigin = {};
    try {
      const decisions = await deps.crowdsecGet('/v1/decisions?limit=500');
      const list = Array.isArray(decisions) ? decisions : [];
      digest.crowdsec.activeTotal = list.length;
      const byOrigin = {};
      for (const d of list) {
        const origin = d.origin || 'unknown';
        byOrigin[origin] = (byOrigin[origin] || 0) + 1;
      }
      digest.crowdsec.byOrigin = byOrigin;
    } catch (e) { digest.errors.push(`crowdsec: ${e.message}`); }
  }

  if (deps.getBlocklistStats) {
    try { digest.blocklists = await deps.getBlocklistStats({ hours: periodHours }); }
    catch (e) { digest.errors.push(`blocklists: ${e.message}`); }
  }

  try {
    const certs = deps.listExistingCerts();
    digest.certs.expiringSoon = certs
      .filter(c => c.daysLeft != null && c.daysLeft <= 30 && c.daysLeft >= 0)
      .map(c => ({ name: c.name, daysLeft: c.daysLeft, notAfter: c.notAfter }))
      .sort((a, b) => a.daysLeft - b.daysLeft);
  } catch (e) { digest.errors.push(`certs: ${e.message}`); }

  return digest;
}

function fmtBytes(n) {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(1)} ${u[i]}`;
}

/** Plain-text rendering for email — no HTML client to assume. */
function formatDigestText(d) {
  const periodLabel = d.periodHours >= 168 ? `${Math.round(d.periodHours / 168)} semaine(s)` : `${d.periodHours}h`;
  const lines = [];
  lines.push(`Résumé Nginx Dashboard — dernières ${periodLabel}`);
  lines.push(`Généré le ${new Date(d.generatedAt).toLocaleString('fr-FR')}`);
  lines.push('');

  if (d.traffic) {
    lines.push(`Trafic : ${d.traffic.totalRequests.toLocaleString('fr-FR')} requêtes, ${fmtBytes(d.traffic.totalBytes)}, ${d.traffic.totalErrors.toLocaleString('fr-FR')} erreurs`);
  } else {
    lines.push('Trafic : analyseur injoignable');
  }

  if (d.bots) {
    const pct = d.bots.total ? Math.round(100 * d.bots.bots / d.bots.total) : 0;
    lines.push(`Visiteurs : ${d.bots.human.toLocaleString('fr-FR')} humains, ${d.bots.bots.toLocaleString('fr-FR')} robots (${pct}%)`);
  }

  if (d.topCountries.length) {
    lines.push('');
    lines.push('Top pays :');
    for (const c of d.topCountries) lines.push(`  ${c.country || '??'} — ${(c.requests || 0).toLocaleString('fr-FR')} requêtes`);
  }

  if (d.waf.configured) {
    lines.push('');
    lines.push(`WAF : ${d.waf.blockedCount.toLocaleString('fr-FR')} requêtes bloquées sur la période`);
  }

  if (d.crowdsec.configured) {
    lines.push('');
    lines.push(`CrowdSec : ${(d.crowdsec.activeTotal || 0).toLocaleString('fr-FR')} décision(s) active(s)`);
    for (const [origin, n] of Object.entries(d.crowdsec.byOrigin || {})) lines.push(`  ${origin} : ${n}`);
  }

  if (d.blocklists?.enable) {
    lines.push('');
    lines.push(`Blocklists IP : ${(d.blocklists.totalUniqueIps || 0).toLocaleString('fr-FR')} adresse(s) IP au total`);
    if (d.blocklists.available) {
      lines.push(`  ${(d.blocklists.totalHits || 0).toLocaleString('fr-FR')} hit(s) sur la periode, ${(d.blocklists.uniqueHitIps || 0).toLocaleString('fr-FR')} IP distincte(s)`);
      for (const s of (d.blocklists.bySource || []).slice(0, 5)) lines.push(`  ${s.name} : ${s.hits.toLocaleString('fr-FR')} hit(s)`);
    } else if (d.blocklists.hitLogging && !d.blocklists.hitLogging.enable) {
      lines.push('  (journalisation des hits desactivee — voir hit_logging_* dans config/blocklists.yml)');
    } else {
      lines.push('  (statistiques de hits indisponibles — analyseur injoignable)');
    }
  }

  if (d.certs.expiringSoon.length) {
    lines.push('');
    lines.push('Certificats à renouveler bientôt :');
    for (const c of d.certs.expiringSoon) lines.push(`  ${c.name} — ${c.daysLeft} jour(s) restant(s)`);
  }

  if (d.errors.length) {
    lines.push('');
    lines.push('(Certaines sections n\'ont pas pu être générées : ' + d.errors.join('; ') + ')');
  }

  return lines.join('\n');
}

module.exports = { generateDigest, formatDigestText, configure };

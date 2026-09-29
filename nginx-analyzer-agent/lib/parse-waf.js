'use strict';
/**
 * ModSecurity JSON audit log parsing.
 *
 * SecAuditLogFormat JSON writes one JSON object per transaction. `transaction`
 * is the only key at the root — request, response, producer and messages are
 * all nested inside it (this project's earlier attempt assumed `messages`
 * sat at the root, which silently produced an empty rule list on every real
 * ModSecurity v3 payload: `Array.isArray(obj.messages)` was always false,
 * since the array actually lives at `obj.transaction.messages`):
 *
 *   {
 *     "transaction": {
 *       "client_ip": "203.0.113.5", "time_stamp": "...",
 *       "request":  { "method": "GET", "uri": "/x?y=1" },
 *       "response": { "http_code": 403 },
 *       "producer": { "secrules_engine": "DetectionOnly", ... },
 *       "messages": [
 *         { "message": "...", "details": {
 *             "ruleId": "942100", "severity": "2",
 *             "tags": ["attack-sqli", "OWASP_CRS"], "data": "..." } }
 *       ]
 *     }
 *   }
 *
 * Deployments vary — this is one of several ModSecurity versions and
 * connectors in the wild, each with slightly different field names. As with
 * every parser in this project, a line that does not match the expected
 * shape is dropped rather than thrown on: a WAF misconfiguration or a
 * connector upgrade must not take log ingestion down.
 *
 * The native "serial" audit format (a MIME-like multi-part document with
 * boundary markers per transaction) is not supported — it has no stable
 * schema across ModSecurity versions and is materially harder to parse
 * correctly. JSON is what this module expects, and what the project
 * documentation tells operators to configure.
 *
 * Whether a request was blocked or only logged is inferred from the response
 * status: 403 is what a `deny` action returns in the vast majority of default
 * OWASP CRS setups. A deployment using a different status for its deny action
 * (or a custom error document) will show blocked events as "detected" — the
 * severity and rule information are unaffected either way, only this one
 * label may need adjusting per environment.
 */

// ModSecurity's numeric severities, 0 (most severe) to 7 (least). Some
// configs use the word form directly (e.g. a custom SecRule with
// severity:'CRITICAL'); both are normalized to the same small vocabulary.
const SEVERITY_MAP = {
  '0': 'critical', '1': 'critical', '2': 'critical',
  '3': 'error', '4': 'warning', '5': 'notice', '6': 'info', '7': 'info',
  EMERGENCY: 'critical', ALERT: 'critical', CRITICAL: 'critical',
  ERROR: 'error', WARNING: 'warning', NOTICE: 'notice',
  INFO: 'info', DEBUG: 'info',
};
const SEVERITY_RANK = { critical: 0, error: 1, warning: 2, notice: 3, info: 4, unknown: 5 };

function normalizeSeverity(raw) {
  if (raw === undefined || raw === null || raw === '') return 'unknown';
  return SEVERITY_MAP[String(raw).trim().toUpperCase()] || 'unknown';
}

/** The single most severe label among a set, for the event's headline severity. */
function worstSeverity(labels) {
  let worst = 'unknown';
  for (const s of labels) if (SEVERITY_RANK[s] < SEVERITY_RANK[worst]) worst = s;
  return worst;
}

/**
 * Always 'json' — kept only so this module can be handed to Tailer the same
 * way the access-log parser is, which auto-detects between two formats.
 * There is nothing to detect here: JSON is the one format this project reads.
 */
function detectFormat() { return 'json'; }

/**
 * Vhost inferred from filename: "example.com.waf.log" → "example.com".
 * Mirrors parse.js's vhostFromFilename for access logs, for the naming
 * convention this project asks operators to use for WAF logs.
 */
function vhostFromFilename(filename) {
  return filename
    .replace(/\.waf\.log(\.\d+)?(\.gz)?$/, '')
    .replace(/\.log$/, '');
}

/**
 * Parse one line of a ModSecurity JSON audit log.
 * Returns null on anything unparseable or missing the fields this module
 * needs — a partial write at the tail of a rotating file is normal, not an
 * error, exactly as with access logs.
 */
function parseLine(line, format, defaultVhost = '') {
  if (!line || line.length < 2) return null;
  let obj;
  try { obj = JSON.parse(line); } catch { return null; }

  const tx = obj.transaction;
  if (!tx || typeof tx !== 'object') return null;

  const ts = parseTimestamp(tx.time_stamp);
  if (ts === null) return null;

  const messages = Array.isArray(tx.messages) ? tx.messages : [];
  const parsedMessages = messages.slice(0, 50).map(m => {
    const d = m?.details || {};
    return {
      ruleId:   d.ruleId != null ? String(d.ruleId) : null,
      message:  m?.message || null,
      severity: normalizeSeverity(d.severity),
      tags:     Array.isArray(d.tags) ? d.tags.slice(0, 10) : [],
    };
  }).filter(m => m.ruleId || m.message);

  const ruleIds = [...new Set(parsedMessages.map(m => m.ruleId).filter(Boolean))];
  const severity = worstSeverity(parsedMessages.map(m => m.severity));

  const httpCode = tx.response?.http_code ?? null;
  // See the module header: 403 is the common OWASP CRS deny status, and this
  // is a best-effort label, not a guarantee for every deployment.
  const blocked = httpCode === 403;

  return {
    ts,
    vhost:    defaultVhost,
    ip:       tx.client_ip || tx.remote_address || null,
    method:   tx.request?.method || null,
    uri:      tx.request?.uri || null,
    status:   httpCode,
    blocked,
    severity,
    ruleIds,
    messages: parsedMessages.slice(0, 10),   // enough for evidence, bounded
    uniqueId: tx.unique_id || tx.id || null,
    // How the engine was running: DetectionOnly means nothing is ever
    // blocked regardless of severity, which otherwise looks like every
    // event being under-classified as "detected".
    engine:   tx.producer?.secrules_engine || null,
    // The complete original line, for an operator who wants to see exactly
    // what ModSecurity recorded rather than the fields this parser extracted.
    // Capped: a transaction with very large headers or a big response body
    // dump could otherwise make one row disproportionately expensive to store.
    raw: line.length > RAW_MAX_LEN ? line.slice(0, RAW_MAX_LEN) + '…(tronque)' : line,
  };
}

/** Cap on how much of the original line is kept for the "view raw" modal. */
const RAW_MAX_LEN = 16 * 1024;

/**
 * OWASP CRS rule ID ranges and what they mean. Generic, well-documented CRS
 * convention — not specific to any one deployment — used to explain a rule
 * when the transaction's own message is terse or when the operator wants the
 * broader category rather than one rule's specific wording.
 */
const CRS_CATEGORIES = [
  [900, 900, 'Initialisation', "Configuration interne du jeu de regles, sans rapport avec une attaque."],
  [901, 901, 'Test', "Regles de verification internes au CRS."],
  [905, 905, 'Verification', "Verifications de bon fonctionnement du moteur."],
  [910, 910, 'Reputation IP', "Adresse presente sur une liste de reputation (IP connue malveillante)."],
  [911, 911, 'Methode HTTP', "Methode HTTP non autorisee par la politique."],
  [912, 912, 'DoS', "Signal de deni de service applicatif."],
  [913, 913, 'Scanner', "Signature d un outil de scan automatise connu."],
  [920, 921, 'Conformite du protocole', "La requete ne respecte pas les regles du protocole HTTP (en-tetes, encodage, format)."],
  [930, 930, 'Traversee de repertoire', "Tentative d acces a des fichiers hors de la racine web (Local File Inclusion)."],
  [931, 931, 'Inclusion distante', "Tentative de faire charger un fichier depuis une source externe (Remote File Inclusion)."],
  [932, 932, 'Execution de commande', "Tentative d execution de commande systeme (Remote Code Execution)."],
  [933, 933, 'Injection PHP', "Tentative d injection de code PHP."],
  [934, 934, 'Attaque generique', "Motif d attaque generique, non specifique a un langage."],
  [941, 941, 'XSS', "Tentative d injection de script cote client (Cross-Site Scripting)."],
  [942, 942, 'Injection SQL', "Motif caracteristique d une injection SQL."],
  [943, 943, 'Fixation de session', "Tentative de manipulation de l identifiant de session."],
  [944, 944, 'Attaque Java', "Motif d attaque visant une application Java."],
  [949, 949, 'Evaluation du score', "Regle d agregation : le score cumule d anomalie depasse le seuil de blocage."],
  [950, 959, 'Fuite de donnees', "La reponse du serveur semble contenir des informations sensibles (erreurs, traces, donnees internes)."],
  [980, 980, 'Correlation', "Regle de synthese reliant plusieurs signaux d une meme transaction."],
];

/** Category info for a rule ID, or a generic fallback for anything else. */
function categorize(ruleId) {
  const n = parseInt(String(ruleId).slice(0, 3), 10);
  if (Number.isFinite(n)) {
    for (const [lo, hi, name, why] of CRS_CATEGORIES) {
      if (n >= lo && n <= hi) return { category: name, why };
    }
  }
  return { category: 'Regle personnalisee', why: "Cette regle ne correspond pas a une plage connue de l OWASP Core Rule Set — probablement une regle ajoutee localement." };
}

/**
 * A link to look up a rule ID's source, for whoever wants the exact matching
 * logic rather than just the category. Built as a GitHub code search rather
 * than a per-rule documentation URL: OWASP CRS does not publish a stable page
 * per rule ID, but its source repository does contain the rule definitions,
 * and a code search always resolves regardless of which CRS version is in use.
 */
function referenceUrl(ruleId) {
  if (!ruleId) return null;
  return `https://github.com/search?q=repo%3Acoreruleset%2Fcoreruleset+%22${encodeURIComponent(ruleId)}%22&type=code`;
}

/**
 * ModSecurity's own timestamp format: "Wed Sep 10 12:00:00 2026" (its default
 * strftime pattern), returned as epoch milliseconds, or null if unparseable.
 * Falls back to whatever Date can make of it, since some builds emit ISO 8601
 * instead depending on configuration.
 *
 * Audit report (Basse/Analyzer, "WAF interprete en UTC alors que ModSecurity
 * ecrit en heure locale"): this format carries NO timezone of its own, so
 * `Date.parse()` — like any correct implementation of it — interprets it in
 * the *runtime's* local zone, not UTC. That was never actually wrong here;
 * what was missing is that the container had no way to be told what that
 * local zone should be (see the Dockerfile's TZ/tzdata fix) — with no TZ
 * set, "local" silently meant UTC, which only matches ModSecurity's own
 * local time if the host it runs on happens to be in UTC too. Set TZ to the
 * nginx/ModSecurity host's actual zone (docker-compose.yml's `environment:`)
 * so this interpretation is correct rather than accidentally matching.
 */
function parseTimestamp(s) {
  if (!s || typeof s !== 'string') return null;
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : t;
}

module.exports = {
  parseLine, detectFormat, vhostFromFilename,
  normalizeSeverity, worstSeverity, SEVERITY_RANK,
  categorize, referenceUrl, RAW_MAX_LEN,
};

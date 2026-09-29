'use strict';
/**
 * Notification delivery and its configuration files.
 *
 * Foundation rather than a feature: the scheduler sends mail on its own
 * (certificate expiry, failed reload, failed backup), and so do the routes that
 * let an operator test the setup.
 *
 * SMTP is spoken directly over net/tls — plain, STARTTLS and implicit TLS —
 * rather than pulling in a mail library, since the dashboard ships with no npm
 * dependencies. Enough of the protocol is implemented to send a plain-text
 * message with optional AUTH LOGIN.
 *
 * Three YAML files drive it, all beside users.yml:
 *   smtp.yml           server, credentials, transport
 *   notifications.yml  which events go to whom
 *   scheduler.yml      recurring tasks
 *
 * Configuration is re-read on demand so a change takes effect without a
 * restart.
 */

const fs  = require('fs');
const net = require('net');
const tls = require('tls');

const cfg = require('./config');
const { stripInlineComment, coerceYmlValue } = require('./simple-yaml');

const { SMTP_CONFIG_FILE, NOTIF_CONFIG_FILE, SCHED_CONFIG_FILE } = cfg;

let smtpCfg  = null;
let notifCfg = null;
let schedCfg = null;

// stripInlineComment/coerceYmlValue now live in ./simple-yaml (fix, audit
// finding MISC-10) — see that module's header comment for the original bug
// this guarded against (`"22 * * * *"   # every Sunday at 4am` parsing as
// the cron string plus a stray quote plus the whole comment glued onto it).
// Every other flat-YAML loader in the project shares that same fix now.

function parseYmlFlat(filePath) {
  if (!fs.existsSync(filePath)) return null;
  try {
    const raw = fs.readFileSync(filePath, 'utf8').replace(/\r/g, '');
    const result = {};
    let currentSection = null;
    let currentSubKey  = null;
    for (const line of raw.split('\n')) {
      if (!line.trim() || line.trim().startsWith('#')) continue;
      const indent = line.match(/^(\s*)/)[1].length;
      const kv     = line.trim().match(/^([a-zA-Z0-9_]+)\s*:\s*(.*)$/);
      if (!kv) {
        // List item
        const li = line.trim().match(/^-\s+(.+)$/);
        if (li && currentSection && currentSubKey) {
          if (!result[currentSection]) result[currentSection] = {};
          if (!result[currentSection][currentSubKey]) result[currentSection][currentSubKey] = [];
          result[currentSection][currentSubKey].push(
            stripInlineComment(li[1]).replace(/^["']|["']$/g, ''));
        }
        continue;
      }
      const [, key, val] = kv;
      const cleanVal = stripInlineComment(val).replace(/^["']|["']$/g, '');
      if (indent === 0) {
        currentSection = key;
        currentSubKey  = null;
        if (cleanVal !== '') {
          result[key] = coerceYmlValue(cleanVal);
          currentSection = null;
        } else {
          result[key] = result[key] || {};
        }
      } else if (indent === 2 && currentSection) {
        currentSubKey = key;
        if (cleanVal !== '') {
          if (!result[currentSection]) result[currentSection] = {};
          result[currentSection][key] = coerceYmlValue(cleanVal);
        } else {
          if (!result[currentSection]) result[currentSection] = {};
          result[currentSection][key] = result[currentSection][key] || [];
        }
      }
    }
    return result;
  } catch(e) {
    console.warn(`[config] Parse error ${filePath}: ${e.message}`);
    return null;
  }
}

function loadSmtpConfig()  { smtpCfg  = parseYmlFlat(SMTP_CONFIG_FILE);  return smtpCfg; }

function loadNotifConfig() { notifCfg = parseYmlFlat(NOTIF_CONFIG_FILE); return notifCfg; }

function loadSchedConfig() { schedCfg = parseYmlFlat(SCHED_CONFIG_FILE); return schedCfg; }

async function sendMail(to, subject, body) {
  const cfg = smtpCfg || loadSmtpConfig();
  if (!cfg || !cfg.enable) return { ok: false, reason: 'SMTP not configured or disabled' };
  const recipients = Array.isArray(to) ? to : [to];
  const net = require('net');
  const tls = require('tls');

  return new Promise((resolve) => {
    const host     = cfg.host || 'localhost';
    const port     = parseInt(cfg.port) || 587;
    const security = (cfg.security || 'tls').toLowerCase();
    const ignoreSSL= cfg.ignore_ssl === true || cfg.ignore_ssl === 'true';
    const from     = cfg.from || 'dashboard@localhost';
    const fromName = cfg.from_name || 'Nginx Dashboard';
    const user     = cfg.username || '';
    const pass     = cfg.password || '';

    const tlsOpts = { host, servername: host, rejectUnauthorized: !ignoreSSL };
    let   sock;
    let   buf       = '';
    let   step      = 0;
    let   upgraded  = false;

    const lines = () => buf.split('\r\n').filter(Boolean);
    const lastCode = () => { const ls = lines(); return ls.length ? parseInt(ls[ls.length-1]) : 0; };

    function send(cmd) { sock.write(cmd + '\r\n'); }

    // Fix (audit finding MISC-06): four distinct SMTP-protocol bugs in this
    // module, all in how a message and its envelope were assembled:
    //
    //  1. No dot-stuffing. RFC 5321 requires any DATA line consisting of, or
    //     starting with, a bare "." to have that leading dot doubled — a
    //     single "." on its own line is how DATA itself ends. `body` is
    //     free text (digest summaries, error excerpts) with no control over
    //     its own content; a line starting with "." silently truncated the
    //     message right there, with everything after it either lost or
    //     resent as spurious SMTP commands to the still-open connection.
    //  2. Message lines used the connection's own CRLF-per-command
    //     convention (`send(l)` appends "\r\n") but `body` itself is a
    //     plain JS string that may contain bare "\n" (not "\r\n"): sent as
    //     one `send()` call, `body` produced bare LFs inside the DATA
    //     stream, which RFC 5321 forbids — tolerated by many servers, but
    //     not guaranteed, and not correct.
    //  3. Non-ASCII subjects ("Résumé quotidien") were inserted into the
    //     `Subject:` header raw. RFC 5322 headers are 7-bit ASCII; an
    //     unencoded UTF-8 byte there is undefined behaviour left to
    //     whichever MTA/client receives it. RFC 2047 encoded-words
    //     (`=?UTF-8?B?<base64>?=`) are the correct escape.
    //  4. Header/envelope injection: `to` (and `subject`) reach this
    //     function from `/api/notify/test`'s request body — a caller who
    //     puts a CRLF in an address ends the `To:` header early and starts
    //     injecting arbitrary headers (or, worse, extra SMTP commands once
    //     that address is used verbatim in `RCPT TO:<...>`). Every
    //     externally-influenced value used in a header or a command is now
    //     stripped of CR/LF before use.
    const stripCrlf = s => String(s || '').replace(/[\r\n]+/g, ' ').trim();

    // RFC 2047 "B" (base64) encoded-word, only when actually needed — a
    // pure-ASCII subject is left untouched and unencoded, exactly as before.
    function encodeHeaderValue(s) {
      const clean = stripCrlf(s);
      if (/^[\x20-\x7e]*$/.test(clean)) return clean;
      return `=?UTF-8?B?${Buffer.from(clean, 'utf8').toString('base64')}?=`;
    }

    /** RFC 5321 dot-stuffing: a line that starts with "." gets a second "." prefixed. */
    function dotStuff(line) { return line.startsWith('.') ? '.' + line : line; }

    const safeRecipients = recipients.map(stripCrlf).filter(Boolean);

    function buildMessage() {
      const toHeader = safeRecipients.join(', ');
      const date     = new Date().toUTCString();
      // Normalize every line ending to CRLF and dot-stuff each one
      // individually — `body` may itself contain "\r\n", "\n" or a lone
      // "\r", and each resulting line is sent as its own SMTP line below via
      // `send()`, so none of the header lines (fixed, never user-controlled
      // free text) need stuffing, only the body's.
      const bodyLines = String(body ?? '').split(/\r\n|\r|\n/).map(dotStuff);
      const msgLines = [
        `From: ${stripCrlf(fromName)} <${stripCrlf(from)}>`,
        `To: ${toHeader}`,
        `Subject: ${encodeHeaderValue(subject)}`,
        `Date: ${date}`,
        `MIME-Version: 1.0`,
        `Content-Type: text/plain; charset=utf-8`,
        ``,
        ...bodyLines,
        `.`,
      ];
      return msgLines;
    }

    function next(data) {
      buf += data;
      if (!buf.endsWith('\r\n')) return; // wait for full line
      const code = parseInt(buf.split('\r\n').find(l => /^\d{3} /.test(l)) || '0');
      buf = '';

      if (step === 0 && code === 220) {
        send(`EHLO ${host}`); step = 1; return;
      }
      if (step === 1 && (code === 250 || code === 220)) {
        if (security === 'tls' && !upgraded) {
          send('STARTTLS'); step = 2; return;
        }
        step = 3; doAuth(); return;
      }
      if (step === 2 && code === 220) {
        // Upgrade to TLS
        const plain = sock;
        sock = tls.connect({ socket: plain, ...tlsOpts }, () => {
          upgraded = true;
          send(`EHLO ${host}`); step = 1;
        });
        sock.on('data', d => next(d.toString()));
        sock.on('error', e => resolve({ ok: false, reason: e.message }));
        return;
      }
      if (step === 3) { // after EHLO post-TLS
        doAuth(); return;
      }
      if (step === 4 && code === 334) { send(Buffer.from(user).toString('base64')); step = 5; return; }
      if (step === 5 && code === 334) { send(Buffer.from(pass).toString('base64')); step = 6; return; }
      if (step === 6 && code === 235) { sendEnvelope(); return; }
      if (step === 6 && code >= 500)  { resolve({ ok: false, reason: `Auth failed: ${code}` }); sock.destroy(); return; }
      // safeRecipients (fix MISC-06): CR/LF stripped, so a caller-supplied
      // address cannot break out of the RCPT TO command into a new one.
      if (step === 10 && code === 250) { send(`RCPT TO:<${safeRecipients[0]}>`); step = 11; return; }
      if (step === 11 && code === 250) {
        // More recipients?
        const remaining = safeRecipients.slice(1);
        if (remaining.length) { remaining.forEach(r => send(`RCPT TO:<${r}>`)); }
        send('DATA'); step = 12; return;
      }
      if (step === 12 && code === 354) {
        buildMessage().forEach(l => send(l));
        step = 13; return;
      }
      if (step === 13 && code === 250) { send('QUIT'); resolve({ ok: true }); sock.destroy(); return; }
      if (code >= 400) { resolve({ ok: false, reason: `SMTP error ${code}` }); sock.destroy(); }
    }

    function doAuth() {
      if (user) { send('AUTH LOGIN'); step = 4; }
      else       { sendEnvelope(); }
    }

    function sendEnvelope() { send(`MAIL FROM:<${stripCrlf(from)}>`); step = 10; }

    function connect() {
      if (security === 'ssl') {
        sock = tls.connect({ host, port, ...tlsOpts }, () => { /* wait for 220 */ });
      } else {
        sock = net.connect({ host, port });
      }
      sock.setTimeout(15000);
      sock.on('data',    d => next(d.toString()));
      sock.on('error',   e => resolve({ ok: false, reason: e.message }));
      sock.on('timeout', () => { resolve({ ok: false, reason: 'SMTP timeout' }); sock.destroy(); });
    }

    connect();
  });
}

async function sendNotification(type, subject, body) {
  const cfg = notifCfg || loadNotifConfig();
  if (!cfg) return;
  const rule = cfg[type];
  if (!rule || !rule.enable) return;
  const recipients = Array.isArray(rule.recipients) ? rule.recipients : [];
  if (!recipients.length) return;
  const result = await sendMail(recipients, subject, body).catch(e => ({ ok: false, reason: e.message }));
  console.log(`[notify] ${type} → ${recipients.join(',')} : ${result.ok ? 'OK' : result.reason}`);
  return result;
}
/** Current configuration objects, reloading from disk first. */
function getSmtpConfig()  { return loadSmtpConfig(); }
function getNotifConfig() { return loadNotifConfig(); }
function getSchedConfig() { return loadSchedConfig(); }

/** Reload all three at once — used by the scheduler on each tick. */
function reloadAll() {
  loadSmtpConfig(); loadNotifConfig(); loadSchedConfig();
  return { smtpCfg, notifCfg, schedCfg };
}

module.exports = {
  parseYmlFlat, coerceYmlValue,
  loadSmtpConfig, loadNotifConfig, loadSchedConfig,
  getSmtpConfig, getNotifConfig, getSchedConfig, reloadAll,
  sendMail, sendNotification,
  SMTP_CONFIG_FILE, NOTIF_CONFIG_FILE, SCHED_CONFIG_FILE,
};

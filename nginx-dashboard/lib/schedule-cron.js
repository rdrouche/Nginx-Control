'use strict';
/**
 * Moteur de planification : validation et correspondance d'une expression cron,
 * calcul des prochaines exécutions, description lisible, et construction d'une
 * expression à partir du formulaire visuel (« tous les jours à 03:00 », « le
 * lundi et le jeudi à 07:30 »…).
 *
 * Pas de dépendance : les motifs utiles tiennent en quelques dizaines de lignes.
 *
 * Syntaxe acceptée (5 champs : minute heure jour-du-mois mois jour-de-semaine) :
 *   *   a   a-b   a,b,c   *\/n   a-b/n   a/n   — et les alias @hourly @daily
 *   @midnight @weekly @monthly @yearly. Jour de semaine 0-7 (0 et 7 = dimanche).
 * Sémantique cron standard : si le jour-du-mois ET le jour-de-semaine sont tous
 * deux restreints, la date correspond dès que l'UN des deux correspond.
 *
 * Tout est exprimé dans le fuseau horaire du processus (TZ du conteneur), comme
 * l'ancien planificateur : l'interface affiche ce fuseau.
 */

const ALIASES = {
  '@hourly': '0 * * * *', '@daily': '0 0 * * *', '@midnight': '0 0 * * *',
  '@weekly': '0 0 * * 0', '@monthly': '0 0 1 * *', '@yearly': '0 0 1 1 *', '@annually': '0 0 1 1 *',
};

const FIELD_DEFS = [
  { key: 'min',  name: 'minute',          lo: 0, hi: 59 },
  { key: 'hour', name: 'heure',           lo: 0, hi: 23 },
  { key: 'dom',  name: 'jour du mois',    lo: 1, hi: 31 },
  { key: 'mon',  name: 'mois',            lo: 1, hi: 12 },
  { key: 'dow',  name: 'jour de semaine', lo: 0, hi: 7 },
];

const MAX_EXPR_LEN = 120;

function parseField(text, def) {
  const values = new Set();
  let star = false;
  for (const part of text.split(',')) {
    if (part === '') return { error: `${def.name} : élément vide` };
    const m = /^(\*|\d+(?:-\d+)?)(?:\/(\d+))?$/.exec(part);
    if (!m) return { error: `${def.name} : « ${part} » n'est pas valide` };
    let [, range, stepRaw] = m;
    const step = stepRaw === undefined ? 1 : Number(stepRaw);
    if (!Number.isInteger(step) || step < 1) return { error: `${def.name} : pas invalide` };
    let a, b;
    if (range === '*') { a = def.lo; b = def.key === 'dow' ? 6 : def.hi; if (stepRaw === undefined) star = true; }
    else if (range.includes('-')) { [a, b] = range.split('-').map(Number); }
    else { a = Number(range); b = stepRaw === undefined ? a : def.hi; }
    if (a < def.lo || b > def.hi || a > b) return { error: `${def.name} : hors limites (${def.lo}-${def.hi})` };
    for (let v = a; v <= b; v += step) values.add(def.key === 'dow' && v === 7 ? 0 : v);
  }
  return { values, star };
}

/** @returns {{ok:true, expr:string, f:object}|{ok:false, error:string}} */
function parseCron(input) {
  if (typeof input !== 'string') return { ok: false, error: 'expression absente' };
  let expr = input.trim().replace(/\s+/g, ' ');
  if (!expr) return { ok: false, error: 'expression vide' };
  if (expr.length > MAX_EXPR_LEN) return { ok: false, error: 'expression trop longue' };
  if (expr[0] === '@') {
    const alias = ALIASES[expr.toLowerCase()];
    if (!alias) return { ok: false, error: `alias inconnu : ${expr}` };
    expr = alias;
  }
  const parts = expr.split(' ');
  if (parts.length !== 5) return { ok: false, error: 'il faut 5 champs : minute heure jour mois jour-de-semaine' };
  const f = {};
  for (let i = 0; i < 5; i++) {
    const r = parseField(parts[i], FIELD_DEFS[i]);
    if (r.error) return { ok: false, error: r.error };
    f[FIELD_DEFS[i].key] = r.values;
    f[FIELD_DEFS[i].key + 'Star'] = r.star;
  }
  return { ok: true, expr, f };
}

function dayMatches(f, date) {
  const domOk = f.dom.has(date.getDate());
  const dowOk = f.dow.has(date.getDay());
  if (f.domStar && f.dowStar) return true;
  if (f.domStar) return dowOk;
  if (f.dowStar) return domOk;
  return domOk || dowOk; // cron standard : l'un OU l'autre quand les deux sont restreints
}

/** Vrai si `date` (à la minute près) correspond à l'expression. Jamais d'exception. */
function cronMatches(expr, date) {
  const p = typeof expr === 'string' ? parseCron(expr) : expr;
  if (!p || !p.ok) return false;
  const f = p.f;
  return f.min.has(date.getMinutes()) && f.hour.has(date.getHours())
    && f.mon.has(date.getMonth() + 1) && dayMatches(f, date);
}

/**
 * Les `count` prochaines exécutions strictement après `from`. Parcourt jour par
 * jour (au plus ~5 ans) puis heure/minute dans l'ordre : pas de boucle minute
 * par minute. Tableau vide si l'expression est invalide ou ne se produit jamais
 * (ex. 31 février).
 */
function nextRuns(expr, from = new Date(), count = 5) {
  const p = typeof expr === 'string' ? parseCron(expr) : expr;
  if (!p || !p.ok) return [];
  const f = p.f;
  const hours = [...f.hour].sort((a, b) => a - b);
  const mins = [...f.min].sort((a, b) => a - b);
  const out = [];
  const day = new Date(from.getFullYear(), from.getMonth(), from.getDate());
  for (let i = 0; i < 366 * 5 && out.length < count; i++, day.setDate(day.getDate() + 1)) {
    if (!f.mon.has(day.getMonth() + 1) || !dayMatches(f, day)) continue;
    for (const h of hours) {
      for (const m of mins) {
        const d = new Date(day.getFullYear(), day.getMonth(), day.getDate(), h, m, 0, 0);
        if (d.getHours() !== h) continue; // heure inexistante (passage à l'heure d'été)
        if (d > from) { out.push(d); if (out.length >= count) return out; }
      }
    }
  }
  return out;
}

// ─── Description lisible ─────────────────────────────────────────────────────
const DAYS = {
  fr: ['dimanche', 'lundi', 'mardi', 'mercredi', 'jeudi', 'vendredi', 'samedi'],
  en: ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'],
};
const pad = n => String(n).padStart(2, '0');
const hhmm = (h, m) => `${pad(h)}:${pad(m)}`;

function isStep(set, lo, hi) {
  // « */n » : valeurs lo, lo+n, … jusqu'à hi
  const arr = [...set].sort((a, b) => a - b);
  if (arr.length < 2 || arr[0] !== lo) return 0;
  const n = arr[1] - arr[0];
  for (let i = 1; i < arr.length; i++) if (arr[i] - arr[i - 1] !== n) return 0;
  return arr[arr.length - 1] + n > hi ? n : 0;
}

/** Description en français (`fr`) ou anglais (`en`) ; repli « Cron personnalisé ». */
function describeCron(expr, lang = 'fr') {
  const L = lang === 'en' ? 'en' : 'fr';
  const p = typeof expr === 'string' ? parseCron(expr) : expr;
  if (!p || !p.ok) return L === 'en' ? 'Invalid schedule' : 'Planification invalide';
  const f = p.f;
  const fallback = L === 'en' ? `Custom cron: ${p.expr}` : `Cron personnalisé : ${p.expr}`;
  const allMon = f.mon.size === 12, allDom = f.domStar, allDow = f.dowStar;
  const oneMin = f.min.size === 1, oneHour = f.hour.size === 1;
  const mm = oneMin ? [...f.min][0] : null;

  if (allMon && allDom && allDow) {
    if (f.min.size === 60 && f.hour.size === 24) return L === 'en' ? 'Every minute' : 'Chaque minute';
    const stepMin = isStep(f.min, 0, 59);
    if (stepMin && f.hour.size === 24) return L === 'en' ? `Every ${stepMin} minutes` : `Toutes les ${stepMin} minutes`;
    if (oneMin && f.hour.size === 24) return L === 'en' ? `Every hour at :${pad(mm)}` : `Chaque heure à :${pad(mm)}`;
    const stepHour = isStep(f.hour, 0, 23);
    if (oneMin && stepHour) {
      return L === 'en' ? `Every ${stepHour} hours (at :${pad(mm)})` : `Toutes les ${stepHour} heures (à :${pad(mm)})`;
    }
    if (oneMin && oneHour) return L === 'en' ? `Every day at ${hhmm([...f.hour][0], mm)}` : `Tous les jours à ${hhmm([...f.hour][0], mm)}`;
  }
  if (allMon && allDom && !allDow && oneMin && oneHour) {
    const days = [...f.dow].sort((a, b) => a - b);
    const t = hhmm([...f.hour][0], mm);
    if (days.length === 7) return L === 'en' ? `Every day at ${t}` : `Tous les jours à ${t}`;
    const names = days.map(d => DAYS[L][d]);
    const list = names.length > 1 ? names.slice(0, -1).join(', ') + (L === 'en' ? ' and ' : ' et ') + names[names.length - 1] : names[0];
    return L === 'en' ? `Every ${list} at ${t}` : `Chaque ${list} à ${t}`;
  }
  if (allMon && !allDom && allDow && oneMin && oneHour && f.dom.size === 1) {
    const d = [...f.dom][0], t = hhmm([...f.hour][0], mm);
    return L === 'en' ? `On day ${d} of every month at ${t}` : `Le ${d === 1 ? '1er' : d} de chaque mois à ${t}`;
  }
  return fallback;
}

// ─── Formulaire visuel → expression ──────────────────────────────────────────
const MINUTE_STEPS = [1, 2, 3, 4, 5, 6, 10, 12, 15, 20, 30];
const HOUR_STEPS = [1, 2, 3, 4, 6, 8, 12];
const TIME_RE = /^([01]?\d|2[0-3]):([0-5]\d)$/;

function parseTime(s) {
  const m = TIME_RE.exec(String(s || '').trim());
  return m ? { h: Number(m[1]), m: Number(m[2]) } : null;
}

/**
 * Valide la planification saisie dans le formulaire et en déduit le cron.
 *   { mode:'interval', every:15, unit:'minutes' }            → *\/15 * * * *
 *   { mode:'interval', every:6,  unit:'hours', minute:5 }    → 5 *\/6 * * *
 *   { mode:'daily',   time:'03:00' }                         → 0 3 * * *
 *   { mode:'weekly',  days:[1,4], time:'07:30' }             → 30 7 * * 1,4
 *   { mode:'monthly', day:1, time:'02:00' }                  → 0 2 1 * *
 *   { mode:'cron',    cron:'0 *\/6 * * *' }                  → tel quel (validé)
 * @returns {{ok:true, schedule:object, cron:string}|{ok:false, error:string}}
 */
function buildSchedule(spec) {
  if (!spec || typeof spec !== 'object') return { ok: false, error: 'planification absente' };
  const mode = spec.mode;
  let cron;
  let schedule;
  if (mode === 'interval') {
    const every = Number(spec.every);
    if (spec.unit === 'minutes') {
      if (!MINUTE_STEPS.includes(every)) return { ok: false, error: `intervalle en minutes parmi ${MINUTE_STEPS.join(', ')}` };
      cron = every === 1 ? '* * * * *' : `*/${every} * * * *`;
      schedule = { mode, every, unit: 'minutes' };
    } else if (spec.unit === 'hours') {
      if (!HOUR_STEPS.includes(every)) return { ok: false, error: `intervalle en heures parmi ${HOUR_STEPS.join(', ')}` };
      const minute = spec.minute === undefined ? 0 : Number(spec.minute);
      if (!Number.isInteger(minute) || minute < 0 || minute > 59) return { ok: false, error: 'minute invalide (0-59)' };
      cron = `${minute} ${every === 1 ? '*' : '*/' + every} * * *`;
      schedule = { mode, every, unit: 'hours', minute };
    } else return { ok: false, error: 'unité : minutes ou hours' };
  } else if (mode === 'daily') {
    const t = parseTime(spec.time);
    if (!t) return { ok: false, error: 'heure invalide (HH:MM)' };
    cron = `${t.m} ${t.h} * * *`;
    schedule = { mode, time: hhmm(t.h, t.m) };
  } else if (mode === 'weekly') {
    const t = parseTime(spec.time);
    if (!t) return { ok: false, error: 'heure invalide (HH:MM)' };
    const days = [...new Set((Array.isArray(spec.days) ? spec.days : []).map(Number))].sort((a, b) => a - b);
    if (!days.length || days.some(d => !Number.isInteger(d) || d < 0 || d > 6)) return { ok: false, error: 'choisissez au moins un jour (0 = dimanche … 6 = samedi)' };
    cron = `${t.m} ${t.h} * * ${days.join(',')}`;
    schedule = { mode, days, time: hhmm(t.h, t.m) };
  } else if (mode === 'monthly') {
    const t = parseTime(spec.time);
    if (!t) return { ok: false, error: 'heure invalide (HH:MM)' };
    const day = Number(spec.day);
    if (!Number.isInteger(day) || day < 1 || day > 31) return { ok: false, error: 'jour du mois invalide (1-31)' };
    cron = `${t.m} ${t.h} ${day} * *`;
    schedule = { mode, day, time: hhmm(t.h, t.m) };
  } else if (mode === 'cron') {
    const p = parseCron(spec.cron);
    if (!p.ok) return { ok: false, error: p.error };
    cron = p.expr;
    schedule = { mode, cron: p.expr };
  } else {
    return { ok: false, error: 'mode inconnu (interval, daily, weekly, monthly, cron)' };
  }
  const check = parseCron(cron);
  if (!check.ok) return { ok: false, error: check.error };
  return { ok: true, schedule, cron };
}

/**
 * Reconstruit le formulaire à partir d'un cron existant (import de l'ancien
 * scheduler.yml) : retombe sur le mode « cron » quand le motif n'est pas
 * exprimable simplement.
 */
function scheduleFromCron(expr) {
  const p = parseCron(expr);
  if (!p.ok) return null;
  const f = p.f;
  const allMon = f.mon.size === 12;
  const oneMin = f.min.size === 1, oneHour = f.hour.size === 1;
  const mm = oneMin ? [...f.min][0] : null;
  const candidates = [];
  if (allMon && f.domStar && f.dowStar) {
    const sm = isStep(f.min, 0, 59);
    if (f.min.size === 60 && f.hour.size === 24) candidates.push({ mode: 'interval', every: 1, unit: 'minutes' });
    else if (sm && f.hour.size === 24) candidates.push({ mode: 'interval', every: sm, unit: 'minutes' });
    const sh = isStep(f.hour, 0, 23);
    if (oneMin && f.hour.size === 24) candidates.push({ mode: 'interval', every: 1, unit: 'hours', minute: mm });
    else if (oneMin && sh) candidates.push({ mode: 'interval', every: sh, unit: 'hours', minute: mm });
    if (oneMin && oneHour) candidates.push({ mode: 'daily', time: hhmm([...f.hour][0], mm) });
  } else if (allMon && f.domStar && !f.dowStar && oneMin && oneHour) {
    candidates.push({ mode: 'weekly', days: [...f.dow].sort((a, b) => a - b), time: hhmm([...f.hour][0], mm) });
  } else if (allMon && !f.domStar && f.dowStar && oneMin && oneHour && f.dom.size === 1) {
    candidates.push({ mode: 'monthly', day: [...f.dom][0], time: hhmm([...f.hour][0], mm) });
  }
  for (const c of candidates) {
    const b = buildSchedule(c);
    if (b.ok && b.cron === p.expr) return b.schedule;
  }
  return { mode: 'cron', cron: p.expr };
}

module.exports = {
  parseCron, cronMatches, nextRuns, describeCron, buildSchedule, scheduleFromCron,
  MINUTE_STEPS, HOUR_STEPS, ALIASES,
};

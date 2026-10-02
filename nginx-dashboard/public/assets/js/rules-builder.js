// ── REGLES D'ANALYSE : formulaire, modeles, onglets (fenetre « Regles » de la page Analyse) ──
// Script global classique (api(), t(), h() du script principal). Le YAML reste le format de
// stockage (analyzer) : ce fichier edite une COPIE de travail (RB.rules), la convertit en YAML
// via POST /api/analyzer/rules/to-yaml (validation + YAML canonique), puis enregistre avec la
// route existante POST /api/analyzer/rules/custom. analyzer.js (rulesLoad) appelle rbSetData().

const RB = { rules: [], errors: [], dirty: false, open: new Set(), packs: null, tab: 'builtin', saving: false, seq: 0, advancedLoaded: false };
const RB_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];

const rbEl = id => document.getElementById(id);
const rbT = (k, v) => t(k, v);

function rbBlank() {
  return {
    _uid: ++RB.seq, id: rbNextId(), name: '', enable: true, severity: 'medium', description: '', scope: 'ip', minIps: 5,
    minMatches: 10, windowMinutes: 5, pathHint: '', uaHint: '', statusIn: [], methodIn: [],
    blocklist: { threshold: null, windowMinutes: 1440, remediation: false, remediationMinutes: null, remediationType: 'block' },
  };
}

function rbFromServer(c) {
  const bl = c.blocklist || {};
  return {
    _uid: ++RB.seq, id: c.id, name: c.name || '', enable: c.enabled !== false, severity: c.severity || 'medium',
    description: c.description || '', scope: c.scope === 'global' ? 'global' : 'ip', minIps: c.minIps || 5,
    minMatches: c.minMatches, windowMinutes: c.windowMinutes || 5, pathHint: c.pathHint || '', uaHint: c.uaHint || '',
    statusIn: (c.statusIn || []).slice(), methodIn: (c.methodIn || []).slice(),
    blocklist: {
      threshold: bl.threshold != null ? bl.threshold : null, windowMinutes: bl.windowMinutes || 1440,
      remediation: bl.remediation === true, remediationMinutes: bl.remediationMinutes != null ? bl.remediationMinutes : null,
      remediationType: bl.remediationType === 'challenge' ? 'challenge' : 'block',
    },
  };
}

function rbNextId() {
  const used = new Set(RB.rules.map(r => +r.id));
  let id = 100;
  while (used.has(id)) id++;
  return id;
}

// ── Onglets ─────────────────────────────────────────────────────────────────
function rulesTab(name) {
  RB.tab = name;
  for (const n of ['builtin', 'mine', 'templates', 'yaml']) {
    const pane = rbEl('rb-pane-' + n), tab = rbEl('rb-tab-' + n);
    if (pane) pane.style.display = n === name ? '' : 'none';
    if (tab) tab.classList.toggle('active', n === name);
  }
  if (name === 'templates') rbLoadTemplates();
  if (name === 'mine') rbRender();
}

// Appele par rulesLoad() (analyzer.js) a chaque (re)chargement des regles.
function rbSetData(custom, errors) {
  RB.errors = errors || [];
  const box = rbEl('rb-yaml-errors');
  if (box) {
    box.style.display = RB.errors.length ? '' : 'none';
    box.textContent = RB.errors.length ? rbT('rb.yamlErrors') + '\n' + RB.errors.join('\n') : '';
  }
  // Ne jamais ecraser une saisie non enregistree (ex. rafraichissement apres un toggle).
  if (!RB.dirty) {
    RB.rules = (custom || []).map(rbFromServer);
    RB.open = new Set();
  }
  rbRender();
}

// ── Resume en langage clair ────────────────────────────────────────────────
function rbCriteria(r) {
  const parts = [];
  if (r.methodIn.length) parts.push(r.methodIn.join('/'));
  if (r.pathHint) parts.push(rbT('rb.crit.path') + ' ' + r.pathHint);
  if (r.uaHint) parts.push(rbT('rb.crit.ua') + ' ' + r.uaHint);
  if (r.statusIn.length) parts.push(rbT('rb.crit.status') + ' ' + r.statusIn.join(','));
  return parts.join(' · ') || rbT('rb.crit.none');
}

function rbSentence(r) {
  const n = +r.minMatches || 0, w = +r.windowMinutes || 0;
  let s = r.scope === 'global'
    ? rbT('rb.sentence.global', { ips: +r.minIps || 0, n, w })
    : rbT('rb.sentence.ip', { n, w });
  const b = r.blocklist;
  if (b.threshold) {
    s += ' ' + rbT(b.remediation ? (b.remediationType === 'challenge' ? 'rb.sentence.challenge' : 'rb.sentence.block') : 'rb.sentence.listOnly', {
      th: b.threshold, win: b.windowMinutes || 1440,
      dur: b.remediationMinutes ? rbT('rb.sentence.dur', { m: b.remediationMinutes }) : rbT('rb.sentence.durDefault'),
    });
  } else {
    s += ' ' + rbT('rb.sentence.noBlock');
  }
  return s;
}

function rbSummary(r) {
  const head = r.scope === 'global'
    ? rbT('rb.sum.global', { n: r.minMatches, w: r.windowMinutes, ips: r.minIps })
    : rbT('rb.sum.ip', { n: r.minMatches, w: r.windowMinutes });
  return head + ' — ' + rbCriteria(r);
}

const RB_SEV = { low: ['badge gy', 'rb.sev.low'], medium: ['badge am', 'rb.sev.medium'], high: ['badge rd', 'rb.sev.high'] };

// ── Rendu de la liste ──────────────────────────────────────────────────────
function rbRender() {
  const list = rbEl('rb-list');
  if (!list) return;
  const cnt = rbEl('rb-count');
  if (cnt) cnt.textContent = String(RB.rules.length);
  const save = rbEl('rb-save'), disc = rbEl('rb-discard');
  const blocked = RB.errors.length > 0;
  if (save) { save.disabled = blocked || RB.saving; save.title = blocked ? rbT('rb.saveBlocked') : ''; }
  if (disc) disc.style.display = RB.dirty ? '' : 'none';
  if (!RB.rules.length) {
    list.innerHTML = '<div class="nf-hint">' + h(rbT('rb.empty')) + '</div>';
    return;
  }
  list.innerHTML = RB.rules.map(rbCardHtml).join('');
}

function rbCardHtml(r) {
  const open = RB.open.has(r._uid);
  const sev = RB_SEV[r.severity] || RB_SEV.medium;
  return '<div class="rb-card' + (r.enable ? '' : ' off') + (r._new ? ' new' : '') + '" id="rb-card-' + r._uid + '">' +
    '<div class="rb-head">' +
      '<label title="' + h(rbT('rb.enable')) + '"><input type="checkbox" ' + (r.enable ? 'checked' : '') + ' onchange="rbSet(' + r._uid + ',\'enable\',this.checked)"></label>' +
      '<span class="rb-id">#' + h(r.id) + '</span>' +
      '<span class="rb-name" id="rb-n-' + r._uid + '">' + h(r.name || rbT('rb.unnamed')) + '</span>' +
      '<span class="' + sev[0] + '" id="rb-sev-' + r._uid + '">' + h(rbT(sev[1])) + '</span>' +
      (r.scope === 'global' ? '<span class="badge bl" id="rb-sc-' + r._uid + '" title="' + h(rbT('rb.scope.globalHelp')) + '">' + h(rbT('rb.scope.global')) + '</span>' : '<span id="rb-sc-' + r._uid + '"></span>') +
      (r._new ? '<span class="badge gn">' + h(rbT('rb.unsaved')) + '</span>' : '') +
      '<span class="rb-sum" id="rb-sum-' + r._uid + '">' + h(rbSummary(r)) + '</span>' +
      '<button class="btn sm" onclick="rbToggle(' + r._uid + ')">' + h(rbT(open ? 'rb.collapse' : 'rb.edit')) + '</button>' +
      '<button class="btn sm" onclick="rbDup(' + r._uid + ')">' + h(rbT('rb.duplicate')) + '</button>' +
      '<button class="btn sm danger" onclick="rbDel(' + r._uid + ')">' + h(rbT('common.delete')) + '</button>' +
    '</div>' + (open ? rbFormHtml(r) : '') + '</div>';
}

function rbField(uid, field, label, value, opts = {}) {
  const type = opts.type || 'text';
  return '<div class="nf-field' + (opts.full ? ' nf-full' : '') + '"><label>' + h(label) + '</label>' +
    '<input type="' + type + '"' + (type === 'number' ? ' min="' + (opts.min || 1) + '"' : '') + ' value="' + h(value == null ? '' : value) + '"' +
    (opts.placeholder ? ' placeholder="' + h(opts.placeholder) + '"' : '') + (opts.mono ? ' spellcheck="false" style="font-family:monospace"' : '') +
    ' oninput="rbSet(' + uid + ',\'' + field + '\',this.value)">' +
    (opts.hint ? '<div class="nf-hint">' + h(opts.hint) + '</div>' : '') + '</div>';
}

function rbFormHtml(r) {
  const u = r._uid, bl = r.blocklist;
  const sel = (field, val, options) => '<select onchange="rbSet(' + u + ',\'' + field + '\',this.value)">' +
    options.map(o => '<option value="' + h(o[0]) + '"' + (o[0] === val ? ' selected' : '') + '>' + h(o[1]) + '</option>').join('') + '</select>';
  return '<div class="rb-body">' +
    '<div class="rb-sec">' + h(rbT('rb.sec.identity')) + '</div>' +
    '<div class="nf-grid">' +
      rbField(u, 'name', rbT('rb.f.name'), r.name, { hint: rbT('rb.f.nameHint'), mono: true }) +
      '<div class="nf-field"><label>' + h(rbT('rb.f.severity')) + '</label>' + sel('severity', r.severity, [['low', rbT('rb.sev.low')], ['medium', rbT('rb.sev.medium')], ['high', rbT('rb.sev.high')]]) + '</div>' +
      rbField(u, 'id', rbT('rb.f.id'), r.id, { type: 'number', min: 100, hint: rbT('rb.f.idHint') }) +
      rbField(u, 'description', rbT('rb.f.description'), r.description, { full: true }) +
    '</div>' +

    '<div class="rb-sec">' + h(rbT('rb.sec.match')) + '</div>' +
    '<div class="nf-hint" style="margin-bottom:6px">' + h(rbT('rb.sec.matchHelp')) + '</div>' +
    '<div class="nf-grid">' +
      rbField(u, 'pathHint', rbT('rb.f.path'), r.pathHint, { mono: true, full: true, placeholder: '/(wp-login\\.php|xmlrpc\\.php)', hint: rbT('rb.f.pathHint') }) +
      rbField(u, 'uaHint', rbT('rb.f.ua'), r.uaHint, { mono: true, full: true, placeholder: 'sqlmap|nikto', hint: rbT('rb.f.uaHint') }) +
      rbField(u, 'statusIn', rbT('rb.f.status'), r.statusIn.join(', '), { placeholder: '401, 403', hint: rbT('rb.f.statusHint') }) +
      '<div class="nf-field"><label>' + h(rbT('rb.f.methods')) + '</label><div class="rb-checks">' +
        RB_METHODS.map(m => '<label><input type="checkbox" ' + (r.methodIn.includes(m) ? 'checked' : '') + ' onchange="rbMethod(' + u + ',\'' + m + '\',this.checked)"> ' + m + '</label>').join('') +
      '</div><div class="nf-hint">' + h(rbT('rb.f.methodsHint')) + '</div></div>' +
    '</div>' +

    '<div class="rb-sec">' + h(rbT('rb.sec.trigger')) + '</div>' +
    '<div class="nf-grid">' +
      '<div class="nf-field"><label>' + h(rbT('rb.f.scope')) + '</label>' + sel('scope', r.scope, [['ip', rbT('rb.scope.ip')], ['global', rbT('rb.scope.global')]]) +
        '<div class="nf-hint">' + h(rbT('rb.scope.help')) + '</div></div>' +
      rbField(u, 'minMatches', rbT('rb.f.minMatches'), r.minMatches, { type: 'number' }) +
      rbField(u, 'windowMinutes', rbT('rb.f.window'), r.windowMinutes, { type: 'number', hint: rbT('rb.f.windowHint') }) +
      (r.scope === 'global' ? rbField(u, 'minIps', rbT('rb.f.minIps'), r.minIps, { type: 'number', hint: rbT('rb.f.minIpsHint') }) : '') +
    '</div>' +
    '<div class="rb-sentence" id="rb-sent-' + u + '">' + h(rbSentence(r)) + '</div>' +

    '<div class="rb-sec">' + h(rbT('rb.sec.block')) + '</div>' +
    '<div class="nf-hint" style="margin-bottom:6px">' + h(rbT('rb.sec.blockHelp')) + '</div>' +
    '<div class="nf-grid">' +
      rbField(u, 'bl.threshold', rbT('rb.f.blThreshold'), bl.threshold, { type: 'number', placeholder: rbT('rb.f.off'), hint: rbT('rb.f.blThresholdHint') }) +
      rbField(u, 'bl.windowMinutes', rbT('rb.f.blWindow'), bl.windowMinutes, { type: 'number' }) +
      '<div class="nf-field"><label>' + h(rbT('rb.f.blRemediation')) + '</label><label><input type="checkbox" style="width:auto" ' + (bl.remediation ? 'checked' : '') + ' onchange="rbSet(' + u + ',\'bl.remediation\',this.checked)"> ' + h(rbT('rb.f.blRemediationLbl')) + '</label>' +
        '<div class="nf-hint">' + h(rbT('rb.f.blRemediationHint')) + '</div></div>' +
      '<div class="nf-field"><label>' + h(rbT('rb.f.blType')) + '</label>' + sel('bl.remediationType', bl.remediationType || 'block', [['block', rbT('rb.f.blTypeBlock')], ['challenge', rbT('rb.f.blTypeChallenge')]]) +
        '<div class="nf-hint">' + h(rbT('rb.f.blTypeHint')) + '</div></div>' +
      rbField(u, 'bl.remediationMinutes', rbT('rb.f.blDuration'), bl.remediationMinutes, { type: 'number', placeholder: rbT('rb.f.blDurationPh'), hint: rbT('rb.f.blDurationHint') }) +
    '</div>' +

    '<div class="rb-sec">' + h(rbT('rb.sec.test')) + '</div>' +
    '<div class="rb-test"><div class="nf-hint">' + h(rbT('rb.test.help')) + '</div>' +
      '<div class="nf-grid" style="margin-top:6px">' +
        '<div class="nf-field"><label>' + h(rbT('rb.test.path')) + '</label><input type="text" id="rb-tp-' + u + '" spellcheck="false" style="font-family:monospace" oninput="rbTest(' + u + ')"></div>' +
        '<div class="nf-field"><label>' + h(rbT('rb.test.ua')) + '</label><input type="text" id="rb-tu-' + u + '" spellcheck="false" style="font-family:monospace" oninput="rbTest(' + u + ')"></div>' +
        '<div class="nf-field"><label>' + h(rbT('rb.test.method')) + '</label><input type="text" id="rb-tm-' + u + '" value="GET" oninput="rbTest(' + u + ')"></div>' +
        '<div class="nf-field"><label>' + h(rbT('rb.test.status')) + '</label><input type="text" id="rb-ts-' + u + '" value="200" oninput="rbTest(' + u + ')"></div>' +
      '</div><div class="rb-test-res" id="rb-tr-' + u + '"></div></div>' +
  '</div>';
}

// ── Edition ────────────────────────────────────────────────────────────────
const rbFind = uid => RB.rules.find(r => r._uid === uid);

function rbMarkDirty() {
  RB.dirty = true;
  const disc = rbEl('rb-discard');
  if (disc) disc.style.display = '';
  rbStatus(rbT('rb.dirty'), null);
}

function rbSet(uid, field, value) {
  const r = rbFind(uid);
  if (!r) return;
  const num = v => (v === '' || v == null ? null : Number(v));
  switch (field) {
    case 'enable': r.enable = !!value; break;
    case 'bl.remediation': r.blocklist.remediation = !!value; break;
    case 'bl.remediationType': r.blocklist.remediationType = value === 'challenge' ? 'challenge' : 'block'; break;
    case 'bl.threshold': r.blocklist.threshold = num(value); break;
    case 'bl.windowMinutes': r.blocklist.windowMinutes = num(value); break;
    case 'bl.remediationMinutes': r.blocklist.remediationMinutes = num(value); break;
    case 'id': case 'minMatches': case 'windowMinutes': case 'minIps': r[field] = num(value); break;
    case 'statusIn': r.statusIn = String(value).split(/[\s,;]+/).filter(Boolean).map(Number).filter(n => Number.isFinite(n)); break;
    default: r[field] = value;
  }
  rbMarkDirty();
  // La portee change les champs affiches : on redessine ; sinon, mise a jour locale (le focus reste dans le champ).
  if (field === 'scope') { rbRerenderCard(r); return; }
  rbRefreshDerived(r);
  if (field === 'enable') { const c = rbEl('rb-card-' + uid); if (c) c.classList.toggle('off', !r.enable); }
}

function rbRerenderCard(r) {
  const c = rbEl('rb-card-' + r._uid);
  if (c) c.outerHTML = rbCardHtml(r);
}

function rbRefreshDerived(r) {
  const u = r._uid;
  const set = (id, txt) => { const el = rbEl(id); if (el) el.textContent = txt; };
  set('rb-n-' + u, r.name || rbT('rb.unnamed'));
  set('rb-sum-' + u, rbSummary(r));
  set('rb-sent-' + u, rbSentence(r));
  const sev = RB_SEV[r.severity] || RB_SEV.medium, sevEl = rbEl('rb-sev-' + u);
  if (sevEl) { sevEl.className = sev[0]; sevEl.textContent = rbT(sev[1]); }
  rbTest(u);
}

function rbMethod(uid, m, on) {
  const r = rbFind(uid);
  if (!r) return;
  r.methodIn = RB_METHODS.filter(x => (x === m ? on : r.methodIn.includes(x)));
  rbMarkDirty();
  rbRefreshDerived(r);
}

function rbToggle(uid) {
  if (RB.open.has(uid)) RB.open.delete(uid); else RB.open.add(uid);
  const r = rbFind(uid);
  if (r) rbRerenderCard(r);
}

function rbAdd() {
  const r = rbBlank();
  r._new = true;
  RB.rules.push(r);
  RB.open.add(r._uid);
  rbMarkDirty();
  rbRender();
  const c = rbEl('rb-card-' + r._uid);
  if (c) c.scrollIntoView({ block: 'center' });
}

function rbDup(uid) {
  const r = rbFind(uid);
  if (!r) return;
  const copy = JSON.parse(JSON.stringify(r));
  copy._uid = ++RB.seq; copy._new = true; copy.id = rbNextId();
  copy.name = (r.name || 'regle') + '_copie';
  RB.rules.splice(RB.rules.indexOf(r) + 1, 0, copy);
  RB.open.add(copy._uid);
  rbMarkDirty();
  rbRender();
}

function rbDel(uid) {
  const r = rbFind(uid);
  if (!r) return;
  if (!confirm(rbT('rb.confirmDelete', { name: r.name || '#' + r.id }))) return;
  RB.rules.splice(RB.rules.indexOf(r), 1);
  RB.open.delete(uid);
  rbMarkDirty();
  rbRender();
}

function rbDiscard() {
  RB.dirty = false;
  rulesLoad();
}

// ── Testeur : a quoi correspond la regle ? (expressions JS, le moteur est insensible a la casse) ──
function rbTest(uid) {
  const r = rbFind(uid), out = rbEl('rb-tr-' + uid);
  if (!r || !out) return;
  const path = (rbEl('rb-tp-' + uid) || {}).value || '', ua = (rbEl('rb-tu-' + uid) || {}).value || '';
  const method = ((rbEl('rb-tm-' + uid) || {}).value || '').trim().toUpperCase(), status = Number(((rbEl('rb-ts-' + uid) || {}).value || '').trim());
  if (!path && !ua) { out.innerHTML = ''; return; }
  const chips = [];
  const chip = (ok, label) => chips.push('<span class="badge ' + (ok ? 'gn' : 'rd') + '">' + h(label) + '</span>');
  let all = true;
  const re = (src, subject, label) => {
    if (!src) return;
    let ok = false;
    try { ok = new RegExp(src, 'i').test(subject); } catch { chips.push('<span class="badge rd">' + h(label + ' : ' + rbT('rb.test.badRegex')) + '</span>'); all = false; return; }
    chip(ok, label); if (!ok) all = false;
  };
  re(r.pathHint, path, rbT('rb.crit.path'));
  if (r.uaHint) { if (!ua) { chips.push('<span class="badge am">' + h(rbT('rb.crit.ua') + ' : ' + rbT('rb.test.noUa')) + '</span>'); all = false; } else re(r.uaHint, ua, rbT('rb.crit.ua')); }
  if (r.statusIn.length) { const ok = r.statusIn.includes(status); chip(ok, rbT('rb.crit.status')); if (!ok) all = false; }
  if (r.methodIn.length) { const ok = r.methodIn.includes(method); chip(ok, rbT('rb.f.methods')); if (!ok) all = false; }
  out.innerHTML = '<span class="badge ' + (all ? 'gn' : 'gy') + '" style="font-weight:700">' + h(rbT(all ? 'rb.test.match' : 'rb.test.noMatch')) + '</span>' + chips.join('');
}

// ── Enregistrement : formulaire -> YAML (validation serveur) -> analyzer ────
function rbStatus(msg, ok) {
  const el = rbEl('rb-status');
  if (!el) return;
  el.textContent = msg || '';
  el.style.color = ok === null ? 'var(--text3)' : ok ? 'var(--green)' : 'var(--red)';
}

function rbPayload() {
  return RB.rules.map(r => ({
    id: r.id, name: r.name, enable: r.enable, severity: r.severity, description: r.description, scope: r.scope,
    minIps: r.minIps, minMatches: r.minMatches, windowMinutes: r.windowMinutes, pathHint: r.pathHint, uaHint: r.uaHint,
    statusIn: r.statusIn, methodIn: r.methodIn, blocklist: r.blocklist,
  }));
}

async function rbSave() {
  if (RB.saving) return;
  const errBox = rbEl('rb-errors');
  errBox.style.display = 'none';
  RB.saving = true; rbRender();
  try {
    const conv = await api('/analyzer/rules/to-yaml', { method: 'POST', body: JSON.stringify({ rules: rbPayload() }) });
    if (!conv || !conv.ok) {
      errBox.style.display = '';
      errBox.textContent = ((conv && conv.errors) || [rbT('common.error')]).join('\n');
      return;
    }
    const r = await api('/analyzer/rules/custom', { method: 'POST', body: JSON.stringify({ yaml: conv.yaml }) });
    if (!r || !r.ok) {
      errBox.style.display = '';
      errBox.textContent = ((r && r.errors) || [rbT('analyzer.rules.saveError')]).join('\n');
      return;
    }
    RB.dirty = false;
    const yamlBox = rbEl('rules-custom-yaml');
    if (yamlBox) delete yamlBox.dataset.touched;
    rbStatus(rbT('rb.saved', { n: r.count != null ? r.count : RB.rules.length }), true);
    RB.saving = false;
    await rulesLoad();
    rbStatus(rbT('rb.saved', { n: RB.rules.length }), true);
  } finally {
    RB.saving = false; rbRender();
  }
}

// ── Modeles par application ────────────────────────────────────────────────
async function rbLoadTemplates() {
  const box = rbEl('rb-tpl-list');
  if (!box) return;
  if (!RB.packs) {
    box.innerHTML = '<div class="nf-hint">…</div>';
    const d = await api('/analyzer/rules/templates?lang=' + encodeURIComponent(LANG));
    RB.packs = (d && d.packs) || [];
  }
  rbRenderTemplates();
}

function rbRenderTemplates() {
  const box = rbEl('rb-tpl-list');
  if (!box) return;
  const have = new Set(RB.rules.map(r => (r.name || '').toLowerCase()));
  box.innerHTML = RB.packs.map(p => {
    const missing = p.rules.filter(r => !have.has(r.name.toLowerCase())).length;
    return '<div class="rb-pack"><div class="row" style="align-items:flex-start;gap:8px;justify-content:space-between">' +
      '<div><div class="ctitle" style="font-size:13px">' + h(p.title) + '</div><div class="psub">' + h(p.description) + '</div>' +
      (p.note ? '<div class="nf-hint" style="margin-top:4px">' + h(p.note) + '</div>' : '') + '</div>' +
      '<button class="btn sm" ' + (missing ? '' : 'disabled') + ' onclick="rbAddPack(\'' + h(p.id) + '\')">' + h(rbT(missing ? 'rb.tpl.addPack' : 'rb.tpl.allAdded', { n: missing })) + '</button></div>' +
      p.rules.map(r => {
        const added = have.has(r.name.toLowerCase());
        const sev = RB_SEV[r.severity] || RB_SEV.medium;
        return '<div class="rb-pack-rule"><span class="' + sev[0] + '">' + h(rbT(sev[1])) + '</span>' +
          (r.scope === 'global' ? '<span class="badge bl">' + h(rbT('rb.scope.global')) + '</span>' : '') +
          (r.enable ? '' : '<span class="badge gy">' + h(rbT('rb.tpl.offByDefault')) + '</span>') +
          '<span class="rb-id">' + h(r.name) + '</span>' +
          '<span class="rb-desc">' + h(r.description) + '<div class="nf-hint">' + h(rbSummary(rbFromTemplate(r))) + '</div></span>' +
          '<button class="btn sm" ' + (added ? 'disabled' : '') + ' onclick="rbAddTemplate(\'' + h(p.id) + '\',\'' + h(r.slug) + '\')">' + h(rbT(added ? 'rb.tpl.added' : 'rb.tpl.add')) + '</button></div>';
      }).join('') + '</div>';
  }).join('');
}

function rbFromTemplate(tpl) {
  const r = rbFromServer({ ...tpl, enabled: tpl.enable, id: 0 });
  r.name = tpl.name;
  return r;
}

function rbInsertTemplate(tpl) {
  const r = rbFromTemplate(tpl);
  r.id = rbNextId();
  r._new = true;
  RB.rules.push(r);
}

function rbAddTemplate(packId, slug) {
  const p = (RB.packs || []).find(x => x.id === packId);
  const tpl = p && p.rules.find(x => x.slug === slug);
  if (!tpl) return;
  if (!RB.rules.some(r => r.name.toLowerCase() === tpl.name.toLowerCase())) rbInsertTemplate(tpl);
  rbMarkDirty();
  rbAfterTemplateAdd();
}

function rbAddPack(packId) {
  const p = (RB.packs || []).find(x => x.id === packId);
  if (!p) return;
  for (const tpl of p.rules) {
    if (!RB.rules.some(r => r.name.toLowerCase() === tpl.name.toLowerCase())) rbInsertTemplate(tpl);
  }
  rbMarkDirty();
  rbAfterTemplateAdd();
}

function rbAfterTemplateAdd() {
  rbRenderTemplates();
  const cnt = rbEl('rb-count');
  if (cnt) cnt.textContent = String(RB.rules.length);
  rbStatus(rbT('rb.tpl.addedHint'), null);
}

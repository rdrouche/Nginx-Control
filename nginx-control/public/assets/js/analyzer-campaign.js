// ── ALERTE DE CAMPAGNE (regle d'analyse personnalisee scope: global) ──────────
// Script global classique (t(), LANG, copyToClipboard() du script principal). Appele par
// analyzer.js (carte d'alerte) : anCampaignPanel(alerte) -> element DOM, ou null.
// Tout le texte passe par textContent (jamais d'HTML construit depuis les preuves).

const AN_CAMP_REFUSED = new Set([401, 403, 404, 405, 429, 444, 499]);

function anCampEl(tag, cls, text, style) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  if (style) e.style.cssText = style;
  return e;
}

function anCampTable(headers, rows) {
  const tb = anCampEl('table', '', null, 'width:100%;border-collapse:collapse;font-size:11px;font-family:monospace');
  const thead = anCampEl('tr');
  for (const hd of headers) thead.appendChild(anCampEl('th', '', hd, 'text-align:left;padding:3px 6px;color:var(--text3);border-bottom:1px solid var(--border2)'));
  tb.appendChild(thead);
  for (const r of rows) {
    const tr = anCampEl('tr');
    for (const c of r) tr.appendChild(anCampEl('td', '', c == null ? '—' : String(c), 'padding:3px 6px;border-bottom:1px dashed var(--border2);word-break:break-all;vertical-align:top'));
    tb.appendChild(tr);
  }
  return tb;
}

function anCampSection(title) {
  const box = anCampEl('div', '', null, 'margin-top:10px');
  box.appendChild(anCampEl('div', '', title, 'font-weight:600;font-size:12px;margin-bottom:4px'));
  return box;
}

function anCampFmt(ts) {
  return ts ? new Date(ts).toLocaleString(LANG === 'fr' ? 'fr-FR' : 'en-GB', { dateStyle: 'short', timeStyle: 'medium' }) : '—';
}

function anCampaignPanel(a) {
  const e = a && a.evidence;
  if (!e || e.campaign !== true) return null;
  const ips = Array.isArray(e.ips) ? e.ips : [];
  const root = anCampEl('div', 'an-expl', null, 'margin-top:8px');

  // Chiffres cles
  const chips = anCampEl('div', '', null, 'display:flex;flex-wrap:wrap;gap:6px');
  const chip = (txt, cls) => chips.appendChild(anCampEl('span', 'badge ' + (cls || 'gy'), txt));
  chip(t('analyzer.campaign.ips', { n: e.globalIps }), 'bl');
  chip(t('analyzer.campaign.requests', { n: e.globalMatches }), 'am');
  if (e.requestsPerMinute != null) chip(t('analyzer.campaign.rate', { n: e.requestsPerMinute }));
  chip(t('analyzer.campaign.window', { n: e.windowMinutes }));
  chip(anCampFmt(e.firstSeen) + ' → ' + anCampFmt(e.lastSeen));
  if (Array.isArray(e.vhosts) && e.vhosts.length) chip(e.vhosts.join(', '));
  if (e.renewal) chip(t('analyzer.campaign.renewal'), 'gn');
  root.appendChild(chips);

  // Part deja refusee (444/403/429...) : informe la decision (le blocage est-il utile ?).
  const sts = e.statuses || {};
  const totalSt = Object.values(sts).reduce((s, n) => s + n, 0);
  const refused = Object.entries(sts).filter(([c]) => AN_CAMP_REFUSED.has(+c)).reduce((s, [, n]) => s + n, 0);
  if (totalSt) {
    const pct = Math.round((refused / totalSt) * 100);
    root.appendChild(anCampEl('div', '', t(pct >= 80 ? 'analyzer.campaign.mostlyRefused' : 'analyzer.campaign.served', { pct }), 'margin-top:8px;font-size:12px;color:' + (pct >= 80 ? 'var(--green)' : 'var(--amber)')));
  }

  if (Array.isArray(e.topPaths) && e.topPaths.length) {
    const sec = anCampSection(t('analyzer.campaign.topPaths'));
    sec.appendChild(anCampTable([t('analyzer.campaign.col.count'), t('analyzer.campaign.col.path')], e.topPaths.map(p => [p.count, p.path])));
    root.appendChild(sec);
  }
  if (Array.isArray(e.topUserAgents) && e.topUserAgents.length) {
    const sec = anCampSection(t('analyzer.campaign.topUas'));
    sec.appendChild(anCampTable([t('analyzer.campaign.col.count'), 'User-Agent'], e.topUserAgents.map(u => [u.count, u.ua])));
    root.appendChild(sec);
  }
  if (totalSt) {
    const sec = anCampSection(t('analyzer.campaign.statuses'));
    const row = anCampEl('div', '', null, 'display:flex;flex-wrap:wrap;gap:6px');
    for (const [code, n] of Object.entries(sts)) row.appendChild(anCampEl('span', 'badge ' + (AN_CAMP_REFUSED.has(+code) ? 'gy' : 'gn'), code + ' × ' + n));
    sec.appendChild(row);
    root.appendChild(sec);
  }
  if (Array.isArray(e.samples) && e.samples.length) {
    const sec = anCampSection(t('analyzer.campaign.samples', { n: e.samples.length }));
    sec.appendChild(anCampTable(['IP', t('analyzer.campaign.col.path'), t('analyzer.campaign.col.code'), 'User-Agent'], e.samples.map(s => [s.ip, s.path, s.status, s.ua])));
    root.appendChild(sec);
  }

  // Liste complete des adresses : consultable et copiable (une IP par ligne), c'est ce que lit le blocage.
  const sec = anCampSection(t('analyzer.campaign.ipList', { n: ips.length }));
  const text = ips.map(p => p[0]).join('\n');
  const btns = anCampEl('div', '', null, 'display:flex;gap:6px;flex-wrap:wrap');
  const area = anCampEl('textarea', '', null, 'display:none;width:100%;min-height:140px;margin-top:6px;font-family:monospace;font-size:11px;background:var(--bg);color:var(--text);border:1px solid var(--border2);border-radius:var(--r);padding:6px');
  area.readOnly = true; area.value = ips.map(p => p[0] + '  ×' + p[1]).join('\n');
  const show = anCampEl('button', 'btn sm', t('analyzer.campaign.showIps'));
  show.addEventListener('click', () => { const open = area.style.display === 'none'; area.style.display = open ? '' : 'none'; show.textContent = t(open ? 'analyzer.campaign.hideIps' : 'analyzer.campaign.showIps'); });
  const copy = anCampEl('button', 'btn sm', t('analyzer.campaign.copyIps'));
  copy.addEventListener('click', async () => {
    const ok = await copyToClipboard(text);
    const old = copy.textContent; copy.textContent = t(ok ? 'common.copyDone' : 'common.copyFailed');
    setTimeout(() => { copy.textContent = old; }, 1500);
  });
  btns.appendChild(show); btns.appendChild(copy);
  sec.appendChild(btns); sec.appendChild(area);
  if (e.ipsTruncated) sec.appendChild(anCampEl('div', 'nf-hint', t('analyzer.campaign.truncated', { n: ips.length, total: e.globalIps }), 'margin-top:4px'));
  root.appendChild(sec);

  root.appendChild(anCampEl('div', 'nf-hint', t('analyzer.campaign.decide'), 'margin-top:10px'));
  return root;
}

/** Preuves brutes sans la longue liste d'IP (deja affichee ci-dessus). */
function anCampaignRaw(e) {
  const copy = { ...e };
  if (Array.isArray(copy.ips)) copy.ips = '[' + copy.ips.length + ' IP — voir la liste]';
  return copy;
}

// ── Recherche globale du header (v12.67.0) ─────────────────────────────────────
// Ctrl+K ou « / » pour ouvrir. Cherche dans : les pages du menu, les fichiers de
// configuration nginx (sites, conf.d, snippets, streams) et les fichiers de
// configuration des intégrations (page Configuration). Filtre aussi le menu en direct.
// Aucun innerHTML avec des valeurs dynamiques : tout passe par textContent.

let gsFilesCache = null;   // { at, items }
const GS_TTL_MS = 60_000;
let gsResults = [];
let gsActive = 0;

function gsNorm(s) {
  return String(s || '').toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '');
}

// Pages du menu actuellement disponibles (items non masqués par les droits / fonctionnalités).
function gsMenuItems() {
  const out = [];
  let section = '';
  document.querySelectorAll('nav > .ns, nav > .ni').forEach(el => {
    if (el.classList.contains('ns')) {
      section = (el.querySelector('span') || el).textContent.trim();
      return;
    }
    if (el.style.display === 'none' || !el.dataset.page) return;
    const label = (el.querySelector('span:not(.nb)') || el).textContent.trim();
    if (label) out.push({ kind: 'page', label, sub: section, page: el.dataset.page, el });
  });
  return out;
}

async function gsLoadFiles() {
  if (gsFilesCache && Date.now() - gsFilesCache.at < GS_TTL_MS) return gsFilesCache.items;
  const items = [];
  const [cfg, ced] = await Promise.all([
    api('/configs').catch(() => null),
    api('/config-editor/files').catch(() => null),
  ]);
  if (cfg) {
    for (const [key, label] of [['sites', 'Sites'], ['conf', 'conf.d'], ['snippets', 'Snippets'], ['streams', 'Streams']]) {
      for (const f of (cfg[key] && cfg[key].files) || []) {
        items.push({ kind: 'file', label: f.name, sub: label, section: key });
      }
    }
  }
  if (ced) {
    for (const f of ced.files || []) items.push({ kind: 'cfg', label: f.label, sub: f.key + '.yml', key: f.key });
  }
  gsFilesCache = { at: Date.now(), items };
  return items;
}

function gsScore(item, q) {
  const l = gsNorm(item.label), s = gsNorm(item.sub);
  if (l === q) return 100;
  if (l.startsWith(q)) return 80;
  if (l.includes(q)) return 60;
  if (s.includes(q)) return 30;
  return 0;
}

function gsFilterMenu(q) {
  document.querySelectorAll('nav > .ni').forEach(el => {
    const hit = !q || gsNorm(el.textContent).includes(q);
    el.classList.toggle('gs-dim', !hit);
  });
}

async function gsSearch() {
  const input = document.getElementById('gs-input');
  const q = gsNorm(input.value.trim());
  gsFilterMenu(q);
  const box = document.getElementById('gs-results');
  if (!q) { box.style.display = 'none'; gsResults = []; return; }
  const pages = gsMenuItems();
  let files = [];
  try { files = await gsLoadFiles(); } catch (e) { /* recherche limitee au menu */ }
  if (gsNorm(input.value.trim()) !== q) return; // saisie plus recente
  gsResults = [...pages, ...files]
    .map(i => ({ i, s: gsScore(i, q) })).filter(x => x.s > 0)
    .sort((a, b) => b.s - a.s || a.i.label.localeCompare(b.i.label))
    .slice(0, 30).map(x => x.i);
  gsActive = 0;
  gsRender();
}

const GS_KIND_KEY = { page: 'gs.kind.page', file: 'gs.kind.file', cfg: 'gs.kind.cfg' };

function gsRender() {
  const box = document.getElementById('gs-results');
  box.textContent = '';
  box.style.display = '';
  if (!gsResults.length) {
    const e = document.createElement('div');
    e.className = 'gs-empty';
    e.textContent = t('gs.noResult');
    box.appendChild(e);
    return;
  }
  gsResults.forEach((r, idx) => {
    const row = document.createElement('div');
    row.className = 'gs-row' + (idx === gsActive ? ' active' : '');
    const k = document.createElement('span'); k.className = 'gs-kind'; k.textContent = t(GS_KIND_KEY[r.kind]);
    const l = document.createElement('span'); l.className = 'gs-label'; l.textContent = r.label;
    const s = document.createElement('span'); s.className = 'gs-sub'; s.textContent = r.sub || '';
    row.appendChild(k); row.appendChild(l); row.appendChild(s);
    row.addEventListener('mousedown', ev => { ev.preventDefault(); gsGo(r); });
    row.addEventListener('mousemove', () => { if (gsActive !== idx) { gsActive = idx; gsHighlight(); } });
    box.appendChild(row);
  });
}

function gsHighlight() {
  document.querySelectorAll('#gs-results .gs-row').forEach((r, i) => r.classList.toggle('active', i === gsActive));
  const cur = document.querySelector('#gs-results .gs-row.active');
  if (cur && cur.scrollIntoView) cur.scrollIntoView({ block: 'nearest' });
}

async function gsGo(r) {
  gsClose();
  if (r.kind === 'page') { openPage(r.page); return; }
  if (r.kind === 'cfg') {
    openPage('config-editor');
    const wait = async () => { for (let i = 0; i < 30 && !(typeof cfgEditorFiles !== 'undefined' && cfgEditorFiles.some(f => f.key === r.key)); i++) await new Promise(ok => setTimeout(ok, 100)); };
    await wait();
    if (typeof cfgEditorSelect === 'function') { cfgEditorCurrent = r.key; cfgEditorRenderList(); await cfgEditorSelect(r.key); }
    return;
  }
  if (r.kind === 'file') {
    openPage('configs');
    for (let i = 0; i < 30; i++) {
      if (typeof cfgFileMap !== 'undefined' && Object.keys(cfgFileMap).length) break;
      await new Promise(ok => setTimeout(ok, 100));
    }
    const sec = document.getElementById('sec-' + r.section);
    if (sec) sec.style.display = '';
    const idx = Object.keys(cfgFileMap).find(k => cfgFileMap[k].name === r.label && cfgFileMap[k]._section === r.section);
    if (idx != null) {
      const row = document.getElementById('cfi-' + idx);
      if (row && row.scrollIntoView) row.scrollIntoView({ block: 'center' });
      openFile(Number(idx));
    }
  }
}

function gsClose() {
  const input = document.getElementById('gs-input');
  if (input) { input.value = ''; input.blur(); }
  const box = document.getElementById('gs-results');
  if (box) box.style.display = 'none';
  gsResults = [];
  gsFilterMenu('');
}

function gsInit() {
  const input = document.getElementById('gs-input');
  if (!input) return;
  input.addEventListener('input', gsSearch);
  input.addEventListener('focus', () => { gsLoadFiles().catch(() => {}); if (input.value) gsSearch(); });
  input.addEventListener('blur', () => setTimeout(() => {
    const box = document.getElementById('gs-results');
    if (box) box.style.display = 'none';
  }, 120));
  input.addEventListener('keydown', ev => {
    if (ev.key === 'Escape') { gsClose(); return; }
    if (!gsResults.length) return;
    if (ev.key === 'ArrowDown') { ev.preventDefault(); gsActive = (gsActive + 1) % gsResults.length; gsHighlight(); }
    else if (ev.key === 'ArrowUp') { ev.preventDefault(); gsActive = (gsActive - 1 + gsResults.length) % gsResults.length; gsHighlight(); }
    else if (ev.key === 'Enter') { ev.preventDefault(); gsGo(gsResults[gsActive]); }
  });
  document.addEventListener('keydown', ev => {
    const tag = (ev.target && ev.target.tagName) || '';
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(tag) || (ev.target && ev.target.isContentEditable);
    if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 'k') { ev.preventDefault(); input.focus(); input.select(); }
    else if (ev.key === '/' && !typing && !ev.ctrlKey && !ev.metaKey && !ev.altKey) { ev.preventDefault(); input.focus(); }
  });
}
document.addEventListener('DOMContentLoaded', gsInit);
if (document.readyState !== 'loading') gsInit();

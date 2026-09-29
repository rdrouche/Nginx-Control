'use strict';
/**
 * Sections repliables du menu de navigation, persistées par section dans
 * localStorage. Extrait de public/index.html (voir CHANGELOG.md).
 */
// Le menu s est charge au fil des fonctionnalites (12 items rien que dans
// "Integrations"). Plutot que de re-designer toute la nav, chaque en-tete de
// section (.ns) devient un simple bouton pliant/depliant qui masque les .ni
// qui le suivent jusqu a la prochaine .ns — persiste par section dans
// localStorage pour ne pas re-plier a chaque navigation/rafraichissement.
const NAV_COLLAPSE_KEY = 'ngx_nav_collapsed';

function loadNavCollapseState() {
  try { return JSON.parse(localStorage.getItem(NAV_COLLAPSE_KEY) || '{}'); }
  catch (e) { return {}; }
}

function saveNavCollapseState(state) {
  try { localStorage.setItem(NAV_COLLAPSE_KEY, JSON.stringify(state)); } catch (e) { /* navigation privee, etc. */ }
}

// Renvoie, pour un .ns donne, la liste des .ni qui lui appartiennent
// (tous les freres suivants jusqu a la prochaine .ns ou la fin du <nav>).
function navSectionItems(nsEl) {
  const items = [];
  let el = nsEl.nextElementSibling;
  while (el && !el.classList.contains('ns')) {
    if (el.classList.contains('ni')) items.push(el);
    el = el.nextElementSibling;
  }
  return items;
}

function setNavSectionCollapsed(nsEl, collapsed, state) {
  const key = nsEl.dataset.section;
  nsEl.classList.toggle('collapsed', collapsed);
  navSectionItems(nsEl).forEach(ni => ni.classList.toggle('nav-hidden', collapsed));
  if (key && state) {
    if (collapsed) state[key] = true; else delete state[key];
  }
}

function initNavSections() {
  const state = loadNavCollapseState();
  document.querySelectorAll('nav > .ns[data-section]').forEach(ns => {
    setNavSectionCollapsed(ns, !!state[ns.dataset.section], null);
    ns.addEventListener('click', () => {
      const cur = loadNavCollapseState();
      const collapsed = !ns.classList.contains('collapsed');
      setNavSectionCollapsed(ns, collapsed, cur);
      saveNavCollapseState(cur);
    });
  });
}

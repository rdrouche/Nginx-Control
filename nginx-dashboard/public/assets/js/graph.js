'use strict';
/**
 * Page "Schéma" (visualisation graphique des vhosts) — extrait de
 * public/index.html dans le cadre du decoupage JS (voir CHANGELOG.md), meme
 * demarche que crowdsec.js/vhost-generator.js/system-info.js. Charge apres le
 * script inline principal : partage le meme scope global (api(), h(), svgEsc(),
 * ...), pas un module ES.
 *
 * Reutilise telle quelle la resolution de /api/backends (aucune route
 * dediee) : ce n en est qu une seconde presentation, un dessin plutot qu une
 * liste. SVG construit a la main (pas de librairie) — coherent avec le reste
 * du projet, zero dependance npm.
 *
 * renderVhostGraphSvg() est aussi appelee depuis l onglet "Schéma" du panneau
 * Diagnostic (voir public/assets/js/diagnostic.js#renderDiagGraph()) — les
 * deux partagent ce meme rendu plutot que d en dupliquer un second.
 */
const GRAPH_KIND_COLOR = { direct:'#8b93a1', upstream:'#2dd4bf', docker:'#4f8cff', variable:'#f5a623', unresolved:'#ff4d6a' };
let graphVhosts = [];

/** Largeur approximative d un texte en police monospace (chaque caractere a la meme largeur, ~0.62x la taille de police). */
function svgTextWidth(text, fontSize){ return String(text).length * fontSize * 0.62; }

/** Un vhost -> ses locations avec au moins une cible resolue (statique, non resolu sans cible, ou redirection pure : rien a dessiner). */
function graphRowsFor(v){
  const rows = [];
  (v.serverBlocks||[]).forEach(b => {
    if (b.redirectsToHttps && (!b.locations || !b.locations.length)) return;
    (b.locations||[]).forEach(loc => {
      if (!loc.targets || !loc.targets.length) return;
      rows.push({ ssl: b.ssl, path: loc.path, kind: loc.kind, targets: loc.targets });
    });
  });
  return rows;
}

/**
 * [VHOST] --chemin--> [CIBLE(S)], en eventail quand une location a plusieurs
 * cibles (LB/HA) — le schema demande a l origine : "[REVERSER] -- HTTP
 * (8080) -- [TARGET]", pour tous les vhosts ou pour un seul (mode `big`,
 * plus lisible, utilise quand un vhost precis est selectionne).
 */
function renderVhostGraphSvg(v, { big = false } = {}){
  const rows = graphRowsFor(v);
  if (!rows.length) return '<div style="color:var(--text3);font-size:11px;padding:6px 0">Rien à schématiser (pas de backend résolu)</div>';

  const rowH = big ? 34 : 26;
  const fontSize = big ? 12 : 10.5;
  const pad = big ? 20 : 16;

  // Largeurs calculees a partir du texte reel plutot que fixes : un nom de
  // vhost ou une cible un peu longs etaient soit tronques soit debordaient
  // de leur boite (et pouvaient alors chevaucher le libelle du chemin sur la
  // fleche). Le conteneur appelant scrolle horizontalement au besoin
  // (overflow-x:auto), donc rien n a besoin d etre coupe ici.
  const vhostLabel = (v.name || '').replace(/\.conf(\.DISABLE)?$/, '');
  const minBoxW = big ? 150 : 120;
  const vhostW = Math.max(minBoxW, svgTextWidth(vhostLabel, fontSize + 0.5) + pad, svgTextWidth('HTTPS', fontSize - 1) + pad);

  const targetLabelText = (t) => `${t.scheme}://${t.host}:${t.port}`;
  let targetW = minBoxW;
  rows.forEach(r => r.targets.forEach(t => {
    targetW = Math.max(targetW, svgTextWidth(targetLabelText(t), fontSize - 1) + pad);
  }));

  const midGap = big ? 90 : 70;

  let y = 12;
  const blocks = rows.map(r => {
    const n = Math.max(1, r.targets.length);
    const blockH = n * rowH;
    const block = { r, top: y, mid: y + blockH / 2, n };
    y += blockH;
    return block;
  });
  const totalH = y + 12;
  const x0 = 4, vhostRight = x0 + vhostW, anchorX = vhostRight + midGap / 2, targetX = vhostRight + midGap;
  const width = targetX + targetW + 16;

  // Largeur fixe (pas de width="100%") : le schema garde sa taille naturelle
  // et le conteneur scrolle plutot que de le retrecir (ce qui aurait aussi
  // retreci le texte jusqu a le rendre illisible).
  let svg = `<svg viewBox="0 0 ${width} ${totalH}" width="${width}" height="${totalH}" style="display:block;font-family:monospace">`;
  svg += `<rect x="${x0}" y="4" width="${vhostW}" height="${totalH - 8}" rx="6" fill="#1b2130" stroke="#3a4257"/>`;
  svg += `<text x="${x0 + vhostW / 2}" y="${totalH / 2 - (rows.length > 1 ? 6 : 0)}" text-anchor="middle" fill="#e8ecf4" font-size="${fontSize + 0.5}" font-weight="600"><title>${svgEsc(vhostLabel)}</title>${svgEsc(vhostLabel)}</text>`;
  svg += `<text x="${x0 + vhostW / 2}" y="${totalH / 2 + 12}" text-anchor="middle" fill="${rows[0].ssl ? '#2dd4bf' : '#8b93a1'}" font-size="${fontSize - 1}">${rows[0].ssl ? 'HTTPS' : 'HTTP'}</text>`;

  blocks.forEach(({ r, top, mid, n }) => {
    svg += `<line x1="${vhostRight}" y1="${mid}" x2="${anchorX}" y2="${mid}" stroke="#3a4257" stroke-width="1.5"/>`;
    svg += `<text x="${(vhostRight + anchorX) / 2}" y="${mid - 6}" text-anchor="middle" fill="#8b93a1" font-size="${fontSize - 2}"><title>${svgEsc(r.path)}</title>${svgEsc(r.path)}</text>`;
    svg += `<circle cx="${anchorX}" cy="${mid}" r="2.5" fill="#3a4257"/>`;
    if (n > 1) svg += `<text x="${anchorX}" y="${top - 2}" text-anchor="middle" fill="#f5a623" font-size="${fontSize - 2}">LB/HA (${n})</text>`;
    r.targets.forEach((t, i) => {
      const ty = top + rowH * i + rowH / 2;
      const color = GRAPH_KIND_COLOR[r.kind] || GRAPH_KIND_COLOR.unresolved;
      const label = targetLabelText(t);
      svg += `<line x1="${anchorX}" y1="${mid}" x2="${targetX}" y2="${ty}" stroke="${color}" stroke-width="1.5" opacity="0.7"/>`;
      svg += `<rect x="${targetX}" y="${ty - rowH / 2 + 3}" width="${targetW}" height="${rowH - 6}" rx="5" fill="${color}22" stroke="${color}"/>`;
      svg += `<text x="${targetX + targetW / 2}" y="${ty + 4}" text-anchor="middle" fill="${color}" font-size="${fontSize - 1}"><title>${svgEsc(label)}</title>${svgEsc(label)}</text>`;
    });
  });
  svg += '</svg>';
  return svg;
}

async function loadGraph(){
  const list = document.getElementById('graph-list');
  const sel = document.getElementById('graph-select');
  const d = await api('/backends').catch(()=>null);
  if(!d){ list.innerHTML = '<div class="card" style="color:var(--red)">Erreur — impossible de lire les vhosts</div>'; return; }
  graphVhosts = (d.vhosts||[]).filter(v => graphRowsFor(v).length);
  document.getElementById('graph-count').textContent = graphVhosts.length;
  const current = sel.value || '__all__';
  sel.innerHTML = `<option value="__all__">Tous les vhosts (${graphVhosts.length})</option>` +
    graphVhosts.map(v => `<option value="${h(v.name)}">${h(v.name)}</option>`).join('');
  sel.value = [...sel.options].some(o=>o.value===current) ? current : '__all__';
  renderGraphView(sel.value);
}

function renderGraphView(selected){
  const list = document.getElementById('graph-list');
  if(!graphVhosts.length){ list.innerHTML = '<div class="card" style="color:var(--text3)">Aucun vhost avec un backend à schématiser</div>'; return; }
  const isSingle = selected && selected !== '__all__';
  const toShow = isSingle ? graphVhosts.filter(v => v.name === selected) : graphVhosts;
  list.innerHTML = toShow.map(v => `<div class="card">
    <div style="font-family:monospace;font-size:11px;color:var(--text3);margin-bottom:4px">${h(v.name)}</div>
    <div style="overflow-x:auto">${renderVhostGraphSvg(v, { big: isSingle })}</div>
  </div>`).join('');
}

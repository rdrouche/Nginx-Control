'use strict';
/**
 * Page "Certificats SSL" — extrait de public/index.html dans le cadre du
 * decoupage JS (voir CHANGELOG.md), meme demarche que crowdsec.js/
 * vhost-generator.js/system-info.js. Charge apres le script inline principal :
 * partage le meme scope global (api(), h(), ...), pas un module ES.
 */
async function loadSSL(){
  const d = await api('/ssl').catch(()=>null);
  const cards = document.getElementById('ssl-cards');
  if(!d){cards.innerHTML='<div class="card" style="color:var(--red)">Erreur — volumes montés ?</div>';return;}
  const s=d.summary||{};
  document.getElementById('ssl-total').textContent=s.total||0;
  document.getElementById('ssl-ok').textContent=s.ok||0;
  document.getElementById('ssl-warn').textContent=s.warning||0;
  document.getElementById('ssl-exp').textContent=s.expired||0;
  document.getElementById('ssl-count').textContent=s.total||0;
  if(!d.certificates?.length){cards.innerHTML='<div class="card" style="color:var(--text3)">Aucun certificat trouvé dans les répertoires montés</div>';return;}
  cards.innerHTML = d.certificates.map((c,i)=>{
    if(c.error) return`<div class="cert-card"><div class="cert-info"><div class="cert-name">${h(c.name)}</div><div class="cert-domain" style="color:var(--red)">${h(c.error)}</div></div></div>`;
    const cls=c.expired?'exp':c.warning?'warn':'';
    const dayColor=c.expired?'var(--red)':c.warning?'var(--amber)':'var(--green)';
    const iconColor=c.expired?'var(--red)':c.warning?'var(--amber)':'var(--green)';
    const iconBg=c.expired?'var(--red-dim)':c.warning?'var(--amber-dim)':'var(--green-dim)';
    const pct=Math.max(0,Math.min(100,c.daysLeft>0?Math.min(c.daysLeft,365)/365*100:0));
    const barColor=c.expired?'#ff4d6a':c.warning?'#f5a623':'#00e87a';
    // Extract CN from subject
    const cn=(c.subject||'').match(/CN=([^,\n]+)/)?.[1]||c.name;
    const issuerCN=(c.issuer||'').match(/CN=([^,\n]+)/)?.[1]||c.issuer||'—';
    const sourceBadge=c.source==='certbot'?`<span class="badge te">Let's Encrypt</span>`:`<span class="badge gy">Manuel</span>`;
    return`<div class="cert-card ${cls}" onclick="toggleCert(${i})">
      <div class="cert-icon" style="background:${iconBg}">
        <svg viewBox="0 0 24 24" stroke="${iconColor}"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
      </div>
      <div class="cert-info">
        <div class="cert-name">${h(cn)}</div>
        <div class="cert-domain">${h(c.sans?.slice(0,3).join(', '))||h(cn)}</div>
        <div class="cert-meta">
          ${sourceBadge}
          <span class="badge ${c.expired?'rd':c.warning?'am':'gn'}">${c.expired?'EXPIRÉ':c.warning?'EXPIRE BIENTÔT':'VALIDE'}</span>
          <span>Émis par: ${h(issuerCN)}</span>
          <span>${h(c.keyType?.toUpperCase()||'?')}</span>
        </div>
        <div class="progress-wrap"><div class="progress-bar" style="width:${pct}%;background:${barColor}"></div></div>
        <div class="cert-detail" id="cert-detail-${i}">
          <div class="cert-detail-row"><span class="cert-detail-k">Sujet</span><span class="cert-detail-v">${h(c.subject||'—')}</span></div>
          <div class="cert-detail-row"><span class="cert-detail-k">Émetteur</span><span class="cert-detail-v">${h(c.issuer||'—')}</span></div>
          <div class="cert-detail-row"><span class="cert-detail-k">Valide du</span><span class="cert-detail-v">${c.validFrom?new Date(c.validFrom).toLocaleString('fr'):'-'}</span></div>
          <div class="cert-detail-row"><span class="cert-detail-k">Expire le</span><span class="cert-detail-v" style="color:${dayColor}">${c.validTo?new Date(c.validTo).toLocaleString('fr'):'-'}</span></div>
          <div class="cert-detail-row"><span class="cert-detail-k">Jours restants</span><span class="cert-detail-v" style="color:${dayColor};font-weight:600">${c.daysLeft}</span></div>
          <div class="cert-detail-row"><span class="cert-detail-k">Numéro série</span><span class="cert-detail-v">${h(c.serialNumber||'—')}</span></div>
          <div class="cert-detail-row"><span class="cert-detail-k">Fingerprint</span><span class="cert-detail-v" style="font-size:10px">${h(c.fingerprint||'—')}</span></div>
          <div class="cert-detail-row"><span class="cert-detail-k">SHA-256</span><span class="cert-detail-v" style="font-size:10px">${h(c.fingerprint256||'—')}</span></div>
          ${c.sans?.length?`<div class="cert-detail-row"><span class="cert-detail-k">SANs (${c.sans.length})</span><div class="cert-detail-v"><div class="sans-list">${c.sans.map(s=>`<span class="san-tag">${h(s)}</span>`).join('')}</div></div></div>`:''}
          <div class="cert-detail-row"><span class="cert-detail-k">Fichier</span><span class="cert-detail-v" style="font-size:10px">${h(c.path||'—')}</span></div>
          <div class="cert-detail-row"><span class="cert-detail-k">Source</span><span class="cert-detail-v">${h(c.source||'—')}</span></div>
        </div>
      </div>
      <div class="cert-days">
        <div class="days-num" style="color:${dayColor}">${c.daysLeft<0?0:c.daysLeft}</div>
        <div class="days-lab">jours</div>
        <span class="badge ${c.source==='certbot'?'te':'gy'}" style="font-size:9px">${c.source==='certbot'?"Let's Encrypt":'SSL manuel'}</span>
      </div>
    </div>`;
  }).join('');
}

function toggleCert(i){
  const el=document.getElementById('cert-detail-'+i);
  el?.classList.toggle('open');
}

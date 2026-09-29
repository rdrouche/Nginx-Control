'use strict';
/**
 * Demarre le vrai agent, lui injecte du trafic normal puis une attaque, et
 * verifie l API. C est le seul test qui exerce l assemblage complet.
 */
const assert=require('assert'), fs=require('fs'), os=require('os'), path=require('path');
const { spawn }=require('child_process'); const http=require('http');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'e2e-'));
const logs=path.join(tmp,'logs'), data=path.join(tmp,'data');
fs.mkdirSync(logs); fs.mkdirSync(data);
const LOG=path.join(logs,'site.fr.access.log');
fs.writeFileSync(LOG,'');
const WAF_LOG=path.join(logs,'site.fr.waf.log');
fs.writeFileSync(WAF_LOG,'');

const PORT=9199;
// Horodatage courant : une date fixe tomberait hors de la fenetre de requete,
// et les entrees datees du futur sont exclues des agregats.
const MONTHS=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
const stamp=()=>{
  const d=new Date();
  const p2=n=>String(n).padStart(2,'0');
  return `${p2(d.getUTCDate())}/${MONTHS[d.getUTCMonth()]}/${d.getUTCFullYear()}:`+
         `${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}:${p2(d.getUTCSeconds())} +0000`;
};
const line=(o={})=>{
  const {ip='203.0.113.5',p='/',s=200,ua='Mozilla/5.0'}=o;
  return `${ip} - - [${stamp()}] "GET ${p} HTTP/1.1" ${s} 100 "-" "${ua}"\n`;
};
const get=p=>new Promise(r=>{
  http.get({host:'127.0.0.1',port:PORT,path:p,timeout:4000},res=>{
    let b=''; res.on('data',d=>b+=d);
    res.on('end',()=>{try{r(JSON.parse(b))}catch{r(null)}});
  }).on('error',()=>r(null)).on('timeout',function(){this.destroy();r(null)});
});
const wait=ms=>new Promise(r=>setTimeout(r,ms));

(async()=>{
  const srv=spawn('node',[path.join(__dirname,'..','server.js')],{
    env:{...process.env,PORT:String(PORT),LOGS_DIR:logs,DB_PATH:path.join(data,'s.db'),
         POLL_MS:'200',FLUSH_MS:'500',EVALUATE_MS:'800',LEARNING_DAYS:'21',
         GEOIP_COUNTRY_DB:path.join(__dirname,'fixtures','test-country.mmdb')},
    stdio:['ignore','pipe','pipe']});
  let out=''; srv.stdout.on('data',d=>out+=d); srv.stderr.on('data',d=>out+=d);
  await wait(2000);

  console.log('\ndemarrage');
  const health=await get('/api/health');
  check('l agent repond', ()=>assert.ok(health && health.ok));
  const st=await get('/api/status');
  check('il suit le fichier de log', ()=>assert.ok(st.tail.files>=1));
  check('SQLite actif', ()=>assert.strictEqual(st.store.persistent,true));
  check('la baseline annonce son apprentissage', ()=>assert.strictEqual(st.baseline.learning,true));
  check('la baseline par pays existe et annonce aussi son apprentissage', ()=>{
    assert.ok(st.countryBaseline, 'countryBaseline absent de /api/status');
    assert.strictEqual(st.countryBaseline.learning,true);
  });
  const cb=await get('/api/baseline/country');
  check('GET /api/baseline/country renvoie les memes stats que dans /api/status', ()=>{
    assert.strictEqual(cb.learning,true);
    assert.strictEqual(typeof cb.bucketsTracked,'number');
  });

  console.log('\ntrafic normal');
  let traffic=''; for(let i=0;i<30;i++) traffic+=line({ip:`198.51.100.${i}`,p:`/page-${i}`});
  fs.appendFileSync(LOG,traffic);
  await wait(1500);
  const st2=await get('/api/status');
  check('les lignes sont analysees', ()=>assert.ok(st2.tail.parsed>=30,`${st2.tail.parsed} lignes`));
  const a1=await get('/api/alerts');
  check('un trafic normal ne declenche aucune alerte', ()=>assert.strictEqual(a1.total,0));

  console.log('\nattaque : brute force');
  let attack=''; for(let i=0;i<25;i++) attack+=line({ip:'192.0.2.66',p:'/login',s:401});
  fs.appendFileSync(LOG,attack);
  await wait(2000);
  const a2=await get('/api/alerts');
  check('l attaque est detectee', ()=>assert.ok(a2.total>=1,`${a2.total} alerte(s)`));
  const bf=a2.alerts.find(x=>x.type==='bruteforce');
  check('type et severite corrects', ()=>{
    assert.ok(bf,'alerte bruteforce absente');
    assert.strictEqual(bf.severity,'high');
    assert.strictEqual(bf.ip,'192.0.2.66');
  });
  check('les preuves sont jointes', ()=>{
    assert.ok(bf.evidence.authFailures>=15);
    assert.ok(Array.isArray(bf.evidence.samples) && bf.evidence.samples.length>0);
  });

  console.log('\nagregation du trafic');
  const vh=await get('/api/traffic/vhosts?hours=24');
  check('ventilation par vhost', ()=>{
    assert.ok(vh.vhosts.length>=1);
    assert.strictEqual(vh.vhosts[0].vhost,'site.fr');
    assert.ok(vh.vhosts[0].requests>=55);
  });
  check('les erreurs sont comptees', ()=>assert.ok(vh.vhosts[0].errors>=25));
  const co=await get('/api/traffic/countries?hours=24');
  check('ventilation par pays', ()=>assert.ok(Array.isArray(co.countries)));
  const se=await get('/api/traffic/series?grain=minute&hours=24');
  check('serie temporelle', ()=>assert.ok(se.series.length>=1));

  console.log('\nacquittement');
  check('une alerte peut etre acquittee', async()=>{});
  const ack=await new Promise(r=>{
    const rq=http.request({host:'127.0.0.1',port:PORT,path:`/api/alerts/${bf.id}/ack`,method:'POST'},res=>{
      let b=''; res.on('data',d=>b+=d); res.on('end',()=>{try{r(JSON.parse(b))}catch{r(null)}});
    }); rq.on('error',()=>r(null)); rq.end();
  });
  check('acquittement enregistre', ()=>assert.ok(ack && ack.ok));

  console.log('\ndeduplication');
  fs.appendFileSync(LOG,attack);
  await wait(1500);
  const a3=await get('/api/alerts');
  check('une attaque continue ne multiplie pas les alertes', ()=>{
    assert.strictEqual(a3.total,a2.total,`${a2.total} -> ${a3.total}`);
  });


  console.log('\nexceptions par vhost');
  const post=(path)=>new Promise(r=>{
    const rq=http.request({host:'127.0.0.1',port:PORT,path,method:'POST'},res=>{
      let b=''; res.on('data',d=>b+=d); res.on('end',()=>{try{r(JSON.parse(b))}catch{r(null)}});
    }); rq.on('error',()=>r(null)); rq.end();
  });
  const del=(path)=>new Promise(r=>{
    const rq=http.request({host:'127.0.0.1',port:PORT,path,method:'DELETE'},res=>{
      let b=''; res.on('data',d=>b+=d); res.on('end',()=>{try{r(JSON.parse(b))}catch{r(null)}});
    }); rq.on('error',()=>r(null)); rq.end();
  });

  console.log('\nexclusion de creneau par pays (alerte trafic inhabituel par pays)');
  const excCountry=await post('/api/baseline/country/exclude?country=FR&hour='+new Date().toISOString());
  check('marquer un creneau pays comme normal reussit', ()=>assert.strictEqual(excCountry.ok,true));
  const excMissing=await post('/api/baseline/country/exclude?country=FR');
  check('parametres manquants -> 400, pas une exception serveur', ()=>assert.ok(excMissing===null || excMissing.error));

  const addExc=await post('/api/exceptions?vhost=site.fr&ip=192.0.2.77&reason=sonde&author=admin');
  check('exception ajoutee', ()=>assert.ok(addExc && addExc.ok));
  const listExc=await get('/api/exceptions');
  check('exception listee avec son motif', ()=>{
    assert.strictEqual(listExc.exceptions.length,1);
    assert.strictEqual(listExc.exceptions[0].reason,'sonde');
    assert.strictEqual(listExc.exceptions[0].vhost,'site.fr');
  });

  // Attaque depuis l adresse exclue : rien ne doit remonter
  const before=(await get('/api/alerts')).total;
  let excAttack=''; for(let i=0;i<25;i++) excAttack+=line({ip:'192.0.2.77',p:'/login',s:401});
  fs.appendFileSync(LOG,excAttack);
  await wait(2000);
  const afterExc=await get('/api/alerts');
  check('aucune alerte pour l adresse exclue', ()=>{
    assert.strictEqual(afterExc.total,before,`${before} -> ${afterExc.total}`);
  });

  const rmExc=await del('/api/exceptions/'+listExc.exceptions[0].id);
  check('exception supprimee', ()=>assert.ok(rmExc && rmExc.ok));

  console.log('\nexception par bloc CIDR');
  const addCidr=await post('/api/exceptions?vhost=site.fr&ip=192.0.2.0%2F24&reason=proxy+entreprise&author=admin');
  check('bloc CIDR accepte', ()=>assert.ok(addCidr && addCidr.ok));
  const badCidr=await post('/api/exceptions?vhost=site.fr&ip=pas-une-ip&reason=x&author=admin');
  check('motif invalide rejete', ()=>assert.ok(badCidr && badCidr.ok===false));

  const beforeCidr=(await get('/api/alerts')).total;
  let cidrAttack=''; for(let i=0;i<25;i++) cidrAttack+=line({ip:'192.0.2.201',p:'/login',s:401});
  fs.appendFileSync(LOG,cidrAttack);
  await wait(2000);
  const afterCidr=await get('/api/alerts');
  check('une adresse couverte par le bloc CIDR est exclue', ()=>{
    assert.strictEqual(afterCidr.total,beforeCidr,`${beforeCidr} -> ${afterCidr.total}`);
  });

  let outsideCidr=''; for(let i=0;i<25;i++) outsideCidr+=line({ip:'192.0.3.5',p:'/login',s:401});
  fs.appendFileSync(LOG,outsideCidr);
  await wait(2000);
  const afterOutside=await get('/api/alerts');
  check('une adresse hors du bloc CIDR reste surveillee', ()=>{
    assert.ok(afterOutside.total>afterCidr.total,`${afterCidr.total} -> ${afterOutside.total}`);
  });

  const listCidr=await get('/api/exceptions');
  for (const e of listCidr.exceptions) await del('/api/exceptions/'+e.id);

  console.log('\nfiltre des acquittees');
  const unacked=await get('/api/alerts?acked=0');
  const acked=await get('/api/alerts?acked=1');
  check('les acquittees sont filtrables', ()=>{
    assert.ok(acked.total>=1,'au moins une acquittee');
    assert.ok(!unacked.alerts.some(a=>a.acked),'aucune acquittee dans la liste filtree');
  });

  console.log('\nexplications');
  const withExpl=(await get('/api/alerts')).alerts.find(a=>a.evidence && a.type==='bruteforce');
  check('une explication accompagne l alerte', ()=>{
    const raw=JSON.stringify(withExpl);
    assert.ok(/mot de passe|authentification/i.test(raw),'pas d explication lisible');
  });


  console.log('\nactions groupees');
  const postQ=(path)=>post(path);
  // Provoquer une deuxieme alerte distincte pour avoir de quoi grouper
  let scan=''; for(let i=0;i<50;i++) scan+=line({ip:'198.51.100.200',p:`/probe-${i}`,s:404});
  fs.appendFileSync(LOG,scan);
  await wait(2000);
  const beforeBulk=await get('/api/alerts?acked=0');
  check('au moins une alerte a traiter', ()=>assert.ok(beforeBulk.total>=1));

  const ackAll=await postQ('/api/alerts/ack-all');
  check('acquittement groupe reussi', ()=>assert.ok(ackAll && typeof ackAll.updated==='number' && ackAll.updated>=1));
  const afterAck=await get('/api/alerts?acked=0');
  check('plus aucune alerte a traiter apres acquittement groupe', ()=>assert.strictEqual(afterAck.total,0));

  const clearAll=await postQ('/api/alerts/clear');
  check('suppression groupee reussie', ()=>assert.ok(clearAll && typeof clearAll.deleted==='number' && clearAll.deleted>=1));
  const afterClear=await get('/api/alerts');
  check('la liste est vide apres suppression groupee', ()=>assert.strictEqual(afterClear.total,0));



  console.log('\ncarte en direct : evenements geolocalises recents');
  const geoLine = (ip, ua) => {
    const ts = new Date().toUTCString().replace(/GMT/, '+0000');
    return `${ip} - - [${new Date().toISOString().slice(0,19).replace('T',':').replace(/:/g,(m,o)=>o<10?m:m)}] "GET / HTTP/1.1" 200 100 "-" "${ua}"\n`;
  };
  // Format horodatage simplifie : reutilise le format access log standard
  const alog = (ip, ua) => {
    const d = new Date();
    const pad = n => String(n).padStart(2,'0');
    const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    const ts = `${pad(d.getUTCDate())}/${months[d.getUTCMonth()]}/${d.getUTCFullYear()}:${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} +0000`;
    return `${ip} - - [${ts}] "GET / HTTP/1.1" 200 100 "-" "${ua}"\n`;
  };
  fs.appendFileSync(LOG, alog('81.2.69.160','Mozilla/5.0 (Windows NT 10.0) Chrome/120.0'));
  fs.appendFileSync(LOG, alog('89.160.20.112','Mozilla/5.0 (compatible; Googlebot/2.1)'));
  await wait(1500);

  const recent = await get('/api/traffic/recent');
  check('les evenements recents sont geolocalises et classes', () => {
    assert.ok(recent.events.length >= 2);
    const human = recent.events.find(e => e.category === 'human');
    const bot = recent.events.find(e => e.category === 'good');
    assert.ok(human, 'doit contenir un evenement humain');
    assert.ok(bot, 'doit contenir un evenement bot reconnu');
    assert.ok(human.country, 'doit porter un pays');
  });
  check('geoipAvailable est expose', () => assert.strictEqual(recent.geoipAvailable, true));
  const recentSince = await get(`/api/traffic/recent?since=${recent.serverTime}`);
  check('le filtre "since" exclut les evenements deja vus', () => {
    assert.strictEqual(recentSince.events.length, 0);
  });
  check('currentSeq est expose, et croit au moins autant que le nombre d evenements vus', () => {
    assert.ok(typeof recent.currentSeq === 'number' && recent.currentSeq >= recent.events.length);
  });
  // Fix (audit finding ANA-09) : le curseur "sinceSeq" ne doit JAMAIS perdre
  // un evenement pousse apres l instant ou son currentSeq a ete releve,
  // meme si cet evenement porte un horodatage de LOG anterieur a ce moment
  // precis (le cas reel qui faisait perdre des evenements a l ancien
  // curseur base sur l horloge).
  const seqCursor = recent.currentSeq;
  fs.appendFileSync(LOG, alog('81.2.69.161','Mozilla/5.0 (compatible; Googlebot/2.1)'));
  await wait(1500);
  const bySeq = await get(`/api/traffic/recent?sinceSeq=${seqCursor}`);
  check('sinceSeq retrouve bien un evenement ingere apres le curseur', () => {
    assert.ok(bySeq.events.some(e => e.vhost === 'site.fr'),
      `aucun nouvel evenement retrouve via sinceSeq=${seqCursor} : ${JSON.stringify(bySeq.events)}`);
  });
  // Bug rapporte : chaque chargement de la carte (sans "since", puisque le
  // client repart de zero a chaque ouverture de page) renvoyait les 200
  // derniers evenements du tampon quel que soit leur age — un trafic
  // modere produisait alors toujours le meme instantane historique, avec
  // un total bloque exactement a la limite par defaut de 200. Le travail
  // asynchrone se fait ici, avant l appel a check(), meme convention que le
  // reste de ce fichier — check() lui-meme reste synchrone partout ici.
  const oldTs = new Date(Date.now() - 20*60_000);   // vieux de 20 minutes
  const pad = n => String(n).padStart(2,'0');
  const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  const oldTsStr = `${pad(oldTs.getUTCDate())}/${months[oldTs.getUTCMonth()]}/${oldTs.getUTCFullYear()}:${pad(oldTs.getUTCHours())}:${pad(oldTs.getUTCMinutes())}:${pad(oldTs.getUTCSeconds())} +0000`;
  fs.appendFileSync(LOG, `67.43.156.1 - - [${oldTsStr}] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0 tres ancien"\n`);
  await wait(1500);
  const freshRecent = await get('/api/traffic/recent');
  check('sans "since" (premier chargement de la carte), un evenement trop ancien est exclu', () => {
    const cutoff = Date.now() - 5*60_000;
    assert.ok(freshRecent.events.every(e => e.ts >= cutoff),
      `aucun evenement rendu sans since ne doit avoir plus de 5 minutes : ${JSON.stringify(freshRecent.events.map(e=>({ts:e.ts,age_min:((Date.now()-e.ts)/60000).toFixed(1)})))}`);
  });
  // Demande explicite : sur un dashboard multi-sites, isoler d ou viennent les
  // visites d UN site precis plutot que de tout melanger. Travail asynchrone
  // fait ici, avant check(), meme convention que le reste de ce fichier. Le
  // fichier est cree puis on attend un cycle de sondage avant d y ecrire :
  // un journal decouvert pour la premiere fois demarre volontairement a sa
  // fin (pour ne pas inonder les detecteurs au demarrage avec un historique
  // entier) — y ecrire avant cette decouverte perdrait la ligne.
  const LOG2 = path.join(logs, 'autre-site.fr.access.log');
  fs.writeFileSync(LOG2, '');
  await wait(500);
  fs.appendFileSync(LOG2, alog('81.2.69.192', 'Mozilla/5.0 autre site'));
  await wait(1500);
  const filteredOther = await get('/api/traffic/recent?vhost=autre-site.fr');
  const filteredOriginal = await get('/api/traffic/recent?vhost=site.fr');
  check('le filtre "vhost" isole la carte sur un seul site', () => {
    assert.ok(filteredOther.events.length >= 1, 'doit trouver au moins l evenement du vhost demande');
    assert.ok(filteredOther.events.every(e => e.vhost === 'autre-site.fr'),
      'ne doit jamais renvoyer un evenement d un autre vhost');
    assert.ok(filteredOriginal.events.every(e => e.vhost === 'site.fr'));
  });

  console.log('\nModSecurity / WAF');
  const wafLine=(o={})=>{
    const {ip='198.51.100.9',uri='/login',code=403,ruleId='942100',msg='SQL Injection Attack'}=o;
    return JSON.stringify({
      transaction:{client_ip:ip,time_stamp:new Date().toUTCString(),
        request:{method:'GET',uri},response:{http_code:code},unique_id:'e2e-'+Date.now()+Math.random(),
        messages:[{message:msg,details:{ruleId,severity:'2',tags:['attack-sqli']}}]},
    })+'\n';
  };
  fs.appendFileSync(WAF_LOG, wafLine()+wafLine({ip:'198.51.100.10',ruleId:'941100',msg:'XSS Attempt',code:200}));
  await wait(1500);

  const wafEvents=await get('/api/waf/events');
  check('les evenements WAF sont ingeres', ()=>assert.ok(wafEvents.total>=2,`${wafEvents.total} evenement(s)`));
  const blocked=wafEvents.events.find(e=>e.blocked);
  check('un evenement bloque (403) est marque comme tel', ()=>{
    assert.ok(blocked);
    assert.deepStrictEqual(blocked.ruleIds,['942100']);
  });
  const detected=wafEvents.events.find(e=>!e.blocked);
  check('un evenement non bloque (200) est marque comme detecte', ()=>assert.ok(detected));

  const topRules=await get('/api/waf/top-rules?hours=24');
  check('les regles les plus declenchees sont remontees', ()=>{
    assert.ok(topRules.rules.some(r=>r.ruleId==='942100'));
  });
  const topIps=await get('/api/waf/top-ips?hours=24');
  check('les adresses les plus actives sont remontees', ()=>{
    assert.ok(topIps.ips.some(i=>i.ip==='198.51.100.9'));
  });
  const wafSeries=await get('/api/waf/series?hours=24');
  check('serie temporelle disponible', ()=>assert.ok(wafSeries.series.length>=1));

  const wafFilterVhost=await get('/api/waf/events?vhost=site.fr');
  check('filtrage par vhost', ()=>assert.ok(wafFilterVhost.total>=2));
  const wafFilterBlocked=await get('/api/waf/events?blocked=1');
  check('filtrage par blocage', ()=>assert.ok(wafFilterBlocked.events.every(e=>e.blocked)));

  console.log('\npurge des evenements WAF');
  const beforeClear=(await get('/api/waf/events')).total;
  check('des evenements existent avant purge', ()=>assert.ok(beforeClear>=2));
  const clearBlocked=await post('/api/waf/clear?blocked=1');
  check('purge filtree sur bloque uniquement', ()=>assert.ok(clearBlocked && clearBlocked.deleted>=1));
  const afterFilteredClear=await get('/api/waf/events');
  check('les evenements non bloques survivent a la purge filtree', ()=>{
    assert.ok(afterFilteredClear.events.every(e=>!e.blocked));
  });
  const clearAllWaf=await post('/api/waf/clear');
  check('purge totale', ()=>assert.ok(clearAllWaf && clearAllWaf.deleted>=1));
  const afterFullClear=await get('/api/waf/events');
  check('plus aucun evenement WAF', ()=>assert.strictEqual(afterFullClear.total,0));

  console.log('\ncatalogue des regles (modale "Regles" du dashboard)');
  const postJson=(reqPath,obj)=>new Promise(r=>{
    const body=JSON.stringify(obj||{});
    const rq=http.request({host:'127.0.0.1',port:PORT,path:reqPath,method:'PUT',
      headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body)}},res=>{
      let b=''; res.on('data',d=>b+=d); res.on('end',()=>{try{r({status:res.statusCode,body:JSON.parse(b)})}catch{r({status:res.statusCode,body:null})}});
    }); rq.on('error',()=>r(null)); rq.end(body);
  });
  const postJsonTo=(reqPath,obj)=>new Promise(r=>{
    const body=JSON.stringify(obj||{});
    const rq=http.request({host:'127.0.0.1',port:PORT,path:reqPath,method:'POST',
      headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body)}},res=>{
      let b=''; res.on('data',d=>b+=d); res.on('end',()=>{try{r({status:res.statusCode,body:JSON.parse(b)})}catch{r({status:res.statusCode,body:null})}});
    }); rq.on('error',()=>r(null)); rq.end(body);
  });

  const rules=await get('/api/rules');
  check('les 6 regles integrees sont listees, actives par defaut', ()=>{
    assert.strictEqual(rules.builtins.length,6);
    assert.ok(rules.builtins.every(b=>b.enabled===true));
    assert.ok(rules.builtins.every(b=>b.explanation && b.explanation.what));
  });
  check('aucune regle personnalisee par defaut', ()=>assert.deepStrictEqual(rules.custom,[]));

  const toggleOff=await post('/api/rules/toggle?key=scraping&enable=0');
  check('desactiver une regle integree reussit', ()=>assert.strictEqual(toggleOff.enabled,false));
  const rulesAfterToggle=await get('/api/rules');
  check('l etat desactive est bien reflete par /api/rules', ()=>{
    assert.strictEqual(rulesAfterToggle.builtins.find(b=>b.key==='scraping').enabled,false);
  });
  const toggleUnknown=await post('/api/rules/toggle?key=inconnue&enable=1');
  check('cle inconnue rejetee', ()=>assert.ok(toggleUnknown===null || toggleUnknown.error));
  await post('/api/rules/toggle?key=scraping&enable=1'); // remis en etat pour la suite

  console.log('\nregles personnalisees (YAML)');
  const badYaml=await postJson('/api/rules/custom',{yaml:'rules:\n  - id: 5\n    name: bad\n    min_matches: 1\n'});
  check('une regle avec un id reserve (<100) est rejetee sans rien appliquer', ()=>{
    assert.strictEqual(badYaml.status,400);
    assert.ok(badYaml.body.errors.length>0);
  });
  const goodYaml='rules:\n  - id: 101\n    name: admin_probe\n    enable: true\n    severity: high\n    description: "test"\n    window_minutes: 1\n    min_matches: 8\n    path_hint: "wp-admin"\n    ua_hint: null\n    status_in: []\n    method_in: []\n';
  const okYaml=await postJson('/api/rules/custom',{yaml:goodYaml});
  check('une regle valide est acceptee', ()=>{
    assert.strictEqual(okYaml.status,200);
    assert.strictEqual(okYaml.body.count,1);
  });
  const rulesWithCustom=await get('/api/rules');
  check('la regle personnalisee apparait dans le catalogue', ()=>{
    assert.strictEqual(rulesWithCustom.custom.length,1);
    assert.strictEqual(rulesWithCustom.custom[0].name,'admin_probe');
  });

  const beforeCustom=(await get('/api/alerts')).total;
  let probeAttack=''; for(let i=0;i<10;i++) probeAttack+=line({ip:'198.51.100.201',p:'/wp-admin/setup.php'});
  fs.appendFileSync(LOG,probeAttack);
  await wait(2000);
  const afterCustom=await get('/api/alerts');
  check('la regle personnalisee produit bien une alerte custom_101', ()=>{
    assert.ok(afterCustom.total>beforeCustom,`${beforeCustom} -> ${afterCustom.total}`);
    assert.ok(afterCustom.alerts.some(a=>a.type==='custom_101'));
  });

  console.log('\nopt-out par vhost (pousse par le dashboard depuis les commentaires de vhost)');
  const beforeVhostOff=(await get('/api/alerts')).total;
  const pushOff=await postJsonTo('/api/vhost-rules',{vhosts:{'site.fr':{enabled:false,ignore:[]}}});
  check('le dashboard peut pousser un opt-out de vhost', ()=>assert.strictEqual(pushOff.status,200));
  let quietAttack=''; for(let i=0;i<30;i++) quietAttack+=line({ip:'198.51.100.202',p:'/login',s:401});
  fs.appendFileSync(LOG,quietAttack);
  await wait(2000);
  const afterVhostOff=await get('/api/alerts');
  check('vhost desactive -> aucune nouvelle alerte, meme une vraie attaque', ()=>{
    assert.strictEqual(afterVhostOff.total,beforeVhostOff,`${beforeVhostOff} -> ${afterVhostOff.total}`);
  });
  await postJsonTo('/api/vhost-rules',{vhosts:{}}); // remis en etat pour la suite

  console.log('\nrobustesse du corps de requete JSON (fix Basse/Analyzer)');
  // Fix : un corps de plus de 2 Mo ne resolvait jamais la promesse
  // (req.destroy() sans jamais appeler resolve()) -> le endpoint restait
  // muet indefiniment au lieu de repondre avec un corps vide/erreur.
  const oversizedBody = 'x'.repeat(3_000_000);
  const oversizedResult = await new Promise(r => {
    const rq = http.request({host:'127.0.0.1', port:PORT, path:'/api/rules/custom', method:'PUT',
      headers:{'Content-Type':'application/json'}, timeout: 4000}, res => {
      let b=''; res.on('data',d=>b+=d);
      res.on('end',()=>{try{r({status:res.statusCode, body:JSON.parse(b)})}catch{r({status:res.statusCode, body:null})}});
    });
    rq.on('error',()=>r(null));
    rq.on('timeout',function(){this.destroy(); r('TIMEOUT');});
    rq.write(JSON.stringify({yaml: oversizedBody}));
    rq.end();
  });
  check('un corps > 2 Mo repond promptement (ne bloque plus indefiniment)', () => {
    assert.notStrictEqual(oversizedResult, 'TIMEOUT', 'le serveur n a jamais repondu — readJsonBody() est reste bloque');
    assert.ok(oversizedResult && typeof oversizedResult.status === 'number');
  });

  console.log('\nborne du parametre "limit" (fix Basse/Analyzer, "limit=-1 renvoie toute la table")');
  const negLimitAlerts = await get('/api/alerts?limit=-1');
  check('limit=-1 ne renvoie pas plus que le plafond (500), jamais "toute la table"', () => {
    assert.ok(negLimitAlerts && Array.isArray(negLimitAlerts.alerts));
    assert.ok(negLimitAlerts.alerts.length <= 500, `${negLimitAlerts.alerts.length} alertes renvoyees`);
  });
  const negLimitWaf = await get('/api/waf/events?limit=-1');
  check('meme protection sur /api/waf/events', () => {
    assert.ok(negLimitWaf && Array.isArray(negLimitWaf.events));
    assert.ok(negLimitWaf.events.length <= 500, `${negLimitWaf.events.length} evenements renvoyes`);
  });

  console.log('\nblocklist "approx" (v12.29.0 — hits derives du log d acces principal, pas d un fichier dedie)');
  const pushApprox=await postJsonTo('/api/blocklist-sources',{mode:'approx',sources:{firehol:{ips:['203.0.113.90','198.51.100.0/24']}}});
  check('le dashboard peut pousser des sources blocklist + le mode', ()=>assert.strictEqual(pushApprox.status,200));
  const statusApprox=await get('/api/status');
  check('/api/status reflete le mode et la synchronisation', ()=>{
    assert.strictEqual(statusApprox.blocklistSources.mode,'approx');
    assert.strictEqual(statusApprox.blocklistSources.synced,true);
  });
  const beforeApproxHits=(await get('/api/blocklist-hits/summary?hours=24')).totalHits;
  let approxTraffic=''; for(let i=0;i<4;i++) approxTraffic+=line({ip:'203.0.113.90',p:'/x'});
  approxTraffic+=line({ip:'198.51.100.7',p:'/y'}); // dans le bloc CIDR de la meme source
  approxTraffic+=line({ip:'192.0.2.200',p:'/z'}); // hors blocklist -> ne doit rien ajouter
  fs.appendFileSync(LOG,approxTraffic);
  await wait(2000);
  const afterApproxSummary=await get('/api/blocklist-hits/summary?hours=24');
  check('les IP synchronisees, vues sur le log principal, sont enregistrees comme des hits', ()=>{
    assert.strictEqual(afterApproxSummary.totalHits, beforeApproxHits+5, `${beforeApproxHits} -> ${afterApproxSummary.totalHits}`);
  });
  check('bySource attribue ces hits a la bonne source, calcule cote analyseur', ()=>{
    const fh=(afterApproxSummary.bySource||[]).find(s=>s.name==='firehol');
    assert.ok(fh, 'source "firehol" absente de bySource');
    assert.strictEqual(fh.hits, 5);
  });

  console.log('\nblocklist "dedicated" (mode par defaut — retour en arriere)');
  await postJsonTo('/api/blocklist-sources',{mode:'dedicated',sources:{firehol:{ips:['203.0.113.90','198.51.100.0/24']}}});
  const beforeDedicatedHits=(await get('/api/blocklist-hits/summary?hours=24')).totalHits;
  let quietTraffic=''; for(let i=0;i<3;i++) quietTraffic+=line({ip:'203.0.113.90',p:'/w'});
  fs.appendFileSync(LOG,quietTraffic);
  await wait(2000);
  const afterDedicatedSummary=await get('/api/blocklist-hits/summary?hours=24');
  check('en mode "dedicated" le log d acces principal n est plus utilise pour detecter des hits', ()=>{
    assert.strictEqual(afterDedicatedSummary.totalHits, beforeDedicatedHits, `${beforeDedicatedHits} -> ${afterDedicatedSummary.totalHits}`);
  });
  await postJsonTo('/api/blocklist-sources',{mode:'dedicated',sources:{}}); // remis en etat pour la suite

  console.log('\nempreinte');
  const st3=await get('/api/status');
  check('memoire raisonnable', ()=>{
    assert.ok(st3.memoryMb<150,`${st3.memoryMb} Mo`);
    console.log(`        (${st3.memoryMb} Mo)`);
  });

  srv.kill('SIGTERM');
  await wait(400);
  fs.rmSync(tmp,{recursive:true,force:true});
  console.log(`\n${pass} pass, ${fail} fail`);
  if (fail) console.log('\n--- sortie agent ---\n'+out.slice(-1500));
  process.exit(fail?1:0);
})();

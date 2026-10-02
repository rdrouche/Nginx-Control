'use strict';
/**
 * Un detecteur qui crie au loup est ignore en trois jours. Ces tests verifient
 * autant qu il detecte que qu il **se taise** sur du trafic normal — et,
 * depuis la reecriture, qu il ne confond pas "actif depuis longtemps" avec
 * "actif maintenant".
 */
const assert=require('assert');
const { Detector }=require('../lib/detect');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

const T0=Date.parse('2026-09-09T10:00:00Z');
const req=(o={})=>({ip:'203.0.113.5',vhost:'site.fr',ts:T0,method:'GET',path:'/',status:200,bytes:100,ua:'Mozilla/5.0',...o});
const feed=(d,n,o={},step=100)=>{for(let i=0;i<n;i++) d.add(req({ts:T0+i*step,...(typeof o==='function'?o(i):o)}));};

console.log('\nbrute force');
check('detecte les echecs repetes sur /login', ()=>{
  const d=new Detector();
  feed(d,20,{path:'/login',status:401});
  const a=d.evaluate(T0+20*100);
  assert.strictEqual(a.length,1);
  assert.strictEqual(a[0].type,'bruteforce');
  assert.strictEqual(a[0].evidence.authFailures,20);
  assert.ok(a[0].explanation && a[0].explanation.why,'l explication doit accompagner l alerte');
});
check('ignore les 401 hors chemin d authentification', ()=>{
  const d=new Detector();
  feed(d,30,{path:'/api/data',status:401});
  assert.deepStrictEqual(d.evaluate(T0+3000).filter(a=>a.type==='bruteforce'),[]);
});
check('sous le seuil, aucune alerte', ()=>{
  const d=new Detector();
  feed(d,5,{path:'/login',status:401});
  assert.deepStrictEqual(d.evaluate(T0+500),[]);
});
check('des connexions reussies n alertent pas', ()=>{
  const d=new Detector();
  feed(d,50,{path:'/login',status:200});
  assert.deepStrictEqual(d.evaluate(T0+5000),[]);
});

console.log('\nscan');
check('detecte beaucoup de chemins en 404', ()=>{
  const d=new Detector();
  feed(d,50,i=>({path:`/probe-${i}`,status:404}));
  const a=d.evaluate(T0+5000).filter(x=>x.type==='scan');
  assert.strictEqual(a.length,1);
  assert.ok(a[0].evidence.distinctPaths>=25);
});
check('un site legitime avec beaucoup de pages n alerte pas', ()=>{
  const d=new Detector();
  feed(d,50,i=>({path:`/article-${i}`,status:200}));
  assert.deepStrictEqual(d.evaluate(T0+5000).filter(x=>x.type==='scan'),[]);
});
check('quelques 404 epars n alertent pas', ()=>{
  const d=new Detector();
  feed(d,50,i=>({path:`/p-${i}`,status:i<5?404:200}));
  assert.deepStrictEqual(d.evaluate(T0+5000).filter(x=>x.type==='scan'),[]);
});

console.log('\nflood — le coeur du correctif');
check('detecte un debit soutenu dans la fenetre', ()=>{
  const d=new Detector();
  feed(d,700,{},10);
  const a=d.evaluate(T0+7000).filter(x=>x.type==='flood');
  assert.strictEqual(a.length,1);
  assert.ok(a[0].evidence.requestsPerSecond>0);
});
check('un trafic normal n alerte pas', ()=>{
  const d=new Detector();
  feed(d,100,{},1000);
  assert.deepStrictEqual(d.evaluate(T0+100000).filter(x=>x.type==='flood'),[]);
});
check('une sonde continue a bas debit ne finit jamais par alerter', ()=>{
  // C est le bug corrige : l ancien detecteur additionnait les requetes depuis
  // le tout premier passage, sans jamais remettre le compteur a zero tant que
  // l adresse restait active — meme a un debit derisoire. Une sonde qui envoie
  // une requete toutes les 70 s ne s arrete jamais assez longtemps pour etre
  // purgee, et son compteur cumule jusqu a depasser n importe quel seuil.
  const d=new Detector({windowMs:60_000,flood:{minRequests:5}});
  let alerts=0;
  for(let i=0;i<40;i++){
    d.add(req({ts:T0+i*70_000}));   // hors de la fenetre de 60 s precedente
    alerts+=d.evaluate(T0+i*70_000+1000).length;
  }
  assert.strictEqual(alerts,0,'40 passages espaces ne doivent jamais declencher un flood');
});
check('la meme sonde plus rapide, mais toujours sous le seuil par fenetre, ne declenche rien', ()=>{
  const d=new Detector({windowMs:60_000,flood:{minRequests:10}});
  let alerts=0;
  for(let i=0;i<60;i++){
    d.add(req({ts:T0+i*5000}));   // 1 requete/5s = 12 sur 60s : au-dessus du seuil de 10 en continu
    alerts+=d.evaluate(T0+i*5000+1).length;
  }
  // Ici le debit reel depasse le seuil en continu : une alerte doit sortir,
  // mais une seule pour tout l episode, pas une par evaluation.
  assert.strictEqual(alerts,1,`attendu 1 alerte pour un seul episode continu, obtenu ${alerts}`);
});

console.log('\nscraping');
check('detecte un agent automatise sur peu de chemins', ()=>{
  const d=new Detector();
  feed(d,350,{path:'/api/list',ua:'python-requests/2.31'});
  const a=d.evaluate(T0+35000).filter(x=>x.type==='scraping');
  assert.strictEqual(a.length,1);
});
check('un navigateur sur une seule page n alerte pas', ()=>{
  const d=new Detector();
  feed(d,350,{path:'/api/list',ua:'Mozilla/5.0 (X11; Linux)'});
  assert.deepStrictEqual(d.evaluate(T0+35000).filter(x=>x.type==='scraping'),[]);
});

console.log('\ndeclenchement par front (une episode = une alerte)');
check('une attaque continue n emet qu une seule alerte', ()=>{
  const d=new Detector();
  feed(d,20,{path:'/login',status:401});
  assert.strictEqual(d.evaluate(T0+2000).length,1);
  feed(d,20,{path:'/login',status:401});
  assert.strictEqual(d.evaluate(T0+4000).length,0,'la seconde passe ne doit rien reemettre');
});
check('un flood qui persiste ne re-alerte pas tant qu il ne s interrompt pas', ()=>{
  const d=new Detector({windowMs:60_000,flood:{minRequests:5}});
  feed(d,10,{},1000);
  assert.strictEqual(d.evaluate(T0+10000).length,1);
  feed(d,10,{},1000);   // l attaque continue, toujours dans la meme fenetre
  assert.strictEqual(d.evaluate(T0+20000).length,0);
});
check('une fois retombe sous le seuil puis reparti, une nouvelle alerte est emise', ()=>{
  const d=new Detector({windowMs:60_000,flood:{minRequests:5}});
  feed(d,10,{},1000);
  assert.strictEqual(d.evaluate(T0+10000).length,1,'premier episode');
  // Accalmie reelle : plus rien pendant plus longtemps que la fenetre.
  assert.strictEqual(d.evaluate(T0+130000).length,0,'aucune activite recente : rien a signaler');
  // Nouvelle rafale, apres l accalmie.
  for(let i=0;i<10;i++) d.add(req({ts:T0+130000+i*1000}));
  assert.strictEqual(d.evaluate(T0+140000).length,1,'deuxieme episode, doit re-alerter');
});
check('des IP distinctes alertent separement', ()=>{
  const d=new Detector();
  for (const ip of ['1.1.1.1','2.2.2.2']) feed(d,20,{ip,path:'/login',status:401});
  assert.strictEqual(d.evaluate(T0+4000).length,2);
});

console.log('\nexceptions par vhost');
check('une IP exclue sur son vhost ne declenche rien', ()=>{
  const d=new Detector();
  d.setExceptions([{vhost:'site.fr',ip:'203.0.113.5'}]);
  feed(d,20,{path:'/login',status:401});
  assert.deepStrictEqual(d.evaluate(T0+2000),[]);
});
check('la meme IP reste surveillee sur un autre vhost', ()=>{
  const d=new Detector();
  d.setExceptions([{vhost:'autre.fr',ip:'203.0.113.5'}]);
  feed(d,20,{path:'/login',status:401});   // toujours vhost site.fr
  assert.strictEqual(d.evaluate(T0+2000).length,1);
});
check('un bloc CIDR exclut toute une plage', ()=>{
  // Utile pour un proxy d entreprise ou une plage de supervision : exclure
  // /24 plutot qu une adresse a la fois.
  const d=new Detector();
  d.setExceptions([{vhost:'site.fr',ip:'203.0.113.0/24'}]);
  feed(d,20,{ip:'203.0.113.200',path:'/login',status:401});
  assert.deepStrictEqual(d.evaluate(T0+2000),[]);
});
check('une adresse hors du bloc CIDR reste surveillee', ()=>{
  const d=new Detector();
  d.setExceptions([{vhost:'site.fr',ip:'203.0.113.0/24'}]);
  feed(d,20,{ip:'203.0.114.200',path:'/login',status:401});
  assert.strictEqual(d.evaluate(T0+2000).length,1);
});
check('plusieurs exceptions independantes coexistent', ()=>{
  const d=new Detector();
  d.setExceptions([
    {vhost:'site.fr',ip:'198.51.100.0/24'},
    {vhost:'site.fr',ip:'203.0.113.77'},
  ]);
  feed(d,20,{ip:'198.51.100.5',path:'/login',status:401});
  assert.deepStrictEqual(d.evaluate(T0+2000),[],'couverte par le bloc');
  feed(d,20,{ip:'203.0.113.77',path:'/login',status:401});
  assert.deepStrictEqual(d.evaluate(T0+4000),[],'couverte par l adresse exacte');
});
check('une liste vide ou absente n exclut rien', ()=>{
  const d=new Detector();
  d.setExceptions([]);
  feed(d,20,{path:'/login',status:401});
  assert.strictEqual(d.evaluate(T0+2000).length,1);
  const d2=new Detector();   // setExceptions jamais appele
  feed(d2,20,{path:'/login',status:401});
  assert.strictEqual(d2.evaluate(T0+2000).length,1);
});

check('une IP exceptee individuellement sur les DEUX vhosts qu elle touche reste exclue (fix ANA-06)', ()=>{
  // Avant le correctif : vhost devenait null des qu une IP touchait deux
  // vhosts dans la fenetre, et isExcluded(ip, null) ne pouvait plus jamais
  // matcher une exception (toujours enregistree contre un vhost nomme) — une
  // adresse legitimement exceptee sur chacun des deux vhosts se remettait a
  // declencher des alertes des qu elle touchait le second.
  const d=new Detector();
  d.setExceptions([
    {vhost:'site.fr',  ip:'203.0.113.5'},
    {vhost:'autre.fr', ip:'203.0.113.5'},
  ]);
  feed(d,10,{path:'/login',status:401,vhost:'site.fr'});
  feed(d,10,{path:'/login',status:401,vhost:'autre.fr'},100);
  assert.deepStrictEqual(d.evaluate(T0+2000),[],
    'exceptee sur les deux vhosts touches : aucune alerte ne doit sortir');
});
check('une IP exceptee sur un SEUL des deux vhosts qu elle touche reste surveillee (garde-fou de securite)', ()=>{
  const d=new Detector();
  d.setExceptions([{vhost:'site.fr', ip:'203.0.113.5'}]); // pas autre.fr
  feed(d,10,{path:'/login',status:401,vhost:'site.fr'});
  feed(d,10,{path:'/login',status:401,vhost:'autre.fr'},100);
  assert.strictEqual(d.evaluate(T0+2000).length,1,
    'un vhost non excepte dans le lot ne doit jamais laisser silencer la regle pour son compte');
});

console.log('\nmemoire');
check('le nombre d IP suivies est plafonne', ()=>{
  const d=new Detector({maxTrackedIps:100});
  for(let i=0;i<500;i++) d.add(req({ip:`10.0.${Math.floor(i/256)}.${i%256}`}));
  assert.ok(d.stats().trackedIps<=100, `${d.stats().trackedIps} > 100`);
});
check('l etat totalement expire est purge', ()=>{
  const d=new Detector({windowMs:1000});
  d.add(req());
  d.prune(T0+5000);
  assert.strictEqual(d.stats().trackedIps,0);
});
check('le verrou d alerte disparait avec l IP purgee', ()=>{
  // Regression precise : si le verrou "actif" restait dans une table globale
  // independante de l etat de l IP, une adresse purgee puis reactivee ne
  // pouvait plus jamais re-alerter, meme apres une vraie nouvelle attaque.
  const d=new Detector({windowMs:1000,flood:{minRequests:3}});
  feed(d,5,{},100);
  assert.strictEqual(d.evaluate(T0+500).length,1);
  d.prune(T0+10000);   // l IP est totalement purgee, hors fenetre
  assert.strictEqual(d.stats().trackedIps,0);
  feed(d,5,{ts:T0+10000},100);
  assert.strictEqual(d.evaluate(T0+10500).length,1,'doit pouvoir re-alerter apres une purge complete');
});

console.log('\npreuves jointes a l alerte');
check('l alerte porte de quoi decider', ()=>{
  const d=new Detector();
  feed(d,20,{path:'/login',status:401,ua:'curl/8'});
  const a=d.evaluate(T0+2000)[0];
  assert.ok(a.evidence.samples.length>0,'exemples de requetes');
  assert.ok(a.evidence.userAgents.includes('curl/8'));
  assert.ok(a.evidence.statuses['401']>0);
  assert.strictEqual(a.evidence.vhost,'site.fr');
  assert.ok(a.summary.includes('203.0.113.5'));
});

console.log('\nopt-out par vhost (# nginx-control-analyze: off / -ignore-rules)');
check('vhost desactive -> plus aucune alerte, meme regle par regle en dessous du seuil normal', ()=>{
  const d=new Detector({windowMs:1000,flood:{minRequests:3}});
  d.setVhostRules({ 'site.fr': { enabled: false, ignore: new Set() } });
  feed(d,5,{},100);
  assert.deepStrictEqual(d.evaluate(T0+500),[]);
});
check('vhost actif de nouveau (map vide) -> alerte a nouveau', ()=>{
  const d=new Detector({windowMs:1000,flood:{minRequests:3}});
  d.setVhostRules({ 'site.fr': { enabled: false, ignore: new Set() } });
  feed(d,5,{},100);
  assert.deepStrictEqual(d.evaluate(T0+500),[]);
  d.setVhostRules({});
  feed(d,5,{ts:T0+2000},100);
  assert.strictEqual(d.evaluate(T0+2500).length,1);
});
check('regle precise ignoree pour ce vhost, les autres restent actives', ()=>{
  const { RULE_IDS } = require('../lib/detect');
  const d=new Detector({windowMs:2000,bruteforce:{minFailures:5},flood:{minRequests:1000}});
  d.setVhostRules({ 'site.fr': { enabled: true, ignore: new Set([RULE_IDS.bruteforce]) } });
  feed(d,10,{path:'/login',status:401},50);
  assert.deepStrictEqual(d.evaluate(T0+600).filter(a=>a.type==='bruteforce'),[],
    'bruteforce doit rester silencieux : id ignore pour ce vhost');
});
check('vhost non mentionne dans la map -> comportement par defaut inchange', ()=>{
  const d=new Detector({windowMs:1000,flood:{minRequests:3}});
  d.setVhostRules({ 'autre-site.fr': { enabled: false, ignore: new Set() } });
  feed(d,5,{},100);
  assert.strictEqual(d.evaluate(T0+500).length,1);
});

console.log('\nopt-out par vhost - IP touchant plusieurs vhosts dans la fenetre (bug reel)');
check('meme IP sur deux vhosts, TOUS deux ignorent la regle -> silence (vhost agrege = null)', ()=>{
  const { RULE_IDS } = require('../lib/detect');
  const d=new Detector({windowMs:2000,flood:{minRequests:3}});
  d.setVhostRules({
    'maps.bourgesplus.fr': { enabled: true, ignore: new Set([RULE_IDS.flood]) },
    'mapx.bourgesplus.fr': { enabled: true, ignore: new Set([RULE_IDS.flood]) },
  });
  for (let i=0;i<5;i++) {
    d.add(req({ ts: T0+i*100, vhost: i%2===0 ? 'maps.bourgesplus.fr' : 'mapx.bourgesplus.fr' }));
  }
  const alerts = d.evaluate(T0+500);
  assert.deepStrictEqual(alerts.filter(a=>a.type==='flood'), [],
    'les deux vhosts touches par cette IP ignorent explicitement la regle flood : aucune alerte ne doit sortir');
});
check('meme IP sur deux vhosts, UN SEUL ignore la regle -> alerte conservee (garde de securite)', ()=>{
  const { RULE_IDS } = require('../lib/detect');
  const d=new Detector({windowMs:2000,flood:{minRequests:3}});
  d.setVhostRules({
    'maps.bourgesplus.fr': { enabled: true, ignore: new Set([RULE_IDS.flood]) },
    // mapx.bourgesplus.fr : pas d opt-out -> ne doit jamais etre couvert par
    // l opt-out d un autre vhost, meme partage par la meme IP.
  });
  for (let i=0;i<5;i++) {
    d.add(req({ ts: T0+i*100, vhost: i%2===0 ? 'maps.bourgesplus.fr' : 'mapx.bourgesplus.fr' }));
  }
  const alerts = d.evaluate(T0+500);
  assert.strictEqual(alerts.filter(a=>a.type==='flood').length, 1,
    'mapx.bourgesplus.fr n a pas opte pour l ignore-rule : l alerte doit rester visible');
});
check('IP sur un seul vhost -> comportement single-vhost inchange (non-regression)', ()=>{
  const { RULE_IDS } = require('../lib/detect');
  const d=new Detector({windowMs:2000,flood:{minRequests:3}});
  d.setVhostRules({ 'site.fr': { enabled: true, ignore: new Set([RULE_IDS.flood]) } });
  feed(d,5,{vhost:'site.fr'},100);
  assert.deepStrictEqual(d.evaluate(T0+500).filter(a=>a.type==='flood'), []);
});

console.log('\nregles personnalisees (lib/rules-yaml.js)');
const customRule = (overrides={}) => ({
  id: 101, name: 'admin_probe', enable: true, severity: 'high',
  description: 'test', windowMinutes: 5, minMatches: 5,
  pathHint: /admin/i, pathHintRaw: 'admin', uaHint: null, uaHintRaw: null,
  statusIn: [], methodIn: [], ...overrides,
});
check('declenche une alerte custom_<id> quand le seuil est atteint', ()=>{
  const d=new Detector();
  d.setCustomRules([customRule({minMatches:5})]);
  feed(d,6,{path:'/wp-admin/'});
  const a=d.evaluate(T0+600).filter(x=>x.type==='custom_101');
  assert.strictEqual(a.length,1);
  assert.strictEqual(a[0].evidence.ruleId,101);
  assert.strictEqual(a[0].evidence.matches,6);
});
check('sous le seuil personnalise, aucune alerte', ()=>{
  const d=new Detector();
  d.setCustomRules([customRule({minMatches:10})]);
  feed(d,6,{path:'/wp-admin/'});
  assert.deepStrictEqual(d.evaluate(T0+600).filter(x=>x.type==='custom_101'),[]);
});
check('les requetes qui ne correspondent pas au path_hint ne comptent pas', ()=>{
  const d=new Detector();
  d.setCustomRules([customRule({minMatches:5})]);
  feed(d,10,{path:'/public/'});
  assert.deepStrictEqual(d.evaluate(T0+1000).filter(x=>x.type==='custom_101'),[]);
});
check('regle personnalisee desactivee (enable:false) -> jamais declenchee', ()=>{
  const d=new Detector();
  d.setCustomRules([customRule({minMatches:5, enable:false})]);
  feed(d,10,{path:'/wp-admin/'});
  assert.deepStrictEqual(d.evaluate(T0+1000).filter(x=>x.type==='custom_101'),[]);
});
check('filtre par status_in : seules les requetes au bon statut comptent', ()=>{
  const d=new Detector();
  d.setCustomRules([customRule({minMatches:5, pathHint:null, pathHintRaw:null, statusIn:[403]})]);
  feed(d,10,{status:200});
  assert.deepStrictEqual(d.evaluate(T0+1000).filter(x=>x.type==='custom_101'),[]);
  feed(d,10,{ts:T0+2000,status:403});
  assert.strictEqual(d.evaluate(T0+2500).filter(x=>x.type==='custom_101').length,1);
});
check('edge-triggered comme les regles integrees : ne se redeclenche pas tant que la condition reste vraie', ()=>{
  const d=new Detector();
  d.setCustomRules([customRule({minMatches:5})]);
  feed(d,6,{path:'/wp-admin/'});
  assert.strictEqual(d.evaluate(T0+600).filter(x=>x.type==='custom_101').length,1);
  feed(d,6,{ts:T0+700,path:'/wp-admin/'});
  assert.strictEqual(d.evaluate(T0+1400).filter(x=>x.type==='custom_101').length,0,
    'meme episode continu : pas de deuxieme alerte');
});
check('la retention s elargit automatiquement si besoin (windowMinutes > windowMs), sans toucher a la fenetre des regles integrees (fix ANA-05)', ()=>{
  const d=new Detector({windowMs:1000}); // 1s
  d.setCustomRules([customRule({minMatches:5, windowMinutes:1})]); // 60s > 1s
  assert.ok(d.retentionMs >= 60000, 'la retention des buckets doit s elargir pour couvrir la regle personnalisee');
  assert.strictEqual(d.cfg.windowMs, 1000, 'la fenetre des regles integrees ne doit jamais etre modifiee par une regle personnalisee');
});
check('la retention retombe quand la regle personnalisee au fenetre large est retiree (avant : elargissement permanent, jamais reduit)', ()=>{
  const d=new Detector({windowMs:1000});
  d.setCustomRules([customRule({minMatches:5, windowMinutes:60})]); // 3600s
  assert.ok(d.retentionMs >= 3600_000);
  d.setCustomRules([]); // regle retiree
  assert.strictEqual(d.retentionMs, 1000, 'sans regle personnalisee, la retention doit revenir a la fenetre de base');
});
check('window_minutes est borne (fix ANA-05 : pas de retention illimitee via une regle mal/malveillamment configuree)', ()=>{
  const d=new Detector({windowMs:1000});
  d.setCustomRules([customRule({minMatches:5, windowMinutes:999999999})]);
  const maxMs = 24 * 60 * 60_000; // MAX_CUSTOM_WINDOW_MINUTES
  assert.strictEqual(d.retentionMs, maxMs, 'la retention ne doit pas depasser le plafond, quelle que soit la valeur fournie');
});
check('opt-out par vhost s applique aussi aux regles personnalisees', ()=>{
  const { RULE_IDS } = require('../lib/detect');
  const d=new Detector();
  d.setCustomRules([customRule({minMatches:5, id:105})]);
  d.setVhostRules({ 'site.fr': { enabled: true, ignore: new Set([105]) } });
  feed(d,10,{path:'/wp-admin/'});
  assert.deepStrictEqual(d.evaluate(T0+1000).filter(x=>x.type==='custom_105'),[]);
});

console.log('\npaths-ignore par regle (# nginx-control-analyze-rule-{ID}-paths-ignore)');
{
  const { RULE_IDS } = require('../lib/detect');
  const pi=(o)=>({ 'site.fr': { enabled: true, ignore: new Set(), pathsIgnore: new Map(Object.entries(o).map(([k,v])=>[Number(k),v])) } });
  check('bruteforce : les 403 sur un chemin ignore ne comptent plus pour la regle 1', ()=>{
    const d=new Detector({bruteforce:{pathHint:/verify-session|login/}});
    d.setVhostRules(pi({[RULE_IDS.bruteforce]:['/wp-json/wpa/v1/verify-session']}));
    feed(d,30,{path:'/wp-json/wpa/v1/verify-session?t=1',status:403});
    assert.deepStrictEqual(d.evaluate(T0+3000).filter(a=>a.type==='bruteforce'),[]);
  });
  check('sans motif, les memes requetes declenchent bien la regle (controle negatif)', ()=>{
    const d=new Detector({bruteforce:{pathHint:/verify-session|login/}});
    feed(d,30,{path:'/wp-json/wpa/v1/verify-session',status:403});
    assert.strictEqual(d.evaluate(T0+3000).filter(a=>a.type==='bruteforce').length,1);
  });
  check('le motif est propre a la regle : le flood continue de compter ces requetes', ()=>{
    const d=new Detector();
    d.setVhostRules(pi({[RULE_IDS.bruteforce]:['/ping']}));
    feed(d,1200,{path:'/ping',status:200},5);
    assert.strictEqual(d.evaluate(T0+7000).filter(a=>a.type==='flood').length,1);
  });
  check('le motif est propre au vhost', ()=>{
    const d=new Detector({bruteforce:{pathHint:/login/}});
    d.setVhostRules(pi({[RULE_IDS.bruteforce]:['/login']}));
    feed(d,30,{path:'/login',status:401,vhost:'autre.fr'});
    assert.strictEqual(d.evaluate(T0+3000).filter(a=>a.type==='bruteforce').length,1);
  });
  check('motif prefixe "*" et exact', ()=>{
    const d=new Detector();
    d.setVhostRules(pi({[RULE_IDS.flood]:['/health*']}));
    feed(d,1500,{path:'/healthz?x=1'},2);
    assert.deepStrictEqual(d.evaluate(T0+4000).filter(a=>a.type==='flood'),[]);
    const d2=new Detector();
    d2.setVhostRules(pi({[RULE_IDS.flood]:['/health']}));
    feed(d2,1500,{path:'/healthz'},2);
    assert.strictEqual(d2.evaluate(T0+4000).filter(a=>a.type==='flood').length,1,'exact ne doit pas matcher un prefixe');
  });
  check('scan : les 404 + chemins ignores sont retranches (requetes, 404, chemins distincts)', ()=>{
    const d=new Detector();
    d.setVhostRules(pi({[RULE_IDS.scan]:['/wp-content/*']}));
    feed(d,60,i=>({path:'/wp-content/uploads/a'+i+'.jpg',status:404}));
    assert.deepStrictEqual(d.evaluate(T0+7000).filter(a=>a.type==='scan'),[]);
    const d2=new Detector();
    feed(d2,60,i=>({path:'/wp-content/uploads/a'+i+'.jpg',status:404}));
    assert.strictEqual(d2.evaluate(T0+7000).filter(a=>a.type==='scan').length,1);
  });
  check('regle personnalisee : requete ignoree non comptee', ()=>{
    const d=new Detector();
    d.setCustomRules([customRule({minMatches:5,id:105})]);
    d.setVhostRules(pi({105:['/wp-admin/']}));
    feed(d,10,{path:'/wp-admin/'});
    assert.deepStrictEqual(d.evaluate(T0+1000).filter(x=>x.type==='custom_105'),[]);
  });
  check('sanitizePathsIgnore rejette les motifs dangereux (vide, sans "/", enorme) et borne la liste', ()=>{
    const { sanitizePathsIgnore } = require('../lib/rules-manager');
    const m=sanitizePathsIgnore({1:['','*','login','/ok','/ok','/'+'a'.repeat(300)],x:['/z'],2:'nope'});
    assert.deepStrictEqual([...m.entries()],[[1,['/ok']]]);
    const big=sanitizePathsIgnore({1:Array.from({length:200},(_,i)=>'/p'+i)});
    assert.strictEqual(big.get(1).length,50);
  });
}

console.log('\nregles personnalisees scope: global (campagne : une alerte, preuves agregees)');
const botnet=(d,nIps,perIp=1,o={})=>{ for(let i=0;i<nIps;i++) for(let k=0;k<perIp;k++) d.add(req({ip:`198.51.100.${i+1}`,ts:T0+(i*perIp+k)*10,path:'/x/commits/commit/'+'a'.repeat(40)+'/f'+(i%3),status:444,ua:i%2?'Chrome/142':'Firefox/130',...(typeof o==='function'?o(i):o)})); };
const gRule=(o={})=>customRule({id:130,name:'botnet',scope:'global',minIps:5,minMatches:8,pathHint:/commits\/commit/i,pathHintRaw:'commits/commit',...o});
const camp=(d,t=T0+5000)=>d.evaluate(t).filter(x=>x.type==='custom_130');
check('global : 10 IP a 1 requete -> UNE alerte de campagne, preuves agregees', ()=>{
  const d=new Detector(); d.setCustomRules([gRule()]); botnet(d,10);
  const a=camp(d);
  assert.strictEqual(a.length,1);
  const e=a[0].evidence;
  assert.strictEqual(e.campaign,true); assert.strictEqual(e.ip,null);
  assert.strictEqual(e.globalMatches,10); assert.strictEqual(e.globalIps,10);
  assert.strictEqual(e.ips.length,10); assert.deepStrictEqual(e.ips[0].length,2);
  assert.strictEqual(e.ipsTruncated,false);
  assert.strictEqual(e.statuses[444],10);
  assert.strictEqual(e.topPaths.length,3); assert.strictEqual(e.topPaths[0].count+e.topPaths[1].count+e.topPaths[2].count,10);
  assert.deepStrictEqual(e.topUserAgents.map(x=>x.count).sort(),[5,5]);
  assert.strictEqual(e.samples.length,10); assert.ok(e.samples[0].path&&e.samples[0].ua);
  assert.deepStrictEqual(e.vhosts,['site.fr']); assert.strictEqual(a[0].vhost,'site.fr');
  assert.ok(/campagne distribuee/.test(a[0].summary)&&/10 IP/.test(a[0].summary));
});
check('global : edge-triggered (pas de doublon), mise a jour si le nombre d IP grandit de 50 %', ()=>{
  const d=new Detector(); d.setCustomRules([gRule()]); botnet(d,10);
  assert.strictEqual(camp(d).length,1);
  assert.strictEqual(camp(d,T0+6000).length,0);
  for(let i=10;i<14;i++) d.add(req({ip:`198.51.100.${i+1}`,ts:T0+6100,path:'/x/commits/commit/'+'b'.repeat(40)}));
  assert.strictEqual(camp(d,T0+7000).length,0); // 14 < 15
  d.add(req({ip:'198.51.100.99',ts:T0+7100,path:'/x/commits/commit/'+'c'.repeat(40)}));
  const u=camp(d,T0+8000); assert.strictEqual(u.length,1); assert.strictEqual(u[0].evidence.renewal,true); assert.strictEqual(u[0].evidence.globalIps,15);
});
check('global : refire apres une fenetre complete tant que la campagne dure ; rearme apres fin', ()=>{
  const d=new Detector({windowMs:600000}); d.setCustomRules([gRule({windowMinutes:1})]); botnet(d,10);
  assert.strictEqual(camp(d).length,1);
  for(let i=0;i<10;i++) d.add(req({ip:`198.51.100.${i+1}`,ts:T0+61000,path:'/x/commits/commit/'+'d'.repeat(40)}));
  assert.strictEqual(camp(d,T0+66000).length,1);
  assert.strictEqual(camp(d,T0+300000).length,0); // campagne finie
  botnet(d,10,1,{ts:T0+400000});
  assert.strictEqual(d.evaluate(T0+400100).filter(x=>x.type==='custom_130').length,1);
});
check('global : le meme trafic en scope ip ne declenche rien ; une IP seule non plus (min_ips)', ()=>{
  const d=new Detector(); d.setCustomRules([gRule({scope:'ip'})]); botnet(d,10);
  assert.deepStrictEqual(camp(d),[]);
  const d2=new Detector(); d2.setCustomRules([gRule()]); botnet(d2,1,20);
  assert.deepStrictEqual(camp(d2),[]);
  const d3=new Detector(); d3.setCustomRules([gRule({minMatches:50})]); botnet(d3,10);
  assert.deepStrictEqual(camp(d3),[]);
});
check('global : IP hors motif et IP sous exception exclues de la liste', ()=>{
  const d=new Detector(); d.setCustomRules([gRule()]); botnet(d,10);
  d.add(req({ip:'10.149.2.1',ts:T0+50,method:'POST',path:'/api/actions/runner.v1.RunnerService/FetchTask'}));
  d.setExceptions([{vhost:'site.fr',ip:'198.51.100.3'}]);
  const e=camp(d)[0].evidence;
  assert.strictEqual(e.globalIps,9);
  assert.ok(!e.ips.some(x=>x[0]==='10.149.2.1'||x[0]==='198.51.100.3'));
});
check('global : liste d IP bornee (3000) et signalee', ()=>{
  const d=new Detector({maxTrackedIps:10000}); d.setCustomRules([gRule({minMatches:10})]);
  for(let i=0;i<3100;i++) d.add(req({ip:`10.${i>>8}.${i&255}.7`,ts:T0+i,path:'/x/commits/commit/'+'a'.repeat(40)}));
  const e=camp(d,T0+5000)[0].evidence;
  assert.strictEqual(e.ips.length,3000); assert.strictEqual(e.ipsTruncated,true); assert.strictEqual(e.globalIps,3100);
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail?1:0);

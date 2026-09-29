'use strict';
const assert=require('assert');
const W=require('../lib/parse-waf');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

const line = (tx={}, messages=[]) => JSON.stringify({
  transaction: {
    client_ip: '203.0.113.5', time_stamp: 'Wed Sep 10 12:00:00 2026',
    request: { method: 'GET', uri: '/login' },
    response: { http_code: 403 },
    unique_id: 'abc123',
    messages,
    ...tx,
  },
});

console.log('\nanalyse d une transaction ModSecurity');
check('champs de base extraits', ()=>{
  const r=W.parseLine(line(),[],'site.fr');
  assert.strictEqual(r.vhost,'site.fr');
  assert.strictEqual(r.ip,'203.0.113.5');
  assert.strictEqual(r.method,'GET');
  assert.strictEqual(r.uri,'/login');
  assert.strictEqual(r.status,403);
  assert.strictEqual(r.uniqueId,'abc123');
});
check('403 -> bloque', ()=>{
  assert.strictEqual(W.parseLine(line(),'json').blocked,true);
});
check('200 -> detecte, non bloque', ()=>{
  const r=W.parseLine(line({response:{http_code:200}}),'json');
  assert.strictEqual(r.blocked,false);
});
check('regles et messages extraits', ()=>{
  const r=W.parseLine(line({},[
    {message:'SQL Injection', details:{ruleId:'942100',severity:'2',tags:['attack-sqli']}},
    {message:'XSS attempt',   details:{ruleId:'941100',severity:'2',tags:['attack-xss']}},
  ]),'json');
  assert.deepStrictEqual(r.ruleIds,['942100','941100']);
  assert.strictEqual(r.messages.length,2);
  assert.strictEqual(r.messages[0].message,'SQL Injection');
});
check('regles dupliquees dedupliquees', ()=>{
  const r=W.parseLine(line({},[
    {message:'a',details:{ruleId:'942100',severity:'2'}},
    {message:'b',details:{ruleId:'942100',severity:'4'}},
  ]),'json');
  assert.deepStrictEqual(r.ruleIds,['942100']);
});
check('severite la plus grave retenue', ()=>{
  const r=W.parseLine(line({},[
    {message:'a',details:{ruleId:'1',severity:'5'}},   // notice
    {message:'b',details:{ruleId:'2',severity:'2'}},   // critical
  ]),'json');
  assert.strictEqual(r.severity,'critical');
});
check('aucun message -> severite inconnue, pas d exception', ()=>{
  const r=W.parseLine(line({},[]),'json');
  assert.strictEqual(r.severity,'unknown');
  assert.deepStrictEqual(r.ruleIds,[]);
});

console.log('\nnormalisation de la severite');
for (const [raw,expected] of [['0','critical'],['2','critical'],['3','error'],['4','warning'],
                              ['5','notice'],['6','info'],['7','info'],
                              ['CRITICAL','critical'],['warning','warning'],['DEBUG','info']])
  check(`severite ${raw} -> ${expected}`, ()=>assert.strictEqual(W.normalizeSeverity(raw),expected));
check('severite absente ou invalide -> unknown', ()=>{
  assert.strictEqual(W.normalizeSeverity(undefined),'unknown');
  assert.strictEqual(W.normalizeSeverity(null),'unknown');
  assert.strictEqual(W.normalizeSeverity('n importe quoi'),'unknown');
});

console.log('\nrobustesse (une ligne illisible est normale en fin de fichier)');
for (const [label,bad] of [
  ['pas du JSON','n importe quoi'],
  ['JSON tronque','{"transaction":{'],
  ['JSON valide mais sans transaction','{"foo":"bar"}'],
  ['transaction sans horodatage','{"transaction":{"client_ip":"1.2.3.4"}}'],
  ['ligne vide',''],
  ['ligne trop courte','{}'],
])
  check(`${label} -> null`, ()=>assert.strictEqual(W.parseLine(bad,'json'),null));

console.log('\nvhost depuis le nom de fichier');
check('suffixe .waf.log retire', ()=>assert.strictEqual(W.vhostFromFilename('example.com.waf.log'),'example.com'));
check('rotation numerique geree', ()=>assert.strictEqual(W.vhostFromFilename('site.fr.waf.log.1'),'site.fr'));
check('rotation gzip geree', ()=>assert.strictEqual(W.vhostFromFilename('site.fr.waf.log.1.gz'),'site.fr'));

console.log('\nformat');
check('detectFormat renvoie toujours json', ()=>assert.strictEqual(W.detectFormat(['n importe quoi']),'json'));


console.log('\nstructure reelle (ModSecurity v3 + connecteur nginx v1.0.4)');
check('messages est imbrique dans transaction, pas a la racine', ()=>{
  // Une premiere version du parseur lisait obj.messages, en supposant que le
  // tableau des regles declenchees vivait a la racine du document. Dans le
  // format reellement produit par ModSecurity v3, seul "transaction" existe a
  // la racine ; request, response, producer et messages sont tous imbriques
  // dedans. Le tableau des regles restait donc systematiquement vide, sans
  // aucune erreur — Array.isArray(undefined) est simplement false.
  const real = JSON.stringify({
    transaction: {
      client_ip: '89.91.226.61', time_stamp: 'Fri Sep 11 08:49:48 2026',
      unique_id: '178911658855.650745',
      request: { method: 'POST', uri: '/pro/LUD/ils/RecordManagementService.svc/CheckIn' },
      response: { body: '', http_code: 200 },
      producer: { modsecurity: 'ModSecurity v3.0.12 (Linux)', connector: 'ModSecurity-nginx v1.0.4',
                  secrules_engine: 'DetectionOnly', components: ['OWASP_CRS/4.30.0-dev'] },
      messages: [
        { message: 'Request content type is not allowed by policy',
          details: { ruleId: '920420', severity: '2', tags: ['attack-protocol'] } },
        { message: 'Inbound Anomaly Score Exceeded (Total Score: 5)',
          details: { ruleId: '949110', severity: '0', tags: ['anomaly-evaluation'] } },
      ],
    },
  });
  const r = W.parseLine(real, 'json', 'mediatheque.ville-bourges.fr');
  assert.strictEqual(r.status, 200, 'response.http_code doit etre lu depuis transaction.response');
  assert.deepStrictEqual(r.ruleIds, ['920420','949110'], 'les regles ne doivent plus rester vides');
  assert.strictEqual(r.messages.length, 2);
  assert.strictEqual(r.messages[0].message, 'Request content type is not allowed by policy');
  assert.strictEqual(r.severity, 'critical', 'la plus severe des deux (severity 0 = critical) doit etre retenue');
});
check('aucun message quand transaction.messages est absent', ()=>{
  const noMsg = JSON.stringify({ transaction: {
    client_ip: '1.2.3.4', time_stamp: 'Fri Sep 11 08:49:48 2026',
    request: { method: 'GET', uri: '/' }, response: { http_code: 200 },
  }});
  const r = W.parseLine(noMsg, 'json');
  assert.deepStrictEqual(r.ruleIds, []);
  assert.strictEqual(r.severity, 'unknown');
});


console.log('\nligne brute et moteur (pour le detail complet et le contexte)');
check('la ligne originale est conservee', ()=>{
  const raw = line();
  const r = W.parseLine(raw, 'json');
  assert.strictEqual(r.raw, raw);
});
check('une ligne demesuree est tronquee, pas rejetee', ()=>{
  const bigTag = 'x'.repeat(20000);
  const raw = line({}, [{message:'m', details:{ruleId:'1', severity:'2', tags:[bigTag]}}]);
  const r = W.parseLine(raw, 'json');
  assert.ok(r.raw.length <= W.RAW_MAX_LEN + 20);
  assert.ok(r.raw.endsWith('(tronque)'));
});
check('le moteur ModSecurity est expose (DetectionOnly explique un blocage absent)', ()=>{
  const raw = JSON.stringify({transaction:{client_ip:'1.2.3.4',time_stamp:'Wed Sep 10 12:00:00 2026',
    request:{method:'GET',uri:'/'}, response:{http_code:200},
    producer:{secrules_engine:'DetectionOnly'}, messages:[]}});
  const r = W.parseLine(raw,'json');
  assert.strictEqual(r.engine,'DetectionOnly');
});
check('moteur absent -> null, pas d exception', ()=>{
  assert.strictEqual(W.parseLine(line(),'json').engine, null);
});

console.log('\ncategorisation des regles (plages OWASP CRS)');
for (const [id,cat] of [['920420','Conformite du protocole'],['930100','Traversee de repertoire'],
                        ['932100','Execution de commande'],['941100','XSS'],['942100','Injection SQL'],
                        ['949110','Evaluation du score'],['980100','Correlation']])
  check(`${id} -> ${cat}`, ()=>assert.strictEqual(W.categorize(id).category, cat));
check('regle hors plage connue -> categorie generique', ()=>{
  assert.strictEqual(W.categorize('123456').category, 'Regle personnalisee');
});
check('regle absente ou invalide -> pas d exception', ()=>{
  assert.doesNotThrow(()=>W.categorize(null));
  assert.doesNotThrow(()=>W.categorize(undefined));
  assert.doesNotThrow(()=>W.categorize('abc'));
});

console.log('\nlien de reference externe');
check('lien construit pour une regle donnee', ()=>{
  const url = W.referenceUrl('942100');
  assert.ok(url.startsWith('https://github.com/search'));
  assert.ok(url.includes('942100'));
});
check('aucun lien sans identifiant de regle', ()=>assert.strictEqual(W.referenceUrl(null),null));

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail?1:0);

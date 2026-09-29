'use strict';
const assert=require('assert');
const D=require('../lib/docker');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

// Construit une trame Docker multiplexee
function frame(type, text){
  const p=Buffer.from(text,'utf8');
  const h=Buffer.alloc(8); h[0]=type; h.writeUInt32BE(p.length,4);
  return Buffer.concat([h,p]);
}

console.log('\ndemultiplexage du flux Docker (les caracteres parasites dans les logs)');
check('stdout simple', ()=>{
  const {stdout,stderr}=D.demuxStream(frame(1,'hello'));
  assert.strictEqual(stdout,'hello'); assert.strictEqual(stderr,'');
});
check('stderr separe', ()=>{
  const {stdout,stderr}=D.demuxStream(frame(2,'boom'));
  assert.strictEqual(stdout,''); assert.strictEqual(stderr,'boom');
});
check('trames multiples', ()=>{
  const buf=Buffer.concat([frame(1,'a'),frame(2,'b'),frame(1,'c')]);
  const {stdout,stderr}=D.demuxStream(buf);
  assert.strictEqual(stdout,'ac'); assert.strictEqual(stderr,'b');
});
check('aucun octet d en-tete ne subsiste', ()=>{
  const line='2026-05-26T11:46:08Z info msg="GoDNS started"';
  const {stdout}=D.demuxStream(frame(1,line));
  assert.strictEqual(stdout,line);
  assert.ok(!/^[l{]/.test(stdout), 'un octet de header a fuite');
});
check('flux TTY sans trames', ()=>{
  const {stdout}=D.demuxStream(Buffer.from('plain text','utf8'));
  assert.strictEqual(stdout,'plain text');
});
check('buffer vide', ()=>{
  const {stdout,stderr}=D.demuxStream(Buffer.alloc(0));
  assert.strictEqual(stdout,''); assert.strictEqual(stderr,'');
});
check('trame tronquee ignoree sans planter', ()=>{
  const buf=Buffer.concat([frame(1,'ok'),Buffer.from([1,0,0,0])]);
  assert.strictEqual(D.demuxStream(buf).stdout,'ok');
});
check('demuxToText concatene', ()=>{
  assert.strictEqual(D.demuxToText(Buffer.concat([frame(1,'out'),frame(2,'err')])),'outerr');
});


console.log('\nstatistiques du conteneur (CPU/RAM/reseau, la meme formule que docker stats)');
check('CPU calcule a partir des deux echantillons du meme appel', ()=>{
  const r = D.computeContainerStats({
    cpu_stats:{cpu_usage:{total_usage:2500000000},system_cpu_usage:50000000000,online_cpus:2},
    precpu_stats:{cpu_usage:{total_usage:2200000000},system_cpu_usage:48000000000},
    memory_stats:{usage:250*1024*1024, limit:512*1024*1024, stats:{cache:50*1024*1024}},
  });
  assert.strictEqual(r.cpuPercent, 30);
  assert.strictEqual(r.memUsedBytes, 200*1024*1024, 'le cache doit etre retire de l usage');
  assert.strictEqual(r.memPercent, 39.1);
});
check('le cache cgroup v2 (inactive_file) est aussi reconnu', ()=>{
  const r = D.computeContainerStats({
    cpu_stats:{}, precpu_stats:{},
    memory_stats:{usage:300*1024*1024, limit:1024*1024*1024, stats:{inactive_file:100*1024*1024}},
  });
  assert.strictEqual(r.memUsedBytes, 200*1024*1024);
});
check('reseau : somme de toutes les interfaces', ()=>{
  const r = D.computeContainerStats({
    cpu_stats:{}, precpu_stats:{}, memory_stats:{},
    networks:{eth0:{rx_bytes:1000,tx_bytes:500}, eth1:{rx_bytes:200,tx_bytes:100}},
  });
  assert.strictEqual(r.netRxBytes, 1200);
  assert.strictEqual(r.netTxBytes, 600);
});
check('sans echantillon precedent (juste demarre) -> pas de division par zero', ()=>{
  const r = D.computeContainerStats({
    cpu_stats:{}, precpu_stats:{}, memory_stats:{usage:1000,limit:0,stats:{}},
  });
  assert.strictEqual(r.cpuPercent, null, 'aucun delta systeme -> pas de pourcentage invente');
  assert.strictEqual(r.memPercent, null, 'pas de limite -> pas de pourcentage invente');
});
check('aucune section presente -> tout degrade sans exception', ()=>{
  assert.doesNotThrow(()=>D.computeContainerStats({}));
  const r = D.computeContainerStats({});
  assert.strictEqual(r.cpuPercent, null);
  assert.strictEqual(r.memUsedBytes, null);
  assert.strictEqual(r.netRxBytes, 0);
});
check('nombre de coeurs deduit de percpu_usage a defaut de online_cpus', ()=>{
  const r = D.computeContainerStats({
    cpu_stats:{cpu_usage:{total_usage:100,percpu_usage:[1,2,3,4]},system_cpu_usage:1000},
    precpu_stats:{cpu_usage:{total_usage:0},system_cpu_usage:0},
    memory_stats:{},
  });
  assert.strictEqual(r.onlineCpus, 4);
});

console.log('\nparseImageTag — extraire le tag d une reference d image Docker complete');
check('cas simple : registre + depot + tag', () => {
  assert.strictEqual(D.parseImageTag('ghcr.io/rdrouche/nginx-dashboard:1.4.2'), '1.4.2');
});
check('suffixe de variante conserve dans le tag extrait', () => {
  // Bug reel signale : le nom d image complet etait compare tel quel, jamais
  // egal a une version nue publiee par un flux de mise a jour.
  assert.strictEqual(D.parseImageTag('ghcr.io/rdrouche/nginx-dashboard:1.4.2-waf'), '1.4.2-waf');
  assert.strictEqual(D.parseImageTag('ghcr.io/rdrouche/nginx-dashboard:1.4.2-coraza'), '1.4.2-coraza');
});
check('un port de registre n est pas confondu avec le separateur de tag', () => {
  assert.strictEqual(D.parseImageTag('registry.example.com:5000/user/image:2.0.1'), '2.0.1');
});
check('aucun tag explicite -> latest, comme Docker lui-meme', () => {
  assert.strictEqual(D.parseImageTag('nginx'), 'latest');
  assert.strictEqual(D.parseImageTag('user/image'), 'latest');
});
check('reference par digest -> le digest, faute de tag a extraire', () => {
  const r = D.parseImageTag('user/image@sha256:' + 'a'.repeat(64));
  assert.strictEqual(r, 'sha256:' + 'a'.repeat(64));
});
check('entree vide ou absente ne leve pas d exception', () => {
  assert.strictEqual(D.parseImageTag(''), null);
  assert.strictEqual(D.parseImageTag(null), null);
  assert.strictEqual(D.parseImageTag(undefined), null);
});

console.log('\nstripVariantSuffix — comparer les versions independamment du variant WAF');
check('les suffixes connus sont retires', () => {
  assert.strictEqual(D.stripVariantSuffix('1.4.2-waf'), '1.4.2');
  assert.strictEqual(D.stripVariantSuffix('1.4.2-coraza'), '1.4.2');
});
check('une version sans suffixe reste inchangee', () => {
  assert.strictEqual(D.stripVariantSuffix('1.4.2'), '1.4.2');
});
check('un suffixe inconnu n est pas retire (on ne devine pas)', () => {
  assert.strictEqual(D.stripVariantSuffix('1.4.2-trixie'), '1.4.2-trixie');
});


console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail?1:0);

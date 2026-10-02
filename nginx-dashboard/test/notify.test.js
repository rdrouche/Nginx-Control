'use strict';
/**
 * Le parseur YAML est maison : il doit encaisser les fins de ligne Windows
 * (deja source d un incident), les listes de destinataires et les fichiers
 * absents, sans jamais lever.
 */
const assert=require('assert'), fs=require('fs'), os=require('os'), path=require('path');
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'notify-'));
process.env.USERS_FILE=path.join(tmp,'users.yml');
const N=require('../lib/notify');
let pass=0,fail=0;
const check=(n,f)=>{try{f();console.log('  PASS  '+n);pass++}catch(e){console.log('  FAIL  '+n+'\n        '+e.message);fail++}};

const write=(name,txt)=>{const p=path.join(tmp,name);fs.writeFileSync(p,txt);return p;};

console.log('\nparseYmlFlat');
check('fichier absent -> null (et non une exception)', ()=>assert.strictEqual(N.parseYmlFlat(path.join(tmp,'nope.yml')),null));
check('cles simples', ()=>{
  const p=write('a.yml','host: smtp.example.com\nport: 587\nenable: true\n');
  const c=N.parseYmlFlat(p);
  assert.strictEqual(c.host,'smtp.example.com');
  assert.strictEqual(c.enable,true);
});
check('fins de ligne Windows absorbees', ()=>{
  const p=write('b.yml','host: smtp.example.com\r\nenable: true\r\nport: 587\r\n');
  const c=N.parseYmlFlat(p);
  assert.strictEqual(c.host,'smtp.example.com','le \\r ne doit pas coller a la valeur');
  assert.strictEqual(c.enable,true);
});
check('sections et listes de destinataires', ()=>{
  const p=write('c.yml',
    'cert_expiry:\n  enable: true\n  days_before: 30\n  recipients:\n    - a@x.fr\n    - b@x.fr\n');
  const c=N.parseYmlFlat(p);
  assert.strictEqual(c.cert_expiry.enable,true);
  assert.strictEqual(c.cert_expiry.days_before,30);
  assert.deepStrictEqual(c.cert_expiry.recipients,['a@x.fr','b@x.fr']);
});
check('valeurs entre guillemets nettoyees', ()=>{
  const p=write('d.yml','password: "s3cr3t"\nfrom: \'a@b.c\'\n');
  const c=N.parseYmlFlat(p);
  assert.strictEqual(c.password,'s3cr3t');
  assert.strictEqual(c.from,'a@b.c');
});
check('conversion coherente racine / imbrique', ()=>{
  const p=write('f.yml','port: 25\nsection:\n  port: 25\n');
  const c=N.parseYmlFlat(p);
  assert.strictEqual(c.port,25,'racine doit etre un nombre');
  assert.strictEqual(c.section.port,25,'imbrique doit etre un nombre');
});
check('commentaires et lignes vides ignores', ()=>{
  const p=write('e.yml','# commentaire\n\nhost: x\n\n# autre\nport: 25\n');
  const c=N.parseYmlFlat(p);
  assert.strictEqual(c.host,'x');
  assert.strictEqual(c.port,25);
});
check('commentaire en fin de ligne, apres une valeur entre guillemets, correctement separe', ()=>{
  // Bug reel signale en production : une tache planifiee ne se declenchait
  // jamais, quelle que soit l heure. Cause : "22 * * * *"   # chaque
  // dimanche a 4h analysait comme la chaine litterale
  // 22 * * * *\"   # chaque dimanche a 4h — guillemet fermant et commentaire
  // colles a la valeur. matchCron() decoupait alors ce charabia par espace,
  // decalant ses 5 champs ; le jour de la semaine devenait *" au lieu de *,
  // qui ne correspond plus jamais a rien. Le meme style de commentaire en
  // fin de ligne existait deja dans l exemple livre pour goaccess_restart.
  const p=write('g.yml','cron: "22 * * * *"   # chaque dimanche a 4h\n');
  const c=N.parseYmlFlat(p);
  assert.strictEqual(c.cron,'22 * * * *','le commentaire ne doit jamais faire partie de la valeur');
});
check('commentaire en fin de ligne, apres une valeur simple (non guillemetee)', ()=>{
  const p=write('h.yml','grace_seconds: 20   # delai avant SIGKILL\n');
  const c=N.parseYmlFlat(p);
  assert.strictEqual(c.grace_seconds,20);
});
check('un # sans espace avant reste dans la valeur (pas de commentaire ambigu)', ()=>{
  const p=write('i.yml','tag: "release#42"\n');
  const c=N.parseYmlFlat(p);
  assert.strictEqual(c.tag,'release#42','un # colle a la valeur, sans espace, ne doit pas etre traite comme un commentaire');
});
check('une valeur entre guillemets peut contenir un # sans perdre le reste apres le guillemet fermant', ()=>{
  const p=write('j.yml','path: "/tmp/dir#1"   # commentaire\n');
  const c=N.parseYmlFlat(p);
  assert.strictEqual(c.path,'/tmp/dir#1');
});
check('cle imbriquee (indentation 2) avec commentaire en fin de ligne', ()=>{
  const p=write('k.yml','nginx_restart:\n  enable: true\n  cron: "0 4 * * 0"   # chaque dimanche a 4h\n  grace_seconds: 10\n');
  const c=N.parseYmlFlat(p);
  assert.strictEqual(c.nginx_restart.cron,'0 4 * * 0');
  assert.strictEqual(c.nginx_restart.grace_seconds,10);
});

console.log('\nenvoi');
(async()=>{
  try{
    const r=await N.sendMail(['a@b.c'],'sujet','corps');
    assert.strictEqual(r.ok,false);
    assert.ok(/not configured|disabled/i.test(r.reason));
    console.log('  PASS  sans configuration SMTP, echec propre sans exception'); pass++;
  }catch(e){ console.log('  FAIL  sendMail leve\n        '+e.message); fail++; }
  try{
    const r=await N.sendNotification('type_inconnu','s','b');
    assert.ok(r===undefined||r.ok===false);
    console.log('  PASS  type de notification inconnu ignore'); pass++;
  }catch(e){ console.log('  FAIL  sendNotification leve\n        '+e.message); fail++; }

  console.log('\nprotocole SMTP (fix MISC-06 : dot-stuffing, CRLF, sujet non-ASCII, injection CRLF)');
  {
    // Faux serveur SMTP minimal : suit exactement l enchainement que
    // sendMail() attend (pas de STARTTLS/AUTH ici — security:'none', pas
    // d utilisateur) et capture le flux DATA tel quel pour l inspecter.
    const net = require('net');
    function fakeSmtp() {
      return new Promise(resolveServer => {
        const chunks = []; // toutes les lignes recues, dans l ordre
        let dataMode = false, dataLines = [];
        const srv = net.createServer(sock => {
          sock.write('220 fake.local ESMTP\r\n');
          let buf = '';
          sock.on('data', d => {
            buf += d.toString();
            let idx;
            while ((idx = buf.indexOf('\r\n')) !== -1) {
              const line = buf.slice(0, idx); buf = buf.slice(idx + 2);
              if (dataMode) {
                if (line === '.') { dataMode = false; sock.write('250 OK queued\r\n'); continue; }
                dataLines.push(line);
                continue;
              }
              chunks.push(line);
              if (/^EHLO/i.test(line)) sock.write('250-fake.local\r\n250 OK\r\n');
              else if (/^MAIL FROM/i.test(line)) sock.write('250 OK\r\n');
              else if (/^RCPT TO/i.test(line)) sock.write('250 OK\r\n');
              else if (/^DATA/i.test(line)) { dataMode = true; sock.write('354 Go ahead\r\n'); }
              else if (/^QUIT/i.test(line)) { sock.write('221 Bye\r\n'); sock.end(); }
            }
          });
        });
        srv.listen(0, '127.0.0.1', () => resolveServer({ srv, port: srv.address().port, chunks, dataLines: () => dataLines }));
      });
    }

    const { srv, port, chunks, dataLines } = await fakeSmtp();
    fs.writeFileSync(N.SMTP_CONFIG_FILE,
      `host: 127.0.0.1\nport: ${port}\nsecurity: none\nfrom: dashboard@example.com\nfrom_name: Nginx Dashboard\nenable: true\n`);
    N.reloadAll();

    const bodyWithDotLine = 'Ligne normale\n.\nAutre ligne apres le point seul\n.Encore une qui commence par un point';
    const r = await N.sendMail(['dest@example.com'], 'Résumé quotidien', bodyWithDotLine);
    await new Promise(res => setTimeout(res, 200)); // laisser QUIT/close se propager
    check('l envoi vers le faux serveur reussit (protocole mene jusqu au bout)', () => assert.strictEqual(r.ok, true));
    check('le sujet non-ASCII est encode RFC 2047 (=?UTF-8?B?...?=), jamais envoye brut', () => {
      const subjLine = chunks.concat(dataLines()).find(l => /^Subject:/.test(l));
      assert.ok(subjLine, 'aucune ligne Subject: trouvee');
      assert.ok(/^Subject: =\?UTF-8\?B\?/.test(subjLine), `sujet non encode : ${subjLine}`);
      assert.ok(!subjLine.includes('Résumé'), 'le sujet ne doit jamais contenir les octets UTF-8 bruts');
    });
    check('une ligne "." seule dans le corps est dot-stuffee en ".." et ne termine pas DATA prematurement', () => {
      const dl = dataLines();
      assert.ok(dl.includes('..'), `ligne "." attendue doublee en ".." : ${JSON.stringify(dl)}`);
      // Tout le corps doit avoir ete transmis, y compris ce qui suit le point seul.
      assert.ok(dl.some(l => l === 'Autre ligne apres le point seul'), 'la ligne apres le point seul a ete perdue (DATA termine trop tot)');
    });
    check('une ligne commencant par "." (mais pas seule) est aussi dot-stuffee', () => {
      const dl = dataLines();
      assert.ok(dl.includes('..Encore une qui commence par un point'), `dot-stuffing manquant : ${JSON.stringify(dl)}`);
    });

    srv.close();
  }

  {
    // Injection CRLF : un destinataire ou un expediteur avec un \r\n integre
    // ne doit jamais pouvoir demarrer une nouvelle commande SMTP ou un
    // nouvel en-tete.
    const net = require('net');
    function fakeSmtpCapture() {
      return new Promise(resolveServer => {
        const commands = [];
        const srv = net.createServer(sock => {
          sock.write('220 fake.local ESMTP\r\n');
          let buf = '', dataMode = false;
          sock.on('data', d => {
            buf += d.toString();
            let idx;
            while ((idx = buf.indexOf('\r\n')) !== -1) {
              const line = buf.slice(0, idx); buf = buf.slice(idx + 2);
              if (dataMode) { commands.push('DATA> ' + line); if (line === '.') { dataMode = false; sock.write('250 OK\r\n'); } continue; }
              commands.push(line);
              if (/^EHLO/i.test(line)) sock.write('250-fake.local\r\n250 OK\r\n');
              else if (/^MAIL FROM/i.test(line)) sock.write('250 OK\r\n');
              else if (/^RCPT TO/i.test(line)) sock.write('250 OK\r\n');
              else if (/^DATA/i.test(line)) { dataMode = true; sock.write('354 Go ahead\r\n'); }
              else if (/^QUIT/i.test(line)) { sock.write('221 Bye\r\n'); sock.end(); }
            }
          });
        });
        srv.listen(0, '127.0.0.1', () => resolveServer({ srv, port: srv.address().port, commands }));
      });
    }
    const { srv, port, commands } = await fakeSmtpCapture();
    fs.writeFileSync(N.SMTP_CONFIG_FILE, `host: 127.0.0.1\nport: ${port}\nsecurity: none\nfrom: dashboard@example.com\nenable: true\n`);
    N.reloadAll();
    const evilTo = 'victim@example.com>\r\nRCPT TO:<attacker@evil.com';
    const r2 = await N.sendMail([evilTo], 'sujet', 'corps');
    await new Promise(res => setTimeout(res, 200));
    check('un destinataire contenant un CRLF ne peut pas injecter une seconde commande RCPT TO', () => {
      const rcptCmds = commands.filter(c => /^RCPT TO/i.test(c));
      assert.strictEqual(rcptCmds.length, 1, `une seule commande RCPT TO attendue, recu : ${JSON.stringify(rcptCmds)}`);
      // Le texte injecte peut rester present comme partie inoffensive d une
      // seule adresse malformee (le CRLF est neutralise en espace) ; ce qui
      // compte est qu il n a jamais pu demarrer sa PROPRE commande RCPT TO.
      assert.ok(!commands.some(c => c === 'RCPT TO:<attacker@evil.com>'), 'une commande RCPT TO distincte pour l adresse injectee ne doit jamais avoir ete envoyee');
    });
    srv.close();
  }
  fs.rmSync(tmp,{recursive:true,force:true});
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail?1:0);
})();

'use strict';
const assert = require('assert');
const fs = require('fs'), path = require('path'), os = require('os');
const T = require('../lib/fs-tree');

let pass = 0, fail = 0;
const check = (name, fn) => {
  try { fn(); console.log('  PASS  ' + name); pass++; }
  catch (e) { console.log('  FAIL  ' + name + '\n        ' + e.message); fail++; }
};

// ── safeResolveWithin : la faille de traversee de chemin ────────────────────
console.log('\nsafeResolveWithin');
const BASE = '/nginx/logs';
const allowed = ['/nginx/logs/access.log', '/nginx/logs/sub/a.log', '/nginx/logs'];
const denied  = ['/nginx/logs/../../etc/shadow', '/nginx/logs/../../proc/self/environ',
                 '/nginx/logsEVIL/x', '/etc/passwd', '', null, '/nginx/logs/\0x'];
for (const p of allowed)
  check(`autorise ${JSON.stringify(p)}`, () => assert.ok(T.safeResolveWithin(p, [BASE])));
for (const p of denied)
  check(`refuse   ${JSON.stringify(p)}`, () => assert.strictEqual(T.safeResolveWithin(p, [BASE]), null));

// ── listTreeFiles / copyTree : les sous-dossiers ────────────────────────────
console.log('\nlistTreeFiles / copyTree');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'fstree-'));
const src = path.join(tmp, 'src'), dst = path.join(tmp, 'dst');
fs.mkdirSync(path.join(src, 'cainternal'), { recursive: true });
fs.mkdirSync(path.join(src, 'sub', 'deep'), { recursive: true });
fs.mkdirSync(path.join(dst, 'old'), { recursive: true });
fs.writeFileSync(path.join(src, 'cainternal', 'site.cer'), 'cert');
fs.writeFileSync(path.join(src, 'sub', 'deep', 'x.cer'), 'deep');
fs.writeFileSync(path.join(src, 'top.cer'), 'top');
fs.writeFileSync(path.join(src, '.gitkeep'), '');
fs.writeFileSync(path.join(dst, 'old', 'obsolete.cer'), 'obs');

check('remonte les fichiers imbriques', () => {
  const got = T.listTreeFiles(src).sort();
  assert.deepStrictEqual(got, ['.gitkeep', 'cainternal/site.cer', 'sub/deep/x.cer', 'top.cer']);
});
check('copyTree preserve la structure', () => {
  assert.strictEqual(T.copyTree(src, dst), 4);
  assert.ok(fs.existsSync(path.join(dst, 'cainternal', 'site.cer')));
  assert.ok(fs.existsSync(path.join(dst, 'sub', 'deep', 'x.cer')));
});
check('pruneEmptyDirs retire les dossiers vides', () => {
  fs.unlinkSync(path.join(dst, 'old', 'obsolete.cer'));
  T.pruneEmptyDirs(dst);
  assert.ok(!fs.existsSync(path.join(dst, 'old')));
  assert.ok(fs.existsSync(dst), 'la racine doit survivre');
});
check('listTreeFiles tolere un dossier absent', () => {
  assert.deepStrictEqual(T.listTreeFiles(path.join(tmp, 'nope')), []);
});

// ── protection des fichiers caches ──────────────────────────────────────────
console.log('\nfichiers proteges');
check('.gitkeep protege',            () => assert.ok(T.isProtectedFile('.gitkeep')));
check('site.conf non protege',       () => assert.ok(!T.isProtectedFile('site.conf')));
check('segment cache detecte',       () => assert.ok(T.hasProtectedSegment('.git/config')));
check('chemin normal non detecte',   () => assert.ok(!T.hasProtectedSegment('ca/site.cer')));

fs.rmSync(tmp, { recursive: true, force: true });
console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);

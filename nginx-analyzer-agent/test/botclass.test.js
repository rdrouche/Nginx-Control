'use strict';
const assert = require('assert');
const B = require('../lib/botclass');
let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; }
  catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

console.log('\nclassification bot/humain (memes motifs que nginx)');
check('un navigateur reel est humain', () => {
  const r = B.classifyAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36');
  assert.strictEqual(r.isBot, false);
  assert.strictEqual(r.category, 'human');
});
check('googlebot -> bon robot', () => {
  assert.deepStrictEqual(B.classifyAgent('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'),
    { isBot: true, category: 'good' });
});
check('bingbot -> bon robot', () => {
  assert.strictEqual(B.classifyAgent('bingbot/2.0').category, 'good');
});
check('GPTBot -> robot IA', () => {
  assert.strictEqual(B.classifyAgent('Mozilla/5.0 (compatible; GPTBot/1.0)').category, 'ai');
});
check('ClaudeBot -> robot IA', () => {
  assert.strictEqual(B.classifyAgent('ClaudeBot/1.0').category, 'ai');
});
check('AhrefsBot -> robot indesirable', () => {
  assert.strictEqual(B.classifyAgent('Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)').category, 'bad');
});
check('scanner de securite -> robot indesirable', () => {
  assert.strictEqual(B.classifyAgent('Shodan').category, 'bad');
});
check('client HTTP generique -> robot non catalogue', () => {
  assert.strictEqual(B.classifyAgent('python-requests/2.31.0').category, 'unknown');
  assert.strictEqual(B.classifyAgent('curl/8.4.0').category, 'unknown');
});
check('en-tete absent -> ni humain ni robot, distinct des deux', () => {
  assert.deepStrictEqual(B.classifyAgent(null), { isBot: null, category: null });
  assert.deepStrictEqual(B.classifyAgent(''), { isBot: null, category: null });
  assert.deepStrictEqual(B.classifyAgent(undefined), { isBot: null, category: null });
});
check('un robot connu ne doit jamais retomber dans la categorie generique', () => {
  // Un bot precisement identifie perd son identite si le motif generique
  // "bot" matche en premier — verifie l ordre de priorite des listes.
  const r = B.classifyAgent('Googlebot-Image/1.0');
  assert.strictEqual(r.category, 'good', 'ne doit pas devenir "unknown" juste parce que le mot bot y figure aussi');
});

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);

'use strict';
const assert = require('assert');
const { createLogParser, buildRecreateBody } = require('../lib/docker-stream');
let pass = 0, fail = 0;
const check = (n, f) => { try { f(); console.log('  PASS  ' + n); pass++; } catch (e) { console.log('  FAIL  ' + n + '\n        ' + e.message); fail++; } };

const frame = (type, text) => {
  const p = Buffer.from(text); const h = Buffer.alloc(8); h[0] = type; h.writeUInt32BE(p.length, 4);
  return Buffer.concat([h, p]);
};

check('trames stdout/stderr -> lignes', () => {
  const p = createLogParser();
  const out = p.push(Buffer.concat([frame(1, 'a\nb\n'), frame(2, 'err\n')]));
  assert.deepStrictEqual(out, [{ stream: 'out', line: 'a' }, { stream: 'out', line: 'b' }, { stream: 'err', line: 'err' }]);
});
check('trame coupee entre deux chunks', () => {
  const p = createLogParser();
  const all = frame(1, 'hello world\n');
  assert.deepStrictEqual(p.push(all.slice(0, 5)), []);
  assert.deepStrictEqual(p.push(all.slice(5, 12)), []);
  assert.deepStrictEqual(p.push(all.slice(12)), [{ stream: 'out', line: 'hello world' }]);
});
check('ligne coupee entre deux trames + flush', () => {
  const p = createLogParser();
  assert.deepStrictEqual(p.push(frame(1, 'par')), []);
  assert.deepStrictEqual(p.push(frame(1, 'tial\nrest')), [{ stream: 'out', line: 'partial' }]);
  assert.deepStrictEqual(p.flush(), [{ stream: 'out', line: 'rest' }]);
});
check('mode TTY : flux brut, CRLF nettoye', () => {
  const p = createLogParser({ tty: true });
  assert.deepStrictEqual(p.push(Buffer.from('x\r\ny\n')), [{ stream: 'out', line: 'x' }, { stream: 'out', line: 'y' }]);
});
check('ligne geante coupee (anti-memoire)', () => {
  const p = createLogParser({ tty: true });
  const out = p.push(Buffer.from('z'.repeat(20000)));
  assert.strictEqual(out.length, 1);
});
check('buildRecreateBody : reseaux, alias auto retires, hostname auto retire', () => {
  const b = buildRecreateBody({
    Config: { Image: 'img:1', Hostname: 'abcdef123456', Env: ['A=1'] },
    HostConfig: { NetworkMode: 'mynet', Binds: ['/a:/b'] },
    NetworkSettings: { Networks: { mynet: { Aliases: ['svc', 'abcdef123456'], NetworkID: 'x' } } },
  });
  assert.strictEqual(b.Image, 'img:1');
  assert.strictEqual(b.Hostname, undefined);
  assert.deepStrictEqual(b.NetworkingConfig.EndpointsConfig, { mynet: { Aliases: ['svc'] } });
  assert.deepStrictEqual(b.HostConfig.Binds, ['/a:/b']);
});
check('buildRecreateBody : mode host sans NetworkingConfig, hostname perso conserve', () => {
  const b = buildRecreateBody({
    Config: { Image: 'i', Hostname: 'my-host' }, HostConfig: { NetworkMode: 'host' },
    NetworkSettings: { Networks: { host: {} } },
  });
  assert.strictEqual(b.NetworkingConfig, undefined);
  assert.strictEqual(b.Hostname, 'my-host');
});
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

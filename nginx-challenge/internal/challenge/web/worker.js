'use strict';
// Cherche un compteur tel que SHA-256(jeton ":" compteur) ait `bits` bits à zéro
// en tête. Chaque worker teste start, start+step, start+2*step, …
self.onmessage = async (e) => {
  const { token, bits, start, step } = e.data;
  const enc = new TextEncoder();
  const BATCH = 256;
  const full = bits >> 3, rest = bits & 7, mask = rest ? (0xff << (8 - rest)) & 0xff : 0;
  let c = start;
  for (;;) {
    const cs = new Array(BATCH), ps = new Array(BATCH);
    for (let i = 0; i < BATCH; i++) { cs[i] = c; c += step; ps[i] = crypto.subtle.digest('SHA-256', enc.encode(token + ':' + cs[i])); }
    const out = await Promise.all(ps);
    for (let i = 0; i < BATCH; i++) {
      const d = new Uint8Array(out[i]);
      let ok = true;
      for (let j = 0; j < full; j++) if (d[j] !== 0) { ok = false; break; }
      if (ok && mask && (d[full] & mask) !== 0) ok = false;
      if (ok) { self.postMessage({ counter: String(cs[i]) }); return; }
    }
    self.postMessage({ progress: c });
  }
};

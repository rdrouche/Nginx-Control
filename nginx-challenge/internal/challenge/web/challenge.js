'use strict';
(function () {
  var root = document.getElementById('nc');
  var target = root.getAttribute('data-target') || '/';
  var assets = root.getAttribute('data-assets') || '/.nc-challenge/assets/';
  var api = assets.replace(/assets\/$/, 'api/');
  // Meme langue que celle choisie par le serveur (NC_LANG / Accept-Language).
  var attr = root.getAttribute('data-lang');
  var fr = attr ? attr === 'fr' : /^fr/i.test(navigator.language || '');
  var T = fr ? {
    title: 'Vérification de votre navigateur', work: "Un instant, nous vérifions que vous n'êtes pas un robot…",
    ok: 'Vérification réussie, redirection…', err: 'La vérification a échoué. ', retry: 'Réessayer',
    secure: 'Cette vérification nécessite une connexion sécurisée (HTTPS).', many: 'Trop de tentatives, patientez une minute puis réessayez.'
  } : {
    title: 'Checking your browser', work: 'One moment, we are checking that you are not a robot…',
    ok: 'Check passed, redirecting…', err: 'The check failed. ', retry: 'Retry',
    secure: 'This check requires a secure connection (HTTPS).', many: 'Too many attempts, wait a minute and retry.'
  };
  var $ = function (id) { return document.getElementById(id); };
  $('nc-title').textContent = T.title; $('nc-msg').textContent = T.work; $('nc-retry').textContent = T.retry;
  document.title = T.title;
  var workers = [];
  function stop() { workers.forEach(function (w) { w.terminate(); }); workers = []; }
  function fail(msg) {
    stop(); var m = $('nc-msg'); m.textContent = msg; m.className = 'err'; $('nc-retry').hidden = false;
  }
  function run() {
    $('nc-retry').hidden = true; $('nc-msg').className = ''; $('nc-msg').textContent = T.work; root.classList.remove('done');
    if (!window.crypto || !crypto.subtle) { fail(T.secure); return; }
    fetch(api + 'start', { credentials: 'same-origin', cache: 'no-store' }).then(function (r) {
      if (r.status === 429) throw new Error(T.many);
      if (!r.ok) throw new Error(T.err);
      return r.json();
    }).then(function (ch) {
      var n = Math.max(1, Math.min(4, navigator.hardwareConcurrency || 2)), done = false;
      for (var i = 0; i < n; i++) {
        var w = new Worker(assets + 'worker.js'); workers.push(w);
        w.onmessage = function (e) {
          if (done || !e.data.counter) return; done = true; stop();
          fetch(api + 'verify', {
            method: 'POST', credentials: 'same-origin', cache: 'no-store',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: ch.token, counter: e.data.counter, target: target })
          }).then(function (r) { return r.json().then(function (j) { return { s: r.status, j: j }; }); })
            .then(function (x) {
              if (x.s === 200 && x.j.ok) { root.classList.add('done'); $('nc-msg').textContent = T.ok; location.replace(x.j.target || '/'); }
              else fail(x.s === 429 ? T.many : T.err);
            }).catch(function () { fail(T.err); });
        };
        w.onerror = function () { if (!done) fail(T.err); };
        w.postMessage({ token: ch.token, bits: ch.bits, start: i, step: n });
      }
    }).catch(function (e) { fail(e && e.message ? e.message : T.err); });
  }
  $('nc-retry').addEventListener('click', run);
  run();
})();

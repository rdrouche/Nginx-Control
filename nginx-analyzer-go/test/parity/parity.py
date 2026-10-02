#!/usr/bin/env python3
"""Outils de parite Node <-> Go pour nginx-analyzer (aucune dependance Python tierce).

Trois modes, tous bases sur les VRAIS binaires lances sur les memes fichiers de log :

  api   Envoie le meme trafic aux deux implementations, puis compare les reponses
        JSON des routes consommees par le dashboard (champs volatils normalises).
  db    Cree la base SQLite avec une implementation et la rouvre avec l'autre (dans
        les deux sens) : memes reponses, offsets de lecture repris sans re-parsing.
  mem   Mesure debit d'ingestion et RSS de chaque implementation sous charge.

Usage :
  go build -o /tmp/analyzer-go ../../cmd/analyzer
  python3 parity.py api
  python3 parity.py db
  N=60000 python3 parity.py mem            # 5 fichiers x N lignes ; K=node|go pour un seul

Variables : NODE_SERVER (defaut ../../../nginx-analyzer/server.js), GO_BIN (defaut /tmp/analyzer-go).
Code de sortie != 0 si une divergence non volatile est detectee (modes api et db).
"""
import datetime, json, os, random, shutil, subprocess, sys, tempfile, time, urllib.error, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
NODE_SERVER = os.environ.get('NODE_SERVER', os.path.join(HERE, '..', '..', '..', 'nginx-analyzer', 'server.js'))
GO_BIN = os.environ.get('GO_BIN', '/tmp/analyzer-go')

# Champs dont la valeur differe legitimement d'une execution a l'autre.
VOLATILE = {'id', 'ts', 'at', 'uptime', 'rssMb', 'memoryMb', 'memoryMB', 'rss', 'createdAt', 'generatedAt', 'firstSeen',
            'lastSeen', 'time', 'startedAt', 'from', 'to', 'bucket', 'hour', 'minute', 'lastLineAt', 'ackedAt',
            'detectedAt', 'logsDir', 'dbPath', 'lastSeenAt', 'firstSeenAt', 'first', 'last'}

ENDPOINTS = ['/api/alerts?limit=100', '/api/traffic/vhosts?hours=24', '/api/traffic/countries?hours=24',
             '/api/traffic/bots?hours=24', '/api/traffic/bots/vhosts?hours=24', '/api/traffic/series?hours=24',
             '/api/rules', '/api/rules/blocklist-config', '/api/rules/custom', '/api/waf/events',
             '/api/waf/top-rules?hours=24', '/api/waf/top-ips?hours=24', '/api/waf/series?hours=24',
             '/api/baseline', '/api/baseline/country', '/api/exceptions', '/api/blocklist-hits/summary?hours=24']


def api(port, path, method='GET', body=None, timeout=5):
    req = urllib.request.Request(f'http://127.0.0.1:{port}{path}', method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b'null')
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b'null')


def launch(kind, port, tmp):
    env = dict(os.environ, PORT=str(port), LOGS_DIR=os.path.join(tmp, 'logs'), DB_PATH=os.path.join(tmp, 'data', 's.db'),
               POLL_MS='100', FLUSH_MS='300', EVALUATE_MS='500', LEARNING_DAYS='21',
               GEOIP_CITY_DB='/x/no', GEOIP_COUNTRY_DB='/x/no', GEOIP_ASN_DB='/x/no')
    cmd = ['node', NODE_SERVER] if kind == 'node' else [GO_BIN]
    p = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            if api(port, '/api/health')[0] == 200:
                return p
        except Exception:
            time.sleep(0.2)
    p.kill()
    raise RuntimeError(f'{kind} ne demarre pas')


def stop(p):
    p.terminate()
    try:
        p.wait(timeout=15)
    except subprocess.TimeoutExpired:
        p.kill()


def mkenv(prefix, files=('a.fr.access.log', 'b.fr.access.log', 'a.fr.waf.log')):
    tmp = tempfile.mkdtemp(prefix=prefix)
    os.makedirs(os.path.join(tmp, 'logs')); os.makedirs(os.path.join(tmp, 'data'))
    for f in files:
        open(os.path.join(tmp, 'logs', f), 'w').close()
    return tmp


def scenario_lines():
    """Trafic couvrant : normal, bots, bruteforce, scan multi-vhost, flood/scraping, 403."""
    random.seed(7)
    ts = datetime.datetime.now(datetime.timezone.utc).strftime('%d/%b/%Y:%H:%M:%S +0000')
    uas = ['Mozilla/5.0 (X11; Linux) Firefox/120', 'Googlebot/2.1 (+http://www.google.com/bot.html)', 'GPTBot/1.0',
           'curl/8.1', 'python-requests/2.31', 'SemrushBot/7', '-']
    out = {'a.fr': [], 'b.fr': []}

    def line(ip, path, st, ua, m='GET'):
        return f'{ip} - - [{ts}] "{m} {path} HTTP/1.1" {st} {random.randint(100, 5000)} "-" "{ua}"\n'
    for i in range(60): out['a.fr'].append(line(f'198.51.100.{i % 40}', f'/p{i}', 200, uas[i % len(uas)]))
    for i in range(30): out['a.fr'].append(line('192.0.2.66', '/login', 401, uas[0], 'POST'))
    for i in range(50): out['b.fr'].append(line('192.0.2.77', f'/wp-{i}.php', 404, uas[3]))
    for i in range(25): out['a.fr'].append(line('192.0.2.77', f'/admin{i}', 404, uas[3]))
    for i in range(400): out['b.fr'].append(line('192.0.2.88', '/api/x', 200, uas[4]))
    for i in range(20): out['a.fr'].append(line('203.0.113.9', f'/q{i}', 403, uas[5]))
    return out


def waf_lines():
    out = ''
    for i, (ip, code, rid, msg) in enumerate([('198.51.100.9', 403, '942100', 'SQLi'), ('198.51.100.10', 200, '941100', 'XSS')]):
        out += json.dumps({'transaction': {
            'client_ip': ip, 'time_stamp': datetime.datetime.now(datetime.timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT'),
            'request': {'method': 'GET', 'uri': '/l'}, 'response': {'http_code': code}, 'unique_id': f'u{i}',
            'messages': [{'message': msg, 'details': {'ruleId': rid, 'severity': '2', 'tags': ['attack-sqli']}}]}}) + '\n'
    return out


def feed(tmp):
    for v, ls in scenario_lines().items():
        open(os.path.join(tmp, 'logs', v + '.access.log'), 'a').write(''.join(ls))
    open(os.path.join(tmp, 'logs', 'a.fr.waf.log'), 'a').write(waf_lines())


# ---- comparaison --------------------------------------------------------------------------------
def norm(x):
    if isinstance(x, dict):
        d = {k: ('<v>' if k in VOLATILE else norm(v)) for k, v in x.items()}
        # L'ordre de readdir (Node) n'est pas garanti : on compare par nom de fichier.
        if isinstance(d.get('following'), list):
            d['following'] = sorted(d['following'], key=lambda f: str(f.get('file')))
        return d
    if isinstance(x, list):
        return [norm(i) for i in x]
    return x


def diff(a, b, p=''):
    o = []
    num = (int, float)
    if type(a) != type(b) and not (isinstance(a, num) and isinstance(b, num)):
        return [f'{p}: type {type(a).__name__} vs {type(b).__name__} (A={str(a)[:50]} B={str(b)[:50]})']
    if isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a: o.append(f'{p}/{k}: absent de A')
            elif k not in b: o.append(f'{p}/{k}: absent de B')
            else: o += diff(a[k], b[k], f'{p}/{k}')
    elif isinstance(a, list):
        if len(a) != len(b): o.append(f'{p}: longueur A={len(a)} B={len(b)}')
        for i, (x, y) in enumerate(zip(a, b)): o += diff(x, y, f'{p}[{i}]')
    elif a != b and not (isinstance(a, num) and isinstance(b, num) and abs(a - b) < 1e-6):
        o.append(f'{p}: A={str(a)[:50]} B={str(b)[:50]}')
    return o


def report(title, A, B, ignore=()):
    bad = 0
    print(f'== {title}')
    for k in A:
        df = [] if A[k][0] == B[k][0] else [f'statut A={A[k][0]} B={B[k][0]}']
        df += [d for d in diff(norm(A[k][1]), norm(B[k][1])) if not any(i in d for i in ignore)]
        print(('  OK    ' if not df else '  DIFF  ') + k)
        for d in df[:8]: print('         ', d)
        bad += bool(df)
    return bad


# ---- modes --------------------------------------------------------------------------------------
def run_api(kind, port):
    tmp = mkenv('par-' + kind + '-'); p = launch(kind, port, tmp)
    try:
        time.sleep(1.0); feed(tmp)
        api(port, '/api/vhost-rules', 'POST', {'vhosts': {'b.fr': {'ignore': [2]}}})
        time.sleep(4.0)
        R = {e: api(port, e) for e in ENDPOINTS}
        R['POST rules/blocklist'] = api(port, '/api/rules/blocklist?key=scan', 'POST', {'threshold': 5, 'windowMinutes': 30, 'remediation': True, 'remediationMinutes': 60})
        R['POST rules/blocklist (cle inconnue)'] = api(port, '/api/rules/blocklist?key=nope', 'POST', {'threshold': -1})
        R['blocklist-config apres'] = api(port, '/api/rules/blocklist-config')
        R['PUT rules/custom (yaml invalide)'] = api(port, '/api/rules/custom', 'PUT', {'yaml': 'not: [valid'})
        R['POST exceptions'] = api(port, '/api/exceptions', 'POST', {'vhost': 'a.fr', 'ip': '192.0.2.66', 'reason': 't', 'author': 'x'})
        R['exceptions apres'] = api(port, '/api/exceptions')
        R['POST blocklist-sources'] = api(port, '/api/blocklist-sources', 'POST', {'mode': 'approx', 'sources': {'s': {'ips': ['203.0.113.0/24']}}})
        R['status'] = api(port, '/api/status')
        return R
    finally:
        stop(p); shutil.rmtree(tmp, ignore_errors=True)


def mode_api():
    n, g = run_api('node', 9301), run_api('go', 9302)
    # memoryMb/config.* : attendus differents ; le reste doit etre identique.
    return report('API Node (A) vs Go (B)', n, g)


def mode_db():
    bad = 0
    for first, second in (('node', 'go'), ('go', 'node')):
        tmp = mkenv('sh-'); p = launch(first, 9311, tmp); time.sleep(1); feed(tmp); time.sleep(4)
        api(9311, '/api/rules/blocklist?key=scan', 'POST', {'threshold': 5, 'windowMinutes': 30, 'remediation': True, 'remediationMinutes': 60})
        api(9311, '/api/exceptions', 'POST', {'vhost': 'a.fr', 'ip': '192.0.2.99', 'reason': 't', 'author': 'x'})
        time.sleep(1); A = {e: api(9311, e) for e in ENDPOINTS}; stop(p)
        p2 = launch(second, 9312, tmp); time.sleep(2.5); B = {e: api(9312, e) for e in ENDPOINTS}
        bad += report(f'Base creee par {first}, reprise par {second}', A, B)
        # Du nouveau trafic doit etre ingere apres reouverture ; les 5 lignes seules (offsets repris).
        lines = scenario_lines()['a.fr'][:5]
        open(os.path.join(tmp, 'logs', 'a.fr.access.log'), 'a').write(''.join(lines)); time.sleep(1.5)
        parsed = api(9312, '/api/status')[1]['tail']['parsed']
        ok = parsed == 5
        print(f'  {"OK  " if ok else "DIFF"}  lignes lues apres reouverture = {parsed} (attendu 5 : offsets repris sans re-parsing)')
        bad += (not ok)
        stop(p2); shutil.rmtree(tmp, ignore_errors=True)
    return bad


def mode_mem():
    N = int(os.environ.get('N', '60000'))
    kinds = [os.environ['K']] if os.environ.get('K') else ['node', 'go']
    for i, kind in enumerate(kinds):
        tmp = mkenv('mem-', [f'v{j}.fr.access.log' for j in range(5)]); p = launch(kind, 9320 + i, tmp)
        try:
            time.sleep(1.5)
            def status():
                for _ in range(60):
                    try: return api(9320 + i, '/api/status')[1]
                    except Exception: time.sleep(1)
            m0 = status()['memoryMb']
            random.seed(1); ts = datetime.datetime.now(datetime.timezone.utc).strftime('%d/%b/%Y:%H:%M:%S +0000')
            for j in range(5):
                with open(os.path.join(tmp, 'logs', f'v{j}.fr.access.log'), 'a') as h:
                    h.write(''.join(f'10.{random.randint(0,80)}.{random.randint(0,250)}.{random.randint(1,250)} - - [{ts}] "GET /p{random.randint(0,3000)} HTTP/1.1" {random.choice([200,200,200,301,404,500])} {random.randint(100,9000)} "-" "Mozilla/5.0 (X11; Linux x86_64) Chrome/120 Safari/537.36"\n' for _ in range(N)))
            t = time.time()
            while time.time() - t < 180:
                st = status()
                if st and st['tail'].get('parsed', 0) >= 5 * N: break
                time.sleep(0.5)
            el = time.time() - t; time.sleep(3); st = status()
            print(f"{kind:5} lignes={st['tail'].get('parsed')} ingestion={el:.1f}s  RSS repos={m0} Mo  apres charge={st['memoryMb']} Mo  IP suivies={st['detector']['trackedIps']}", flush=True)
        finally:
            stop(p); shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == '__main__':
    modes = {'api': mode_api, 'db': mode_db, 'mem': mode_mem}
    if len(sys.argv) != 2 or sys.argv[1] not in modes:
        sys.exit(__doc__)
    rc = modes[sys.argv[1]]()
    print('\nRESULTAT :', 'OK' if not rc else f'{rc} divergence(s)')
    sys.exit(1 if rc else 0)

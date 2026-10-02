package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nginx-analyzer-go/internal/app"
	"nginx-analyzer-go/internal/blocklistsources"
	"nginx-analyzer-go/internal/config"
)

// startTestServer assemble un vrai agent (comme e2e_test.go) avec l'env donne.
func startTestServer(t *testing.T, extra map[string]string) (srvURL, logsDir string, cleanup func()) {
	t.Helper()
	tmp := t.TempDir()
	logsDir = filepath.Join(tmp, "logs")
	dataDir := filepath.Join(tmp, "data")
	for _, d := range []string{logsDir, dataDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	env := map[string]string{
		"LOGS_DIR": logsDir, "DB_PATH": filepath.Join(dataDir, "s.db"),
		"POLL_MS": "50", "FLUSH_MS": "150", "EVALUATE_MS": "300", "LEARNING_DAYS": "21",
		"GEOIP_CITY_DB": "/nexiste/pas.mmdb", "GEOIP_COUNTRY_DB": "/nexiste/pas.mmdb", "GEOIP_ASN_DB": "/nexiste/pas.mmdb",
	}
	for k, v := range extra {
		env[k] = v
	}
	restore := setEnv(t, env)
	a := app.New(config.Load())
	stop := make(chan struct{})
	a.StartBackgroundLoops(stop)
	a.Boot()
	srv := httptest.NewServer(NewHandler(a))
	return srv.URL, logsDir, func() {
		srv.Close()
		close(stop)
		a.Close()
		restore()
	}
}

func doReq(t *testing.T, method, u string, headers map[string]string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, u, rd)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, u, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, m
}

// Port de analyzer-token.test.js (audit ANA-10).
func TestTokenAuth(t *testing.T) {
	t.Run("jeton pose", func(t *testing.T) {
		u, _, done := startTestServer(t, map[string]string{"ANALYZER_TOKEN": "abc123token"})
		defer done()
		if c, _ := doReq(t, "GET", u+"/api/status", nil, nil); c != 401 {
			t.Errorf("sans jeton: %d, attendu 401", c)
		}
		if c, _ := doReq(t, "GET", u+"/api/status", map[string]string{"X-Analyzer-Token": "nope"}, nil); c != 401 {
			t.Errorf("mauvais jeton: %d, attendu 401", c)
		}
		if c, _ := doReq(t, "GET", u+"/api/status", map[string]string{"X-Analyzer-Token": "abc123token"}, nil); c != 200 {
			t.Errorf("bon jeton: %d, attendu 200", c)
		}
		if c, _ := doReq(t, "POST", u+"/api/alerts/clear", nil, nil); c != 401 {
			t.Errorf("POST sans jeton: %d, attendu 401", c)
		}
		if c, _ := doReq(t, "GET", u+"/api/health", nil, nil); c != 200 {
			t.Errorf("/api/health doit rester ouvert: %d", c)
		}
	})
	t.Run("jeton absent", func(t *testing.T) {
		u, _, done := startTestServer(t, map[string]string{"ANALYZER_TOKEN": ""})
		defer done()
		if c, _ := doReq(t, "GET", u+"/api/status", nil, nil); c != 200 {
			t.Errorf("sans ANALYZER_TOKEN: %d, attendu 200 (non-regression)", c)
		}
	})
}

// v12.50.0 : blocklist configuree par regle ; v12.29.0 : sources poussees par
// le dashboard et attribution des hits (mode approx).
func TestBlocklistPerRuleAndSources(t *testing.T) {
	u, logsDir, done := startTestServer(t, nil)
	defer done()
	t.Cleanup(func() { blocklistsources.SetSources(nil); blocklistsources.SetMode("") })

	code, cfg := doReq(t, "GET", u+"/api/rules/blocklist-config", nil, nil)
	if code != 200 {
		t.Fatalf("blocklist-config: %d", code)
	}
	if rs, _ := cfg["rules"].([]any); len(rs) != 0 {
		t.Errorf("aucune regle integree n'a opte au depart: %v", cfg["rules"])
	}

	if code, res := doReq(t, "POST", u+"/api/rules/blocklist?key=inconnue", nil, map[string]any{"threshold": 5}); code != 400 {
		t.Errorf("cle inconnue: %d %v, attendu 400", code, res)
	}
	code, res := doReq(t, "POST", u+"/api/rules/blocklist?key=bruteforce", nil, map[string]any{
		"threshold": 5, "windowMinutes": 30, "remediation": true, "remediationMinutes": 120,
	})
	if code != 200 || res["ok"] != true {
		t.Fatalf("set blocklist: %d %v", code, res)
	}
	_, cfg = doReq(t, "GET", u+"/api/rules/blocklist-config", nil, nil)
	list, _ := cfg["rules"].([]any)
	if len(list) != 1 {
		t.Fatalf("attendu 1 regle apres opt-in: %v", cfg)
	}
	r0 := list[0].(map[string]any)
	if r0["remediation"] != true || r0["threshold"].(float64) != 5 {
		t.Errorf("config relue incorrecte: %v", r0)
	}
	t.Logf("blocklist-config rule: %v", r0)

	// Sources poussees + hit "approx" depuis le log d'acces.
	logFile := filepath.Join(logsDir, "site.fr.access.log")
	_ = os.WriteFile(logFile, nil, 0o644)
	time.Sleep(300 * time.Millisecond) // laisse le tailer decouvrir le fichier
	code, res = doReq(t, "POST", u+"/api/blocklist-sources", nil, map[string]any{
		"mode": "approx", "sources": map[string]any{"listeA": map[string]any{"ips": []string{"203.0.113.0/24"}}},
	})
	if code != 200 || res["mode"] != "approx" {
		t.Fatalf("blocklist-sources: %d %v", code, res)
	}
	_, st := doReq(t, "GET", u+"/api/status", nil, nil)
	bs, _ := st["blocklistSources"].(map[string]any)
	if bs["mode"] != "approx" || bs["synced"] != true {
		t.Errorf("status.blocklistSources = %v", bs)
	}

	ts := time.Now().UTC().Format("02/Jan/2006:15:04:05 +0000")
	f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0o644)
	for i := 0; i < 3; i++ {
		fmt.Fprintf(f, "203.0.113.7 - - [%s] \"GET /x HTTP/1.1\" 403 10 \"-\" \"curl/8\"\n", ts)
	}
	f.Close()
	time.Sleep(900 * time.Millisecond)

	_, sum := doReq(t, "GET", u+"/api/blocklist-hits/summary?hours=1", nil, nil)
	by, _ := sum["bySource"].([]any)
	if len(by) != 1 || by[0].(map[string]any)["name"] != "listeA" || by[0].(map[string]any)["hits"].(float64) != 3 {
		t.Fatalf("bySource = %v (summary=%v)", sum["bySource"], sum)
	}

	if c, _ := doReq(t, "GET", u+"/api/blocklist-hits/check?ip=pas-une-ip", nil, nil); c != 400 {
		t.Errorf("check ip invalide: %d", c)
	}
	if c, r := doReq(t, "POST", u+"/api/blocklist-hits/clear", nil, nil); c != 200 || r["deleted"].(float64) != 3 {
		t.Errorf("clear: %d %v", c, r)
	}
}

func TestClampLimit(t *testing.T) {
	cases := []struct {
		raw      string
		def, max int
		want     int
	}{
		{"", 100, 500, 100}, {"abc", 100, 500, 100}, {"-5", 100, 500, 1}, {"0", 100, 500, 1},
		{"9999", 100, 500, 500}, {"42.9", 100, 500, 42}, {"NaN", 100, 500, 100}, {"Infinity", 100, 500, 100},
	}
	for _, c := range cases {
		if got := clampLimit(c.raw, c.def, c.max); got != c.want {
			t.Errorf("clampLimit(%q) = %d, attendu %d", c.raw, got, c.want)
		}
	}
}

func TestWindowParams(t *testing.T) {
	from, to := windowParams(url.Values{"to": {"10000000"}, "hours": {"2"}})
	if to != 10000000 || from != 10000000-2*3_600_000 {
		t.Errorf("window = %d..%d", from, to)
	}
	from, to = windowParams(url.Values{"from": {"5"}, "to": {"9"}})
	if from != 5 || to != 9 {
		t.Errorf("from/to explicites ignores: %d..%d", from, to)
	}
	from, to = windowParams(url.Values{})
	if to-from != 24*3_600_000 {
		t.Errorf("fenetre par defaut = %d ms", to-from)
	}
}

func TestReadJSONBodyOverCapAndInvalid(t *testing.T) {
	big := `{"a":"` + strings.Repeat("x", config.ReadJSONBodyMaxBytes+10) + `"}`
	if m := readJSONBody(httptest.NewRequest("POST", "/", strings.NewReader(big))); len(m) != 0 {
		t.Errorf("corps > plafond doit donner {}: %d cles", len(m))
	}
	if m := readJSONBody(httptest.NewRequest("POST", "/", strings.NewReader("pas du json"))); len(m) != 0 {
		t.Errorf("json invalide doit donner {}")
	}
	if m := readJSONBody(httptest.NewRequest("POST", "/", strings.NewReader(`{"k":1}`))); m["k"] != float64(1) {
		t.Errorf("json valide mal lu: %v", m)
	}
}

func TestTokensMatch(t *testing.T) {
	if !tokensMatch("abc", "abc") || tokensMatch("abc", "abd") || tokensMatch("ab", "abc") || tokensMatch("", "abc") {
		t.Error("tokensMatch incorrect")
	}
}

func TestEmptyNilSlices(t *testing.T) {
	var nilStrs []string
	in := map[string]any{
		"a": nilStrs, "b": []map[string]any(nil), "c": []any{nilStrs, map[string]any{"d": []int(nil)}},
		"e": map[string]any{"f": []string(nil)}, "g": nil, "h": []string{"x"},
	}
	b, _ := json.Marshal(emptyNilSlices(in))
	var got map[string]any
	_ = json.Unmarshal(b, &got)
	for _, k := range []string{"a", "b"} {
		if l, ok := got[k].([]any); !ok || len(l) != 0 {
			t.Errorf("%s = %v, attendu []", k, got[k])
		}
	}
	c := got["c"].([]any)
	if l, ok := c[0].([]any); !ok || len(l) != 0 {
		t.Errorf("c[0] = %v", c[0])
	}
	if l, ok := c[1].(map[string]any)["d"].([]any); !ok || len(l) != 0 {
		t.Errorf("c[1].d = %v", c[1])
	}
	if l, ok := got["e"].(map[string]any)["f"].([]any); !ok || len(l) != 0 {
		t.Errorf("e.f = %v", got["e"])
	}
	if got["g"] != nil {
		t.Errorf("g doit rester null: %v", got["g"])
	}
	if emptyNilSlices(nil) != nil {
		t.Error("nil -> nil")
	}
}

func TestNullableHelpersAndJSNumber(t *testing.T) {
	if nullStr("") != nil || nullStr("x") != "x" || nullInt(0) != nil || nullInt(403) != 403 {
		t.Error("nullStr/nullInt")
	}
	for in, want := range map[any]int{float64(3): 3, "4": 4, " 5 ": 5} {
		if got, ok := jsNumber(in); !ok || got != want {
			t.Errorf("jsNumber(%v) = %d,%v", in, got, ok)
		}
	}
	if _, ok := jsNumber("abc"); ok {
		t.Error("jsNumber(abc) doit etre ignore (NaN)")
	}
	if _, ok := jsNumber(nil); ok {
		t.Error("jsNumber(nil)")
	}
}

// Regression (parite Node) : `enabled` absent dans /api/vhost-rules vaut true
// (JS : cfg.enabled !== false). Un vhost sans `enabled` ne doit pas etre coupe
// de l'analyse ; `enabled:false` explicite, si.
func TestVhostRulesEnabledDefault(t *testing.T) {
	u, logsDir, done := startTestServer(t, nil)
	defer done()
	for _, v := range []string{"on.fr", "off.fr"} {
		_ = os.WriteFile(filepath.Join(logsDir, v+".access.log"), nil, 0o644)
	}
	time.Sleep(300 * time.Millisecond)
	doReq(t, "POST", u+"/api/vhost-rules", nil, map[string]any{"vhosts": map[string]any{
		"on.fr": map[string]any{"ignore": []any{"2"}}, "off.fr": map[string]any{"enabled": false},
	}})
	ts := time.Now().UTC().Format("02/Jan/2006:15:04:05 +0000")
	// Une IP par vhost : une meme IP sur deux vhosts serait agregee en une
	// seule alerte multi-vhost (vhost null), ce qui est un autre cas.
	for v, ip := range map[string]string{"on.fr": "192.0.2.50", "off.fr": "192.0.2.51"} {
		f, _ := os.OpenFile(filepath.Join(logsDir, v+".access.log"), os.O_APPEND|os.O_WRONLY, 0o644)
		for i := 0; i < 30; i++ {
			fmt.Fprintf(f, "%s - - [%s] \"POST /login HTTP/1.1\" 401 10 \"-\" \"Mozilla/5.0\"\n", ip, ts)
		}
		f.Close()
	}
	time.Sleep(1200 * time.Millisecond)
	_, res := doReq(t, "GET", u+"/api/alerts?limit=50", nil, nil)
	vhosts := map[string]bool{}
	for _, a := range res["alerts"].([]any) {
		vhosts[fmt.Sprint(a.(map[string]any)["vhost"])] = true
	}
	if !vhosts["on.fr"] {
		t.Errorf("on.fr (enabled absent, ignore [\"2\"]) devrait alerter bruteforce: %v", vhosts)
	}
	if vhosts["off.fr"] {
		t.Errorf("off.fr (enabled:false) ne doit pas alerter: %v", vhosts)
	}
}

// Test de charge concurrent : ingestion massive pendant que tous les endpoints
// de lecture/ecriture sont interroges en boucle. N'a de valeur que sous
// `go test -race` (Node, mono-thread, ne pouvait pas avoir ces races) ; hors
// -race il verifie au moins l'absence de crash ("concurrent map ...") et de blocage.
func TestConcurrentLoad(t *testing.T) {
	u, logsDir, done := startTestServer(t, nil)
	defer done()
	logFile := filepath.Join(logsDir, "load.fr.access.log")
	_ = os.WriteFile(logFile, nil, 0o644)
	_ = os.WriteFile(filepath.Join(logsDir, "load.fr.waf.log"), nil, 0o644)
	time.Sleep(300 * time.Millisecond)

	stop := make(chan struct{})
	finished := make(chan struct{}, 8)
	paths := []string{
		"/api/status", "/api/alerts?limit=50", "/api/traffic/vhosts?hours=24", "/api/traffic/countries?hours=24",
		"/api/traffic/bots?hours=24", "/api/traffic/series?hours=24", "/api/traffic/recent", "/api/rules",
		"/api/rules/blocklist-config", "/api/baseline", "/api/baseline/country", "/api/waf/events",
		"/api/blocklist-hits/summary?hours=1", "/api/exceptions",
	}
	for w := 0; w < 4; w++ {
		go func(w int) {
			defer func() { finished <- struct{}{} }()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				p := paths[(i+w)%len(paths)]
				resp, err := http.Get(u + p)
				if err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
				switch i % 7 {
				case 0:
					http.Post(u+"/api/rules/toggle?key=flood&enable="+fmt.Sprint(i%2), "application/json", nil)
				case 3:
					b, _ := json.Marshal(map[string]any{"vhosts": map[string]any{"load.fr": map[string]any{"ignore": []int{i % 5}}}})
					http.Post(u+"/api/vhost-rules", "application/json", bytes.NewReader(b))
				case 5:
					b, _ := json.Marshal(map[string]any{"mode": "approx", "sources": map[string]any{"s": map[string]any{"ips": []string{"10.0.0.0/8"}}}})
					http.Post(u+"/api/blocklist-sources", "application/json", bytes.NewReader(b))
				}
			}
		}(w)
	}

	ts := time.Now().UTC().Format("02/Jan/2006:15:04:05 +0000")
	for round := 0; round < 10; round++ {
		var sb strings.Builder
		for i := 0; i < 3000; i++ {
			fmt.Fprintf(&sb, "10.%d.%d.%d - - [%s] \"GET /p%d HTTP/1.1\" %d 500 \"-\" \"Mozilla/5.0 Googlebot\"\n",
				round, i%250, (i/7)%250+1, ts, i%300, []int{200, 404, 401, 500}[i%4])
		}
		f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0o644)
		f.WriteString(sb.String())
		f.Close()
		time.Sleep(150 * time.Millisecond)
	}
	time.Sleep(800 * time.Millisecond)
	close(stop)
	for w := 0; w < 4; w++ {
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			t.Fatal("un worker de requetes est bloque (deadlock ?)")
		}
	}
	_, st := doReq(t, "GET", u+"/api/status", nil, nil)
	if p := st["tail"].(map[string]any)["parsed"].(float64); p < 30000 {
		t.Errorf("parsed = %v, attendu 30000", p)
	}
}

// /api/vhost-rules accepte pathsIgnore (cles non numeriques et valeurs non-chaine ecartees sans erreur).
func TestVhostRulesAcceptsPathsIgnore(t *testing.T) {
	u, _, cleanup := startTestServer(t, nil)
	defer cleanup()
	code, body := doReq(t, "POST", u+"/api/vhost-rules", nil, map[string]any{"vhosts": map[string]any{
		"site.fr": map[string]any{"pathsIgnore": map[string]any{"1": []any{"/a", 42, "no-slash"}, "x": []any{"/z"}}},
	}})
	if code != 200 || body["ok"] != true {
		t.Fatalf("attendu 200 ok, obtenu %d %v", code, body)
	}
}

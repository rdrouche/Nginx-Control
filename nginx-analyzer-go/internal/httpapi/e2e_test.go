package httpapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nginx-analyzer-go/internal/app"
	"nginx-analyzer-go/internal/config"
)

// Ce test porte, en abrege, test/e2e.test.js : demarre le vrai agent assemble
// (App + Handler), lui injecte du trafic normal puis une attaque via de
// vrais fichiers de log sur disque, et verifie l'API bout en bout - le seul
// test qui exerce l'assemblage complet plutot qu'un paquet isole.
func TestE2E(t *testing.T) {
	tmp := t.TempDir()
	logsDir := filepath.Join(tmp, "logs")
	dataDir := filepath.Join(tmp, "data")
	if err := os.MkdirAll(logsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	logFile := filepath.Join(logsDir, "site.fr.access.log")
	if err := os.WriteFile(logFile, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	// Le tailer demarre a la FIN d'un fichier nouvellement decouvert : le log
	// WAF doit donc exister (vide) avant Boot pour ne pas perdre la ligne.
	wafLogPath := filepath.Join(logsDir, "site.fr.waf.log")
	if err := os.WriteFile(wafLogPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	env := map[string]string{
		"LOGS_DIR": logsDir, "DB_PATH": filepath.Join(dataDir, "s.db"),
		"POLL_MS": "50", "FLUSH_MS": "200", "EVALUATE_MS": "300", "LEARNING_DAYS": "21",
		"GEOIP_COUNTRY_DB": "../geoip/testdata/test-country.mmdb",
		"GEOIP_CITY_DB":    "/nexiste/pas.mmdb", "GEOIP_ASN_DB": "/nexiste/pas.mmdb",
	}
	restore := setEnv(t, env)
	defer restore()

	cfg := config.Load()
	a := app.New(cfg)
	stop := make(chan struct{})
	a.StartBackgroundLoops(stop)
	a.Boot()
	defer func() {
		close(stop)
		a.Close()
	}()

	srv := httptest.NewServer(NewHandler(a))
	defer srv.Close()

	get := func(path string) map[string]any {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		var m map[string]any
		body, _ := io.ReadAll(resp.Body)
		_ = json.Unmarshal(body, &m)
		return m
	}
	post := func(path string) map[string]any {
		resp, err := http.Post(srv.URL+path, "application/json", nil)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		defer resp.Body.Close()
		var m map[string]any
		body, _ := io.ReadAll(resp.Body)
		_ = json.Unmarshal(body, &m)
		return m
	}

	t.Run("demarrage", func(t *testing.T) {
		health := get("/api/health")
		if health["ok"] != true {
			t.Fatalf("health = %v", health)
		}
		st := get("/api/status")
		tail, _ := st["tail"].(map[string]any)
		if tail == nil || tail["files"].(float64) < 1 {
			t.Fatalf("status.tail = %v", st["tail"])
		}
		storeStats, _ := st["store"].(map[string]any)
		if storeStats["persistent"] != true {
			t.Fatalf("store not persistent: %v", storeStats)
		}
		baselineStats, _ := st["baseline"].(map[string]any)
		if baselineStats["learning"] != true {
			t.Fatalf("baseline should be learning: %v", baselineStats)
		}
	})

	appendLog := func(lines string) {
		f, err := os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(lines); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}

	accessLine := func(ip, path string, status int) string {
		ts := time.Now().UTC().Format("02/Jan/2006:15:04:05 +0000")
		return fmt.Sprintf(`%s - - [%s] "GET %s HTTP/1.1" %d 100 "-" "Mozilla/5.0"`+"\n", ip, ts, path, status)
	}

	t.Run("trafic normal", func(t *testing.T) {
		var lines string
		for i := 0; i < 30; i++ {
			lines += accessLine(fmt.Sprintf("198.51.100.%d", i), fmt.Sprintf("/page-%d", i), 200)
		}
		appendLog(lines)
		time.Sleep(800 * time.Millisecond)
		st := get("/api/status")
		tail := st["tail"].(map[string]any)
		if tail["parsed"].(float64) < 30 {
			t.Fatalf("parsed = %v", tail["parsed"])
		}
		alerts := get("/api/alerts")
		if alerts["total"].(float64) != 0 {
			t.Fatalf("un trafic normal ne devrait declencher aucune alerte: %v", alerts)
		}
	})

	var bruteforceAlert map[string]any
	t.Run("attaque bruteforce", func(t *testing.T) {
		var attack string
		for i := 0; i < 25; i++ {
			attack += accessLine("192.0.2.66", "/login", 401)
		}
		appendLog(attack)
		time.Sleep(1200 * time.Millisecond)
		alerts := get("/api/alerts")
		if alerts["total"].(float64) < 1 {
			t.Fatalf("l attaque n a pas ete detectee: %v", alerts)
		}
		list, _ := alerts["alerts"].([]any)
		for _, raw := range list {
			al := raw.(map[string]any)
			if al["type"] == "bruteforce" {
				bruteforceAlert = al
			}
		}
		if bruteforceAlert == nil {
			t.Fatal("alerte bruteforce absente")
		}
		if bruteforceAlert["severity"] != "high" {
			t.Fatalf("severity = %v", bruteforceAlert["severity"])
		}
		if bruteforceAlert["ip"] != "192.0.2.66" {
			t.Fatalf("ip = %v", bruteforceAlert["ip"])
		}
		evidence, _ := bruteforceAlert["evidence"].(map[string]any)
		if evidence == nil || evidence["authFailures"].(float64) < 15 {
			t.Fatalf("evidence.authFailures manquant ou insuffisant: %v", evidence)
		}
	})

	t.Run("agregation du trafic", func(t *testing.T) {
		vh := get("/api/traffic/vhosts?hours=24")
		vhosts, _ := vh["vhosts"].([]any)
		if len(vhosts) < 1 {
			t.Fatalf("vhosts vide: %v", vh)
		}
		first := vhosts[0].(map[string]any)
		if first["vhost"] != "site.fr" {
			t.Fatalf("vhost = %v", first["vhost"])
		}
	})

	t.Run("acquittement", func(t *testing.T) {
		if bruteforceAlert == nil {
			t.Skip("pas d alerte bruteforce")
		}
		id := int64(bruteforceAlert["id"].(float64))
		ack := post(fmt.Sprintf("/api/alerts/%d/ack", id))
		if ack["ok"] != true {
			t.Fatalf("ack = %v", ack)
		}
	})

	t.Run("exceptions par vhost", func(t *testing.T) {
		addExc := post("/api/exceptions?vhost=site.fr&ip=192.0.2.77&reason=sonde&author=admin")
		if addExc["ok"] != true {
			t.Fatalf("addExc = %v", addExc)
		}
		listExc := get("/api/exceptions")
		exceptions, _ := listExc["exceptions"].([]any)
		if len(exceptions) != 1 {
			t.Fatalf("exceptions = %v", listExc)
		}
	})

	t.Run("catalogue des regles", func(t *testing.T) {
		rules := get("/api/rules")
		builtins, _ := rules["builtins"].([]any)
		if len(builtins) != 6 {
			t.Fatalf("attendu 6 regles integrees, obtenu %d", len(builtins))
		}
		for _, b := range builtins {
			bm := b.(map[string]any)
			if bm["enabled"] != true {
				t.Fatalf("regle %v devrait etre active par defaut", bm["key"])
			}
		}
	})

	t.Run("toggle d une regle", func(t *testing.T) {
		toggleOff := post("/api/rules/toggle?key=scraping&enable=0")
		if toggleOff["enabled"] != false {
			t.Fatalf("toggleOff = %v", toggleOff)
		}
		rulesAfter := get("/api/rules")
		builtins, _ := rulesAfter["builtins"].([]any)
		found := false
		for _, b := range builtins {
			bm := b.(map[string]any)
			if bm["key"] == "scraping" {
				found = true
				if bm["enabled"] != false {
					t.Fatalf("scraping devrait etre desactive: %v", bm)
				}
			}
		}
		if !found {
			t.Fatal("scraping introuvable dans le catalogue")
		}
	})

	t.Run("WAF", func(t *testing.T) {
		wafLogFile := wafLogPath
		wafLine := map[string]any{
			"transaction": map[string]any{
				"client_ip": "198.51.100.9", "time_stamp": time.Now().UTC().Format(http.TimeFormat),
				"request":   map[string]any{"method": "GET", "uri": "/login"},
				"response":  map[string]any{"http_code": 403},
				"unique_id": "e2e-1", "messages": []map[string]any{
					{"message": "SQL Injection Attack", "details": map[string]any{"ruleId": "942100", "severity": "2", "tags": []string{"attack-sqli"}}},
				},
			},
		}
		b, _ := json.Marshal(wafLine)
		if err := appendTo(wafLogFile, append(b, '\n')); err != nil {
			t.Fatal(err)
		}
		time.Sleep(800 * time.Millisecond)
		wafEvents := get("/api/waf/events")
		if wafEvents["total"].(float64) < 1 {
			t.Fatalf("evenement WAF non ingere: %v", wafEvents)
		}
	})
}

func setEnv(t *testing.T, env map[string]string) func() {
	t.Helper()
	prev := map[string]string{}
	hadPrev := map[string]bool{}
	for k, v := range env {
		if old, ok := os.LookupEnv(k); ok {
			prev[k] = old
			hadPrev[k] = true
		}
		os.Setenv(k, v)
	}
	return func() {
		for k := range env {
			if hadPrev[k] {
				os.Setenv(k, prev[k])
			} else {
				os.Unsetenv(k)
			}
		}
	}
}

func appendTo(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

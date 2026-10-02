package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func evt(o WafRecordInput) WafRecordInput {
	if o.Vhost == "" {
		o.Vhost = "site.fr"
	}
	if o.IP == "" {
		o.IP = "203.0.113.5"
	}
	if o.Method == "" {
		o.Method = "GET"
	}
	if o.URI == "" {
		o.URI = "/login"
	}
	if o.Status == 0 {
		o.Status = 403
	}
	if o.Severity == "" {
		o.Severity = "critical"
	}
	if o.RuleIDs == nil {
		o.RuleIDs = []string{"942100"}
	}
	if o.Messages == nil {
		o.Messages = []WafMessage{{RuleID: "942100", Message: "SQLi", Severity: "critical"}}
	}
	if o.UniqueID == "" {
		o.UniqueID = "u1"
	}
	return o
}

func TestWafStore(t *testing.T) {
	tmp := t.TempDir()
	s := New(filepath.Join(tmp, "w.db"))
	defer s.Close()
	tNow := time.Now().UnixMilli()

	t.Run("un evenement se relit a l identique", func(t *testing.T) {
		s.RecordWaf(evt(WafRecordInput{Ts: tNow, Blocked: true}))
		r := s.ListWaf(ListWafOptions{})
		if r.Total != 1 {
			t.Fatalf("total: %d", r.Total)
		}
		if r.Events[0].IP != "203.0.113.5" {
			t.Fatalf("ip: %s", r.Events[0].IP)
		}
		if len(r.Events[0].RuleIDs) != 1 || r.Events[0].RuleIDs[0] != "942100" {
			t.Fatalf("ruleIds: %+v", r.Events[0].RuleIDs)
		}
		if !r.Events[0].Blocked {
			t.Fatal("blocked devrait etre true")
		}
	})

	t.Run("filtrage par vhost, severite, blocage", func(t *testing.T) {
		s.RecordWaf(evt(WafRecordInput{Ts: tNow, Vhost: "autre.fr", Severity: "warning", Blocked: false, RuleIDs: []string{"920100"}}))
		if s.ListWaf(ListWafOptions{Vhost: "autre.fr"}).Total != 1 {
			t.Fatal("filtre vhost")
		}
		if s.ListWaf(ListWafOptions{Severity: "critical"}).Total != 1 {
			t.Fatal("filtre severity")
		}
		f := false
		if s.ListWaf(ListWafOptions{Blocked: &f}).Total != 1 {
			t.Fatal("filtre blocked=false")
		}
		tr := true
		if s.ListWaf(ListWafOptions{Blocked: &tr}).Total != 1 {
			t.Fatal("filtre blocked=true")
		}
	})

	t.Run("comptage regles meme sur plusieurs regles par evenement", func(t *testing.T) {
		s.RecordWaf(evt(WafRecordInput{Ts: tNow, Blocked: true, RuleIDs: []string{"942100", "949110"},
			Messages: []WafMessage{{RuleID: "942100", Message: "SQLi"}, {RuleID: "949110", Message: "Anomaly"}}}))
		top := s.WafTopRules(tNow-1000, tNow+1000, "", 0)
		var r942 *WafTopRule
		for i := range top {
			if top[i].RuleID == "942100" {
				r942 = &top[i]
			}
		}
		if r942 == nil || r942.Count != 2 {
			t.Fatalf("r942: %+v", r942)
		}
		if r942.Example != "SQLi" {
			t.Fatalf("example: %s", r942.Example)
		}
	})

	t.Run("adresses les plus actives", func(t *testing.T) {
		top := s.WafTopIps(tNow-1000, tNow+1000, "")
		var ip *WafTopIP
		for i := range top {
			if top[i].IP == "203.0.113.5" {
				ip = &top[i]
			}
		}
		if ip == nil || ip.Count < 2 || ip.Blocked < 1 {
			t.Fatalf("ip: %+v", ip)
		}
	})

	t.Run("serie temporelle par heure", func(t *testing.T) {
		series := s.WafSeries(tNow-3600000, tNow+3600000, "")
		if len(series) < 1 || series[0].Count <= 0 {
			t.Fatalf("series: %+v", series)
		}
	})

	t.Run("purge par anciennete", func(t *testing.T) {
		s.RecordWaf(evt(WafRecordInput{Ts: tNow - 100*86400000, Blocked: true}))
		before := s.WafStats().Rows
		deleted := s.PurgeWaf(tNow - 30*86400000)
		if deleted < 1 {
			t.Fatal("au moins une suppression attendue")
		}
		if s.WafStats().Rows >= before {
			t.Fatal("le nombre de lignes doit diminuer")
		}
	})

	t.Run("getWafEvent renvoie la ligne brute absente de la liste", func(t *testing.T) {
		s.RecordWaf(evt(WafRecordInput{Ts: tNow, Blocked: true, Raw: `{"transaction":{"client_ip":"203.0.113.5"}}`, Engine: "DetectionOnly"}))
		listed := s.ListWaf(ListWafOptions{Limit: 1})
		if listed.Events[0].Raw != "" {
			t.Fatal("la liste ne doit pas transporter la ligne brute")
		}
		full := s.GetWafEvent(listed.Events[0].ID)
		if full == nil || full.Raw == "" {
			t.Fatal("getWafEvent doit renvoyer raw")
		}
		if full.Engine != "DetectionOnly" {
			t.Fatalf("engine: %s", full.Engine)
		}
	})

	t.Run("identifiant inconnu -> nil", func(t *testing.T) {
		if s.GetWafEvent(999999999) != nil {
			t.Fatal("devrait etre nil")
		}
	})
}

func TestWafDegradationSansSQLite(t *testing.T) {
	tmp := t.TempDir()
	blocker := filepath.Join(tmp, "pas-un-dossier")
	os.WriteFile(blocker, []byte("x"), 0o644)
	bad := New(filepath.Join(blocker, "w.db"))
	if bad.Persistent() {
		t.Fatal("ne devrait pas etre persistant")
	}
	tNow := time.Now().UnixMilli()
	bad.RecordWaf(evt(WafRecordInput{Ts: tNow, Blocked: true}))
	if len(bad.ListWaf(ListWafOptions{}).Events) != 1 {
		t.Fatal("attendu 1 evenement en memoire")
	}
	if len(bad.WafTopRules(tNow-1000, tNow+1000, "", 0)) < 1 {
		t.Fatal("wafTopRules doit fonctionner en memoire")
	}
}

func TestWafMigrationColonnes(t *testing.T) {
	tmp := t.TempDir()
	oldDB := filepath.Join(tmp, "old-schema.db")
	raw, err := openRawForTest(oldDB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE waf_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, vhost TEXT NOT NULL,
		ip TEXT, method TEXT, uri TEXT, status INTEGER, blocked INTEGER NOT NULL DEFAULT 0,
		severity TEXT, ruleIds TEXT, messages TEXT, uniqueId TEXT)`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	migrated := New(oldDB)
	defer migrated.Close()
	migrated.RecordWaf(evt(WafRecordInput{Ts: time.Now().UnixMilli(), Blocked: true, Engine: "On", Raw: "test"}))
	got := migrated.ListWaf(ListWafOptions{Limit: 1})
	if len(got.Events) != 1 || got.Events[0].Engine != "On" {
		t.Fatalf("engine attendu 'On': %+v", got.Events)
	}
}

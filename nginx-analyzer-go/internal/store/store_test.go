package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const T = 1789041600000 // Date.parse('2026-09-09T10:00:00Z')

func e(o Entry) Entry {
	if o.Vhost == "" {
		o.Vhost = "site.fr"
	}
	if o.Status == 0 {
		o.Status = 200
	}
	if o.Method == "" {
		o.Method = "GET"
	}
	if o.Bytes == 0 {
		o.Bytes = 100
	}
	return o
}

func TestStockage(t *testing.T) {
	tmp := t.TempDir()
	s := New(filepath.Join(tmp, "state.db"))
	defer s.Close()

	t.Run("SQLite disponible", func(t *testing.T) {
		if !s.Persistent() {
			t.Fatal("SQLite devrait etre disponible")
		}
	})

	t.Run("agregation en buckets", func(t *testing.T) {
		for i := int64(0); i < 10; i++ {
			s.Record(e(Entry{Ts: T + i*1000}), "FR")
		}
		n := s.Flush()
		if n <= 0 {
			t.Fatal("des buckets doivent etre ecrits")
		}
	})

	t.Run("les requetes sont cumulees, pas dupliquees", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			s.Record(e(Entry{Ts: T}), "FR")
		}
		s.Flush()
		v := s.ByVhost(T-60000, T+60000)
		if len(v) != 1 {
			t.Fatalf("attendu 1 ligne, obtenu %d", len(v))
		}
		if v[0].Requests != 15 {
			t.Fatalf("attendu 15 (10+5), obtenu %d", v[0].Requests)
		}
	})

	t.Run("par pays", func(t *testing.T) {
		s.Record(e(Entry{Ts: T + 2000}), "DE")
		s.Record(e(Entry{Ts: T + 2000}), "DE")
		s.Flush()
		c := s.ByCountry(T-60000, T+60000, "")
		var fr, de *CountryStat
		for i := range c {
			if c[i].Country == "FR" {
				fr = &c[i]
			}
			if c[i].Country == "DE" {
				de = &c[i]
			}
		}
		if fr == nil || fr.Requests != 15 {
			t.Fatalf("FR: %+v", fr)
		}
		if de == nil || de.Requests != 2 {
			t.Fatalf("DE: %+v", de)
		}
	})

	t.Run("pays inconnu regroupe", func(t *testing.T) {
		s.Record(e(Entry{Ts: T + 3000}), "")
		s.Flush()
		c := s.ByCountry(T-60000, T+60000, "")
		found := false
		for _, r := range c {
			if r.Country == "??" {
				found = true
			}
		}
		if !found {
			t.Fatal("le pays '??' devrait apparaitre")
		}
	})

	t.Run("erreurs comptees a part", func(t *testing.T) {
		s.Record(e(Entry{Ts: T + 4000, Status: 404}), "FR")
		s.Record(e(Entry{Ts: T + 4000, Status: 500}), "FR")
		s.Flush()
		v := s.ByVhost(T-60000, T+60000)
		if v[0].Errors != 2 {
			t.Fatalf("attendu 2 erreurs (4xx+5xx), obtenu %d", v[0].Errors)
		}
	})

	t.Run("agregation par heure", func(t *testing.T) {
		h := s.HourlyMetrics("site.fr", T-3600000, T+3600000)
		if len(h) < 1 {
			t.Fatal("au moins une ligne attendue")
		}
		if h[0].Requests <= 0 {
			t.Fatal("requests devrait etre positif")
		}
	})

	t.Run("les minutes anciennes deviennent des heures", func(t *testing.T) {
		s2 := New(filepath.Join(tmp, "r.db"))
		defer s2.Close()
		vieux := time.Now().UnixMilli() - 48*3600*1000
		for i := int64(0); i < 20; i++ {
			s2.Record(e(Entry{Ts: vieux + i*60000}), "FR")
		}
		s2.Flush()
		avant := s2.Stats().Rows
		r, d := s2.Rollup()
		apres := s2.Stats().Rows
		if r <= 0 && d <= 0 {
			t.Fatal("le rollup doit agir")
		}
		if apres["minute"] >= avant["minute"] && avant["minute"] != 0 {
			t.Fatal("les minutes anciennes doivent disparaitre")
		}
		if apres["hour"] <= 0 {
			t.Fatal("elles doivent survivre en heures")
		}
	})

	t.Run("les donnees recentes sont preservees", func(t *testing.T) {
		s3 := New(filepath.Join(tmp, "r2.db"))
		defer s3.Close()
		now := time.Now().UnixMilli()
		for i := int64(0); i < 5; i++ {
			s3.Record(e(Entry{Ts: now - i*60000}), "FR")
		}
		s3.Flush()
		s3.Rollup()
		if s3.Stats().Rows["minute"] <= 0 {
			t.Fatal("les 24 dernieres heures doivent rester en minutes")
		}
	})

	t.Run("alertes enregistrement et relecture", func(t *testing.T) {
		s.AddAlert(AlertInput{Type: "bruteforce", Severity: "high", Summary: "test",
			Evidence: map[string]any{"ip": "1.2.3.4", "vhost": "site.fr", "requests": float64(20)}})
		r := s.ListAlerts(ListAlertsOptions{})
		if r.Total != 1 {
			t.Fatalf("total attendu 1, obtenu %d", r.Total)
		}
		if r.Alerts[0].IP != "1.2.3.4" {
			t.Fatalf("ip attendue 1.2.3.4, obtenu %s", r.Alerts[0].IP)
		}
		ev, ok := r.Alerts[0].Evidence.(map[string]any)
		if !ok || ev["requests"] != float64(20) {
			t.Fatalf("les preuves doivent survivre au JSON: %+v", r.Alerts[0].Evidence)
		}
	})

	t.Run("filtrage par type et severite", func(t *testing.T) {
		s.AddAlert(AlertInput{Type: "scan", Severity: "low", Summary: "x", Evidence: map[string]any{"ip": "5.6.7.8"}})
		if s.ListAlerts(ListAlertsOptions{Type: "scan"}).Total != 1 {
			t.Fatal("filtre type=scan")
		}
		if s.ListAlerts(ListAlertsOptions{Severity: "high"}).Total != 1 {
			t.Fatal("filtre severity=high")
		}
	})

	t.Run("acquittement", func(t *testing.T) {
		id := s.ListAlerts(ListAlertsOptions{}).Alerts[0].ID
		if !s.AckAlert(id) {
			t.Fatal("ackAlert devrait reussir")
		}
		found := false
		for _, a := range s.ListAlerts(ListAlertsOptions{}).Alerts {
			if a.ID == id {
				found = a.Acked
			}
		}
		if !found {
			t.Fatal("l alerte devrait etre marquee acked")
		}
	})

	t.Run("cle/valeur", func(t *testing.T) {
		s.SetState("baseline", map[string]any{"startedAt": float64(123), "buckets": map[string]any{"a": []any{1, 2}}})
		v := s.GetState("baseline")
		m, ok := v.(map[string]any)
		if !ok || m["startedAt"] != float64(123) {
			t.Fatalf("getState: %+v", v)
		}
	})

	t.Run("offset de lecture par fichier", func(t *testing.T) {
		s.SetOffset("/logs/a.log", 42, 1000, "vhost")
		inode, offset, format, ok := s.GetOffset("/logs/a.log")
		if !ok || inode != 42 || offset != 1000 || format != "vhost" {
			t.Fatalf("getOffset: inode=%d offset=%d format=%s ok=%v", inode, offset, format, ok)
		}
	})

	t.Run("offset inconnu -> not ok", func(t *testing.T) {
		_, _, _, ok := s.GetOffset("/nope")
		if ok {
			t.Fatal("un offset inconnu ne doit pas etre trouve")
		}
	})
}

func TestDegradationSansSQLite(t *testing.T) {
	tmp := t.TempDir()
	blocker := filepath.Join(tmp, "pas-un-dossier")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	bad := New(filepath.Join(blocker, "x.db"))
	if bad.Persistent() {
		t.Fatal("ne devrait pas etre persistant")
	}
	bad.Record(e(Entry{Ts: T}), "FR")
	bad.Flush()
	bad.AddAlert(AlertInput{Type: "x", Summary: "y", Evidence: map[string]any{}})
	if len(bad.ListAlerts(ListAlertsOptions{}).Alerts) != 1 {
		t.Fatal("les alertes doivent rester en memoire")
	}
}

func TestANA04PruneBucketsMemoire(t *testing.T) {
	tmp := t.TempDir()
	blocker := filepath.Join(tmp, "pas-un-dossier-2")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	bad := New(filepath.Join(blocker, "x.db"), Options{Retention: Retention{MinuteHours: 1}})
	if bad.Persistent() {
		t.Fatal("ne devrait pas etre persistant")
	}
	now := time.Now().UnixMilli()
	old := now - 3*3600_000
	bad.Record(e(Entry{Ts: old}), "FR")
	bad.RecordBot(e(Entry{Ts: old}), "bot", "FR")
	bad.Record(e(Entry{Ts: now}), "FR")
	if len(bad.memBuckets) != 2 {
		t.Fatalf("attendu 2 buckets avant flush, obtenu %d", len(bad.memBuckets))
	}
	bad.Flush()
	if len(bad.memBuckets) != 1 {
		t.Fatalf("le bucket ancien doit avoir ete elague, obtenu %d", len(bad.memBuckets))
	}
	if len(bad.memBotBuckets) != 0 {
		t.Fatal("le bot-bucket ancien doit avoir ete elague")
	}
}

func boolPtr(b bool) *bool { return &b }

func TestANA11PurgesAgeBased(t *testing.T) {
	tmp := t.TempDir()

	t.Run("purgeAlerts", func(t *testing.T) {
		blocker := filepath.Join(tmp, "pas-un-dossier-3")
		os.WriteFile(blocker, []byte("x"), 0o644)
		bad := New(filepath.Join(blocker, "x.db"))
		bad.memAlerts = []Alert{{ID: 1, Ts: T - 100000, Type: "a"}, {ID: 2, Ts: T, Type: "b"}}
		n := bad.PurgeAlerts(T - 50000)
		if n != 1 {
			t.Fatalf("attendu 1 suppression, obtenu %d", n)
		}
		alerts := bad.ListAlerts(ListAlertsOptions{}).Alerts
		if len(alerts) != 1 || alerts[0].ID != 2 {
			t.Fatalf("alerte recente attendue survivante: %+v", alerts)
		}
	})

	t.Run("purgeWaf", func(t *testing.T) {
		blocker := filepath.Join(tmp, "pas-un-dossier-4")
		os.WriteFile(blocker, []byte("x"), 0o644)
		bad := New(filepath.Join(blocker, "x.db"))
		bad.memWaf = []WafEvent{{ID: 1, Ts: T - 100000}, {ID: 2, Ts: T}}
		n := bad.PurgeWaf(T - 50000)
		if n != 1 {
			t.Fatalf("attendu 1, obtenu %d", n)
		}
		if len(bad.memWaf) != 1 || bad.memWaf[0].ID != 2 {
			t.Fatalf("attendu id=2 survivant: %+v", bad.memWaf)
		}
	})

	t.Run("purgeBlocklistHits", func(t *testing.T) {
		blocker := filepath.Join(tmp, "pas-un-dossier-5")
		os.WriteFile(blocker, []byte("x"), 0o644)
		bad := New(filepath.Join(blocker, "x.db"))
		bad.memBlocklist = []BlocklistHit{{ID: 1, Ts: T - 100000}, {ID: 2, Ts: T}}
		n := bad.PurgeBlocklistHits(T - 50000)
		if n != 1 {
			t.Fatalf("attendu 1, obtenu %d", n)
		}
		if len(bad.memBlocklist) != 1 || bad.memBlocklist[0].ID != 2 {
			t.Fatalf("attendu id=2 survivant: %+v", bad.memBlocklist)
		}
	})
}

func TestBotRepartitionParPaysEtVhost(t *testing.T) {
	tmp := t.TempDir()
	s := New(filepath.Join(tmp, "bots.db"))
	defer s.Close()

	t.Run("botByVhost pivote humains vs robots", func(t *testing.T) {
		t4 := time.Now().UnixMilli() + 300_000
		s.RecordBot(e(Entry{Ts: t4, Vhost: "p1.fr"}), "human", "FR")
		s.RecordBot(e(Entry{Ts: t4, Vhost: "p1.fr"}), "human", "FR")
		s.RecordBot(e(Entry{Ts: t4, Vhost: "p1.fr"}), "good", "FR")
		s.RecordBot(e(Entry{Ts: t4, Vhost: "p2.fr"}), "bad", "DE")
		s.Flush()
		rows := s.BotByVhost(t4-3_600_000, t4+3_600_000)
		var p1, p2 *BotPivotRow
		for i := range rows {
			if rows[i].Key == "p1.fr" {
				p1 = &rows[i]
			}
			if rows[i].Key == "p2.fr" {
				p2 = &rows[i]
			}
		}
		if p1 == nil || p1.Human != 2 || p1.Bots != 1 || p1.Total != 3 {
			t.Fatalf("p1: %+v", p1)
		}
		if p2 == nil || p2.Human != 0 || p2.Bots != 1 {
			t.Fatalf("p2: %+v", p2)
		}
	})

	t.Run("botByCountry pivote avec filtre vhost optionnel", func(t *testing.T) {
		t5 := time.Now().UnixMilli() + 400_000
		s.RecordBot(e(Entry{Ts: t5, Vhost: "x.fr"}), "human", "FR")
		s.RecordBot(e(Entry{Ts: t5, Vhost: "x.fr"}), "ai", "FR")
		s.RecordBot(e(Entry{Ts: t5, Vhost: "y.fr"}), "human", "FR")
		s.Flush()
		forX := s.BotByCountry(t5-3_600_000, t5+3_600_000, "x.fr")
		var frX *BotPivotRow
		for i := range forX {
			if forX[i].Key == "FR" {
				frX = &forX[i]
			}
		}
		if frX == nil || frX.Human != 1 || frX.Bots != 1 {
			t.Fatalf("frX: %+v", frX)
		}
		forY := s.BotByCountry(t5-3_600_000, t5+3_600_000, "y.fr")
		var frY *BotPivotRow
		for i := range forY {
			if forY[i].Key == "FR" {
				frY = &forY[i]
			}
		}
		if frY == nil || frY.Human != 1 || frY.Bots != 0 {
			t.Fatalf("frY: %+v", frY)
		}
	})

	t.Run("adresse non resolue regroupee sous ??", func(t *testing.T) {
		t6 := time.Now().UnixMilli() + 500_000
		s.RecordBot(e(Entry{Ts: t6, Vhost: "z.fr"}), "human", "")
		s.Flush()
		rows := s.BotByCountry(t6-3_600_000, t6+3_600_000, "z.fr")
		if len(rows) != 1 || rows[0].Key != "??" || rows[0].Human != 1 {
			t.Fatalf("rows: %+v", rows)
		}
	})

	t.Run("rollup preserve la dimension pays", func(t *testing.T) {
		old := New(filepath.Join(tmp, "rollup-bot-country.db"))
		defer old.Close()
		past := time.Now().UnixMilli() - 40*3600*1000
		old.RecordBot(e(Entry{Ts: past, Vhost: "r.fr"}), "human", "JP")
		old.Flush()
		old.Rollup(time.Now().UnixMilli())
		rows := old.db.QueryRow(`SELECT COUNT(*) FROM bot_traffic WHERE grain='hour' AND country='JP'`)
		var n int
		if err := rows.Scan(&n); err != nil || n == 0 {
			t.Fatal("le pays doit survivre a la promotion minute -> heure")
		}
	})
}

func TestBotRepartitionIndependanteDeGeoIP(t *testing.T) {
	tmp := t.TempDir()
	s := New(filepath.Join(tmp, "botcat.db"))
	defer s.Close()

	t.Run("categories agregees correctement", func(t *testing.T) {
		t2 := time.Now().UnixMilli() + 100_000
		for i := 0; i < 5; i++ {
			s.RecordBot(e(Entry{Ts: t2, Vhost: "bots.fr"}), "human", "")
		}
		for i := 0; i < 3; i++ {
			s.RecordBot(e(Entry{Ts: t2, Vhost: "bots.fr"}), "good", "")
		}
		for i := 0; i < 2; i++ {
			s.RecordBot(e(Entry{Ts: t2, Vhost: "bots.fr"}), "bad", "")
		}
		s.Flush()
		rows := s.ByBotCategory(t2-3_600_000, t2+3_600_000, "bots.fr")
		byCat := map[string]int64{}
		for _, r := range rows {
			byCat[r.Category] = r.Requests
		}
		if byCat["human"] != 5 || byCat["good"] != 3 || byCat["bad"] != 2 {
			t.Fatalf("byCat: %+v", byCat)
		}
	})

	t.Run("categorie absente ignoree sans exception", func(t *testing.T) {
		s.RecordBot(e(Entry{Ts: time.Now().UnixMilli(), Vhost: "x.fr"}), "", "")
	})

	t.Run("filtre par vhost", func(t *testing.T) {
		t3 := time.Now().UnixMilli() + 200_000
		s.RecordBot(e(Entry{Ts: t3, Vhost: "v1.fr"}), "human", "")
		s.RecordBot(e(Entry{Ts: t3, Vhost: "v2.fr"}), "human", "")
		s.Flush()
		rows := s.ByBotCategory(t3-3_600_000, t3+3_600_000, "v1.fr")
		if len(rows) != 1 || rows[0].Requests != 1 {
			t.Fatalf("rows: %+v", rows)
		}
	})

	t.Run("rollup promeut aussi bot_traffic", func(t *testing.T) {
		old := New(filepath.Join(tmp, "rollup-bot.db"))
		defer old.Close()
		past := time.Now().UnixMilli() - 40*3600*1000
		old.RecordBot(e(Entry{Ts: past, Vhost: "r.fr"}), "human", "")
		old.Flush()
		var before int
		old.db.QueryRow(`SELECT COUNT(*) FROM bot_traffic WHERE grain='minute'`).Scan(&before)
		old.Rollup(time.Now().UnixMilli())
		var afterMinute, afterHour int
		old.db.QueryRow(`SELECT COUNT(*) FROM bot_traffic WHERE grain='minute'`).Scan(&afterMinute)
		old.db.QueryRow(`SELECT COUNT(*) FROM bot_traffic WHERE grain='hour'`).Scan(&afterHour)
		if before < 1 {
			t.Fatal("la bucket minute doit exister avant le rollup")
		}
		if afterMinute != 0 {
			t.Fatal("la bucket minute perimee doit avoir ete promue puis supprimee")
		}
		if afterHour < 1 {
			t.Fatal("elle doit reapparaitre en grain heure")
		}
	})
}

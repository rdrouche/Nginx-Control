package rules

import (
	"strings"
	"testing"

	"nginx-analyzer-go/internal/detect"
)

// fakeStore reproduit fakeStore() du test JS : store en memoire, pas besoin
// d'une vraie base sqlite pour tester RulesManager.
type fakeStore struct {
	data map[string]any
}

func newFakeStore() *fakeStore { return &fakeStore{data: map[string]any{}} }

func (f *fakeStore) GetState(key string) any        { return f.data[key] }
func (f *fakeStore) SetState(key string, value any) { f.data[key] = value }

func intPtr(n int) *int         { return &n }
func f64Ptr(f float64) *float64 { return &f }

func TestCatalogSansThresholds(t *testing.T) {
	t.Run("config: null pour chaque regle integree quand aucun threshold n est fourni", func(t *testing.T) {
		rm := New(newFakeStore(), nil)
		cat := rm.Catalog(detect.Explanations, Thresholds{})
		if len(cat.Builtins) != 6 {
			t.Fatalf("attendu 6 builtins, obtenu %d", len(cat.Builtins))
		}
		for _, b := range cat.Builtins {
			if b.Config != nil {
				t.Fatalf("%s devrait avoir config: null, obtenu %v", b.Key, b.Config)
			}
		}
	})
}

func TestCatalogAvecThresholds(t *testing.T) {
	t.Run("flood : windowMinutes + minRequests exposes tels que configures", func(t *testing.T) {
		rm := New(newFakeStore(), nil)
		cat := rm.Catalog(detect.Explanations, Thresholds{
			WindowMs:   5 * 60_000,
			Bruteforce: &BruteforceThresholds{MinFailures: 15},
			Scan:       &ScanThresholds{MinRequests: 40, MinDistinct: 25, MinNotFoundRatio: 0.5},
			Flood:      &FloodThresholds{MinRequests: 600},
			Scraping:   &ScrapingThresholds{MinRequests: 300, MaxDistinct: 5},
		})
		var flood *BuiltinCatalogEntry
		for i := range cat.Builtins {
			if cat.Builtins[i].Key == "flood" {
				flood = &cat.Builtins[i]
			}
		}
		if flood == nil {
			t.Fatal("flood introuvable")
		}
		want := map[string]any{"windowMinutes": 5.0, "minRequests": 600}
		if flood.Config["windowMinutes"] != want["windowMinutes"] || flood.Config["minRequests"] != want["minRequests"] {
			t.Fatalf("flood.config = %v, want %v", flood.Config, want)
		}
	})

	t.Run("scan : minNotFoundRatio converti en pourcentage entier", func(t *testing.T) {
		rm := New(newFakeStore(), nil)
		cat := rm.Catalog(detect.Explanations, Thresholds{
			WindowMs: 10 * 60_000,
			Scan:     &ScanThresholds{MinRequests: 40, MinDistinct: 25, MinNotFoundRatio: 0.5},
		})
		var scan *BuiltinCatalogEntry
		for i := range cat.Builtins {
			if cat.Builtins[i].Key == "scan" {
				scan = &cat.Builtins[i]
			}
		}
		if scan == nil {
			t.Fatal("scan introuvable")
		}
		if scan.Config["windowMinutes"] != 10.0 || scan.Config["minRequests"] != 40 ||
			scan.Config["minDistinct"] != 25 || scan.Config["minNotFoundRatioPercent"] != 50 {
			t.Fatalf("scan.config = %v", scan.Config)
		}
	})

	t.Run("volumetric/country_traffic : config Baseline, pas de windowMinutes", func(t *testing.T) {
		rm := New(newFakeStore(), nil)
		cat := rm.Catalog(detect.Explanations, Thresholds{
			Volumetric:     &VolumetricThresholds{LearningDays: 21, SigmaThreshold: 6, MinAbsoluteRequests: 100},
			CountryTraffic: &VolumetricThresholds{LearningDays: 21, SigmaThreshold: 6, MinAbsoluteRequests: 300},
		})
		var vol, country *BuiltinCatalogEntry
		for i := range cat.Builtins {
			switch cat.Builtins[i].Key {
			case "volumetric":
				vol = &cat.Builtins[i]
			case "country_traffic":
				country = &cat.Builtins[i]
			}
		}
		if vol == nil || country == nil {
			t.Fatal("volumetric/country_traffic introuvables")
		}
		if vol.Config["learningDays"] != 21 || vol.Config["sigmaThreshold"] != 6.0 || vol.Config["minAbsoluteRequests"] != int64(100) {
			t.Fatalf("vol.config = %v", vol.Config)
		}
		if country.Config["minAbsoluteRequests"] != int64(300) {
			t.Fatalf("country.config = %v", country.Config)
		}
	})

	t.Run("un threshold absent pour UNE regle -> config:null seulement pour celle-la", func(t *testing.T) {
		rm := New(newFakeStore(), nil)
		cat := rm.Catalog(detect.Explanations, Thresholds{WindowMs: 5 * 60_000, Flood: &FloodThresholds{MinRequests: 600}})
		var flood, bruteforce *BuiltinCatalogEntry
		for i := range cat.Builtins {
			switch cat.Builtins[i].Key {
			case "flood":
				flood = &cat.Builtins[i]
			case "bruteforce":
				bruteforce = &cat.Builtins[i]
			}
		}
		if flood.Config["minRequests"] != 600 {
			t.Fatalf("flood.config = %v", flood.Config)
		}
		if bruteforce.Config != nil {
			t.Fatalf("bruteforce.config devrait etre nil, obtenu %v", bruteforce.Config)
		}
	})
}

func TestCatalogProcessing(t *testing.T) {
	t.Run("mentionne la fenetre reelle en minutes quand windowMs est fourni", func(t *testing.T) {
		rm := New(newFakeStore(), nil)
		cat := rm.Catalog(detect.Explanations, Thresholds{WindowMs: 7 * 60_000})
		if !strings.Contains(cat.Processing.Aggregation, "7 min") {
			t.Fatalf("aggregation = %q", cat.Processing.Aggregation)
		}
	})
	t.Run("sans windowMs fourni -> repli sur 5 min", func(t *testing.T) {
		rm := New(newFakeStore(), nil)
		cat := rm.Catalog(detect.Explanations, Thresholds{})
		if !strings.Contains(cat.Processing.Aggregation, "5 min") {
			t.Fatalf("aggregation = %q", cat.Processing.Aggregation)
		}
		if strings.Contains(cat.Processing.Aggregation, "undefined") {
			t.Fatal("aggregation ne doit jamais contenir 'undefined'")
		}
	})
	t.Run("explique le declenchement par transition", func(t *testing.T) {
		rm := New(newFakeStore(), nil)
		cat := rm.Catalog(detect.Explanations, Thresholds{})
		if !strings.Contains(strings.ToLower(cat.Processing.EdgeTriggered), "transition") {
			t.Fatalf("edgeTriggered = %q", cat.Processing.EdgeTriggered)
		}
	})
	t.Run("explique la regle multi-vhost de l opt-out", func(t *testing.T) {
		rm := New(newFakeStore(), nil)
		cat := rm.Catalog(detect.Explanations, Thresholds{})
		if !strings.Contains(cat.Processing.VhostOptOut, "TOUS") {
			t.Fatalf("vhostOptOut = %q", cat.Processing.VhostOptOut)
		}
		if !strings.Contains(strings.ToLower(cat.Processing.VhostOptOut), "plusieurs vhosts") {
			t.Fatalf("vhostOptOut = %q", cat.Processing.VhostOptOut)
		}
	})
}

func assertBlocklistEqual(t *testing.T, got *BlocklistConfig, want BlocklistConfig) {
	t.Helper()
	if got == nil {
		t.Fatal("blocklist config nil")
	}
	if (got.Threshold == nil) != (want.Threshold == nil) || (got.Threshold != nil && *got.Threshold != *want.Threshold) {
		t.Fatalf("threshold: got %v want %v", got.Threshold, want.Threshold)
	}
	if got.WindowMinutes != want.WindowMinutes {
		t.Fatalf("windowMinutes: got %v want %v", got.WindowMinutes, want.WindowMinutes)
	}
	if got.Remediation != want.Remediation {
		t.Fatalf("remediation: got %v want %v", got.Remediation, want.Remediation)
	}
	if (got.RemediationMinutes == nil) != (want.RemediationMinutes == nil) ||
		(got.RemediationMinutes != nil && *got.RemediationMinutes != *want.RemediationMinutes) {
		t.Fatalf("remediationMinutes: got %v want %v", got.RemediationMinutes, want.RemediationMinutes)
	}
}

func TestBlocklistCrowdSecBuiltins(t *testing.T) {
	t.Run("getBlocklistConfig() par defaut", func(t *testing.T) {
		rm := New(newFakeStore(), nil)
		assertBlocklistEqual(t, rm.GetBlocklistConfig("flood"), BlocklistConfig{
			Threshold: nil, WindowMinutes: 1440, Remediation: false, RemediationMinutes: nil,
		})
	})

	t.Run("setBlocklistConfig() valide, persiste et se relit", func(t *testing.T) {
		store := newFakeStore()
		rm := New(store, nil)
		result := rm.SetBlocklistConfig("flood", BlocklistConfigInput{
			Threshold: f64Ptr(5), WindowMinutes: f64Ptr(60), Remediation: true, RemediationMinutes: f64Ptr(120),
		})
		if !result.OK {
			t.Fatalf("setBlocklistConfig failed: %v", result.Errors)
		}
		assertBlocklistEqual(t, rm.GetBlocklistConfig("flood"), BlocklistConfig{
			Threshold: intPtr(5), WindowMinutes: 60, Remediation: true, RemediationMinutes: intPtr(120),
		})
		rm2 := New(store, nil)
		assertBlocklistEqual(t, rm2.GetBlocklistConfig("flood"), BlocklistConfig{
			Threshold: intPtr(5), WindowMinutes: 60, Remediation: true, RemediationMinutes: intPtr(120),
		})
		if !rm2.IsEnabled("flood") {
			t.Fatal("flood devrait rester enabled")
		}
	})

	t.Run("valeurs invalides -> erreur explicite, rien de persiste", func(t *testing.T) {
		rm := New(newFakeStore(), nil)
		if rm.SetBlocklistConfig("flood", BlocklistConfigInput{Threshold: f64Ptr(0)}).OK {
			t.Fatal("threshold 0 devrait echouer")
		}
		if rm.SetBlocklistConfig("flood", BlocklistConfigInput{WindowMinutes: f64Ptr(-1)}).OK {
			t.Fatal("windowMinutes -1 devrait echouer")
		}
		if rm.SetBlocklistConfig("flood", BlocklistConfigInput{RemediationMinutes: f64Ptr(0)}).OK {
			t.Fatal("remediationMinutes 0 devrait echouer")
		}
		if rm.SetBlocklistConfig("inconnue", BlocklistConfigInput{Threshold: f64Ptr(5)}).OK {
			t.Fatal("regle inconnue devrait echouer")
		}
		assertBlocklistEqual(t, rm.GetBlocklistConfig("flood"), BlocklistConfig{
			Threshold: nil, WindowMinutes: 1440, Remediation: false, RemediationMinutes: nil,
		})
	})

	t.Run("migration : rule_state pre-v12.50.0 (booleen brut)", func(t *testing.T) {
		store := newFakeStore()
		store.SetState("rule_state", map[string]any{"flood": false, "scan": true})
		rm := New(store, nil)
		if rm.IsEnabled("flood") {
			t.Fatal("flood devrait etre disabled")
		}
		if !rm.IsEnabled("scan") {
			t.Fatal("scan devrait etre enabled")
		}
		assertBlocklistEqual(t, rm.GetBlocklistConfig("flood"), BlocklistConfig{
			Threshold: nil, WindowMinutes: 1440, Remediation: false, RemediationMinutes: nil,
		})
	})

	t.Run("toggle() ne touche jamais a la config blocklist", func(t *testing.T) {
		rm := New(newFakeStore(), nil)
		rm.SetBlocklistConfig("flood", BlocklistConfigInput{Threshold: f64Ptr(3)})
		rm.Toggle("flood", false)
		if rm.IsEnabled("flood") {
			t.Fatal("flood devrait etre disabled")
		}
		if *rm.GetBlocklistConfig("flood").Threshold != 3 {
			t.Fatal("threshold devrait rester 3")
		}
	})
}

func TestListBlocklistRules(t *testing.T) {
	t.Run("seules les regles avec threshold configure apparaissent", func(t *testing.T) {
		rm := New(newFakeStore(), nil)
		rm.SetBlocklistConfig("flood", BlocklistConfigInput{Threshold: f64Ptr(5), Remediation: true})
		res := rm.SetCustomYaml(strings.Join([]string{
			"rules:",
			"  - id: 100",
			"    name: admin_probe",
			"    min_matches: 10",
			`    path_hint: "/wp-admin"`,
			"    blocklist_threshold: 3",
			"    blocklist_remediation: true",
			"    blocklist_remediation_minutes: 30",
		}, "\n"))
		if !res.OK {
			t.Fatalf("setCustomYaml failed: %v", res.Errors)
		}
		list := rm.ListBlocklistRules()
		if len(list) != 2 {
			t.Fatalf("attendu 2 regles, obtenu %d: %+v", len(list), list)
		}
		var flood, custom *BlocklistRule
		for i := range list {
			switch list[i].Key {
			case "flood":
				flood = &list[i]
			case "custom_100":
				custom = &list[i]
			}
		}
		if flood == nil || custom == nil {
			t.Fatalf("flood/custom introuvables: %+v", list)
		}
		if flood.ID != 3 || flood.Name != "flood" || flood.Custom || flood.Threshold != 5 ||
			flood.WindowMinutes != 1440 || !flood.Remediation || flood.RemediationMinutes != nil {
			t.Fatalf("flood = %+v", flood)
		}
		if custom.ID != 100 || custom.Name != "admin_probe" || !custom.Custom || custom.Threshold != 3 ||
			custom.WindowMinutes != 1440 || !custom.Remediation || custom.RemediationMinutes == nil || *custom.RemediationMinutes != 30 {
			t.Fatalf("custom = %+v", custom)
		}
	})

	t.Run("aucune regle opt-in -> liste vide", func(t *testing.T) {
		rm := New(newFakeStore(), nil)
		if list := rm.ListBlocklistRules(); len(list) != 0 {
			t.Fatalf("attendu liste vide, obtenu %+v", list)
		}
	})
}

func TestCatalogExposeBlocklist(t *testing.T) {
	t.Run("chaque regle integree porte son bloc blocklist", func(t *testing.T) {
		rm := New(newFakeStore(), nil)
		rm.SetBlocklistConfig("scan", BlocklistConfigInput{Threshold: f64Ptr(8)})
		cat := rm.Catalog(detect.Explanations, Thresholds{})
		var scan, flood *BuiltinCatalogEntry
		for i := range cat.Builtins {
			switch cat.Builtins[i].Key {
			case "scan":
				scan = &cat.Builtins[i]
			case "flood":
				flood = &cat.Builtins[i]
			}
		}
		if scan.Blocklist.Threshold == nil || *scan.Blocklist.Threshold != 8 {
			t.Fatalf("scan.blocklist.threshold = %v", scan.Blocklist.Threshold)
		}
		if flood.Blocklist.Threshold != nil {
			t.Fatalf("flood.blocklist.threshold devrait etre nil, obtenu %v", *flood.Blocklist.Threshold)
		}
	})
}

// Parite avec sanitizePathsIgnore() de rules-manager.js.
func TestSanitizePathsIgnoreParity(t *testing.T) {
	long := "/" + strings.Repeat("a", 300)
	got := SanitizePathsIgnore(map[int][]string{
		1: {"", "*", "login", "/ok", "/ok", long},
		2: nil,
	})
	if len(got) != 1 || len(got[1]) != 1 || got[1][0] != "/ok" {
		t.Fatalf("attendu {1:[/ok]}, obtenu %v", got)
	}
	var many []string
	for i := 0; i < 200; i++ {
		many = append(many, "/p"+strings.Repeat("x", i%5)+string(rune('a'+i%26))+strings.Repeat("y", i/26))
	}
	if n := len(SanitizePathsIgnore(map[int][]string{1: many})[1]); n != MaxPathsIgnorePerRule {
		t.Fatalf("liste bornee a %d, obtenu %d", MaxPathsIgnorePerRule, n)
	}
}

func TestRemediationType(t *testing.T) {
	t.Run("builtin : challenge persiste, inconnu refuse, expose par la liste", func(t *testing.T) {
		st := newFakeStore()
		rm := New(st, nil)
		bad := rm.SetBlocklistConfig("flood", BlocklistConfigInput{Threshold: f64Ptr(3), Remediation: true, RemediationType: "captcha"})
		if bad.OK {
			t.Fatal("captcha devrait etre refuse")
		}
		ok := rm.SetBlocklistConfig("flood", BlocklistConfigInput{Threshold: f64Ptr(3), Remediation: true, RemediationType: "challenge"})
		if !ok.OK {
			t.Fatalf("challenge refuse: %v", ok.Errors)
		}
		if New(st, nil).GetBlocklistConfigNL("flood").RemediationType != "challenge" {
			t.Fatal("non persiste")
		}
		for _, r := range rm.ListBlocklistRulesNL() {
			if r.Key == "flood" && r.RemediationType != "challenge" {
				t.Fatalf("liste: %s", r.RemediationType)
			}
		}
		if rm.GetBlocklistConfigNL("scan").RemediationType != "block" {
			t.Fatal("defaut attendu block")
		}
	})
	t.Run("personnalisee : YAML challenge, aller-retour, valeur inconnue refusee", func(t *testing.T) {
		base := "rules:\n  - id: 120\n    name: a\n    min_matches: 1\n    blocklist_threshold: 1\n    blocklist_remediation: true\n"
		_, errs, valid := ParseAndValidate(base + "    blocklist_remediation_type: challenge\n")
		if len(errs) != 0 || valid[0].BlocklistRemediationType != "challenge" {
			t.Fatalf("errs=%v", errs)
		}
		_, _, v2 := ParseAndValidate(base)
		if v2[0].BlocklistRemediationType != "block" {
			t.Fatal("defaut block")
		}
		_, errs3, _ := ParseAndValidate(base + "    blocklist_remediation_type: captcha\n")
		if len(errs3) == 0 {
			t.Fatal("captcha devrait etre refuse")
		}
	})
}

package rules

import (
	"strings"
	"testing"
)

func TestParseRulesYamlSyntaxe(t *testing.T) {
	t.Run("parse une regle simple avec tous les champs", func(t *testing.T) {
		yaml := `rules:
  - id: 101
    name: admin_probe
    enable: true
    severity: high
    description: "Beaucoup de requetes vers des chemins d administration"
    window_minutes: 5
    min_matches: 10
    path_hint: "(wp-admin|phpmyadmin)"
    ua_hint: null
    status_in: [401, 403]
    method_in: []
`
		rulesOut, errs := ParseRulesYaml(yaml)
		if len(errs) != 0 {
			t.Fatalf("errors: %v", errs)
		}
		if len(rulesOut) != 1 {
			t.Fatalf("attendu 1 regle, obtenu %d", len(rulesOut))
		}
		r := rulesOut[0]
		if v, _ := asFloat(r["id"]); v != 101 {
			t.Fatalf("id: %v", r["id"])
		}
		if r["name"] != "admin_probe" {
			t.Fatalf("name: %v", r["name"])
		}
		if r["enable"] != true {
			t.Fatalf("enable: %v", r["enable"])
		}
		if v, _ := asFloat(r["min_matches"]); v != 10 {
			t.Fatalf("min_matches: %v", r["min_matches"])
		}
		if r["path_hint"] != "(wp-admin|phpmyadmin)" {
			t.Fatalf("path_hint: %v", r["path_hint"])
		}
		if r["ua_hint"] != nil {
			t.Fatalf("ua_hint: %v", r["ua_hint"])
		}
		statusIn, _ := r["status_in"].([]any)
		if len(statusIn) != 2 {
			t.Fatalf("status_in: %v", r["status_in"])
		}
		methodIn, _ := r["method_in"].([]any)
		if len(methodIn) != 0 {
			t.Fatalf("method_in: %v", r["method_in"])
		}
	})

	t.Run("plusieurs regles a la suite", func(t *testing.T) {
		yaml := "rules:\n  - id: 101\n    name: a\n    min_matches: 5\n  - id: 102\n    name: b\n    min_matches: 8\n"
		rulesOut, _ := ParseRulesYaml(yaml)
		if len(rulesOut) != 2 {
			t.Fatalf("attendu 2, obtenu %d", len(rulesOut))
		}
		if v, _ := asFloat(rulesOut[1]["id"]); v != 102 {
			t.Fatalf("rulesOut[1].id: %v", rulesOut[1]["id"])
		}
	})

	t.Run("commentaires et lignes vides ignores", func(t *testing.T) {
		yaml := "# commentaire\nrules:\n  # une autre regle\n  - id: 101\n    name: a\n\n    min_matches: 5\n"
		rulesOut, errs := ParseRulesYaml(yaml)
		if len(errs) != 0 {
			t.Fatalf("errors: %v", errs)
		}
		if len(rulesOut) != 1 {
			t.Fatalf("attendu 1, obtenu %d", len(rulesOut))
		}
	})

	t.Run("une ligne mal formee est signalee avec son numero", func(t *testing.T) {
		yaml := "rules:\n  - id: 101\n    name: a\nthis ne va pas\n"
		_, errs := ParseRulesYaml(yaml)
		found := false
		for _, e := range errs {
			if strings.Contains(e, "Ligne 4") {
				found = true
			}
		}
		if !found {
			t.Fatalf("errors: %v", errs)
		}
	})

	t.Run("fichier vide -> aucune regle, aucune erreur", func(t *testing.T) {
		rulesOut, errs := ParseRulesYaml("")
		if len(rulesOut) != 0 || len(errs) != 0 {
			t.Fatalf("rulesOut=%v errs=%v", rulesOut, errs)
		}
	})

	t.Run("contenu non reconnu sur un fichier non vide -> erreur", func(t *testing.T) {
		_, errs := ParseRulesYaml("foo: bar\n")
		if len(errs) == 0 {
			t.Fatal("attendu au moins une erreur")
		}
	})
}

func TestValidateRuleChampParChamp(t *testing.T) {
	t.Run("regle valide -> aucune erreur", func(t *testing.T) {
		errs := ValidateRule(RawRule{"id": 101.0, "name": "ok", "min_matches": 5.0}, map[int]bool{})
		if len(errs) != 0 {
			t.Fatalf("errs: %v", errs)
		}
	})
	t.Run("id absent ou < 100 rejete", func(t *testing.T) {
		if len(ValidateRule(RawRule{"id": 5.0, "name": "a", "min_matches": 1.0}, map[int]bool{})) == 0 {
			t.Fatal("id < 100 devrait etre rejete")
		}
		if len(ValidateRule(RawRule{"name": "a", "min_matches": 1.0}, map[int]bool{})) == 0 {
			t.Fatal("id absent devrait etre rejete")
		}
	})
	t.Run("id deja utilise rejete", func(t *testing.T) {
		seen := map[int]bool{101: true}
		if len(ValidateRule(RawRule{"id": 101.0, "name": "a", "min_matches": 1.0}, seen)) == 0 {
			t.Fatal("id deja utilise devrait etre rejete")
		}
	})
	t.Run("name manquant ou invalide rejete", func(t *testing.T) {
		if len(ValidateRule(RawRule{"id": 101.0, "min_matches": 1.0}, map[int]bool{})) == 0 {
			t.Fatal("name manquant devrait etre rejete")
		}
		if len(ValidateRule(RawRule{"id": 101.0, "name": "a b", "min_matches": 1.0}, map[int]bool{})) == 0 {
			t.Fatal("name invalide devrait etre rejete")
		}
	})
	t.Run("severity hors enum rejetee", func(t *testing.T) {
		if len(ValidateRule(RawRule{"id": 101.0, "name": "a", "min_matches": 1.0, "severity": "critical"}, map[int]bool{})) == 0 {
			t.Fatal("severity invalide devrait etre rejetee")
		}
	})
	t.Run("min_matches manquant ou <= 0 rejete", func(t *testing.T) {
		if len(ValidateRule(RawRule{"id": 101.0, "name": "a"}, map[int]bool{})) == 0 {
			t.Fatal("min_matches manquant devrait etre rejete")
		}
		if len(ValidateRule(RawRule{"id": 101.0, "name": "a", "min_matches": 0.0}, map[int]bool{})) == 0 {
			t.Fatal("min_matches=0 devrait etre rejete")
		}
	})
	t.Run("path_hint/ua_hint regex invalide rejetee", func(t *testing.T) {
		if len(ValidateRule(RawRule{"id": 101.0, "name": "a", "min_matches": 1.0, "path_hint": "("}, map[int]bool{})) == 0 {
			t.Fatal("regex invalide devrait etre rejetee")
		}
	})
	t.Run("status_in/method_in non-tableau rejete", func(t *testing.T) {
		if len(ValidateRule(RawRule{"id": 101.0, "name": "a", "min_matches": 1.0, "status_in": 401.0}, map[int]bool{})) == 0 {
			t.Fatal("status_in non-tableau devrait etre rejete")
		}
	})
}

func TestParseAndValidate(t *testing.T) {
	t.Run("regle valide gardee, regle invalide reportee", func(t *testing.T) {
		yaml := "rules:\n  - id: 101\n    name: ok_rule\n    min_matches: 5\n  - id: 50\n    name: bad_id\n    min_matches: 5\n"
		_, errs, valid := ParseAndValidate(yaml)
		if len(valid) != 1 || valid[0].Name != "ok_rule" {
			t.Fatalf("valid: %+v", valid)
		}
		found := false
		for _, e := range errs {
			if strings.Contains(e, "bad_id") {
				found = true
			}
		}
		if !found {
			t.Fatalf("errs: %v", errs)
		}
	})
	t.Run("valeurs par defaut appliquees", func(t *testing.T) {
		_, _, valid := ParseAndValidate("rules:\n  - id: 101\n    name: a\n    min_matches: 5\n")
		if !valid[0].Enable {
			t.Fatal("enable devrait etre true par defaut")
		}
		if valid[0].Severity != "medium" {
			t.Fatalf("severity: %s", valid[0].Severity)
		}
		if valid[0].WindowMinutes != 5 {
			t.Fatalf("windowMinutes: %d", valid[0].WindowMinutes)
		}
	})
	t.Run("path_hint/ua_hint compiles en regex exploitables", func(t *testing.T) {
		_, _, valid := ParseAndValidate("rules:\n  - id: 101\n    name: a\n    min_matches: 5\n    path_hint: \"admin\"\n")
		if valid[0].PathHint == nil {
			t.Fatal("pathHint devrait etre compile")
		}
		if !valid[0].PathHint.MatchString("/wp-admin/x") {
			t.Fatal("pathHint devrait matcher")
		}
	})
}

func TestStringifyRulesAllerRetour(t *testing.T) {
	t.Run("une regle serialisee puis reparsee redonne les memes valeurs", func(t *testing.T) {
		original := []map[string]any{{
			"id": 101, "name": "x", "enable": true, "severity": "high", "description": "d",
			"window_minutes": 7, "min_matches": 3, "path_hint": "a", "ua_hint": nil,
			"status_in": []any{403}, "method_in": []any{"GET"},
		}}
		text := StringifyRules(original)
		_, errs, valid := ParseAndValidate(text)
		if len(errs) != 0 {
			t.Fatalf("errs: %v", errs)
		}
		if len(valid) != 1 {
			t.Fatalf("valid: %+v", valid)
		}
		if valid[0].ID != 101 {
			t.Fatalf("id: %d", valid[0].ID)
		}
		if valid[0].MinMatches != 3 {
			t.Fatalf("minMatches: %d", valid[0].MinMatches)
		}
		if valid[0].WindowMinutes != 7 {
			t.Fatalf("windowMinutes: %d", valid[0].WindowMinutes)
		}
		if len(valid[0].StatusIn) != 1 || valid[0].StatusIn[0] != 403 {
			t.Fatalf("statusIn: %v", valid[0].StatusIn)
		}
	})
	t.Run("liste vide -> rules: []", func(t *testing.T) {
		if got := StringifyRules(nil); got != "rules: []\n" {
			t.Fatalf("got: %q", got)
		}
	})
}

func TestBlocklistParRegle(t *testing.T) {
	t.Run("champs absents -> defauts", func(t *testing.T) {
		_, _, valid := ParseAndValidate("rules:\n  - id: 100\n    name: x\n    min_matches: 5")
		if valid[0].BlocklistThreshold != nil {
			t.Fatalf("threshold: %v", valid[0].BlocklistThreshold)
		}
		if valid[0].BlocklistWindowMinutes != 1440 {
			t.Fatalf("window: %d", valid[0].BlocklistWindowMinutes)
		}
		if valid[0].BlocklistRemediation {
			t.Fatal("remediation devrait etre false")
		}
		if valid[0].BlocklistRemediationMinutes != nil {
			t.Fatalf("remediationMinutes: %v", valid[0].BlocklistRemediationMinutes)
		}
	})
	t.Run("champs fournis repris tels quels", func(t *testing.T) {
		yaml := strings.Join([]string{
			"rules:", "  - id: 100", "    name: x", "    min_matches: 5",
			"    blocklist_threshold: 3", "    blocklist_window_minutes: 120",
			"    blocklist_remediation: true", "    blocklist_remediation_minutes: 60",
		}, "\n")
		_, _, valid := ParseAndValidate(yaml)
		if valid[0].BlocklistThreshold == nil || *valid[0].BlocklistThreshold != 3 {
			t.Fatalf("threshold: %v", valid[0].BlocklistThreshold)
		}
		if valid[0].BlocklistWindowMinutes != 120 {
			t.Fatalf("window: %d", valid[0].BlocklistWindowMinutes)
		}
		if !valid[0].BlocklistRemediation {
			t.Fatal("remediation devrait etre true")
		}
		if valid[0].BlocklistRemediationMinutes == nil || *valid[0].BlocklistRemediationMinutes != 60 {
			t.Fatalf("remediationMinutes: %v", valid[0].BlocklistRemediationMinutes)
		}
	})
	t.Run("blocklist_threshold < 1 -> erreur explicite", func(t *testing.T) {
		_, errs, _ := ParseAndValidate("rules:\n  - id: 100\n    name: x\n    min_matches: 5\n    blocklist_threshold: 0")
		found := false
		for _, e := range errs {
			if strings.Contains(e, "blocklist_threshold") {
				found = true
			}
		}
		if !found {
			t.Fatalf("errs: %v", errs)
		}
	})
	t.Run("blocklist_window_minutes est borne", func(t *testing.T) {
		yaml := "rules:\n  - id: 100\n    name: x\n    min_matches: 5\n    blocklist_window_minutes: 999999"
		_, _, valid := ParseAndValidate(yaml)
		if valid[0].BlocklistWindowMinutes != MaxBlocklistWindowMinutes {
			t.Fatalf("window: %d", valid[0].BlocklistWindowMinutes)
		}
	})
	t.Run("blocklist_remediation_minutes est borne", func(t *testing.T) {
		yaml := "rules:\n  - id: 100\n    name: x\n    min_matches: 5\n    blocklist_remediation_minutes: 999999"
		_, _, valid := ParseAndValidate(yaml)
		if valid[0].BlocklistRemediationMinutes == nil || *valid[0].BlocklistRemediationMinutes != MaxBlocklistRemediationMinutes {
			t.Fatalf("remediationMinutes: %v", valid[0].BlocklistRemediationMinutes)
		}
	})
	t.Run("blocklist_remediation: absent ou false -> false, seul true l active", func(t *testing.T) {
		_, _, va := ParseAndValidate("rules:\n  - id: 100\n    name: a\n    min_matches: 5")
		_, _, vb := ParseAndValidate("rules:\n  - id: 101\n    name: b\n    min_matches: 5\n    blocklist_remediation: false")
		_, _, vc := ParseAndValidate("rules:\n  - id: 102\n    name: c\n    min_matches: 5\n    blocklist_remediation: true")
		if va[0].BlocklistRemediation || vb[0].BlocklistRemediation || !vc[0].BlocklistRemediation {
			t.Fatalf("a=%v b=%v c=%v", va[0].BlocklistRemediation, vb[0].BlocklistRemediation, vc[0].BlocklistRemediation)
		}
	})
	t.Run("stringifyRules aller-retour conserve les champs blocklist", func(t *testing.T) {
		original := []map[string]any{{
			"id": 105, "name": "y", "min_matches": 4,
			"blocklist_threshold": 7, "blocklist_window_minutes": 30,
			"blocklist_remediation": true, "blocklist_remediation_minutes": 15,
		}}
		text := StringifyRules(original)
		_, errs, valid := ParseAndValidate(text)
		if len(errs) != 0 {
			t.Fatalf("errs: %v", errs)
		}
		if valid[0].BlocklistThreshold == nil || *valid[0].BlocklistThreshold != 7 {
			t.Fatalf("threshold: %v", valid[0].BlocklistThreshold)
		}
		if valid[0].BlocklistWindowMinutes != 30 {
			t.Fatalf("window: %d", valid[0].BlocklistWindowMinutes)
		}
		if !valid[0].BlocklistRemediation {
			t.Fatal("remediation devrait etre true")
		}
		if valid[0].BlocklistRemediationMinutes == nil || *valid[0].BlocklistRemediationMinutes != 15 {
			t.Fatalf("remediationMinutes: %v", valid[0].BlocklistRemediationMinutes)
		}
	})
}

func TestScopeGlobalYaml(t *testing.T) {
	y := "rules:\n  - id: 120\n    name: botnet\n    min_matches: 20\n    scope: global\n  - id: 121\n    name: normal\n    min_matches: 3\n"
	_, errs, valid := ParseAndValidate(y)
	if len(errs) != 0 || len(valid) != 2 {
		t.Fatalf("errs=%v valid=%d", errs, len(valid))
	}
	if valid[0].Scope != "global" || valid[0].MinIPs != 5 || valid[1].Scope != "ip" || valid[1].MinIPs != 0 {
		t.Fatalf("valid: %+v %+v", valid[0], valid[1])
	}
	_, errs, _ = ParseAndValidate("rules:\n  - id: 120\n    name: a\n    min_matches: 1\n    scope: monde\n  - id: 121\n    name: b\n    min_matches: 1\n    scope: global\n    min_ips: 0\n")
	joined := strings.Join(errs, "\n")
	if !strings.Contains(joined, `"scope"`) || !strings.Contains(joined, `"min_ips"`) {
		t.Fatalf("errs: %v", errs)
	}
	out := StringifyRules([]map[string]any{{"id": 120, "name": "botnet", "min_matches": 20, "scope": "global", "min_ips": 7}})
	if !strings.Contains(out, "scope: global\n    min_ips: 7") {
		t.Fatalf("stringify: %s", out)
	}
}

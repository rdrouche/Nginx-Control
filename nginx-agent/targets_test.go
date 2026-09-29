package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPublishesTo(t *testing.T) {
	cases := []struct {
		name    string
		publish []string
		target  string
		want    bool
	}{
		{"nil (par defaut) -> toutes les cibles", nil, "dmz", true},
		{"nil -> matche aussi une cible au nom vide (mode a une seule cible)", nil, "", true},
		{"liste contenant \"all\" -> toutes les cibles", []string{"dmz", "all"}, "lan", true},
		{"nom present dans la liste -> vrai", []string{"dmz", "lan"}, "lan", true},
		{"nom absent de la liste -> faux", []string{"dmz"}, "lan", false},
		{"comparaison insensible a la casse", []string{"DMZ"}, "dmz", true},
		// Fix v12.22.0 (audit finding BAS-GO-a, regression v12.21.0) : en
		// mode mono-cible (targetName == ""), un label publish= qui ne
		// nommerait qu une autre cible ne doit JAMAIS masquer le conteneur —
		// il n y a qu une seule cible possible, donc rien a filtrer. Avant
		// ce correctif, ce cas precis renvoyait false (le conteneur
		// disparaissait), contrairement a ce que le README et le commentaire
		// de publishesTo() annoncaient deja ("matche toujours" en
		// mono-cible).
		{"publish=[\"lan\"] mais mono-cible (\"\") -> matche quand meme", []string{"lan"}, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := publishesTo(c.publish, c.target)
			if got != c.want {
				t.Fatalf("publishesTo(%v, %q) = %v, attendu %v", c.publish, c.target, got, c.want)
			}
		})
	}
}

func writeTargetsFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("ecriture du fichier de test : %v", err)
	}
	return path
}

func TestLoadTargetsFile_Valid(t *testing.T) {
	path := writeTargetsFile(t, `[
		{"name": "dmz", "dashboardUrl": "https://dmz.example.com/", "stateFile": "/data/dmz.json"},
		{"name": "LAN", "dashboardUrl": "http://lan.internal:3000", "stateFile": "/data/lan.json", "tokenFile": "/data/lan-token", "insecureSkipVerify": true}
	]`)
	targets, err := loadTargetsFile(path)
	if err != nil {
		t.Fatalf("loadTargetsFile : %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("attendu 2 cibles, obtenu %d", len(targets))
	}
	if targets[0].Name != "dmz" || targets[0].DashboardURL != "https://dmz.example.com" {
		t.Fatalf("cible 0 mal normalisee : %+v", targets[0])
	}
	if targets[1].Name != "lan" {
		t.Fatalf("le nom doit etre normalise en minuscules, obtenu %q", targets[1].Name)
	}
	if !targets[1].InsecureSkipVerify || targets[1].TokenFile != "/data/lan-token" {
		t.Fatalf("champs optionnels de la cible 1 perdus : %+v", targets[1])
	}
}

func TestLoadTargetsFile_Errors(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"JSON invalide", `not json`},
		{"tableau vide", `[]`},
		{"name manquant", `[{"dashboardUrl": "http://a", "stateFile": "/a.json"}]`},
		{"name reserve \"all\"", `[{"name": "all", "dashboardUrl": "http://a", "stateFile": "/a.json"}]`},
		{"noms dupliques", `[
			{"name": "dmz", "dashboardUrl": "http://a", "stateFile": "/a.json"},
			{"name": "DMZ", "dashboardUrl": "http://b", "stateFile": "/b.json"}
		]`},
		{"dashboardUrl manquant", `[{"name": "dmz", "stateFile": "/a.json"}]`},
		{"stateFile manquant", `[{"name": "dmz", "dashboardUrl": "http://a"}]`},
		// Fix v12.22.0 (audit finding BAS-GO-b, regression v12.21.0) : le
		// commentaire de targetConfig annoncait deja que deux cibles ne
		// pouvaient pas partager le meme stateFile, mais rien ne le
		// verifiait — deux cibles auraient silencieusement ecrase leur
		// agentId/jeton persistes l une l autre.
		{"stateFile duplique entre deux cibles de noms differents", `[
			{"name": "dmz", "dashboardUrl": "http://a", "stateFile": "/shared.json"},
			{"name": "lan", "dashboardUrl": "http://b", "stateFile": "/shared.json"}
		]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := writeTargetsFile(t, c.content)
			if _, err := loadTargetsFile(path); err == nil {
				t.Fatalf("attendu une erreur pour %q, obtenu nil", c.name)
			}
		})
	}
}

func TestLoadTargetsFile_MissingFile(t *testing.T) {
	if _, err := loadTargetsFile(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("attendu une erreur pour un fichier absent")
	}
}

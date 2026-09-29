package main

import (
	"testing"
)

func TestVhostFromLabels_MinimalDirect(t *testing.T) {
	labels := map[string]string{
		"nginx-control.enable":                  "true",
		"nginx-control.vhost.server_name":       "app.example.com",
		"nginx-control.vhost.location01":        "/",
		"nginx-control.vhost.location01.target": "http://203.0.113.10:8080",
	}
	v, _, ok := vhostFromLabels(labels)
	if !ok {
		t.Fatal("attendu un vhost valide")
	}
	if v.Mode != "direct" {
		t.Errorf("mode par defaut attendu 'direct', obtenu %q", v.Mode)
	}
	if len(v.Locations) != 1 || v.Locations[0].Target != "http://203.0.113.10:8080" {
		t.Errorf("location inattendue : %+v", v.Locations)
	}
}

func TestVhostFromLabels_NotEnabled(t *testing.T) {
	labels := map[string]string{
		"nginx-control.vhost.server_name":       "app.example.com",
		"nginx-control.vhost.location01":        "/",
		"nginx-control.vhost.location01.target": "http://203.0.113.10:8080",
	}
	if _, _, ok := vhostFromLabels(labels); ok {
		t.Fatal("nginx-control.enable absent -> ne doit jamais produire de vhost")
	}
}

func TestVhostFromLabels_NoServerName(t *testing.T) {
	labels := map[string]string{
		"nginx-control.enable":                  "true",
		"nginx-control.vhost.location01":        "/",
		"nginx-control.vhost.location01.target": "http://203.0.113.10:8080",
	}
	if _, _, ok := vhostFromLabels(labels); ok {
		t.Fatal("server_name absent -> ne doit jamais produire de vhost")
	}
}

func TestVhostFromLabels_NoLocation(t *testing.T) {
	labels := map[string]string{
		"nginx-control.enable":            "true",
		"nginx-control.vhost.server_name": "app.example.com",
	}
	if _, _, ok := vhostFromLabels(labels); ok {
		t.Fatal("aucune location utilisable -> ne doit jamais produire de vhost")
	}
}

func TestVhostFromLabels_ProxyPassAlias(t *testing.T) {
	labels := map[string]string{
		"nginx-control.enable":                      "true",
		"nginx-control.vhost.server_name":           "app.example.com",
		"nginx-control.vhost.location01":            "/",
		"nginx-control.vhost.location01.proxy_pass": "http://203.0.113.11:9090",
	}
	v, _, ok := vhostFromLabels(labels)
	if !ok || len(v.Locations) != 1 || v.Locations[0].Target != "http://203.0.113.11:9090" {
		t.Fatalf(".proxy_pass doit etre accepte comme alias de .target : %+v", v)
	}
}

func TestVhostFromLabels_MultipleLocationsOrdered(t *testing.T) {
	labels := map[string]string{
		"nginx-control.enable":                  "true",
		"nginx-control.vhost.server_name":       "app.example.com",
		"nginx-control.vhost.location01":        "/",
		"nginx-control.vhost.location01.target": "http://a:1",
		"nginx-control.vhost.location02":        "/api",
		"nginx-control.vhost.location02.target": "http://b:2",
	}
	v, _, ok := vhostFromLabels(labels)
	if !ok || len(v.Locations) != 2 {
		t.Fatalf("attendu 2 locations, obtenu %+v", v)
	}
	if v.Locations[0].Path != "/" || v.Locations[1].Path != "/api" {
		t.Errorf("ordre des locations incorrect : %+v", v.Locations)
	}
}

// Fix v12.22.0 (audit finding GO-11) : "location1" (sans zero en tete) etait
// silencieusement ignoree — la boucle reconstruisait la cle avec pad2(1) =
// "location01", qui n existe pas dans les labels reels, donc path restait
// vide et toute la location (et le vhost entier, ici, puisque c est la seule
// location) disparaissait sans le moindre message.
func TestVhostFromLabels_LocationWithoutLeadingZero(t *testing.T) {
	labels := map[string]string{
		"nginx-control.enable":                 "true",
		"nginx-control.vhost.server_name":      "app.example.com",
		"nginx-control.vhost.location1":        "/",
		"nginx-control.vhost.location1.target": "http://a:1",
	}
	v, _, ok := vhostFromLabels(labels)
	if !ok {
		t.Fatal("le vhost ne doit pas disparaitre : location1 (sans zero en tete) est une cle valide")
	}
	if len(v.Locations) != 1 || v.Locations[0].Path != "/" || v.Locations[0].Target != "http://a:1" {
		t.Fatalf("location1 mal lue : %+v", v.Locations)
	}
}

// Fix v12.22.0 (audit finding GO-11) : "location01" et "location1" declarees
// ENSEMBLE representent le meme index numerique (1) et ne doivent produire
// qu UNE seule location, jamais un doublon.
func TestVhostFromLabels_LocationDuplicateIndexDeduped(t *testing.T) {
	labels := map[string]string{
		"nginx-control.enable":                  "true",
		"nginx-control.vhost.server_name":       "app.example.com",
		"nginx-control.vhost.location01":        "/",
		"nginx-control.vhost.location01.target": "http://a:1",
		"nginx-control.vhost.location1":         "/",
		"nginx-control.vhost.location1.target":  "http://b:2",
		"nginx-control.vhost.location02":        "/api",
		"nginx-control.vhost.location02.target": "http://c:3",
	}
	v, _, ok := vhostFromLabels(labels)
	if !ok {
		t.Fatal("vhost attendu")
	}
	if len(v.Locations) != 2 {
		t.Fatalf("attendu 2 locations (index 1 dedoublonne + index 2), obtenu %d : %+v", len(v.Locations), v.Locations)
	}
}

func TestVhostFromLabels_TunnelMode(t *testing.T) {
	labels := map[string]string{
		"nginx-control.enable":                  "true",
		"nginx-control.vhost.server_name":       "app.example.com",
		"nginx-control.vhost.mode":              "tunnel",
		"nginx-control.vhost.location01":        "/",
		"nginx-control.vhost.location01.target": "http://127.0.0.1:8080",
	}
	v, _, ok := vhostFromLabels(labels)
	if !ok || v.Mode != "tunnel" {
		t.Fatalf("mode=tunnel doit etre repris tel quel : %+v", v)
	}
}

func TestVhostFromLabels_RelayMode(t *testing.T) {
	labels := map[string]string{
		"nginx-control.enable":                  "true",
		"nginx-control.vhost.server_name":       "app.example.com",
		"nginx-control.vhost.mode":              "relay",
		"nginx-control.vhost.relay_scheme":      "https",
		"nginx-control.vhost.location01":        "/",
		"nginx-control.vhost.location01.target": "http://127.0.0.1:8080",
	}
	v, _, ok := vhostFromLabels(labels)
	if !ok || v.Mode != "relay" || v.RelayScheme != "https" {
		t.Fatalf("mode=relay + relay_scheme=https doivent etre repris tels quels : %+v", v)
	}
}

func TestVhostFromLabels_RelayModeDefaultScheme(t *testing.T) {
	labels := map[string]string{
		"nginx-control.enable":                  "true",
		"nginx-control.vhost.server_name":       "app.example.com",
		"nginx-control.vhost.mode":              "relay",
		"nginx-control.vhost.location01":        "/",
		"nginx-control.vhost.location01.target": "http://127.0.0.1:8080",
	}
	v, _, ok := vhostFromLabels(labels)
	if !ok || v.RelayScheme != "http" {
		t.Fatalf("relay_scheme absent -> defaut 'http' attendu : %+v", v)
	}
}

func TestVhostFromLabels_MonitorDiagnosticAnalyze(t *testing.T) {
	labels := map[string]string{
		"nginx-control.enable":                     "true",
		"nginx-control.vhost.server_name":          "app.example.com",
		"nginx-control.vhost.location01":           "/",
		"nginx-control.vhost.location01.target":    "http://a:1",
		"nginx-control.monitor.enable":             "true",
		"nginx-control.monitor.interval":           "45s",
		"nginx-control.monitor.valid_http_code":    "200,301",
		"nginx-control.diagnostic.enable":          "false",
		"nginx-control.vhost.analyze.enable":       "false",
		"nginx-control.vhost.analyze.ignore_rules": "1,3,7",
	}
	v, _, _ := vhostFromLabels(labels)
	if !v.Monitor.Enable || v.Monitor.Interval != "45s" || v.Monitor.ValidHTTPCode != "200,301" {
		t.Errorf("monitor mal transcrit : %+v", v.Monitor)
	}
	if v.Diagnostic.Enable {
		t.Error("diagnostic.enable=false attendu")
	}
	if v.Analyze.Enable {
		t.Error("analyze.enable=false attendu")
	}
	if len(v.Analyze.IgnoreRules) != 3 || v.Analyze.IgnoreRules[1] != 3 {
		t.Errorf("ignoreRules mal transcrites : %v", v.Analyze.IgnoreRules)
	}
}

func TestVhostFromLabels_PerLocationMonitorOverride(t *testing.T) {
	labels := map[string]string{
		"nginx-control.enable":                          "true",
		"nginx-control.vhost.server_name":               "app.example.com",
		"nginx-control.vhost.location01":                "/health",
		"nginx-control.vhost.location01.target":         "http://a:1",
		"nginx-control.vhost.location01.monitor.enable": "false",
	}
	v, _, _ := vhostFromLabels(labels)
	if !v.Locations[0].MonitorIgnore {
		t.Error("location01.monitor.enable=false doit produire MonitorIgnore=true")
	}
}

func TestVhostFromLabels_Publish(t *testing.T) {
	base := map[string]string{
		"nginx-control.enable":                  "true",
		"nginx-control.vhost.server_name":       "app.example.com",
		"nginx-control.vhost.location01":        "/",
		"nginx-control.vhost.location01.target": "http://203.0.113.10:8080",
	}

	t.Run("absente -> nil (toutes les cibles par defaut, voir publishesTo())", func(t *testing.T) {
		_, publish, ok := vhostFromLabels(base)
		if !ok {
			t.Fatal("attendu un vhost valide")
		}
		if publish != nil {
			t.Errorf("attendu publish nil, obtenu %v", publish)
		}
	})

	t.Run("liste espace/virgule -> normalisee en minuscules", func(t *testing.T) {
		labels := map[string]string{}
		for k, v := range base {
			labels[k] = v
		}
		labels["nginx-control.publish"] = "DMZ, lan"
		_, publish, ok := vhostFromLabels(labels)
		if !ok {
			t.Fatal("attendu un vhost valide")
		}
		if len(publish) != 2 || publish[0] != "dmz" || publish[1] != "lan" {
			t.Errorf("publish inattendu : %v", publish)
		}
	})
}

func TestSetLocalRoutes_And_Resolve(t *testing.T) {
	vhosts := []VhostSpec{
		{ServerName: "tunnel.example.com", Mode: "tunnel", Locations: []LocationSpec{
			{Path: "/", Target: "http://127.0.0.1:8080"},
			{Path: "/api", Target: "http://127.0.0.1:9090"},
		}},
		{ServerName: "direct.example.com", Mode: "direct", Locations: []LocationSpec{
			{Path: "/", Target: "http://203.0.113.1:80"},
		}},
		{ServerName: "relay.example.com", Mode: "relay", RelayScheme: "https", Locations: []LocationSpec{
			{Path: "/", Target: "http://127.0.0.1:9999"},
		}},
	}
	setLocalRoutes(vhostsAsEntries(vhosts, nil))

	if target, ok := resolveLocalTarget("relay.example.com", "/"); !ok || target != "http://127.0.0.1:9999" {
		t.Errorf("mode relay doit aussi etre resolu localement (meme table que tunnel), obtenu %q ok=%v", target, ok)
	}
	// hasTunnelVhosts/resolveTunnelTarget prennent desormais un targetName
	// (fix GO-06) — "" est la cible mono-master par defaut (voir
	// publishesTo()), celle que ces vhosts de test (Publish nil) matchent
	// toujours.
	if !hasTunnelVhosts("") {
		t.Error("hasTunnelVhosts(\"\") doit rester true (un vhost tunnel est present)")
	}
	if target, ok := resolveTunnelTarget("tunnel.example.com", "/api/users", ""); !ok || target != "http://127.0.0.1:9090" {
		t.Errorf("resolveTunnelTarget doit aussi resoudre le mode tunnel pour la cible mono-master, obtenu %q ok=%v", target, ok)
	}
	if _, ok := resolveTunnelTarget("relay.example.com", "/", ""); ok {
		t.Error("resolveTunnelTarget ne doit JAMAIS resoudre un vhost mode=relay (fix GO-06 : seul resolveLocalTarget, non filtre, le fait)")
	}

	if target, ok := resolveLocalTarget("tunnel.example.com", "/api/users"); !ok || target != "http://127.0.0.1:9090" {
		t.Errorf("attendu correspondance /api (prefixe le plus long), obtenu %q ok=%v", target, ok)
	}
	if target, ok := resolveLocalTarget("tunnel.example.com", "/other"); !ok || target != "http://127.0.0.1:8080" {
		t.Errorf("attendu repli sur /, obtenu %q ok=%v", target, ok)
	}
	if _, ok := resolveLocalTarget("direct.example.com", "/"); ok {
		t.Error("un vhost mode=direct ne doit jamais apparaitre dans les routes tunnel")
	}
	if _, ok := resolveLocalTarget("relay-inconnu.example.com", "/"); ok {
		t.Error("hote non enregistre -> ne doit rien resoudre")
	}
}

func TestSetLocalRoutes_RelayOnly_NoTunnel(t *testing.T) {
	setLocalRoutes(vhostsAsEntries([]VhostSpec{
		{ServerName: "relay-seul.example.com", Mode: "relay", Locations: []LocationSpec{
			{Path: "/", Target: "http://127.0.0.1:8080"},
		}},
	}, nil))
	if hasTunnelVhosts("") {
		t.Error("un manifeste ne contenant que du relay ne doit jamais faire croire qu un tunnel est necessaire")
	}
	if _, ok := resolveLocalTarget("inconnu.example.com", "/"); ok {
		t.Error("un hote non tunnel doit rester introuvable")
	}
}

// Fix v12.22.0 (audit finding GO-06) : un vhost tunnel publie vers UNE seule
// cible en multi-master ne doit etre visible (hasTunnelVhosts/
// resolveTunnelTarget) que pour CETTE cible — jamais pour une autre, et
// jamais via resolveLocalTarget (reserve au mode relay, non filtre).
func TestSetLocalRoutes_TunnelIsolatedPerTarget(t *testing.T) {
	entries := []vhostEntry{
		{
			Vhost:   VhostSpec{ServerName: "dmz-only.example.com", Mode: "tunnel", Locations: []LocationSpec{{Path: "/", Target: "http://127.0.0.1:8080"}}},
			Publish: []string{"dmz"},
		},
	}
	setLocalRoutes(entries)

	if !hasTunnelVhosts("dmz") {
		t.Error("hasTunnelVhosts(\"dmz\") doit etre true : le vhost est publie vers dmz")
	}
	if hasTunnelVhosts("lan") {
		t.Error("hasTunnelVhosts(\"lan\") doit etre false : le vhost n est PAS publie vers lan (fix GO-06)")
	}
	if _, ok := resolveTunnelTarget("dmz-only.example.com", "/", "lan"); ok {
		t.Error("resolveTunnelTarget doit refuser de router vers un vhost non publie vers cette cible (fix GO-06)")
	}
	if _, ok := resolveTunnelTarget("dmz-only.example.com", "/", "dmz"); !ok {
		t.Error("resolveTunnelTarget doit router normalement pour la cible a laquelle le vhost EST publie")
	}
	// resolveLocalTarget (utilise par relay.go) reste, lui, delibérément non
	// filtre par cible — voir le commentaire de routeEntry dans tunnel.go.
	if _, ok := resolveLocalTarget("dmz-only.example.com", "/"); !ok {
		t.Error("resolveLocalTarget (mode relay, partage) ne doit pas etre affecte par le filtrage par cible")
	}
}

// vhostsAsEntries est un helper de test uniquement : enveloppe une liste de
// VhostSpec en []vhostEntry avec la meme liste Publish pour chacune (nil par
// defaut = "toutes les cibles", voir publishesTo()).
func vhostsAsEntries(vhosts []VhostSpec, publish []string) []vhostEntry {
	out := make([]vhostEntry, 0, len(vhosts))
	for _, v := range vhosts {
		out = append(out, vhostEntry{Vhost: v, Publish: publish})
	}
	return out
}

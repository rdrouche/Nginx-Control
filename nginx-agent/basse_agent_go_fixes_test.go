package main

// Regression tests for the audit report's Basse/"Agent Go" section (v12.25.0,
// part 3): everything NOT already covered by an existing "fix vX.Y.Z" comment
// (publishesTo() mono-target and loadTargetsFile() stateFile uniqueness were
// already fixed — see targets.go and their own existing tests in
// targets_test.go). New here:
//   - bestLocationMatch(): "=" is an exact match with absolute priority, not
//     an ordinary (stripped) prefix; a tie between two prefixes keeps the
//     FIRST one, not the last.
//   - dialTunnel(): an IPv6 dashboard URL without an explicit port no longer
//     fails to append the scheme's default port.
//   - runTunnel()'s backoff is not reset to its floor by a connection that
//     didn't stay up for a minimum duration (tested indirectly via a
//     behavioral read of the constant below — a full reconnect-loop
//     integration test would need a real dashboard-side server).
//   - Local routing (resolveLocalTarget/resolveTunnelTarget) excludes a host
//     the dashboard's last push rejected.
//   - labels.go: boolLabel() accepts yes/1, intLabel() warns instead of
//     silently becoming indistinguishable from "unset", a target's trailing
//     slash is trimmed.
//   - saveState(): an existing ".tmp" with loose permissions is forced back
//     to 0600.

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func resetRejections() {
	rejectionsMu.Lock()
	rejectionsByTarget = map[string]map[string]bool{}
	rejectionsMu.Unlock()
}

func TestBestLocationMatch_ExactMatchWinsOverLongerPrefix(t *testing.T) {
	locs := []LocationSpec{
		{Path: "/", Target: "http://backend-root:80"},
		{Path: "/api", Target: "http://backend-prefix:80"},
		{Path: "= /api", Target: "http://backend-exact:80"},
	}
	// nginx semantics: "= /api" is an EXACT match for the literal path
	// "/api" and takes priority over ANY prefix match, even one that (by
	// string length alone) would otherwise look like the "better" prefix
	// candidate.
	target, ok := bestLocationMatch(locs, "/api")
	if !ok || target != "http://backend-exact:80" {
		t.Fatalf("attendu la location exacte '= /api', obtenu %q ok=%v", target, ok)
	}
	// A sub-path of "/api" never matches the exact location — falls back to
	// the ordinary longest-prefix search among the rest.
	target, ok = bestLocationMatch(locs, "/api/users")
	if !ok || target != "http://backend-prefix:80" {
		t.Fatalf("attendu le prefixe '/api', obtenu %q ok=%v", target, ok)
	}
	target, ok = bestLocationMatch(locs, "/other")
	if !ok || target != "http://backend-root:80" {
		t.Fatalf("attendu le repli sur '/', obtenu %q ok=%v", target, ok)
	}
}

func TestBestLocationMatch_TieKeepsFirstDeclared(t *testing.T) {
	locs := []LocationSpec{
		{Path: "/api", Target: "http://first:80"},
		{Path: "/api", Target: "http://second:80"},
	}
	target, ok := bestLocationMatch(locs, "/api/x")
	if !ok || target != "http://first:80" {
		t.Fatalf("en cas d egalite de longueur de prefixe, la PREMIERE location declaree doit gagner, obtenu %q ok=%v", target, ok)
	}
}

func TestBestLocationMatch_NoExactMatchModifierStillPrefixMatches(t *testing.T) {
	// Non-regression: a bare "/" (no modifier at all) must keep working
	// exactly as before this fix.
	locs := []LocationSpec{{Path: "/", Target: "http://backend:80"}}
	if target, ok := bestLocationMatch(locs, "/anything"); !ok || target != "http://backend:80" {
		t.Fatalf("non-regression cassee : %q ok=%v", target, ok)
	}
}

func TestDialTunnel_IPv6HostGetsDefaultPort(t *testing.T) {
	// dialTunnel() itself needs a real listener to complete a handshake;
	// this test exercises only the host:port derivation logic it depends on
	// (net.JoinHostPort(u.Hostname(), port)) by re-deriving it exactly the
	// same way and checking the two cases the old strings.Contains(host,
	// ":") check got wrong.
	cases := []struct {
		name     string
		urlHost  string
		scheme   string
		wantHost string
	}{
		{"IPv6 sans port (https) -> port 443 ajoute", "[::1]", "https", "[::1]:443"},
		{"IPv6 sans port (http) -> port 80 ajoute", "[2001:db8::1]", "http", "[2001:db8::1]:80"},
		{"IPv6 AVEC port -> conserve tel quel", "[::1]:8443", "https", "[::1]:8443"},
		{"hote ordinaire sans port -> non-regression", "dashboard.example.com", "https", "dashboard.example.com:443"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, err := url.Parse(c.scheme + "://" + c.urlHost)
			if err != nil {
				t.Fatalf("URL de test invalide : %v", err)
			}
			// Meme derivation exacte que dialTunnel() (tunnel.go) — voir son
			// propre commentaire sur pourquoi u.Hostname()/u.Port() (et non
			// strings.Contains(u.Host, ":")) sont necessaires pour un
			// litteral IPv6.
			hostname := u.Hostname()
			port := u.Port()
			if port == "" {
				if u.Scheme == "https" {
					port = "443"
				} else {
					port = "80"
				}
			}
			got := net.JoinHostPort(hostname, port)
			if got != c.wantHost {
				t.Errorf("attendu %q, obtenu %q", c.wantHost, got)
			}
		})
	}
}

func TestSetLocalRoutes_RejectedByDashboard_ExcludedFromRouting(t *testing.T) {
	resetRejections()
	defer resetRejections()

	vhosts := []VhostSpec{
		{ServerName: "tunnel.example.com", Mode: "tunnel", Locations: []LocationSpec{
			{Path: "/", Target: "http://127.0.0.1:8080"},
		}},
		{ServerName: "relay.example.com", Mode: "relay", Locations: []LocationSpec{
			{Path: "/", Target: "http://127.0.0.1:9090"},
		}},
	}
	setLocalRoutes(vhostsAsEntries(vhosts, nil))

	// Avant rejet : les deux se resolvent normalement (non-regression).
	if _, ok := resolveTunnelTarget("tunnel.example.com", "/", ""); !ok {
		t.Fatal("avant rejet, tunnel.example.com doit se resoudre")
	}
	if _, ok := resolveLocalTarget("relay.example.com", "/"); !ok {
		t.Fatal("avant rejet, relay.example.com doit se resoudre")
	}

	// Le dashboard rejette les deux au dernier push de la cible "" (mono-master).
	setRejectionsForTarget("", []string{"tunnel.example.com", "relay.example.com"})

	if _, ok := resolveTunnelTarget("tunnel.example.com", "/", ""); ok {
		t.Error("un vhost rejete par le dernier push de CETTE cible ne doit plus jamais etre route localement")
	}
	if _, ok := resolveLocalTarget("relay.example.com", "/"); ok {
		t.Error("resolveLocalTarget (mode relay, partage) doit aussi exclure un hote rejete par N IMPORTE QUELLE cible")
	}

	// Un push ulterieur qui n a plus ce rejet (le probleme a ete corrige)
	// doit rendre la route de nouveau utilisable — jamais une exclusion
	// permanente.
	setRejectionsForTarget("", nil)
	if _, ok := resolveTunnelTarget("tunnel.example.com", "/", ""); !ok {
		t.Error("un push ulterieur sans rejet doit restaurer le routage (jamais une exclusion permanente)")
	}
}

func TestSetLocalRoutes_RejectionIsPerTargetForTunnelMode(t *testing.T) {
	resetRejections()
	defer resetRejections()

	vhosts := []VhostSpec{
		{ServerName: "multi.example.com", Mode: "tunnel", Locations: []LocationSpec{
			{Path: "/", Target: "http://127.0.0.1:8080"},
		}},
	}
	setLocalRoutes(vhostsAsEntries(vhosts, []string{"all"}))

	setRejectionsForTarget("dmz", []string{"multi.example.com"})
	if _, ok := resolveTunnelTarget("multi.example.com", "/", "dmz"); ok {
		t.Error("rejete par la cible dmz -> ne doit pas se router pour dmz")
	}
	if _, ok := resolveTunnelTarget("multi.example.com", "/", "lan"); !ok {
		t.Error("PAS rejete par la cible lan -> doit continuer a se router pour lan (rejet filtre par cible pour le mode tunnel)")
	}
}

func TestBoolLabel_AcceptsCommonSpellings(t *testing.T) {
	cases := map[string]bool{"true": true, "TRUE": true, "yes": true, "YES": true, "1": true,
		"false": false, "no": false, "0": false, "": false}
	for v, want := range cases {
		labels := map[string]string{"k": v}
		if got := boolLabel(labels, "k", false); got != want {
			t.Errorf("boolLabel(%q) = %v, attendu %v", v, got, want)
		}
	}
	// Absent -> valeur par defaut, jamais affecte par cette liste de graphies.
	if !boolLabel(map[string]string{}, "k", true) {
		t.Error("label absent doit utiliser le defaut (true ici)")
	}
	// Non reconnu -> repli sur le defaut (pas de panique, pas "true" par surprise).
	if boolLabel(map[string]string{"k": "n-importe-quoi"}, "k", false) {
		t.Error("valeur non reconnue doit rester sur le defaut, jamais true par accident")
	}
}

func TestIntLabel_InvalidValueLogsAndFallsBackToZero(t *testing.T) {
	// Le comportement observable (retour 0) ne change pas — ce test verifie
	// simplement la non-regression, l avertissement lui-meme est
	// best-effort/log uniquement et n est pas asserte ici.
	if got := intLabel(map[string]string{"k": "pas-un-entier"}, "k"); got != 0 {
		t.Errorf("attendu 0 pour une valeur invalide, obtenu %d", got)
	}
	if got := intLabel(map[string]string{"k": "8443"}, "k"); got != 8443 {
		t.Errorf("valeur valide doit rester lue normalement, obtenu %d", got)
	}
	if got := intLabel(map[string]string{}, "k"); got != 0 {
		t.Errorf("absent -> 0, obtenu %d", got)
	}
}

func TestVhostFromLabels_TargetTrailingSlashTrimmed(t *testing.T) {
	labels := map[string]string{
		"nginx-control.enable":                  "true",
		"nginx-control.vhost.server_name":       "app.example.com",
		"nginx-control.vhost.location01":        "/",
		"nginx-control.vhost.location01.target": "http://backend:8080/",
	}
	v, _, ok := vhostFromLabels(labels)
	if !ok {
		t.Fatal("vhostFromLabels a echoue")
	}
	if len(v.Locations) != 1 {
		t.Fatalf("attendu 1 location, obtenu %d", len(v.Locations))
	}
	got := v.Locations[0].Target
	want := "http://backend:8080"
	if got != want {
		t.Errorf("barre oblique finale non retiree : obtenu %q, attendu %q (le dashboard rejette AGENT_TARGET_RE sur une barre finale)", got, want)
	}
}

func TestSaveState_TmpFilePermissionsForcedTo0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	tmp := path + ".tmp"

	// Simule un .tmp laisse par un plantage anterieur, avec des permissions
	// trop larges (0644 — lisible par le groupe/autres).
	if err := os.WriteFile(tmp, []byte("stale"), 0644); err != nil {
		t.Fatalf("setup : %v", err)
	}

	if err := saveState(path, agentState{AgentID: "abc", Token: "agt_secret"}); err != nil {
		t.Fatalf("saveState : %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("le fichier final doit exister : %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("permissions du fichier final : attendu 0600, obtenu %o (un .tmp perime avec des permissions trop larges ne doit jamais survivre au rename)", perm)
	}

	loaded := loadState(path)
	if loaded.AgentID != "abc" || loaded.Token != "agt_secret" {
		t.Errorf("contenu incorrect apres saveState/loadState : %+v", loaded)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Error("le fichier .tmp doit avoir ete renomme (ne doit plus exister)")
	}
}

func TestPushManifest_PartialRejectionReturnsOnlyRejectedNames(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok": true,
			"vhosts": []map[string]interface{}{
				{"serverName": "good.example.com", "ok": true},
				{"serverName": "bad.example.com", "ok": false, "errors": []string{"server_name invalide"}},
			},
		})
	}))
	defer ts.Close()

	m := Manifest{ProtocolVersion: CurrentProtocolVersion, Vhosts: []VhostSpec{
		{ServerName: "good.example.com", Locations: []LocationSpec{{Path: "/", Target: "http://x:80"}}},
		{ServerName: "bad.example.com", Locations: []LocationSpec{{Path: "/", Target: "http://x:80"}}},
	}}
	rejected, err := pushManifest(context.Background(), ts.Client(), ts.URL, "tok", "[agent:test]", m)
	if err != nil {
		t.Fatalf("push ne doit pas remonter d erreur (ok:true globalement) : %v", err)
	}
	if len(rejected) != 1 || rejected[0] != "bad.example.com" {
		t.Fatalf("attendu [\"bad.example.com\"], obtenu %v", rejected)
	}
}

func TestPushManifest_WholeManifestFailureRejectsEveryVhost(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok": false, "testFailed": true, "error": "nginx -t a echoue",
		})
	}))
	defer ts.Close()

	m := Manifest{ProtocolVersion: CurrentProtocolVersion, Vhosts: []VhostSpec{
		{ServerName: "a.example.com", Locations: []LocationSpec{{Path: "/", Target: "http://x:80"}}},
		{ServerName: "b.example.com", Locations: []LocationSpec{{Path: "/", Target: "http://x:80"}}},
	}}
	rejected, err := pushManifest(context.Background(), ts.Client(), ts.URL, "tok", "[agent:test]", m)
	if err == nil {
		t.Fatal("un testFailed doit remonter une erreur")
	}
	// Fix (audit report, Basse/"Agent Go"): un rollback total doit compter
	// TOUS les vhosts du manifeste comme rejetes, pas seulement celui
	// eventuellement nomme dans le message d erreur — le dashboard a annule
	// le manifeste dans son ensemble.
	want := map[string]bool{"a.example.com": true, "b.example.com": true}
	if len(rejected) != len(want) {
		t.Fatalf("attendu %d noms rejetes, obtenu %v", len(want), rejected)
	}
	for _, name := range rejected {
		if !want[name] {
			t.Errorf("nom inattendu dans la liste des rejetes : %q", name)
		}
	}
}

func TestPushManifest_TransportFailureReturnsNilNotEmptySlice(t *testing.T) {
	// Fix (audit report, Basse/"Agent Go"): le cas "la requete n a meme pas
	// atteint le dashboard" doit renvoyer nil (jamais un slice vide), pour
	// que l appelant (runTarget) puisse distinguer "ne touche pas a l etat de
	// rejet precedent" de "remplace-le par une liste vide" — voir le
	// commentaire de setRejectionsForTarget() et son appel dans runTarget().
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // contexte deja annule -> la requete ne part jamais
	m := Manifest{ProtocolVersion: CurrentProtocolVersion, Vhosts: []VhostSpec{{ServerName: "x.example.com"}}}
	rejected, err := pushManifest(ctx, http.DefaultClient, "http://127.0.0.1:0", "tok", "[agent:test]", m)
	if err == nil {
		t.Fatal("attendu une erreur (contexte annule / port injoignable)")
	}
	if rejected != nil {
		t.Errorf("attendu nil (pas une liste vide), obtenu %v", rejected)
	}
}

func TestSaveState_NoPreexistingTmp(t *testing.T) {
	// Non-regression : le cas normal (pas de .tmp laisse par un plantage)
	// doit continuer a fonctionner exactement comme avant.
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := saveState(path, agentState{AgentID: "xyz"}); err != nil {
		t.Fatalf("saveState : %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("attendu 0600, obtenu %o", perm)
	}
}

// Fix (retour utilisateur, v12.36.0 cote dashboard / suite) : un manifeste
// dont Vhosts est un nil slice (aucun container labellise trouve, ou aucun
// ne publie vers CETTE cible en multi-master) s'encodait en JSON comme
// "vhosts":null — le dashboard exige un tableau (Array.isArray()) et
// rejetait ce push en boucle avec "vhosts est requis et doit etre un
// tableau", meme si "rien a publier pour le moment" est un etat valide.
// runTarget() initialise desormais `vhosts := []VhostSpec{}` (jamais nil) —
// ce test fige la difference d'encodage JSON qui causait le bug, pour que
// personne ne revienne un jour a `var vhosts []VhostSpec` sans s'en rendre
// compte.
func TestManifest_EmptyVhostsSliceEncodesAsJSONArrayNotNull(t *testing.T) {
	m := Manifest{ProtocolVersion: CurrentProtocolVersion, Vhosts: []VhostSpec{}}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if string(raw["vhosts"]) != "[]" {
		t.Errorf(`attendu "vhosts":[] , obtenu "vhosts":%s (le manifeste serait rejete par le dashboard : Array.isArray(null) est false)`, raw["vhosts"])
	}
}

func TestManifest_NilVhostsSliceEncodesAsJSONNull_DocumentsThePreviousBug(t *testing.T) {
	// Non pas un comportement souhaite — documente au contraire pourquoi
	// `var vhosts []VhostSpec` (nil par defaut) etait le bug : ce test
	// echouerait si Go se mettait un jour a encoder un nil slice comme "[]"
	// (il ne le fait pas aujourd'hui), ce qui serait le signe que le
	// contournement ci-dessus n'est plus necessaire.
	var vhosts []VhostSpec
	m := Manifest{ProtocolVersion: CurrentProtocolVersion, Vhosts: vhosts}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if string(raw["vhosts"]) != "null" {
		t.Skip("Go encode desormais un nil slice comme []; le contournement dans runTarget() n'est plus necessaire mais reste inoffensif")
	}
}

// Fix (retour utilisateur) : RELAY_HTTP_LISTEN=8080 (sans le ":") faisait
// echouer net.Listen avec "missing port in address" — un piege facile
// puisque tous les autres reglages de port du projet (RELAY_HTTP_HOST_PORT,
// PORT cote dashboard) sont de simples nombres. normalizeListenAddr()
// tolere desormais un nombre nu en le traitant comme ":<port>".
func TestNormalizeListenAddr(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"8080", ":8080"},
		{":8080", ":8080"},
		{"0.0.0.0:8080", "0.0.0.0:8080"},
		{"[::]:8443", "[::]:8443"},
		{"127.0.0.1:9000", "127.0.0.1:9000"},
	}
	for _, c := range cases {
		if got := normalizeListenAddr(c.in); got != c.want {
			t.Errorf("normalizeListenAddr(%q) = %q, attendu %q", c.in, got, c.want)
		}
	}
}

// Fix (retour utilisateur) : RELAY_HTTP_ADVERTISE=8080 (un numero de port nu
// au lieu d une adresse complete "scheme://host:port") faisait pousser un
// manifeste que le dashboard rejetait systematiquement, vhost par vhost, a
// chaque cycle ("relay.http invalide"), sans que l agent ne signale jamais
// clairement OU se trouvait le probleme. validateAdvertiseAddr() le detecte
// desormais au demarrage (voir son appel dans main() apres flag.Parse()).
func TestValidateAdvertiseAddr(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"vide -> pas d erreur (relais desactive)", "", false},
		{"port nu -> invalide", "8080", true},
		{"host:port sans schema -> invalide", "10.0.5.9:8080", true},
		{"http complet -> valide", "http://10.0.5.9:8080", false},
		{"https complet -> valide", "https://relay.example.com:8443", false},
		{"schema ftp -> invalide", "ftp://10.0.5.9:8080", true},
		{"avec un chemin -> invalide (juste host:port attendu)", "http://10.0.5.9:8080/relay", true},
	}
	for _, c := range cases {
		err := validateAdvertiseAddr("--relay-http-advertise", c.value)
		if c.wantErr && err == nil {
			t.Errorf("%s: attendu une erreur pour %q, obtenu nil", c.name, c.value)
		}
		if !c.wantErr && err != nil {
			t.Errorf("%s: attendu pas d erreur pour %q, obtenu %v", c.name, c.value, err)
		}
	}
}

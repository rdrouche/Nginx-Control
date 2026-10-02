package challenge

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testConfig() Config {
	return Config{
		Bind: ":0", Secret: []byte(strings.Repeat("s", 32)), Bits: 8, CookieName: "nc_chal",
		CookieTTL: time.Hour, TokenTTL: 5 * time.Minute, BindIP: true, Secure: true, RateLimit: 100,
	}
}

func solve(token string, bits int) string {
	for i := 0; ; i++ {
		c := strconv.Itoa(i)
		if SolutionOK(token, c, bits) {
			return c
		}
	}
}

func req(method, path, ip string, body string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.Host = "app.example.com"
	r.Header.Set("X-Real-IP", ip)
	return r
}

func TestLoadConfig(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	c, err := LoadConfig(env(nil))
	if err != nil || !c.SecretGenerated || len(c.Secret) != 32 || c.Bits != 16 || !c.BindIP || !c.Secure {
		t.Fatalf("défauts: %+v %v", c, err)
	}
	if _, err := LoadConfig(env(map[string]string{"NC_SECRET": "court"})); err == nil {
		t.Fatal("secret court accepté")
	}
	if _, err := LoadConfig(env(map[string]string{"NC_DIFFICULTY_BITS": "99"})); err == nil {
		t.Fatal("bits hors bornes acceptés")
	}
	if _, err := LoadConfig(env(map[string]string{"NC_COOKIE_NAME": "a b;"})); err == nil {
		t.Fatal("nom de cookie invalide accepté")
	}
	c, err = LoadConfig(env(map[string]string{"NC_SECRET": strings.Repeat("x", 40), "NC_COOKIE_HOURS": "48", "NC_BIND_IP": "false"}))
	if err != nil || c.SecretGenerated || c.CookieTTL != 48*time.Hour || c.BindIP {
		t.Fatalf("lecture: %+v %v", c, err)
	}
}

func TestClientKey(t *testing.T) {
	if ClientKey("203.0.113.5", true) != "203.0.113.5" {
		t.Fatal("v4")
	}
	a := ClientKey("2001:db8:1:2:aaaa:bbbb:cccc:dddd", true)
	b := ClientKey("2001:db8:1:2:1111:2222:3333:4444", true)
	if a == "" || a != b {
		t.Fatalf("v6 /64: %q %q", a, b)
	}
	if ClientKey("pas une ip", true) != "" || ClientKey("", true) != "" {
		t.Fatal("invalide")
	}
	if ClientKey("1.2.3.4", false) != "*" {
		t.Fatal("sans liaison")
	}
}

func TestSafeTarget(t *testing.T) {
	ok := []string{"/", "/a/b?x=1&y=2", "/commit/abc#x", "/a%20b"}
	for _, s := range ok {
		if SafeTarget(s) != s {
			t.Errorf("%q devrait passer", s)
		}
	}
	bad := []string{"", "http://evil.com", "//evil.com", "/\\evil.com", "evil", "/a\r\nb", "/.nc-challenge/go/x", "/.NC-CHALLENGE/x", "javascript:alert(1)", "/" + strings.Repeat("a", 3000)}
	for _, s := range bad {
		if SafeTarget(s) != "/" {
			t.Errorf("%q devrait être ramené à /", s)
		}
	}
}

func TestJetonEtCookie(t *testing.T) {
	cfg := testConfig()
	s := NewSigner(cfg)
	now := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return now }
	tok, _ := s.NewChallenge("1.2.3.4", "h")
	if bits, ok := s.CheckChallenge(tok, "1.2.3.4", "h"); !ok || bits != 8 {
		t.Fatal("jeton valide refusé")
	}
	if _, ok := s.CheckChallenge(tok, "1.2.3.5", "h"); ok {
		t.Fatal("jeton accepté pour une autre IP")
	}
	if _, ok := s.CheckChallenge(tok, "1.2.3.4", "autre"); ok {
		t.Fatal("jeton accepté pour un autre hôte")
	}
	if _, ok := s.CheckChallenge(tok+"x", "1.2.3.4", "h"); ok {
		t.Fatal("signature altérée acceptée")
	}
	s.now = func() time.Time { return now.Add(10 * time.Minute) }
	if _, ok := s.CheckChallenge(tok, "1.2.3.4", "h"); ok {
		t.Fatal("jeton expiré accepté")
	}
	s.now = func() time.Time { return now }
	v, _ := s.NewCookie("1.2.3.4", "h")
	if !s.CheckCookie(v, "1.2.3.4", "h") || s.CheckCookie(v, "9.9.9.9", "h") || s.CheckCookie(v, "1.2.3.4", "x") {
		t.Fatal("liaison du cookie")
	}
	s.now = func() time.Time { return now.Add(2 * time.Hour) }
	if s.CheckCookie(v, "1.2.3.4", "h") {
		t.Fatal("cookie expiré accepté")
	}
	if s.CheckCookie("v1.9999999999.AAAA", "1.2.3.4", "h") || s.CheckCookie("n'importe quoi", "1.2.3.4", "h") {
		t.Fatal("cookie forgé accepté")
	}
}

func TestPreuveDeTravail(t *testing.T) {
	if LeadingZeroBits([]byte{0, 0x0f}) != 12 || LeadingZeroBits([]byte{0x80}) != 0 || LeadingZeroBits([]byte{0, 0}) != 16 {
		t.Fatal("LeadingZeroBits")
	}
	if SolutionOK("t", "", 8) || SolutionOK("t", "12a", 8) || SolutionOK("t", strings.Repeat("1", 13), 8) {
		t.Fatal("compteur invalide accepté")
	}
}

func flow(t *testing.T, h http.Handler, ip string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req("GET", Prefix+"api/start", ip, ""))
	if w.Code != 200 {
		t.Fatalf("start: %d %s", w.Code, w.Body)
	}
	var st struct {
		Token string `json:"token"`
		Bits  int    `json:"bits"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &st)
	body, _ := json.Marshal(map[string]string{"token": st.Token, "counter": solve(st.Token, st.Bits), "target": "/commit/abc?x=1"})
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req("POST", Prefix+"api/verify", ip, string(body)))
	return w2
}

func TestFluxComplet(t *testing.T) {
	srv, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	// Sans cookie : 401.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req("GET", "/check", "203.0.113.5", ""))
	if w.Code != 401 {
		t.Fatalf("check sans cookie: %d", w.Code)
	}

	v := flow(t, h, "203.0.113.5")
	if v.Code != 200 {
		t.Fatalf("verify: %d %s", v.Code, v.Body)
	}
	var out struct {
		OK     bool   `json:"ok"`
		Target string `json:"target"`
	}
	_ = json.Unmarshal(v.Body.Bytes(), &out)
	if !out.OK || out.Target != "/commit/abc?x=1" {
		t.Fatalf("réponse: %s", v.Body)
	}
	ck := v.Result().Cookies()
	if len(ck) != 1 || !ck[0].HttpOnly || !ck[0].Secure || ck[0].SameSite != http.SameSiteLaxMode || ck[0].Path != "/" {
		t.Fatalf("attributs du cookie: %+v", ck)
	}

	// Avec cookie : 204 ; depuis une autre IP : 401.
	c := req("GET", "/check", "203.0.113.5", "")
	c.AddCookie(ck[0])
	w = httptest.NewRecorder()
	h.ServeHTTP(w, c)
	if w.Code != 204 {
		t.Fatalf("check avec cookie: %d", w.Code)
	}
	c = req("GET", "/check", "203.0.113.99", "")
	c.AddCookie(ck[0])
	w = httptest.NewRecorder()
	h.ServeHTTP(w, c)
	if w.Code != 401 {
		t.Fatalf("cookie volé accepté: %d", w.Code)
	}

	// Page de défi pour un client déjà vérifié : redirection directe vers la cible.
	g := req("GET", Prefix+"go/commit/abc?x=1", "203.0.113.5", "")
	g.AddCookie(ck[0])
	w = httptest.NewRecorder()
	h.ServeHTTP(w, g)
	if w.Code != 302 || w.Header().Get("Location") != "/commit/abc?x=1" {
		t.Fatalf("redirection: %d %s", w.Code, w.Header().Get("Location"))
	}
}

func TestRejeuEtMauvaiseSolution(t *testing.T) {
	srv, _ := New(testConfig())
	h := srv.Handler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req("GET", Prefix+"api/start", "203.0.113.7", ""))
	var st struct {
		Token string `json:"token"`
		Bits  int    `json:"bits"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &st)
	good := solve(st.Token, st.Bits)

	// Mauvais compteur.
	bad := "0"
	for SolutionOK(st.Token, bad, st.Bits) {
		bad += "0"
	}
	b, _ := json.Marshal(map[string]string{"token": st.Token, "counter": bad, "target": "/"})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req("POST", Prefix+"api/verify", "203.0.113.7", string(b)))
	if w.Code != 400 {
		t.Fatalf("mauvaise solution: %d", w.Code)
	}
	// Bonne solution, puis rejeu.
	b, _ = json.Marshal(map[string]string{"token": st.Token, "counter": good, "target": "https://evil.com"})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req("POST", Prefix+"api/verify", "203.0.113.7", string(b)))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"target":"/"`) {
		t.Fatalf("bonne solution: %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req("POST", Prefix+"api/verify", "203.0.113.7", string(b)))
	if w.Code != 400 {
		t.Fatalf("rejeu accepté: %d", w.Code)
	}
	// Jeton émis pour une autre IP.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req("POST", Prefix+"api/verify", "203.0.113.8", string(b)))
	if w.Code != 400 {
		t.Fatalf("jeton d'une autre IP accepté: %d", w.Code)
	}
	// Requête inter-sites refusée.
	r := req("POST", Prefix+"api/verify", "203.0.113.7", string(b))
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("cross-site accepté: %d", w.Code)
	}
}

func TestCheminsEtEntetes(t *testing.T) {
	srv, _ := New(testConfig())
	h := srv.Handler()

	// X-Real-IP absent ou invalide : jamais de cookie, jamais d'accès.
	for _, ip := range []string{"", "n'importe quoi"} {
		w := httptest.NewRecorder()
		r := req("GET", "/check", ip, "")
		r.Header.Del("X-Real-IP")
		if ip != "" {
			r.Header.Set("X-Real-IP", ip)
		}
		h.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatalf("ip %q: %d", ip, w.Code)
		}
	}
	// La page n'altère pas les « // » de l'URL d'origine (pas de nettoyage de chemin).
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req("GET", Prefix+"go/a//b?q=1", "203.0.113.5", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `data-target="/a//b?q=1"`) {
		t.Fatalf("page: %d %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'self'") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("en-têtes: %v", w.Header())
	}
	// Redirection ouverte : //evil.com -> /
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req("GET", Prefix+"go//evil.com", "203.0.113.5", ""))
	if !strings.Contains(w.Body.String(), `data-target="/"`) {
		t.Fatalf("redirection ouverte: %s", w.Body)
	}
	// Assets statiques et inconnus.
	for _, p := range []string{"challenge.js", "worker.js", "style.css"} {
		w = httptest.NewRecorder()
		h.ServeHTTP(w, req("GET", Prefix+"assets/"+p, "203.0.113.5", ""))
		if w.Code != 200 || w.Body.Len() == 0 {
			t.Fatalf("asset %s: %d", p, w.Code)
		}
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req("GET", "/autre", "203.0.113.5", ""))
	if w.Code != 404 {
		t.Fatalf("route inconnue: %d", w.Code)
	}
}

func TestLimiteDeDebit(t *testing.T) {
	cfg := testConfig()
	cfg.RateLimit = 3
	srv, _ := New(cfg)
	h := srv.Handler()
	codes := []int{}
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req("GET", Prefix+"api/start", "203.0.113.50", ""))
		codes = append(codes, w.Code)
	}
	if codes[2] != 200 || codes[3] != 429 || codes[4] != 429 {
		t.Fatalf("limite: %v", codes)
	}
	// Une autre IP n'est pas affectée.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req("GET", Prefix+"api/start", "203.0.113.51", ""))
	if w.Code != 200 {
		t.Fatal("limite partagée entre IP")
	}
}

func TestUsedSetBorne(t *testing.T) {
	u := newUsedSet()
	u.cap = 2
	exp := time.Now().Add(time.Hour)
	if !u.add("a", exp) || !u.add("b", exp) || u.add("c", exp) || u.add("a", exp) {
		t.Fatal("table de rejeu")
	}
}

func fakeBots(addr map[string][]string, host map[string][]string) *BotVerifier {
	v := NewBotVerifier(DefaultBotRules())
	v.lookupAddr = func(_ context.Context, ip string) ([]string, error) {
		if n, ok := addr[ip]; ok {
			return n, nil
		}
		return nil, &net.DNSError{IsNotFound: true}
	}
	v.lookupHost = func(_ context.Context, name string) ([]string, error) {
		if a, ok := host[name]; ok {
			return a, nil
		}
		return nil, &net.DNSError{IsNotFound: true}
	}
	return v
}

func TestBotsFCrDNS(t *testing.T) {
	gua := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	v := fakeBots(
		map[string][]string{
			"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."},
			"203.0.113.9": {"evil.example.com."},
			"203.0.113.8": {"crawl.googlebot.com.evil.net."},
			"203.0.113.7": {"fake.googlebot.com."},
		},
		map[string][]string{
			"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"},
			"evil.example.com":                {"203.0.113.9"},
			"fake.googlebot.com":              {"198.51.100.1"}, // le nom ne pointe pas vers l'IP
		},
	)
	if ok, name := v.Verify(gua, "66.249.66.1"); !ok || name != "googlebot" {
		t.Fatal("vrai Googlebot refusé")
	}
	for _, ip := range []string{"203.0.113.9", "203.0.113.8", "203.0.113.7", "203.0.113.50"} {
		if ok, _ := v.Verify(gua, ip); ok {
			t.Fatalf("faux Googlebot %s accepté", ip)
		}
	}
	if ok, _ := v.Verify("curl/8", "66.249.66.1"); ok {
		t.Fatal("UA inconnu accepté")
	}
	if ok, _ := v.Verify(gua, "pas-une-ip"); ok {
		t.Fatal("IP invalide acceptée")
	}
	// Cache : le second appel ne refait pas de recherche DNS.
	calls := 0
	v.lookupAddr = func(context.Context, string) ([]string, error) { calls++; return nil, nil }
	v.Verify(gua, "66.249.66.1")
	if calls != 0 {
		t.Fatal("résultat non mis en cache")
	}
}

func TestBotsErreurDNSNonMiseEnCache(t *testing.T) {
	v := NewBotVerifier(DefaultBotRules())
	n := 0
	v.lookupAddr = func(context.Context, string) ([]string, error) { n++; return nil, errors.New("timeout") }
	v.Verify("Googlebot", "203.0.113.1")
	v.Verify("Googlebot", "203.0.113.1")
	if n != 2 {
		t.Fatalf("erreur DNS mise en cache (%d appels)", n)
	}
}

func TestBotsExtra(t *testing.T) {
	r, err := ParseExtraBotRules("monbot|(?i)monbot|.monbot.example.com, .monbot.example.net")
	if err != nil || len(r) != 1 || len(r[0].Suffixes) != 2 {
		t.Fatalf("%v %v", r, err)
	}
	for _, bad := range []string{"x", "a b|x|.ex.com", "n|(|.ex.com", "n|x|ex.com", "n|x|", "n||.ex.com"} {
		if _, err := ParseExtraBotRules(bad); err == nil {
			t.Errorf("%q accepté", bad)
		}
	}
}

func TestCheckAutoriseLesBonsRobotsSeulementSiDemande(t *testing.T) {
	srv, _ := New(testConfig())
	srv.bots = fakeBots(
		map[string][]string{"66.249.66.1": {"c.googlebot.com."}},
		map[string][]string{"c.googlebot.com": {"66.249.66.1"}},
	)
	h := srv.Handler()
	do := func(allow, ua, ip string) int {
		r := req("GET", "/check", ip, "")
		r.Header.Set("User-Agent", ua)
		if allow != "" {
			r.Header.Set("X-NC-Allow-Bots", allow)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	gua := "Googlebot/2.1"
	if do("1", gua, "66.249.66.1") != 204 {
		t.Fatal("vrai robot refusé alors que le vhost l'autorise")
	}
	if do("", gua, "66.249.66.1") != 401 {
		t.Fatal("robot accepté sans X-NC-Allow-Bots")
	}
	if do("1", gua, "203.0.113.77") != 401 {
		t.Fatal("faux robot accepté")
	}
}

func TestSecretFileGeneratedAndPersisted(t *testing.T) {
	f := t.TempDir() + "/secret"
	env := func(k string) string {
		if k == "NC_SECRET_FILE" {
			return f
		}
		return ""
	}
	c1, err := LoadConfig(env)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := LoadConfig(env)
	if err != nil {
		t.Fatal(err)
	}
	if len(c1.Secret) < 32 || string(c1.Secret) != string(c2.Secret) {
		t.Fatal("le secret genere doit etre conserve entre deux demarrages")
	}
}

func TestDifficultyBitsUpTo64(t *testing.T) {
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == "NC_DIFFICULTY_BITS" {
				return v
			}
			return ""
		}
	}
	if c, err := LoadConfig(env("64")); err != nil || c.Bits != 64 {
		t.Fatalf("64 bits doit etre accepte : %v", err)
	}
	if _, err := LoadConfig(env("65")); err == nil {
		t.Fatal("65 bits doit etre refuse")
	}
	if _, err := LoadConfig(env("7")); err == nil {
		t.Fatal("7 bits doit etre refuse")
	}
}

func TestPageLang(t *testing.T) {
	cases := []struct{ cfg, accept, want string }{
		{"auto", "fr-FR,fr;q=0.9,en;q=0.8", "fr"},
		{"auto", "en-US,en;q=0.9", "en"},
		{"auto", "de-DE,de;q=0.9", "en"},
		{"auto", "", "en"},
		{"fr", "en-US", "fr"},
		{"en", "fr-FR", "en"},
	}
	for _, c := range cases {
		if got := pageLang(c.cfg, c.accept); got != c.want {
			t.Fatalf("pageLang(%q,%q)=%q, attendu %q", c.cfg, c.accept, got, c.want)
		}
	}
}

func TestLangConfig(t *testing.T) {
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == "NC_LANG" {
				return v
			}
			return ""
		}
	}
	if c, err := LoadConfig(env("EN")); err != nil || c.Lang != "en" {
		t.Fatalf("EN : %v %q", err, c.Lang)
	}
	if _, err := LoadConfig(env("de")); err == nil {
		t.Fatal("de doit etre refuse")
	}
}

func TestStatsEfficacite(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig()
	cfg.StatsFile = dir + "/stats.json"
	srv, _ := New(cfg)
	h := srv.Handler()
	// Visiteur renvoyé vers le défi (pas de cookie), page servie, défi résolu.
	w := httptest.NewRecorder()
	r := req("GET", "/check", "203.0.113.9", "")
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("check: %d", w.Code)
	}
	h.ServeHTTP(httptest.NewRecorder(), req("GET", Prefix+"go/", "203.0.113.9", ""))
	ok := flow(t, h, "203.0.113.9")
	if ok.Code != 200 {
		t.Fatalf("flow: %d", ok.Code)
	}
	// Mauvaise solution.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req("GET", Prefix+"api/start", "203.0.113.10", ""))
	var st struct {
		Token string `json:"token"`
		Bits  int    `json:"bits"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &st)
	bad := "0"
	for SolutionOK(st.Token, bad, st.Bits) {
		bad += "0"
	}
	b, _ := json.Marshal(map[string]string{"token": st.Token, "counter": bad, "target": "/"})
	h.ServeHTTP(httptest.NewRecorder(), req("POST", Prefix+"api/verify", "203.0.113.10", string(b)))
	// Cookie valide -> laissé passer.
	var cookie *http.Cookie
	for _, c := range ok.Result().Cookies() {
		cookie = c
	}
	rc := req("GET", "/check", "203.0.113.9", "")
	rc.AddCookie(cookie)
	h.ServeHTTP(httptest.NewRecorder(), rc)

	w = httptest.NewRecorder()
	h.ServeHTTP(w, req("GET", "/stats", "", ""))
	var snap Snapshot
	if err := json.Unmarshal(w.Body.Bytes(), &snap); err != nil || w.Code != 200 {
		t.Fatalf("stats: %d %v", w.Code, err)
	}
	c := snap.Total
	if c.Redirected != 1 || c.Pages != 1 || c.Started != 2 || c.Solved != 1 || c.Failed != 1 || c.PassCookie != 1 {
		t.Fatalf("compteurs: %+v", c)
	}
	// Persistance : un nouveau serveur relit le fichier.
	if err := srv.Stats().Flush(); err != nil {
		t.Fatal(err)
	}
	srv2, _ := New(cfg)
	if got := srv2.Stats().Snapshot(24).Total; got != c {
		t.Fatalf("persistance: %+v != %+v", got, c)
	}
}

func TestStatsRefuseesViaNginx(t *testing.T) {
	srv, _ := New(testConfig())
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req("GET", "/stats", "198.51.100.1", ""))
	if w.Code != 404 {
		t.Fatalf("un visiteur (X-Real-IP posé) ne doit pas lire /stats : %d", w.Code)
	}
}

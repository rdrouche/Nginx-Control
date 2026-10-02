package detect

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"nginx-analyzer-go/internal/parse"
)

var T0 = mustParseRFC3339("2026-09-09T10:00:00Z")

func mustParseRFC3339(s string) int64 {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t.UnixMilli()
}

type reqOpts struct {
	ip     string
	vhost  string
	ts     int64
	method string
	path   *string
	status int
	ua     string
}

func defaultReq() reqOpts {
	p := "/"
	return reqOpts{ip: "203.0.113.5", vhost: "site.fr", ts: T0, method: "GET", path: &p, status: 200, ua: "Mozilla/5.0"}
}

func entryFromOpts(o reqOpts) parse.AccessEntry {
	e := parse.AccessEntry{
		IP: o.ip, Vhost: o.vhost, TS: o.ts, TSValid: true,
		Status: o.status,
	}
	if o.method != "" {
		m := o.method
		e.Method = &m
	}
	e.Path = o.path
	if o.ua != "" {
		u := o.ua
		e.UA = &u
	}
	return e
}

func req(mut func(*reqOpts)) parse.AccessEntry {
	o := defaultReq()
	if mut != nil {
		mut(&o)
	}
	return entryFromOpts(o)
}

func strp(s string) *string { return &s }

// feed reproduit le helper feed(d,n,o,step) du test Node : ajoute n requetes,
// avec un mutateur optionnel appelable par index (equivalent de la forme
// fonction de `o` en JS).
func feed(d *Detector, n int, step int64, mut func(i int, o *reqOpts)) {
	for i := 0; i < n; i++ {
		o := defaultReq()
		o.ts = T0 + int64(i)*step
		if mut != nil {
			mut(i, &o)
		}
		d.Add(entryFromOpts(o))
	}
}

func countType(alerts []Alert, typ string) int {
	n := 0
	for _, a := range alerts {
		if a.Type == typ {
			n++
		}
	}
	return n
}

func filterType(alerts []Alert, typ string) []Alert {
	var out []Alert
	for _, a := range alerts {
		if a.Type == typ {
			out = append(out, a)
		}
	}
	return out
}

// ── brute force ──────────────────────────────────────────────────────────

func TestBruteforceDetectsRepeatedFailures(t *testing.T) {
	d := NewDefault()
	feed(d, 20, 100, func(i int, o *reqOpts) { o.path = strp("/login"); o.status = 401 })
	a := d.Evaluate(T0 + 20*100)
	if len(a) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(a))
	}
	if a[0].Type != "bruteforce" {
		t.Errorf("type = %q", a[0].Type)
	}
	if a[0].Evidence.AuthFailures != 20 {
		t.Errorf("authFailures = %d", a[0].Evidence.AuthFailures)
	}
	if a[0].Explanation.Why == "" {
		t.Error("explanation.why must be present")
	}
}

func TestBruteforceIgnoresNonAuthPaths(t *testing.T) {
	d := NewDefault()
	feed(d, 30, 100, func(i int, o *reqOpts) { o.path = strp("/api/data"); o.status = 401 })
	if got := filterType(d.Evaluate(T0+3000), "bruteforce"); len(got) != 0 {
		t.Errorf("expected none, got %d", len(got))
	}
}

func TestBruteforceBelowThreshold(t *testing.T) {
	d := NewDefault()
	feed(d, 5, 100, func(i int, o *reqOpts) { o.path = strp("/login"); o.status = 401 })
	if got := d.Evaluate(T0 + 500); len(got) != 0 {
		t.Errorf("expected none, got %d", len(got))
	}
}

func TestBruteforceSuccessfulLoginsDontAlert(t *testing.T) {
	d := NewDefault()
	feed(d, 50, 100, func(i int, o *reqOpts) { o.path = strp("/login"); o.status = 200 })
	if got := d.Evaluate(T0 + 5000); len(got) != 0 {
		t.Errorf("expected none, got %d", len(got))
	}
}

// ── scan ─────────────────────────────────────────────────────────────────

func TestScanDetectsManyPaths404(t *testing.T) {
	d := NewDefault()
	feed(d, 50, 100, func(i int, o *reqOpts) {
		o.path = strp(sprintfPath(i))
		o.status = 404
	})
	a := filterType(d.Evaluate(T0+5000), "scan")
	if len(a) != 1 {
		t.Fatalf("expected 1, got %d", len(a))
	}
	if a[0].Evidence.DistinctPaths < 25 {
		t.Errorf("distinctPaths = %d", a[0].Evidence.DistinctPaths)
	}
}

func sprintfPath(i int) string { return "/probe-" + itoa(i) }
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	s := string(buf[pos:])
	if neg {
		return "-" + s
	}
	return s
}

func TestScanLegitSiteManyPagesNoAlert(t *testing.T) {
	d := NewDefault()
	feed(d, 50, 100, func(i int, o *reqOpts) { o.path = strp("/article-" + itoa(i)); o.status = 200 })
	if got := filterType(d.Evaluate(T0+5000), "scan"); len(got) != 0 {
		t.Errorf("expected none, got %d", len(got))
	}
}

func TestScanFewScattered404sNoAlert(t *testing.T) {
	d := NewDefault()
	feed(d, 50, 100, func(i int, o *reqOpts) {
		o.path = strp("/p-" + itoa(i))
		if i < 5 {
			o.status = 404
		} else {
			o.status = 200
		}
	})
	if got := filterType(d.Evaluate(T0+5000), "scan"); len(got) != 0 {
		t.Errorf("expected none, got %d", len(got))
	}
}

// ── flood ────────────────────────────────────────────────────────────────

func TestFloodDetectsSustainedRate(t *testing.T) {
	d := NewDefault()
	feed(d, 700, 10, nil)
	a := filterType(d.Evaluate(T0+7000), "flood")
	if len(a) != 1 {
		t.Fatalf("expected 1, got %d", len(a))
	}
	if a[0].Evidence.RequestsPerSecond <= 0 {
		t.Errorf("requestsPerSecond = %v", a[0].Evidence.RequestsPerSecond)
	}
}

func TestFloodNormalTrafficNoAlert(t *testing.T) {
	d := NewDefault()
	feed(d, 100, 1000, nil)
	if got := filterType(d.Evaluate(T0+100000), "flood"); len(got) != 0 {
		t.Errorf("expected none, got %d", len(got))
	}
}

func TestFloodLowRateProbeNeverAlerts(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WindowMs = 60_000
	cfg.Flood.MinRequests = 5
	d := New(cfg)
	alerts := 0
	for i := 0; i < 40; i++ {
		d.Add(req(func(o *reqOpts) { o.ts = T0 + int64(i)*70_000 }))
		alerts += len(d.Evaluate(T0 + int64(i)*70_000 + 1000))
	}
	if alerts != 0 {
		t.Errorf("40 passages espaces ne doivent jamais declencher un flood, got %d", alerts)
	}
}

func TestFloodFasterButStillBelowThresholdContinuous(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WindowMs = 60_000
	cfg.Flood.MinRequests = 10
	d := New(cfg)
	alerts := 0
	for i := 0; i < 60; i++ {
		d.Add(req(func(o *reqOpts) { o.ts = T0 + int64(i)*5000 }))
		alerts += len(d.Evaluate(T0 + int64(i)*5000 + 1))
	}
	if alerts != 1 {
		t.Errorf("attendu 1 alerte pour un seul episode continu, obtenu %d", alerts)
	}
}

// ── scraping ─────────────────────────────────────────────────────────────

func TestScrapingDetectsAutomatedAgent(t *testing.T) {
	d := NewDefault()
	feed(d, 350, 100, func(i int, o *reqOpts) { o.path = strp("/api/list"); o.ua = "python-requests/2.31" })
	a := filterType(d.Evaluate(T0+35000), "scraping")
	if len(a) != 1 {
		t.Fatalf("expected 1, got %d", len(a))
	}
}

func TestScrapingBrowserSinglePageNoAlert(t *testing.T) {
	d := NewDefault()
	feed(d, 350, 100, func(i int, o *reqOpts) { o.path = strp("/api/list"); o.ua = "Mozilla/5.0 (X11; Linux)" })
	if got := filterType(d.Evaluate(T0+35000), "scraping"); len(got) != 0 {
		t.Errorf("expected none, got %d", len(got))
	}
}

// ── edge-triggered ───────────────────────────────────────────────────────

func TestEdgeTriggeredSingleAlertForContinuousAttack(t *testing.T) {
	d := NewDefault()
	feed(d, 20, 100, func(i int, o *reqOpts) { o.path = strp("/login"); o.status = 401 })
	if got := len(d.Evaluate(T0 + 2000)); got != 1 {
		t.Fatalf("expected 1, got %d", got)
	}
	feed(d, 20, 100, func(i int, o *reqOpts) { o.path = strp("/login"); o.status = 401 })
	if got := len(d.Evaluate(T0 + 4000)); got != 0 {
		t.Errorf("la seconde passe ne doit rien reemettre, got %d", got)
	}
}

func TestFloodPersistsNoReAlert(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WindowMs = 60_000
	cfg.Flood.MinRequests = 5
	d := New(cfg)
	feed(d, 10, 1000, nil)
	if got := len(d.Evaluate(T0 + 10000)); got != 1 {
		t.Fatalf("expected 1, got %d", got)
	}
	feed(d, 10, 1000, nil)
	if got := len(d.Evaluate(T0 + 20000)); got != 0 {
		t.Errorf("expected 0, got %d", got)
	}
}

func TestFloodReAlertsAfterRealLull(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WindowMs = 60_000
	cfg.Flood.MinRequests = 5
	d := New(cfg)
	feed(d, 10, 1000, nil)
	if got := len(d.Evaluate(T0 + 10000)); got != 1 {
		t.Fatalf("premier episode: got %d", got)
	}
	if got := len(d.Evaluate(T0 + 130000)); got != 0 {
		t.Errorf("aucune activite recente: got %d", got)
	}
	for i := 0; i < 10; i++ {
		d.Add(req(func(o *reqOpts) { o.ts = T0 + 130000 + int64(i)*1000 }))
	}
	if got := len(d.Evaluate(T0 + 140000)); got != 1 {
		t.Errorf("deuxieme episode, doit re-alerter: got %d", got)
	}
}

func TestDistinctIpsAlertSeparately(t *testing.T) {
	d := NewDefault()
	for _, ip := range []string{"1.1.1.1", "2.2.2.2"} {
		ip := ip
		feed(d, 20, 100, func(i int, o *reqOpts) { o.ip = ip; o.path = strp("/login"); o.status = 401 })
	}
	if got := len(d.Evaluate(T0 + 4000)); got != 2 {
		t.Errorf("expected 2, got %d", got)
	}
}

// ── exceptions par vhost ─────────────────────────────────────────────────

func TestExceptionExcludedIpNoAlert(t *testing.T) {
	d := NewDefault()
	d.SetExceptions([]Exception{{Vhost: "site.fr", IP: "203.0.113.5"}})
	feed(d, 20, 100, func(i int, o *reqOpts) { o.path = strp("/login"); o.status = 401 })
	if got := d.Evaluate(T0 + 2000); len(got) != 0 {
		t.Errorf("expected none, got %d", len(got))
	}
}

func TestExceptionSameIpOtherVhostStillWatched(t *testing.T) {
	d := NewDefault()
	d.SetExceptions([]Exception{{Vhost: "autre.fr", IP: "203.0.113.5"}})
	feed(d, 20, 100, func(i int, o *reqOpts) { o.path = strp("/login"); o.status = 401 })
	if got := len(d.Evaluate(T0 + 2000)); got != 1 {
		t.Errorf("expected 1, got %d", got)
	}
}

func TestExceptionCidrBlockExcludesRange(t *testing.T) {
	d := NewDefault()
	d.SetExceptions([]Exception{{Vhost: "site.fr", IP: "203.0.113.0/24"}})
	feed(d, 20, 100, func(i int, o *reqOpts) { o.ip = "203.0.113.200"; o.path = strp("/login"); o.status = 401 })
	if got := d.Evaluate(T0 + 2000); len(got) != 0 {
		t.Errorf("expected none, got %d", len(got))
	}
}

func TestExceptionOutsideCidrStillWatched(t *testing.T) {
	d := NewDefault()
	d.SetExceptions([]Exception{{Vhost: "site.fr", IP: "203.0.113.0/24"}})
	feed(d, 20, 100, func(i int, o *reqOpts) { o.ip = "203.0.114.200"; o.path = strp("/login"); o.status = 401 })
	if got := len(d.Evaluate(T0 + 2000)); got != 1 {
		t.Errorf("expected 1, got %d", got)
	}
}

func TestMultipleIndependentExceptionsCoexist(t *testing.T) {
	d := NewDefault()
	d.SetExceptions([]Exception{
		{Vhost: "site.fr", IP: "198.51.100.0/24"},
		{Vhost: "site.fr", IP: "203.0.113.77"},
	})
	feed(d, 20, 100, func(i int, o *reqOpts) { o.ip = "198.51.100.5"; o.path = strp("/login"); o.status = 401 })
	if got := d.Evaluate(T0 + 2000); len(got) != 0 {
		t.Errorf("couverte par le bloc: got %d", len(got))
	}
	feed(d, 20, 100, func(i int, o *reqOpts) { o.ip = "203.0.113.77"; o.path = strp("/login"); o.status = 401 })
	if got := d.Evaluate(T0 + 4000); len(got) != 0 {
		t.Errorf("couverte par l adresse exacte: got %d", len(got))
	}
}

func TestEmptyOrAbsentExceptionsExcludeNothing(t *testing.T) {
	d := NewDefault()
	d.SetExceptions([]Exception{})
	feed(d, 20, 100, func(i int, o *reqOpts) { o.path = strp("/login"); o.status = 401 })
	if got := len(d.Evaluate(T0 + 2000)); got != 1 {
		t.Errorf("expected 1, got %d", got)
	}
	d2 := NewDefault()
	feed(d2, 20, 100, func(i int, o *reqOpts) { o.path = strp("/login"); o.status = 401 })
	if got := len(d2.Evaluate(T0 + 2000)); got != 1 {
		t.Errorf("expected 1, got %d", got)
	}
}

func TestExceptionOnBothTouchedVhostsExcludes(t *testing.T) {
	d := NewDefault()
	d.SetExceptions([]Exception{
		{Vhost: "site.fr", IP: "203.0.113.5"},
		{Vhost: "autre.fr", IP: "203.0.113.5"},
	})
	feed(d, 10, 100, func(i int, o *reqOpts) { o.path = strp("/login"); o.status = 401; o.vhost = "site.fr" })
	feed(d, 10, 100, func(i int, o *reqOpts) { o.path = strp("/login"); o.status = 401; o.vhost = "autre.fr" })
	if got := d.Evaluate(T0 + 2000); len(got) != 0 {
		t.Errorf("exceptee sur les deux vhosts touches: got %d", len(got))
	}
}

func TestExceptionOnOnlyOneOfTwoVhostsStillWatched(t *testing.T) {
	d := NewDefault()
	d.SetExceptions([]Exception{{Vhost: "site.fr", IP: "203.0.113.5"}})
	feed(d, 10, 100, func(i int, o *reqOpts) { o.path = strp("/login"); o.status = 401; o.vhost = "site.fr" })
	feed(d, 10, 100, func(i int, o *reqOpts) { o.path = strp("/login"); o.status = 401; o.vhost = "autre.fr" })
	if got := len(d.Evaluate(T0 + 2000)); got != 1 {
		t.Errorf("un vhost non excepte ne doit jamais laisser silencer la regle: got %d", got)
	}
}

// ── memoire ──────────────────────────────────────────────────────────────

func TestTrackedIpsCapped(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxTrackedIps = 100
	d := New(cfg)
	for i := 0; i < 500; i++ {
		ip := "10.0." + itoa(i/256) + "." + itoa(i%256)
		d.Add(req(func(o *reqOpts) { o.ip = ip }))
	}
	if got := d.Stats().TrackedIps; got > 100 {
		t.Errorf("%d > 100", got)
	}
}

func TestFullyExpiredStatePruned(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WindowMs = 1000
	d := New(cfg)
	d.Add(req(nil))
	d.Prune(T0 + 5000)
	if got := d.Stats().TrackedIps; got != 0 {
		t.Errorf("expected 0, got %d", got)
	}
}

func TestAlertLockDisappearsWithPrunedIp(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WindowMs = 1000
	cfg.Flood.MinRequests = 3
	d := New(cfg)
	feed(d, 5, 100, nil)
	if got := len(d.Evaluate(T0 + 500)); got != 1 {
		t.Fatalf("expected 1, got %d", got)
	}
	d.Prune(T0 + 10000)
	if got := d.Stats().TrackedIps; got != 0 {
		t.Fatalf("expected 0, got %d", got)
	}
	for i := 0; i < 5; i++ {
		d.Add(req(func(o *reqOpts) { o.ts = T0 + 10000 + int64(i)*100 }))
	}
	if got := len(d.Evaluate(T0 + 10500)); got != 1 {
		t.Errorf("doit pouvoir re-alerter apres une purge complete: got %d", got)
	}
}

// ── preuves jointes ──────────────────────────────────────────────────────

func TestAlertCarriesEvidence(t *testing.T) {
	d := NewDefault()
	feed(d, 20, 100, func(i int, o *reqOpts) { o.path = strp("/login"); o.status = 401; o.ua = "curl/8" })
	a := d.Evaluate(T0 + 2000)[0]
	if len(a.Evidence.Samples) == 0 {
		t.Error("exemples de requetes")
	}
	found := false
	for _, ua := range a.Evidence.UserAgents {
		if ua == "curl/8" {
			found = true
		}
	}
	if !found {
		t.Error("userAgents doit inclure curl/8")
	}
	if a.Evidence.Statuses[401] <= 0 {
		t.Error("statuses[401] doit etre > 0")
	}
	if a.Evidence.Vhost != "site.fr" {
		t.Errorf("vhost = %q", a.Evidence.Vhost)
	}
	if !contains(a.Summary, "203.0.113.5") {
		t.Errorf("summary doit contenir l ip: %q", a.Summary)
	}
}

func contains(s, sub string) bool {
	return regexp.MustCompile(regexp.QuoteMeta(sub)).MatchString(s)
}

// ── opt-out par vhost ────────────────────────────────────────────────────

func TestVhostDisabledNoAlertsAtAll(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WindowMs = 1000
	cfg.Flood.MinRequests = 3
	d := New(cfg)
	f := false
	d.SetVhostRules(map[string]VhostCfg{"site.fr": {Enabled: &f, Ignore: map[int]struct{}{}}})
	feed(d, 5, 100, nil)
	if got := d.Evaluate(T0 + 500); len(got) != 0 {
		t.Errorf("expected none, got %d", len(got))
	}
}

func TestVhostReenabledAlertsAgain(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WindowMs = 1000
	cfg.Flood.MinRequests = 3
	d := New(cfg)
	f := false
	d.SetVhostRules(map[string]VhostCfg{"site.fr": {Enabled: &f, Ignore: map[int]struct{}{}}})
	feed(d, 5, 100, nil)
	if got := d.Evaluate(T0 + 500); len(got) != 0 {
		t.Errorf("expected none, got %d", len(got))
	}
	d.SetVhostRules(map[string]VhostCfg{})
	feed(d, 5, 100, func(i int, o *reqOpts) { o.ts = T0 + 2000 + int64(i)*100 })
	if got := len(d.Evaluate(T0 + 2500)); got != 1 {
		t.Errorf("expected 1, got %d", got)
	}
}

func TestSpecificRuleIgnoredOtherActive(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WindowMs = 2000
	cfg.Bruteforce.MinFailures = 5
	cfg.Flood.MinRequests = 1000
	d := New(cfg)
	d.SetVhostRules(map[string]VhostCfg{"site.fr": {Ignore: map[int]struct{}{RuleBruteforce: {}}}})
	feed(d, 10, 50, func(i int, o *reqOpts) { o.path = strp("/login"); o.status = 401 })
	if got := filterType(d.Evaluate(T0+600), "bruteforce"); len(got) != 0 {
		t.Errorf("bruteforce doit rester silencieux: got %d", len(got))
	}
}

func TestVhostNotMentionedDefaultBehavior(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WindowMs = 1000
	cfg.Flood.MinRequests = 3
	d := New(cfg)
	f := false
	d.SetVhostRules(map[string]VhostCfg{"autre-site.fr": {Enabled: &f, Ignore: map[int]struct{}{}}})
	feed(d, 5, 100, nil)
	if got := len(d.Evaluate(T0 + 500)); got != 1 {
		t.Errorf("expected 1, got %d", got)
	}
}

func TestSameIpTwoVhostsBothIgnoreSilent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WindowMs = 2000
	cfg.Flood.MinRequests = 3
	d := New(cfg)
	d.SetVhostRules(map[string]VhostCfg{
		"maps.bourgesplus.fr": {Ignore: map[int]struct{}{RuleFlood: {}}},
		"mapx.bourgesplus.fr": {Ignore: map[int]struct{}{RuleFlood: {}}},
	})
	for i := 0; i < 5; i++ {
		v := "maps.bourgesplus.fr"
		if i%2 != 0 {
			v = "mapx.bourgesplus.fr"
		}
		d.Add(req(func(o *reqOpts) { o.ts = T0 + int64(i)*100; o.vhost = v }))
	}
	if got := filterType(d.Evaluate(T0+500), "flood"); len(got) != 0 {
		t.Errorf("les deux vhosts ignorent la regle: got %d", len(got))
	}
}

func TestSameIpTwoVhostsOnlyOneIgnoresKeepsAlert(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WindowMs = 2000
	cfg.Flood.MinRequests = 3
	d := New(cfg)
	d.SetVhostRules(map[string]VhostCfg{
		"maps.bourgesplus.fr": {Ignore: map[int]struct{}{RuleFlood: {}}},
	})
	for i := 0; i < 5; i++ {
		v := "maps.bourgesplus.fr"
		if i%2 != 0 {
			v = "mapx.bourgesplus.fr"
		}
		d.Add(req(func(o *reqOpts) { o.ts = T0 + int64(i)*100; o.vhost = v }))
	}
	if got := countType(d.Evaluate(T0+500), "flood"); got != 1 {
		t.Errorf("mapx n a pas opte pour l ignore-rule: got %d", got)
	}
}

func TestSingleVhostBehaviorUnchanged(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WindowMs = 2000
	cfg.Flood.MinRequests = 3
	d := New(cfg)
	d.SetVhostRules(map[string]VhostCfg{"site.fr": {Ignore: map[int]struct{}{RuleFlood: {}}}})
	feed(d, 5, 100, func(i int, o *reqOpts) { o.vhost = "site.fr" })
	if got := filterType(d.Evaluate(T0+500), "flood"); len(got) != 0 {
		t.Errorf("expected none, got %d", len(got))
	}
}

// ── regles personnalisees ────────────────────────────────────────────────

func adminProbeRule(mut func(*CustomRule)) CustomRule {
	r := CustomRule{
		ID: 101, Name: "admin_probe", Severity: "high", Description: "test",
		WindowMinutes: 5, MinMatches: 5, PathHint: regexp.MustCompile(`(?i)admin`),
	}
	if mut != nil {
		mut(&r)
	}
	return r
}

func TestCustomRuleTriggersAtThreshold(t *testing.T) {
	d := NewDefault()
	d.SetCustomRules([]CustomRule{adminProbeRule(func(r *CustomRule) { r.MinMatches = 5 })})
	feed(d, 6, 100, func(i int, o *reqOpts) { o.path = strp("/wp-admin/") })
	a := filterType(d.Evaluate(T0+600), "custom_101")
	if len(a) != 1 {
		t.Fatalf("expected 1, got %d", len(a))
	}
	if a[0].Evidence.RuleID != 101 || a[0].Evidence.Matches != 6 {
		t.Errorf("ruleId=%d matches=%d", a[0].Evidence.RuleID, a[0].Evidence.Matches)
	}
}

func TestCustomRuleBelowThreshold(t *testing.T) {
	d := NewDefault()
	d.SetCustomRules([]CustomRule{adminProbeRule(func(r *CustomRule) { r.MinMatches = 10 })})
	feed(d, 6, 100, func(i int, o *reqOpts) { o.path = strp("/wp-admin/") })
	if got := filterType(d.Evaluate(T0+600), "custom_101"); len(got) != 0 {
		t.Errorf("expected none, got %d", len(got))
	}
}

func TestCustomRuleNonMatchingPathHint(t *testing.T) {
	d := NewDefault()
	d.SetCustomRules([]CustomRule{adminProbeRule(func(r *CustomRule) { r.MinMatches = 5 })})
	feed(d, 10, 100, func(i int, o *reqOpts) { o.path = strp("/public/") })
	if got := filterType(d.Evaluate(T0+1000), "custom_101"); len(got) != 0 {
		t.Errorf("expected none, got %d", len(got))
	}
}

func TestCustomRuleDisabledNeverTriggers(t *testing.T) {
	d := NewDefault()
	f := false
	d.SetCustomRules([]CustomRule{adminProbeRule(func(r *CustomRule) { r.MinMatches = 5; r.Enable = &f })})
	feed(d, 10, 100, func(i int, o *reqOpts) { o.path = strp("/wp-admin/") })
	if got := filterType(d.Evaluate(T0+1000), "custom_101"); len(got) != 0 {
		t.Errorf("expected none, got %d", len(got))
	}
}

func TestCustomRuleStatusInFilter(t *testing.T) {
	d := NewDefault()
	d.SetCustomRules([]CustomRule{adminProbeRule(func(r *CustomRule) {
		r.MinMatches = 5
		r.PathHint = nil
		r.StatusIn = []int{403}
	})})
	feed(d, 10, 100, func(i int, o *reqOpts) { o.status = 200 })
	if got := filterType(d.Evaluate(T0+1000), "custom_101"); len(got) != 0 {
		t.Errorf("expected none for 200s, got %d", len(got))
	}
	feed(d, 10, 100, func(i int, o *reqOpts) { o.ts = T0 + 2000 + int64(i)*100; o.status = 403 })
	if got := countType(d.Evaluate(T0+2500), "custom_101"); got != 1 {
		t.Errorf("expected 1 for 403s, got %d", got)
	}
}

func TestCustomRuleEdgeTriggered(t *testing.T) {
	d := NewDefault()
	d.SetCustomRules([]CustomRule{adminProbeRule(func(r *CustomRule) { r.MinMatches = 5 })})
	feed(d, 6, 100, func(i int, o *reqOpts) { o.path = strp("/wp-admin/") })
	if got := countType(d.Evaluate(T0+600), "custom_101"); got != 1 {
		t.Fatalf("expected 1, got %d", got)
	}
	feed(d, 6, 100, func(i int, o *reqOpts) { o.ts = T0 + 700 + int64(i)*100; o.path = strp("/wp-admin/") })
	if got := countType(d.Evaluate(T0+1400), "custom_101"); got != 0 {
		t.Errorf("meme episode continu: got %d", got)
	}
}

func TestCustomRuleRetentionWidensWithoutTouchingBuiltinWindow(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WindowMs = 1000
	d := New(cfg)
	d.SetCustomRules([]CustomRule{adminProbeRule(func(r *CustomRule) { r.MinMatches = 5; r.WindowMinutes = 1 })})
	if d.RetentionMs() < 60000 {
		t.Errorf("retention doit s elargir, got %d", d.RetentionMs())
	}
	if d.Cfg().WindowMs != 1000 {
		t.Errorf("la fenetre des regles integrees ne doit jamais changer, got %d", d.Cfg().WindowMs)
	}
}

func TestCustomRuleRetentionShrinksBackWhenRemoved(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WindowMs = 1000
	d := New(cfg)
	d.SetCustomRules([]CustomRule{adminProbeRule(func(r *CustomRule) { r.MinMatches = 5; r.WindowMinutes = 60 })})
	if d.RetentionMs() < 3600_000 {
		t.Fatalf("expected >= 3600000, got %d", d.RetentionMs())
	}
	d.SetCustomRules(nil)
	if d.RetentionMs() != 1000 {
		t.Errorf("retention doit revenir a la fenetre de base, got %d", d.RetentionMs())
	}
}

func TestCustomRuleWindowMinutesClamped(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WindowMs = 1000
	d := New(cfg)
	d.SetCustomRules([]CustomRule{adminProbeRule(func(r *CustomRule) { r.MinMatches = 5; r.WindowMinutes = 999999999 })})
	maxMs := int64(24 * 60 * 60_000)
	if d.RetentionMs() != maxMs {
		t.Errorf("retention ne doit pas depasser le plafond, got %d, want %d", d.RetentionMs(), maxMs)
	}
}

func TestCustomRuleVhostOptOutApplies(t *testing.T) {
	d := NewDefault()
	d.SetCustomRules([]CustomRule{adminProbeRule(func(r *CustomRule) { r.MinMatches = 5; r.ID = 105 })})
	d.SetVhostRules(map[string]VhostCfg{"site.fr": {Ignore: map[int]struct{}{105: {}}}})
	feed(d, 10, 100, func(i int, o *reqOpts) { o.path = strp("/wp-admin/") })
	if got := filterType(d.Evaluate(T0+1000), "custom_105"); len(got) != 0 {
		t.Errorf("expected none, got %d", len(got))
	}
}

// ── paths-ignore par regle (# nginx-control-analyze-rule-{ID}-paths-ignore) ──

func pathsIgnoreCfg(id int, pats ...string) map[string]VhostCfg {
	en := true
	return map[string]VhostCfg{"site.fr": {Enabled: &en, Ignore: map[int]struct{}{}, PathsIgnore: map[int][]string{id: pats}}}
}

func TestPathsIgnoreBruteforce(t *testing.T) {
	mk := func() *Detector { return New(DefaultConfig()) }
	path := func(i int, o *reqOpts) { o.path = strp("/wp-json/wpa/v1/verify-session?t=1"); o.status = 403 }
	// le chemin doit etre un chemin d authentification pour que la regle 1 compte (pathHint)
	d := mk()
	d.cfg.Bruteforce.PathHint = regexp.MustCompile(`verify-session|login`)
	d.SetVhostRules(pathsIgnoreCfg(RuleBruteforce, "/wp-json/wpa/v1/verify-session"))
	feed(d, 30, 100, path)
	if n := countType(d.Evaluate(T0+3000), "bruteforce"); n != 0 {
		t.Fatalf("chemin ignore : 0 alerte attendue, obtenu %d", n)
	}
	d2 := mk()
	d2.cfg.Bruteforce.PathHint = regexp.MustCompile(`verify-session|login`)
	feed(d2, 30, 100, path)
	if n := countType(d2.Evaluate(T0+3000), "bruteforce"); n != 1 {
		t.Fatalf("controle negatif : 1 alerte attendue, obtenu %d", n)
	}
}

func TestPathsIgnoreIsPerRuleAndPerVhost(t *testing.T) {
	d := New(DefaultConfig())
	d.SetVhostRules(pathsIgnoreCfg(RuleBruteforce, "/ping"))
	feed(d, 1200, 5, func(i int, o *reqOpts) { o.path = strp("/ping") })
	if n := countType(d.Evaluate(T0+7000), "flood"); n != 1 {
		t.Fatalf("le flood doit toujours compter ces requetes, obtenu %d", n)
	}
	d2 := New(DefaultConfig())
	d2.cfg.Bruteforce.PathHint = regexp.MustCompile(`login`)
	d2.SetVhostRules(pathsIgnoreCfg(RuleBruteforce, "/login"))
	feed(d2, 30, 100, func(i int, o *reqOpts) { o.path = strp("/login"); o.status = 401; o.vhost = "autre.fr" })
	if n := countType(d2.Evaluate(T0+3000), "bruteforce"); n != 1 {
		t.Fatalf("autre vhost : la regle doit s appliquer, obtenu %d", n)
	}
}

func TestPathsIgnorePrefixAndExact(t *testing.T) {
	d := New(DefaultConfig())
	d.SetVhostRules(pathsIgnoreCfg(RuleFlood, "/health*"))
	feed(d, 1500, 2, func(i int, o *reqOpts) { o.path = strp("/healthz?x=1") })
	if n := countType(d.Evaluate(T0+4000), "flood"); n != 0 {
		t.Fatalf("prefixe : 0 attendu, obtenu %d", n)
	}
	d2 := New(DefaultConfig())
	d2.SetVhostRules(pathsIgnoreCfg(RuleFlood, "/health"))
	feed(d2, 1500, 2, func(i int, o *reqOpts) { o.path = strp("/healthz") })
	if n := countType(d2.Evaluate(T0+4000), "flood"); n != 1 {
		t.Fatalf("exact ne doit pas matcher un prefixe, obtenu %d", n)
	}
}

func TestPathsIgnoreScan(t *testing.T) {
	d := New(DefaultConfig())
	d.SetVhostRules(pathsIgnoreCfg(RuleScan, "/wp-content/*"))
	feed(d, 60, 100, func(i int, o *reqOpts) { o.path = strp(fmt.Sprintf("/wp-content/uploads/a%d.jpg", i)); o.status = 404 })
	if n := countType(d.Evaluate(T0+7000), "scan"); n != 0 {
		t.Fatalf("scan ignore : 0 attendu, obtenu %d", n)
	}
	d2 := New(DefaultConfig())
	feed(d2, 60, 100, func(i int, o *reqOpts) { o.path = strp(fmt.Sprintf("/wp-content/uploads/a%d.jpg", i)); o.status = 404 })
	if n := countType(d2.Evaluate(T0+7000), "scan"); n != 1 {
		t.Fatalf("controle negatif scan : 1 attendu, obtenu %d", n)
	}
}

func TestPathsIgnoreHasNoCostWithoutRules(t *testing.T) {
	d := New(DefaultConfig())
	feed(d, 10, 100, nil)
	for _, s := range d.ips {
		for _, b := range s.buckets {
			if b.ign != nil {
				t.Fatal("aucune structure ign ne doit etre allouee sans motif")
			}
		}
	}
}

// ── scope: global : une alerte de campagne, preuves agregees (v12.62.0) ─────

func botnetFeed(d *Detector, nIPs, perIP int, extra func(i int, o *reqOpts)) {
	for i := 0; i < nIPs; i++ {
		for k := 0; k < perIP; k++ {
			o := defaultReq()
			o.ip = fmt.Sprintf("198.51.100.%d", i+1)
			o.ts = T0 + int64(i*perIP+k)*10
			o.path = strp(fmt.Sprintf("/x/commits/commit/%s/f%d", strings.Repeat("a", 40), i%3))
			o.status = 444
			if i%2 == 1 {
				o.ua = "Chrome/142"
			} else {
				o.ua = "Firefox/130"
			}
			if extra != nil {
				extra(i, &o)
			}
			d.Add(entryFromOpts(o))
		}
	}
}

func globalRule(mut func(r *CustomRule)) CustomRule {
	r := CustomRule{
		ID: 130, Name: "botnet", Severity: "high", WindowMinutes: 5, MinMatches: 8,
		PathHint: regexp.MustCompile(`(?i)commits/commit`), Global: true, MinIPs: 5,
	}
	if mut != nil {
		mut(&r)
	}
	return r
}

func campaigns(d *Detector, t int64) []Alert { return filterType(d.Evaluate(t), "custom_130") }

func TestGlobalRuleSingleCampaignAlertWithEvidence(t *testing.T) {
	d := NewDefault()
	d.SetCustomRules([]CustomRule{globalRule(nil)})
	botnetFeed(d, 10, 1, nil)
	a := campaigns(d, T0+5000)
	if len(a) != 1 {
		t.Fatalf("attendu 1 alerte de campagne, obtenu %d", len(a))
	}
	ev := a[0].Evidence
	c := ev.Campaign
	if c == nil || ev.GlobalMatches != 10 || ev.GlobalIPs != 10 || len(c.IPs) != 10 || c.IPsTruncated {
		t.Fatalf("evidence: %+v campaign=%+v", ev, c)
	}
	if c.Statuses[444] != 10 || len(c.TopPaths) != 3 || len(c.TopUserAgents) != 2 || len(c.Samples) != 10 {
		t.Fatalf("campaign: %+v", c)
	}
	if c.TopPaths[0].Count+c.TopPaths[1].Count+c.TopPaths[2].Count != 10 {
		t.Fatalf("topPaths: %+v", c.TopPaths)
	}
	if ev.Vhost != "site.fr" || !strings.Contains(a[0].Summary, "campagne distribuee") || !strings.Contains(a[0].Summary, "10 IP") {
		t.Fatalf("summary/vhost: %q %q", a[0].Summary, ev.Vhost)
	}
}

func TestGlobalRuleEdgeTriggeredAndRenewal(t *testing.T) {
	d := NewDefault()
	d.SetCustomRules([]CustomRule{globalRule(nil)})
	botnetFeed(d, 10, 1, nil)
	if n := len(campaigns(d, T0+5000)); n != 1 {
		t.Fatalf("1re evaluation: %d", n)
	}
	if n := len(campaigns(d, T0+6000)); n != 0 {
		t.Fatalf("doublon: %d", n)
	}
	for i := 10; i < 14; i++ {
		o := defaultReq()
		o.ip, o.ts, o.path = fmt.Sprintf("198.51.100.%d", i+1), T0+6100, strp("/x/commits/commit/"+strings.Repeat("b", 40))
		d.Add(entryFromOpts(o))
	}
	if n := len(campaigns(d, T0+7000)); n != 0 {
		t.Fatalf("14 IP < 15 : %d", n)
	}
	o := defaultReq()
	o.ip, o.ts, o.path = "198.51.100.99", T0+7100, strp("/x/commits/commit/"+strings.Repeat("c", 40))
	d.Add(entryFromOpts(o))
	u := campaigns(d, T0+8000)
	if len(u) != 1 || !u[0].Evidence.Campaign.Renewal || u[0].Evidence.GlobalIPs != 15 {
		t.Fatalf("mise a jour: %+v", u)
	}
}

func TestGlobalRuleNotTriggeredWhenScopeIPOrTooFewIPs(t *testing.T) {
	d := NewDefault()
	d.SetCustomRules([]CustomRule{globalRule(func(r *CustomRule) { r.Global = false })})
	botnetFeed(d, 10, 1, nil)
	if n := len(campaigns(d, T0+5000)); n != 0 {
		t.Fatalf("scope ip : %d", n)
	}
	d2 := NewDefault()
	d2.SetCustomRules([]CustomRule{globalRule(nil)})
	botnetFeed(d2, 1, 20, nil)
	if n := len(campaigns(d2, T0+5000)); n != 0 {
		t.Fatalf("une seule IP : %d", n)
	}
	d3 := NewDefault()
	d3.SetCustomRules([]CustomRule{globalRule(func(r *CustomRule) { r.MinMatches = 50 })})
	botnetFeed(d3, 10, 1, nil)
	if n := len(campaigns(d3, T0+5000)); n != 0 {
		t.Fatalf("total sous le seuil : %d", n)
	}
}

func TestGlobalRuleSkipsNonMatchingAndExcludedIPs(t *testing.T) {
	d := NewDefault()
	d.SetCustomRules([]CustomRule{globalRule(nil)})
	botnetFeed(d, 10, 1, nil)
	o := defaultReq()
	o.ip, o.method, o.ts, o.path = "10.149.2.1", "POST", T0+50, strp("/api/actions/runner.v1.RunnerService/FetchTask")
	d.Add(entryFromOpts(o))
	d.SetExceptions([]Exception{{Vhost: "site.fr", IP: "198.51.100.3"}})
	a := campaigns(d, T0+5000)
	if len(a) != 1 || a[0].Evidence.GlobalIPs != 9 {
		t.Fatalf("attendu 9 IP, obtenu %+v", a)
	}
	for _, x := range a[0].Evidence.Campaign.IPs {
		if x.IP == "10.149.2.1" || x.IP == "198.51.100.3" {
			t.Fatalf("IP exclue listee: %s", x.IP)
		}
	}
}

func TestGlobalRuleIPListBounded(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxTrackedIps = 10000
	d := New(cfg)
	d.SetCustomRules([]CustomRule{globalRule(func(r *CustomRule) { r.MinMatches = 10 })})
	for i := 0; i < 3100; i++ {
		o := defaultReq()
		o.ip, o.ts, o.path = fmt.Sprintf("10.%d.%d.7", i>>8, i&255), T0+int64(i), strp("/x/commits/commit/"+strings.Repeat("a", 40))
		d.Add(entryFromOpts(o))
	}
	a := campaigns(d, T0+5000)
	if len(a) != 1 || len(a[0].Evidence.Campaign.IPs) != MaxCampaignIPs || !a[0].Evidence.Campaign.IPsTruncated || a[0].Evidence.GlobalIPs != 3100 {
		t.Fatalf("liste bornee: %+v", a[0].Evidence.Campaign)
	}
}

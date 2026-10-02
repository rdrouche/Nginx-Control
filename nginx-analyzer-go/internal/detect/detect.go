// Package detect porte lib/detect.js : detection par signature sur une vraie fenetre
// glissante (buckets de temps fixes), avec declenchement par front (edge-triggered) et
// agregation multi-vhost par IP. Parite stricte visee avec le Node d origine — voir les
// commentaires renvoyant a detect.js pour chaque choix delicat.
package detect

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"

	"nginx-analyzer-go/internal/cidr"
	"nginx-analyzer-go/internal/parse"
)

// MaxCustomWindowMinutes plafonne window_minutes d une regle personnalisee (fix ANA-05).
const MaxCustomWindowMinutes = 24 * 60

// ClampCustomWindowMinutes reproduit clampCustomWindowMinutes().
func ClampCustomWindowMinutes(windowMinutes int) int {
	w := windowMinutes
	if w == 0 {
		w = 5
	}
	if w < 1 {
		w = 1
	}
	if w > MaxCustomWindowMinutes {
		w = MaxCustomWindowMinutes
	}
	return w
}

// RULE_IDS — identifiants numeriques stables des regles integrees.
const (
	RuleBruteforce     = 1
	RuleScan           = 2
	RuleFlood          = 3
	RuleScraping       = 4
	RuleVolumetric     = 5
	RuleCountryTraffic = 6
)

// BruteforceCfg / ScanCfg / FloodCfg / ScrapingCfg reproduisent DEFAULTS.{bruteforce,scan,flood,scraping}.
type BruteforceCfg struct {
	Enable      bool
	MinFailures int
	Statuses    []int
	PathHint    *regexp.Regexp
}

type ScanCfg struct {
	Enable           bool
	MinRequests      int
	MinDistinct      int
	MinNotFoundRatio float64
}

type FloodCfg struct {
	Enable      bool
	MinRequests int
}

type ScrapingCfg struct {
	Enable      bool
	MinRequests int
	MaxDistinct int
	UAHint      *regexp.Regexp
}

// Config reproduit DEFAULTS + withDefaults().
type Config struct {
	WindowMs      int64
	BucketMs      int64
	PruneEveryMs  int64
	MaxTrackedIps int

	Bruteforce BruteforceCfg
	Scan       ScanCfg
	Flood      FloodCfg
	Scraping   ScrapingCfg
}

var bruteforcePathHint = regexp.MustCompile(`(?i)(login|signin|auth|admin|wp-login|session|token|oauth)`)
var scrapingUAHint = regexp.MustCompile(`(?i)(bot|crawler|spider|scrapy|python-requests|curl|wget|go-http|java|libwww)`)

// DefaultConfig reproduit DEFAULTS.
func DefaultConfig() Config {
	return Config{
		WindowMs:      5 * 60_000,
		BucketMs:      10_000,
		PruneEveryMs:  60_000,
		MaxTrackedIps: 50_000,
		Bruteforce: BruteforceCfg{
			Enable: true, MinFailures: 15, Statuses: []int{401, 403}, PathHint: bruteforcePathHint,
		},
		Scan: ScanCfg{
			Enable: true, MinRequests: 40, MinDistinct: 25, MinNotFoundRatio: 0.5,
		},
		Flood: FloodCfg{
			Enable: true, MinRequests: 600,
		},
		Scraping: ScrapingCfg{
			Enable: true, MinRequests: 300, MaxDistinct: 5, UAHint: scrapingUAHint,
		},
	}
}

// Explanation reproduit un element de EXPLANATIONS (ou l objet inline d une regle custom).
type Explanation struct {
	ID     int
	What   string
	Why    string
	Legit  string
	Action string
}

var Explanations = map[string]Explanation{
	"bruteforce": {
		ID:     RuleBruteforce,
		What:   "Une meme adresse a enchaine les echecs d authentification sur une page de connexion.",
		Why:    "C est le motif d une tentative de decouverte de mot de passe : un attaquant essaie des identifiants en serie.",
		Legit:  "Un utilisateur qui a oublie son mot de passe, ou un client automatise dont les identifiants ont expire, produisent le meme motif a plus petite echelle.",
		Action: "Verifier si le compte vise existe. Si les tentatives continuent, bloquer l adresse ou renforcer l authentification.",
	},
	"scan": {
		ID:     RuleScan,
		What:   "Une adresse a demande de nombreux chemins differents, dont la plupart n existent pas.",
		Why:    "C est une reconnaissance : on cherche un fichier de configuration oublie, une interface d administration, une faille connue.",
		Legit:  "Un moteur d indexation mal configure, ou un lien casse massivement partage, peuvent generer beaucoup de 404 — mais rarement sur des chemins aussi varies.",
		Action: "Regarder les chemins demandes. S ils visent des fichiers sensibles, l intention est claire.",
	},
	"flood": {
		ID:     RuleFlood,
		What:   "Une seule adresse a envoye un volume de requetes tres au-dessus de la normale, sur les dernieres minutes.",
		Why:    "Saturation volontaire, ou client defectueux qui reessaie en boucle sans attendre.",
		Legit:  "Un script interne mal ecrit, une sonde de supervision trop frequente, un proxy qui regroupe le trafic de nombreux utilisateurs derriere une seule adresse.",
		Action: "Verifier si l adresse vous appartient avant de bloquer : un proxy d entreprise concentre parfois des centaines d utilisateurs legitimes. Si c est le cas, ajoutez une exception pour ce vhost.",
	},
	"scraping": {
		ID:     RuleScraping,
		What:   "Un volume important sur tres peu de chemins, depuis un agent automatise.",
		Why:    "Recuperation systematique de contenu : catalogue, annuaire, donnees tarifaires.",
		Legit:  "Vos propres taches de sauvegarde, un agregateur autorise, ou un moteur de recherche partenaire.",
		Action: "Si l agent vous appartient, ajoutez une exception pour ce vhost plutot que de baisser les seuils.",
	},
	"volumetric": {
		ID:     RuleVolumetric,
		What:   "Le trafic de ce creneau horaire s ecarte nettement de ce qui est habituel pour ce meme creneau.",
		Why:    "Un ecart franc signale soit une attaque, soit un evenement reel — les deux produisent un pic.",
		Legit:  "Un article qui fonctionne, une campagne, une mise en avant. La structure du trafic les distingue : une audience reelle apporte beaucoup d adresses differentes, des chemins varies et peu d erreurs.",
		Action: "Regarder le champ « structure » de l alerte. Si le trafic semble organique, marquez ce creneau comme normal pour qu il n influence pas la reference.",
	},
	"country_traffic": {
		ID:     RuleCountryTraffic,
		What:   "Le volume de requetes en provenance d un pays s ecarte nettement de ce qui est habituel pour ce meme creneau horaire, tous vhosts confondus.",
		Why:    "Un pays qui envoie brutalement beaucoup plus de trafic qu a l accoutumee est le motif d une attaque distribuee (credential stuffing, DDoS applicatif) menee depuis une plage d adresses concentree geographiquement, ou d un scan de masse.",
		Legit:  "Une actualite qui touche particulierement ce pays, une campagne marketing ciblee, ou un evenement (sportif, commercial) genèrent le meme pic sans etre malveillants — la encore, la structure (nombre d adresses distinctes, variete des chemins, taux d erreur) les distingue d un flood.",
		Action: "Regarder le champ « structure » de l alerte et, si besoin, le detail par vhost sur la carte en direct filtree par ce pays. Si le trafic est legitime, marquez ce creneau comme normal.",
	},
}

// CustomRule reproduit un element de lib/rules-yaml.js `valid` (id >= 100).
type CustomRule struct {
	ID            int
	Name          string
	Enable        *bool // nil == non precise == active (parite : "rule.enable !== false")
	Severity      string
	Description   string
	WindowMinutes int
	MinMatches    int
	PathHint      *regexp.Regexp
	UAHint        *regexp.Regexp
	StatusIn      []int
	MethodIn      []string
	Global        bool // scope: global (v12.60.0) : comptage toutes IP confondues
	MinIPs        int  // scope: global : nombre d IP distinctes minimum (defaut 5)
}

func (r CustomRule) enabledForAdd() bool {
	// add(): "if (rule.enable === false) continue" -> actif si nil ou true.
	return r.Enable == nil || *r.Enable
}
func (r CustomRule) enabledForEvaluate() bool {
	// evaluate(): "rule.enable !== false" -> meme semantique.
	return r.Enable == nil || *r.Enable
}

// VhostCfg reproduit { enabled, ignore } pousse par setVhostRules().
type VhostCfg struct {
	Enabled *bool // nil == non precise == actif
	Ignore  map[int]struct{}
	// PathsIgnore : # nginx-control-analyze-rule-{ID}-paths-ignore - motifs de
	// chemin (exact, ou prefixe si fini par "*") a ne pas compter pour la regle {ID}.
	PathsIgnore map[int][]string
}

// ignCounts : ce qu il faut retrancher des compteurs partages pour UNE regle
// (voir effective()). Cree a la demande : nil pour tout bucket sans requete ignoree.
type ignCounts struct {
	requests, authFail, notFound int
	paths                        map[string]struct{}
}

// ruleView : metriques d une fenetre vues par une regle donnee.
type ruleView struct {
	requests, authFail, notFound, pathCount int
}

// pathIgnored : le chemin (sans query string) correspond-il a un motif ?
func pathIgnored(patterns []string, path string) bool {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	for _, pat := range patterns {
		if strings.HasSuffix(pat, "*") {
			if strings.HasPrefix(path, pat[:len(pat)-1]) {
				return true
			}
		} else if path == pat {
			return true
		}
	}
	return false
}

// Exception reproduit { vhost, ip } (ip peut etre une adresse ou un bloc CIDR).
type Exception struct {
	Vhost string
	IP    string
}

// Sample reproduit un element de s.samples.
type Sample struct {
	TS     int64
	Method *string
	Path   *string
	Status int
}

type bucket struct {
	requests, authFail, notFound int
	paths                        map[string]struct{}
	uas                          map[string]struct{}
	vhosts                       map[string]struct{}
	statuses                     map[int]int
	custom                       map[int]int
	ign                          map[int]*ignCounts
	gm                           map[int]*campDetail // regles scope: global (campaign.go)
}

func newBucket() *bucket {
	return &bucket{
		paths: make(map[string]struct{}), uas: make(map[string]struct{}),
		vhosts: make(map[string]struct{}), statuses: make(map[int]int), custom: make(map[int]int),
	}
}

type ipRef struct {
	ip  string
	seq uint64
}

type ipState struct {
	seq     uint64 // ordre d'insertion : les Map JS iterent en ordre d'insertion, pas les map Go
	buckets map[int64]*bucket
	last    int64
	samples []Sample
	active  map[string]struct{}
}

// Evidence reproduit l objet retourne par base(), etendu par champ selon la regle.
type Evidence struct {
	IP            string
	Vhost         string // "" si multi-vhost (equivalent de null)
	FirstSeen     int64
	LastSeen      int64
	Requests      int
	DistinctPaths int
	UserAgents    []string
	Statuses      map[int]int
	Samples       []Sample

	// Champs specifiques a une regle (seuls les pertinents sont renseignes) :
	AuthFailures      int
	NotFound          int
	RequestsPerSecond float64
	RuleID            int
	RuleName          string
	Matches           int
	GlobalMatches     int               // scope: global : total toutes IP confondues
	GlobalIPs         int               // scope: global : nombre d IP distinctes
	Campaign          *CampaignEvidence // scope: global : preuves agregees (nil sinon)
}

// Alert reproduit un element du tableau retourne par evaluate().
type Alert struct {
	Type        string
	Explanation Explanation
	Severity    string
	Summary     string
	Evidence    Evidence
}

// Stats reproduit stats().
type Stats struct {
	TrackedIps   int
	ActiveAlerts int
}

// Detector porte la classe Detector.
type Detector struct {
	cfg         Config
	mu          sync.Mutex
	ips         map[string]*ipState
	nextSeq     uint64
	order       []ipRef // ordre d'insertion (les Map JS iterent ainsi) sans tri a chaque Evaluate
	lastPrune   int64
	retentionMs int64
	exceptions  []Exception
	customRules []CustomRule
	vhostRules  map[string]VhostCfg
	campaigns   map[int]campaignState // campagnes en cours (regles scope: global)
	hasPathsIgn bool                  // evite un lookup par requete tant qu aucun vhost n a de motif
}

// New reproduit new Detector(cfg).
func New(cfg Config) *Detector {
	// bucketMs = max(1, min(bucketMs, windowMs))
	if cfg.BucketMs > cfg.WindowMs {
		cfg.BucketMs = cfg.WindowMs
	}
	if cfg.BucketMs < 1 {
		cfg.BucketMs = 1
	}
	return &Detector{
		cfg:         cfg,
		ips:         make(map[string]*ipState),
		retentionMs: cfg.WindowMs,
		vhostRules:  make(map[string]VhostCfg),
		campaigns:   make(map[int]campaignState),
	}
}

// NewDefault construit un Detector avec DefaultConfig().
func NewDefault() *Detector { return New(DefaultConfig()) }

func (d *Detector) setExceptions(list []Exception) { d.exceptions = list }

func (d *Detector) isExcluded(ip, vhost string) bool {
	for _, e := range d.exceptions {
		if e.Vhost == vhost && cidr.IpInCidr(ip, e.IP) {
			return true
		}
	}
	return false
}

// IsExcludedForVhosts reproduit isExcludedForVhosts() (fix ANA-06).
func (d *Detector) isExcludedForVhosts(ip string, vhosts map[string]struct{}) bool {
	if len(vhosts) == 0 {
		return d.isExcluded(ip, "")
	}
	for v := range vhosts {
		if !d.isExcluded(ip, v) {
			return false
		}
	}
	return true
}

// SetCustomRules reproduit setCustomRules() (fix ANA-05).
func (d *Detector) setCustomRules(list []CustomRule) {
	d.customRules = list
	var widestMs int64
	for _, r := range list {
		ms := int64(ClampCustomWindowMinutes(r.WindowMinutes)) * 60_000
		if ms > widestMs {
			widestMs = ms
		}
	}
	d.retentionMs = d.cfg.WindowMs
	if widestMs > d.retentionMs {
		d.retentionMs = widestMs
	}
}

// RetentionMs expose this.retentionMs pour les tests.
func (d *Detector) retentionSnapshot() int64 { return d.retentionMs }

// Cfg expose this.cfg (lecture seule) pour les tests.
func (d *Detector) cfgSnapshot() Config { return d.cfg }

// SetRuleEnabled bascule l'activation d'une regle integree sans attendre un
// redemarrage - appele par /api/rules/toggle (etape 7/8), meme principe que
// baseline.Baseline.SetEnabled pour volumetric/country_traffic. Renvoie
// false pour une cle qui n'est pas geree par ce Detector (les deux regles
// basees sur Baseline, elles, passent par SetEnabled directement).
func (d *Detector) setRuleEnabled(key string, enable bool) bool {
	switch key {
	case "bruteforce":
		d.cfg.Bruteforce.Enable = enable
	case "scan":
		d.cfg.Scan.Enable = enable
	case "flood":
		d.cfg.Flood.Enable = enable
	case "scraping":
		d.cfg.Scraping.Enable = enable
	default:
		return false
	}
	return true
}

func (d *Detector) setVhostRules(m map[string]VhostCfg) {
	if m == nil {
		m = make(map[string]VhostCfg)
	}
	d.vhostRules = m
	d.hasPathsIgn = false
	for _, c := range m {
		if len(c.PathsIgnore) > 0 {
			d.hasPathsIgn = true
			break
		}
	}
}

func (d *Detector) vhostCfg(vhost string) (VhostCfg, bool) {
	if vhost == "" {
		return VhostCfg{}, false
	}
	c, ok := d.vhostRules[lower(vhost)]
	return c, ok
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func (d *Detector) ruleSuppressed(vhostCfg VhostCfg, hasCfg bool, ruleID int) bool {
	if !hasCfg {
		return false
	}
	if vhostCfg.Enabled != nil && !*vhostCfg.Enabled {
		return true
	}
	if vhostCfg.Ignore != nil {
		_, ignored := vhostCfg.Ignore[ruleID]
		return ignored
	}
	return false
}

// RuleSuppressedForVhosts reproduit _ruleSuppressedForVhosts().
func (d *Detector) ruleSuppressedForVhosts(vhosts map[string]struct{}, ruleID int) bool {
	if len(vhosts) == 0 {
		return false
	}
	for v := range vhosts {
		cfg, ok := d.vhostCfg(v)
		if !d.ruleSuppressed(cfg, ok, ruleID) {
			return false
		}
	}
	return true
}

func (d *Detector) bucketIdx(ts int64) int64 {
	return int64(math.Floor(float64(ts) / float64(d.cfg.BucketMs)))
}

func (d *Detector) state(ip string) *ipState {
	s, ok := d.ips[ip]
	if !ok {
		if len(d.ips) >= d.cfg.MaxTrackedIps {
			return nil
		}
		d.nextSeq++
		s = &ipState{seq: d.nextSeq, buckets: make(map[int64]*bucket), active: make(map[string]struct{})}
		d.ips[ip] = s
		d.order = append(d.order, ipRef{ip: ip, seq: s.seq})
	}
	return s
}

func (s *ipState) bucket(idx int64) *bucket {
	b, ok := s.buckets[idx]
	if !ok {
		b = newBucket()
		s.buckets[idx] = b
	}
	return b
}

// Add reproduit add(entry) : enregistre une requete parsee.
func (d *Detector) add(entry parse.AccessEntry) {
	now := entry.TS
	if now == 0 {
		now = time.Now().UnixMilli()
	}
	s := d.state(entry.IP)
	if s == nil {
		return
	}
	s.last = now

	b := s.bucket(d.bucketIdx(now))
	b.requests++
	// Les chaines de l'entree sont deja des copies independantes (voir
	// parse.ParseLine) : on peut les conserver sans retenir le chunk de log.
	if entry.Path != nil && len(b.paths) < 500 {
		b.paths[*entry.Path] = struct{}{}
	}
	if entry.UA != nil && *entry.UA != "" && len(b.uas) < 50 {
		b.uas[*entry.UA] = struct{}{}
	}
	if entry.Vhost != "" {
		b.vhosts[entry.Vhost] = struct{}{}
	}
	b.statuses[entry.Status]++
	if entry.Status == 404 {
		b.notFound++
	}
	bf := d.cfg.Bruteforce
	if entry.Path != nil && containsInt(bf.Statuses, entry.Status) && bf.PathHint != nil && bf.PathHint.MatchString(*entry.Path) {
		b.authFail++
	}

	// Voir le commentaire equivalent dans detect.js add() : les compteurs
	// partages restent intacts, on note a part ce qu il faut retrancher a la regle.
	var ignoredRules map[int]struct{}
	if d.hasPathsIgn && entry.Vhost != "" && entry.Path != nil {
		if vcfg, ok := d.vhostRules[strings.ToLower(entry.Vhost)]; ok {
			for ruleID, pats := range vcfg.PathsIgnore {
				if !pathIgnored(pats, *entry.Path) {
					continue
				}
				if ignoredRules == nil {
					ignoredRules = make(map[int]struct{})
				}
				ignoredRules[ruleID] = struct{}{}
				if b.ign == nil {
					b.ign = make(map[int]*ignCounts)
				}
				g := b.ign[ruleID]
				if g == nil {
					g = &ignCounts{paths: make(map[string]struct{})}
					b.ign[ruleID] = g
				}
				g.requests++
				if entry.Status == 404 {
					g.notFound++
				}
				if containsInt(bf.Statuses, entry.Status) && bf.PathHint != nil && bf.PathHint.MatchString(*entry.Path) {
					g.authFail++
				}
				if len(g.paths) < 500 {
					g.paths[*entry.Path] = struct{}{}
				}
			}
		}
	}

	for _, rule := range d.customRules {
		if !rule.enabledForAdd() {
			continue
		}
		if _, skip := ignoredRules[rule.ID]; skip {
			continue
		}
		if rule.PathHint != nil && (entry.Path == nil || !rule.PathHint.MatchString(*entry.Path)) {
			continue
		}
		if rule.UAHint != nil && !(entry.UA != nil && *entry.UA != "" && rule.UAHint.MatchString(*entry.UA)) {
			continue
		}
		if len(rule.StatusIn) > 0 && !containsInt(rule.StatusIn, entry.Status) {
			continue
		}
		if len(rule.MethodIn) > 0 && !(entry.Method != nil && containsStr(rule.MethodIn, *entry.Method)) {
			continue
		}
		b.custom[rule.ID]++
		if rule.Global {
			recordCampaignDetail(b, rule.ID, entry, now)
		}
	}

	s.samples = append(s.samples, Sample{TS: now, Method: entry.Method, Path: entry.Path, Status: entry.Status})
	if len(s.samples) > 20 {
		s.samples = s.samples[len(s.samples)-20:]
	}

	if now-d.lastPrune > d.cfg.PruneEveryMs {
		d.prune(now)
	}
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
func containsStr(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// Prune reproduit prune(now).
func (d *Detector) prune(now int64) {
	d.lastPrune = now
	cutoffIdx := d.bucketIdx(now - d.retentionMs)
	for ip, s := range d.ips {
		for idx := range s.buckets {
			if idx < cutoffIdx {
				delete(s.buckets, idx)
			}
		}
		if len(s.buckets) == 0 {
			delete(d.ips, ip)
		}
	}
	// Compacte la liste d'ordre des IP purgees (gardee en ordre d'insertion).
	live := d.order[:0]
	for _, ref := range d.order {
		if s, ok := d.ips[ref.ip]; ok && s.seq == ref.seq {
			live = append(live, ref)
		}
	}
	for i := len(live); i < len(d.order); i++ {
		d.order[i] = ipRef{}
	}
	d.order = live
}

func (d *Detector) customCount(s *ipState, now int64, ruleID int, windowMs int64) int {
	cutoffIdx := d.bucketIdx(now - windowMs)
	count := 0
	for idx, b := range s.buckets {
		if idx < cutoffIdx {
			continue
		}
		count += b.custom[ruleID]
	}
	return count
}

type aggregate struct {
	requests, authFail, notFound int
	paths, uas, vhosts           map[string]struct{}
	statuses                     map[int]int
	custom                       map[int]int
	ign                          map[int]*ignCounts
	samples                      []Sample
	first, last                  int64
}

func (d *Detector) aggregate(s *ipState, now int64) aggregate {
	cutoffIdx := d.bucketIdx(now - d.cfg.WindowMs)
	agg := aggregate{
		paths: make(map[string]struct{}), uas: make(map[string]struct{}), vhosts: make(map[string]struct{}),
		statuses: make(map[int]int), custom: make(map[int]int), first: now,
	}
	for idx, b := range s.buckets {
		if idx < cutoffIdx {
			continue
		}
		bucketStart := idx * d.cfg.BucketMs
		if bucketStart < agg.first {
			agg.first = bucketStart
		}
		agg.requests += b.requests
		agg.authFail += b.authFail
		agg.notFound += b.notFound
		for p := range b.paths {
			if len(agg.paths) < 2000 {
				agg.paths[p] = struct{}{}
			}
		}
		for u := range b.uas {
			if len(agg.uas) < 100 {
				agg.uas[u] = struct{}{}
			}
		}
		for v := range b.vhosts {
			agg.vhosts[v] = struct{}{}
		}
		for code, n := range b.statuses {
			agg.statuses[code] += n
		}
		for id, n := range b.custom {
			agg.custom[id] += n
		}
		for id, g := range b.ign {
			if agg.ign == nil {
				agg.ign = make(map[int]*ignCounts)
			}
			t := agg.ign[id]
			if t == nil {
				t = &ignCounts{paths: make(map[string]struct{})}
				agg.ign[id] = t
			}
			t.requests += g.requests
			t.authFail += g.authFail
			t.notFound += g.notFound
			for p := range g.paths {
				t.paths[p] = struct{}{}
			}
		}
	}
	for _, x := range s.samples {
		if x.TS >= now-d.cfg.WindowMs {
			agg.samples = append(agg.samples, x)
		}
	}
	if len(agg.samples) > 5 {
		agg.samples = agg.samples[len(agg.samples)-5:]
	}
	agg.last = s.last
	return agg
}

// effective reproduit _effective() : metriques de la fenetre pour une regle,
// une fois retranchees les requetes que paths-ignore exclut pour elle.
func (d *Detector) effective(agg aggregate, ruleID int) ruleView {
	v := ruleView{requests: agg.requests, authFail: agg.authFail, notFound: agg.notFound, pathCount: len(agg.paths)}
	g := agg.ign[ruleID]
	if g == nil {
		return v
	}
	pc := 0
	for p := range agg.paths {
		if _, ign := g.paths[p]; !ign {
			pc++
		}
	}
	v.requests = maxInt(0, agg.requests-g.requests)
	v.authFail = maxInt(0, agg.authFail-g.authFail)
	v.notFound = maxInt(0, agg.notFound-g.notFound)
	v.pathCount = pc
	return v
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (d *Detector) enter(s *ipState, typ string) bool {
	if _, ok := s.active[typ]; ok {
		return false
	}
	s.active[typ] = struct{}{}
	return true
}
func (d *Detector) clear(s *ipState, typ string) {
	delete(s.active, typ)
}

func firstUAs(uas map[string]struct{}, n int) []string {
	out := make([]string, 0, n)
	for u := range uas {
		if len(out) >= n {
			break
		}
		out = append(out, u)
	}
	return out
}

func singleVhost(vhosts map[string]struct{}) string {
	if len(vhosts) != 1 {
		return ""
	}
	for v := range vhosts {
		return v
	}
	return ""
}

func anyUAMatches(uas map[string]struct{}, re *regexp.Regexp) bool {
	if re == nil {
		return false
	}
	for u := range uas {
		if re.MatchString(u) {
			return true
		}
	}
	return false
}

// Evaluate reproduit evaluate(now) : la passe de detection par cycle.
func (d *Detector) evaluate(now int64) []Alert {
	d.prune(now)
	var alerts []Alert
	c := d.cfg

	// Regles personnalisees scope: global : une alerte de campagne par regle (campaign.go).
	alerts = append(alerts, d.evaluateCampaigns(now)...)

	// Ordre d'insertion (comme la Map JS) : l'ordre de creation des alertes,
	// donc leurs ids, doit etre deterministe et identique a l'implementation Node.
	// d.order peut contenir des entrees obsolescentes (IP purgee puis revue) : on
	// les ignore en comparant le seq.
	for _, ref := range d.order {
		ip := ref.ip
		s, ok := d.ips[ip]
		if !ok || s.seq != ref.seq {
			continue
		}
		agg := d.aggregate(s, now)
		vhost := singleVhost(agg.vhosts)
		if d.isExcludedForVhosts(ip, agg.vhosts) {
			continue
		}

		// base(v) : v porte les metriques propres a la regle (voir effective()).
		base := func(v ruleView) Evidence {
			return Evidence{
				IP: ip, Vhost: vhost, FirstSeen: agg.first, LastSeen: agg.last,
				Requests: v.requests, DistinctPaths: v.pathCount,
				UserAgents: firstUAs(agg.uas, 3), Statuses: agg.statuses, Samples: agg.samples,
			}
		}

		windowMin := int(math.Round(float64(c.WindowMs) / 60000))

		// Brute force
		bfE := d.effective(agg, RuleBruteforce)
		bfMet := c.Bruteforce.Enable && !d.ruleSuppressedForVhosts(agg.vhosts, RuleBruteforce) &&
			bfE.authFail >= c.Bruteforce.MinFailures
		if bfMet && d.enter(s, "bruteforce") {
			ev := base(bfE)
			ev.AuthFailures = bfE.authFail
			alerts = append(alerts, Alert{
				Type: "bruteforce", Explanation: Explanations["bruteforce"], Severity: "high",
				Summary:  fmt.Sprintf("%d echecs d authentification depuis %s sur les dernieres %d min", bfE.authFail, ip, windowMin),
				Evidence: ev,
			})
		} else if !bfMet {
			d.clear(s, "bruteforce")
		}

		// Scan
		scE := d.effective(agg, RuleScan)
		scanMet := c.Scan.Enable && !d.ruleSuppressedForVhosts(agg.vhosts, RuleScan) &&
			scE.requests >= c.Scan.MinRequests && scE.pathCount >= c.Scan.MinDistinct &&
			scE.requests > 0 && float64(scE.notFound)/float64(scE.requests) >= c.Scan.MinNotFoundRatio
		if scanMet && d.enter(s, "scan") {
			ev := base(scE)
			ev.NotFound = scE.notFound
			pct := 0
			if scE.requests > 0 {
				pct = int(math.Round(100 * float64(scE.notFound) / float64(scE.requests)))
			}
			alerts = append(alerts, Alert{
				Type: "scan", Explanation: Explanations["scan"], Severity: "medium",
				Summary:  fmt.Sprintf("%s sonde %d chemins distincts, %d%% en 404", ip, scE.pathCount, pct),
				Evidence: ev,
			})
		} else if !scanMet {
			d.clear(s, "scan")
		}

		// Flood
		flE := d.effective(agg, RuleFlood)
		floodMet := c.Flood.Enable && !d.ruleSuppressedForVhosts(agg.vhosts, RuleFlood) &&
			flE.requests >= c.Flood.MinRequests
		if floodMet && d.enter(s, "flood") {
			spanSec := math.Max(1, float64(agg.last-agg.first)/1000)
			rps := math.Round((float64(flE.requests)/spanSec)*100) / 100
			ev := base(flE)
			ev.RequestsPerSecond = rps
			alerts = append(alerts, Alert{
				Type: "flood", Explanation: Explanations["flood"], Severity: "high",
				Summary:  fmt.Sprintf("%d requetes depuis %s sur les dernieres %d min (%.1f/s)", flE.requests, ip, windowMin, float64(flE.requests)/spanSec),
				Evidence: ev,
			})
		} else if !floodMet {
			d.clear(s, "flood")
		}

		// Scraping
		srE := d.effective(agg, RuleScraping)
		scrapeMet := c.Scraping.Enable && !d.ruleSuppressedForVhosts(agg.vhosts, RuleScraping) &&
			srE.requests >= c.Scraping.MinRequests && srE.pathCount <= c.Scraping.MaxDistinct &&
			anyUAMatches(agg.uas, c.Scraping.UAHint)
		if scrapeMet && d.enter(s, "scraping") {
			alerts = append(alerts, Alert{
				Type: "scraping", Explanation: Explanations["scraping"], Severity: "low",
				Summary:  fmt.Sprintf("%d requetes depuis %s sur %d chemin(s), agent automatise, dernieres %d min", srE.requests, ip, srE.pathCount, windowMin),
				Evidence: base(srE),
			})
		} else if !scrapeMet {
			d.clear(s, "scraping")
		}

		// Regles personnalisees
		for _, rule := range d.customRules {
			if rule.Global {
				continue // traite par evaluateCampaigns : une alerte de campagne
			}
			stateKey := fmt.Sprintf("custom:%d", rule.ID)
			windowMinutes := ClampCustomWindowMinutes(rule.WindowMinutes)
			count := d.customCount(s, now, rule.ID, int64(windowMinutes)*60_000)
			reached := count >= rule.MinMatches
			met := rule.enabledForEvaluate() && !d.ruleSuppressedForVhosts(agg.vhosts, rule.ID) && reached
			if met && d.enter(s, stateKey) {
				sev := rule.Severity
				if sev == "" {
					sev = "medium"
				}
				what := rule.Description
				if what == "" {
					what = fmt.Sprintf(`Regle personnalisee "%s"`, rule.Name)
				}
				vhostSuffix := ""
				if vhost != "" {
					vhostSuffix = " sur " + vhost
				}
				ev := base(ruleView{requests: agg.requests, authFail: agg.authFail, notFound: agg.notFound, pathCount: len(agg.paths)})
				ev.RuleID = rule.ID
				ev.RuleName = rule.Name
				ev.Matches = count
				summary := fmt.Sprintf(`Regle "%s" declenchee par %s%s : %d correspondance(s) sur les dernieres %d min`, rule.Name, ip, vhostSuffix, count, windowMinutes)
				alerts = append(alerts, Alert{
					Type: fmt.Sprintf("custom_%d", rule.ID),
					Explanation: Explanation{
						ID: rule.ID, What: what,
						Why:    "Regle definie par l operateur — voir sa description.",
						Legit:  "Depend entierement du critere choisi par l operateur.",
						Action: "Verifier le trafic correspondant et ajuster le seuil de la regle si besoin.",
					},
					Severity: sev,
					Summary:  summary,
					Evidence: ev,
				})
			} else if !met {
				d.clear(s, stateKey)
			}
		}
	}
	return alerts
}

// Stats reproduit stats().
func (d *Detector) stats() Stats {
	active := 0
	for _, s := range d.ips {
		active += len(s.active)
	}
	return Stats{TrackedIps: len(d.ips), ActiveAlerts: active}
}

// SetExceptions : version thread-safe (le tailer, la boucle d'evaluation et les
// handlers HTTP y accedent depuis des goroutines distinctes - Node, mono-thread, n'avait pas ce souci).
func (d *Detector) SetExceptions(list []Exception) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.setExceptions(list)
}

// IsExcludedForVhosts : version thread-safe (le tailer, la boucle d'evaluation et les
// handlers HTTP y accedent depuis des goroutines distinctes - Node, mono-thread, n'avait pas ce souci).
func (d *Detector) IsExcludedForVhosts(ip string, vhosts map[string]struct{}) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.isExcludedForVhosts(ip, vhosts)
}

// SetCustomRules : version thread-safe (le tailer, la boucle d'evaluation et les
// handlers HTTP y accedent depuis des goroutines distinctes - Node, mono-thread, n'avait pas ce souci).
func (d *Detector) SetCustomRules(list []CustomRule) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.setCustomRules(list)
}

// RetentionMs : version thread-safe (le tailer, la boucle d'evaluation et les
// handlers HTTP y accedent depuis des goroutines distinctes - Node, mono-thread, n'avait pas ce souci).
func (d *Detector) RetentionMs() int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.retentionSnapshot()
}

// Cfg : version thread-safe (le tailer, la boucle d'evaluation et les
// handlers HTTP y accedent depuis des goroutines distinctes - Node, mono-thread, n'avait pas ce souci).
func (d *Detector) Cfg() Config {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cfgSnapshot()
}

// SetRuleEnabled : version thread-safe (le tailer, la boucle d'evaluation et les
// handlers HTTP y accedent depuis des goroutines distinctes - Node, mono-thread, n'avait pas ce souci).
func (d *Detector) SetRuleEnabled(key string, enable bool) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.setRuleEnabled(key, enable)
}

// SetVhostRules : version thread-safe (le tailer, la boucle d'evaluation et les
// handlers HTTP y accedent depuis des goroutines distinctes - Node, mono-thread, n'avait pas ce souci).
func (d *Detector) SetVhostRules(m map[string]VhostCfg) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.setVhostRules(m)
}

// RuleSuppressedForVhosts : version thread-safe (le tailer, la boucle d'evaluation et les
// handlers HTTP y accedent depuis des goroutines distinctes - Node, mono-thread, n'avait pas ce souci).
func (d *Detector) RuleSuppressedForVhosts(vhosts map[string]struct{}, ruleID int) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.ruleSuppressedForVhosts(vhosts, ruleID)
}

// Add : version thread-safe (le tailer, la boucle d'evaluation et les
// handlers HTTP y accedent depuis des goroutines distinctes - Node, mono-thread, n'avait pas ce souci).
func (d *Detector) Add(entry parse.AccessEntry) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.add(entry)
}

// Prune : version thread-safe (le tailer, la boucle d'evaluation et les
// handlers HTTP y accedent depuis des goroutines distinctes - Node, mono-thread, n'avait pas ce souci).
func (d *Detector) Prune(now int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.prune(now)
}

// Evaluate : version thread-safe (le tailer, la boucle d'evaluation et les
// handlers HTTP y accedent depuis des goroutines distinctes - Node, mono-thread, n'avait pas ce souci).
func (d *Detector) Evaluate(now int64) []Alert {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.evaluate(now)
}

// Stats : version thread-safe (le tailer, la boucle d'evaluation et les
// handlers HTTP y accedent depuis des goroutines distinctes - Node, mono-thread, n'avait pas ce souci).
func (d *Detector) Stats() Stats {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stats()
}

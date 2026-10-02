package baseline

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MadToSigma et HoursPerWeek reproduisent MAD_TO_SIGMA et HOURS_PER_WEEK.
const (
	MadToSigma   = 1.4826
	HoursPerWeek = 168
	// RelevantMinSamples : une cle (vhost, pays) n'est « suivie » pour la couverture
	// qu'a partir de 24 heures observees (un Host croise une fois ne gonfle plus le total).
	RelevantMinSamples = 24
)

// Config reproduit DEFAULTS.
type Config struct {
	MinSamplesPerBucket int
	LearningDays        int
	SigmaThreshold      float64
	MinAbsoluteRequests int64
	// Bascule au niveau de la regle (modale "Regles" du dashboard). Un
	// pointeur nil signifie "non precise -> active" (parite avec le merge
	// JS `{...DEFAULTS, ...cfg}` quand cfg n'a pas la cle "enable"), a
	// l'image de CustomRule.Enable dans internal/detect. L'apprentissage
	// continue meme desactive - seule l'alerte est retenue - pour que
	// reactiver plus tard ne reparte pas de zero. Non lu par ce package :
	// c'est a l'appelant (etape 7/8, l'orchestrateur HTTP) de sauter
	// l'appel a Check() quand Enabled() est faux.
	Enable *bool
}

// Enabled renvoie l'etat effectif de la bascule "enable" (defaut : active).
func (c Config) Enabled() bool { return c.Enable == nil || *c.Enable }

// Cfg expose la config courante (copie) - utilise par l'orchestrateur HTTP
// (etape 7/8) pour exposer les seuils reels dans le catalogue des regles et
// pour lire l'etat enable/disable courant.
func (b *Baseline) CfgNL() Config { return b.cfg }

// SetEnabled bascule la regle "volumetric"/"country_traffic" associee a
// cette instance sans attendre un redemarrage - meme principe que
// detect.Detector.SetRuleEnabled, appele par /api/rules/toggle.
func (b *Baseline) SetEnabledNL(enable bool) { b.cfg.Enable = &enable }

// DefaultConfig reproduit DEFAULTS.
func DefaultConfig() Config {
	return Config{
		MinSamplesPerBucket: 3,
		LearningDays:        21,
		SigmaThreshold:      6,
		MinAbsoluteRequests: 100,
	}
}

func mergeConfig(cfg Config) Config {
	d := DefaultConfig()
	if cfg.MinSamplesPerBucket != 0 {
		d.MinSamplesPerBucket = cfg.MinSamplesPerBucket
	}
	if cfg.LearningDays != 0 {
		d.LearningDays = cfg.LearningDays
	}
	if cfg.SigmaThreshold != 0 {
		d.SigmaThreshold = cfg.SigmaThreshold
	}
	if cfg.MinAbsoluteRequests != 0 {
		d.MinAbsoluteRequests = cfg.MinAbsoluteRequests
	}
	if cfg.Enable != nil {
		d.Enable = cfg.Enable
	}
	return d
}

// median replique median(). sorted doit deja etre trie.
func median(sorted []float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return sorted[(n-1)/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

// mad replique mad() : deviation absolue mediane, mise a l'echelle pour etre
// comparable a un ecart-type.
func mad(values []float64, med float64) float64 {
	if len(values) == 0 {
		return 0
	}
	deviations := make([]float64, len(values))
	for i, v := range values {
		deviations[i] = math.Abs(v - med)
	}
	sort.Float64s(deviations)
	return median(deviations) * MadToSigma
}

// HourOfWeek replique hourOfWeek() : index de creneau, lundi 00h = 0, en
// heure LOCALE du processus (voir le commentaire du fichier JS d'origine sur
// le changement d'heure) - t.Local() suit la meme regle que les getters
// locaux de Date en JS, pilotee par la meme variable d'environnement TZ.
func HourOfWeek(t time.Time) int {
	lt := t.Local()
	day := (int(lt.Weekday()) + 6) % 7 // lundi = 0
	return day*24 + lt.Hour()
}

// Metrics reproduit l'argument "metrics" d'observe()/check().
type Metrics struct {
	Requests      int64
	DistinctIps   int64
	DistinctPaths int64
	Errors        int64
}

// State reproduit la valeur (de)serialisee par toJSON() / le constructeur.
type State struct {
	StartedAt int64              `json:"startedAt"`
	Buckets   map[string][]int64 `json:"buckets"`
	Excluded  []string           `json:"excluded"`
}

// Baseline porte la classe Baseline.
type Baseline struct {
	mu        sync.Mutex
	cfg       Config
	buckets   map[string][]int64 // cle = "vhost|hourOfWeek"
	startedAt int64
	excluded  map[string]struct{}
}

// New reproduit le constructeur. state peut etre nil (demarrage a neuf).
func New(cfg Config, state *State) *Baseline {
	b := &Baseline{
		cfg:      mergeConfig(cfg),
		buckets:  make(map[string][]int64),
		excluded: make(map[string]struct{}),
	}
	if state != nil {
		for k, v := range state.Buckets {
			cp := make([]int64, len(v))
			copy(cp, v)
			b.buckets[k] = cp
		}
		for _, ex := range state.Excluded {
			b.excluded[ex] = struct{}{}
		}
		if state.StartedAt != 0 {
			b.startedAt = state.StartedAt
		}
	}
	if b.startedAt == 0 {
		b.startedAt = time.Now().UnixMilli()
	}
	return b
}

func key(vhost string, how int) string {
	return vhost + "|" + strconv.Itoa(how)
}

// isoHourStamp replique `new Date(date).toISOString().slice(0, 13)` : les 13
// premiers caracteres d'un horodatage ISO 8601 en UTC, soit "AAAA-MM-JJThh".
func isoHourStamp(t time.Time) string {
	s := t.UTC().Format("2006-01-02T15:04:05.000Z")
	if len(s) < 13 {
		return s
	}
	return s[:13]
}

// Observe replique observe() : enregistre une observation horaire. metrics
// porte le volume et les signaux structurels qui distinguent une foule d'un
// flood.
func (b *Baseline) ObserveNL(vhost string, t time.Time, metrics Metrics) {
	how := HourOfWeek(t)
	k := key(vhost, how)
	stamp := vhost + "|" + isoHourStamp(t)
	// Une periode que l'operateur a marquee comme normale ne doit pas
	// instruire la baseline.
	if _, excluded := b.excluded[stamp]; excluded {
		return
	}
	arr := b.buckets[k]
	arr = append(arr, metrics.Requests)
	// Garde les 12 dernieres observations de chaque creneau - environ trois mois.
	if len(arr) > 12 {
		arr = arr[len(arr)-12:]
	}
	b.buckets[k] = arr
}

// LearningDaysElapsed replique learningDaysElapsed().
func (b *Baseline) LearningDaysElapsedNL() float64 {
	return float64(time.Now().UnixMilli()-b.startedAt) / 86_400_000
}

// IsLearning replique isLearning().
func (b *Baseline) IsLearningNL() bool {
	return b.LearningDaysElapsedNL() < float64(b.cfg.LearningDays)
}

// Reference reproduit la valeur de retour de reference().
type Reference struct {
	Median  float64
	Mad     float64
	Samples int
}

// Reference replique reference() : statistiques de reference pour un
// creneau, ou nil quand l'echantillon est trop mince.
func (b *Baseline) ReferenceNL(vhost string, t time.Time) *Reference {
	arr := b.buckets[key(vhost, HourOfWeek(t))]
	if len(arr) < b.cfg.MinSamplesPerBucket {
		return nil
	}
	sorted := make([]float64, len(arr))
	for i, v := range arr {
		sorted[i] = float64(v)
	}
	sort.Float64s(sorted)
	med := median(sorted)
	floatArr := make([]float64, len(arr))
	for i, v := range arr {
		floatArr[i] = float64(v)
	}
	return &Reference{Median: med, Mad: mad(floatArr, med), Samples: len(arr)}
}

// Structure reproduit le sous-objet "structure" du resultat de check().
type Structure struct {
	DistinctIps   int64
	DistinctPaths int64
	ErrorRatio    float64
	LooksOrganic  bool
}

// CheckResult reproduit la valeur de retour de check() (Learning distingue le
// cas "apprentissage en cours" du cas "anomalie", un nil de CheckResult
// reproduit le "null" JS - rien a signaler).
type CheckResult struct {
	Learning     bool
	DaysElapsed  float64
	DaysRequired int

	Anomaly   bool
	Vhost     string
	Hour      string
	Observed  int64
	Expected  int64
	Deviation float64
	Samples   int
	Structure Structure
	Severity  string
	Summary   string
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }
func round3(v float64) float64 { return math.Round(v*1000) / 1000 }

// Check replique check() : compare une observation a sa reference.
//
// Renvoie nil quand il n'y a rien a dire - encore en apprentissage,
// echantillon trop mince, volume trop petit, ou simplement normal. Quand il
// signale, il dit si la structure ressemble a une audience ou a un flood, et
// ne pretend jamais plus de certitude que les donnees n'en portent.
func (b *Baseline) CheckNL(vhost string, t time.Time, metrics Metrics) *CheckResult {
	if b.IsLearningNL() {
		return &CheckResult{
			Learning:     true,
			DaysElapsed:  round1(b.LearningDaysElapsedNL()),
			DaysRequired: b.cfg.LearningDays,
		}
	}
	ref := b.ReferenceNL(vhost, t)
	if ref == nil {
		return nil
	}
	if metrics.Requests < b.cfg.MinAbsoluteRequests {
		return nil
	}

	// Un MAD nul signifie un creneau parfaitement stable ; on retombe sur un
	// plancher relatif pour que la deviation reste finie plutot que
	// d'exploser vers l'infini.
	spread := ref.Mad
	if spread <= 0 {
		spread = math.Max(1, ref.Median*0.1)
	}
	deviation := (float64(metrics.Requests) - ref.Median) / spread
	if deviation < b.cfg.SigmaThreshold {
		return nil
	}

	reqF := math.Max(1, float64(metrics.Requests))
	ipsPerRequest := float64(metrics.DistinctIps) / reqF
	errorRatio := float64(metrics.Errors) / reqF
	pathsPerRequest := float64(metrics.DistinctPaths) / reqF

	// Une vraie audience : beaucoup d'adresses, des chemins varies, peu d'erreurs.
	looksOrganic := ipsPerRequest > 0.1 && pathsPerRequest > 0.05 && errorRatio < 0.2

	severity := "medium"
	if looksOrganic {
		severity = "low"
	} else if deviation > b.cfg.SigmaThreshold*2 {
		severity = "high"
	}

	expected := int64(math.Round(ref.Median))
	var summary string
	if looksOrganic {
		summary = fmt.Sprintf("Trafic inhabituel sur %s : %d requetes contre %d attendues, mais la structure ressemble a une audience reelle",
			vhost, metrics.Requests, expected)
	} else {
		summary = fmt.Sprintf("Pic anormal sur %s : %d requetes contre %d attendues (%.1f ecarts), peu d adresses distinctes",
			vhost, metrics.Requests, expected, deviation)
	}

	return &CheckResult{
		Anomaly:   true,
		Vhost:     vhost,
		Hour:      isoHourStamp(t),
		Observed:  metrics.Requests,
		Expected:  expected,
		Deviation: round1(deviation),
		Samples:   ref.Samples,
		Structure: Structure{
			DistinctIps:   metrics.DistinctIps,
			DistinctPaths: metrics.DistinctPaths,
			ErrorRatio:    round3(errorRatio),
			LooksOrganic:  looksOrganic,
		},
		Severity: severity,
		Summary:  summary,
	}
}

// Exclude replique exclude() : marque une heure comme normale, pour qu'elle
// cesse de compter contre la baseline.
func (b *Baseline) ExcludeNL(vhost, isoHour string) {
	h := isoHour
	if len(h) > 13 {
		h = h[:13]
	}
	b.excluded[vhost+"|"+h] = struct{}{}
}

// ExportState replique toJSON() : etat serialisable, pour survivre a un redemarrage.
func (b *Baseline) ExportStateNL() State {
	buckets := make(map[string][]int64, len(b.buckets))
	for k, v := range b.buckets {
		cp := make([]int64, len(v))
		copy(cp, v)
		buckets[k] = cp
	}
	excluded := make([]string, 0, len(b.excluded))
	for e := range b.excluded {
		excluded = append(excluded, e)
	}
	sort.Strings(excluded)
	return State{StartedAt: b.startedAt, Buckets: buckets, Excluded: excluded}
}

// Stats reproduit stats().
//
// Correctif (retour utilisateur, v12.49.3 cote Node) : coverage() divisait le
// nombre de creneaux remplis par HoursPerWeek (168) sans jamais tenir compte
// du nombre de vhosts suivis, alors que b.buckets est une grille PAR VHOST
// (cle "vhost|hourOfWeek") : avec plusieurs vhosts actifs, il existe
// vhosts*168 creneaux possibles, pas 168. Le nombre de creneaux possibles est
// compte reellement (vhosts suivis x 168), et le taux de couverture est
// rapporte a CE total.
type Stats struct {
	Learning       bool
	DaysElapsed    float64
	DaysRequired   int
	StartedAt      time.Time
	BucketsTracked int
	BucketsUsable  int // creneaux utilisables des cles suivies
	VhostsTracked  int // cles suivies (>= RelevantMinSamples heures observees)
	KeysTracked    int
	SporadicKeys   int
	TotalSlots     int
	Coverage       float64
}

func (b *Baseline) StatsNL() Stats {
	type agg struct{ samples, usable int }
	per := make(map[string]*agg)
	for k, arr := range b.buckets {
		name := k
		if i := strings.LastIndex(k, "|"); i >= 0 {
			name = k[:i]
		}
		e := per[name]
		if e == nil {
			e = &agg{}
			per[name] = e
		}
		e.samples += len(arr)
		if len(arr) >= b.cfg.MinSamplesPerBucket {
			e.usable++
		}
	}
	relevant, filled := 0, 0
	for _, e := range per {
		if e.samples >= RelevantMinSamples {
			relevant++
			filled += e.usable
		}
	}
	totalSlots := relevant
	if totalSlots < 1 {
		totalSlots = 1
	}
	totalSlots *= HoursPerWeek
	return Stats{
		Learning:       b.IsLearningNL(),
		DaysElapsed:    round1(b.LearningDaysElapsedNL()),
		DaysRequired:   b.cfg.LearningDays,
		StartedAt:      time.UnixMilli(b.startedAt).UTC(),
		BucketsTracked: len(b.buckets),
		BucketsUsable:  filled,
		VhostsTracked:  relevant,
		KeysTracked:    len(per),
		SporadicKeys:   len(per) - relevant,
		TotalSlots:     totalSlots,
		Coverage:       round1(100 * float64(filled) / float64(totalSlots)),
	}
}

// Slot : ce qui est appris pour un creneau de la semaine (lundi 0h = 0).
type Slot struct {
	How       int     `json:"how"`
	Samples   int     `json:"samples"`
	Usable    bool    `json:"usable"`
	Median    int64   `json:"median"`
	Spread    float64 `json:"spread"`
	Threshold int64   `json:"threshold"`
}

// Profile : les 168 creneaux d'une cle.
type Profile struct {
	Key                 string  `json:"key"`
	Slots               []Slot  `json:"slots"`
	Sigma               float64 `json:"sigma"`
	MinAbsoluteRequests int64   `json:"minAbsoluteRequests"`
	MinSamples          int     `json:"minSamples"`
}

func (b *Baseline) ProfileNL(k string) Profile {
	p := Profile{Key: k, Slots: make([]Slot, 0, HoursPerWeek), Sigma: b.cfg.SigmaThreshold,
		MinAbsoluteRequests: b.cfg.MinAbsoluteRequests, MinSamples: b.cfg.MinSamplesPerBucket}
	for how := 0; how < HoursPerWeek; how++ {
		arr := b.buckets[key(k, how)]
		if len(arr) == 0 {
			p.Slots = append(p.Slots, Slot{How: how})
			continue
		}
		vals := make([]float64, len(arr))
		for i, v := range arr {
			vals[i] = float64(v)
		}
		sorted := append([]float64(nil), vals...)
		sort.Float64s(sorted)
		med := median(sorted)
		spread := mad(vals, med)
		if spread <= 0 {
			spread = math.Max(1, med*0.1)
		}
		thr := math.Max(med+b.cfg.SigmaThreshold*spread, float64(b.cfg.MinAbsoluteRequests))
		p.Slots = append(p.Slots, Slot{How: how, Samples: len(arr), Usable: len(arr) >= b.cfg.MinSamplesPerBucket,
			Median: int64(math.Round(med)), Spread: round1(spread), Threshold: int64(math.Round(thr))})
	}
	return p
}

// KeySummary : resume d'une cle.
type KeySummary struct {
	Key            string `json:"key"`
	Samples        int    `json:"samples"`
	UsableSlots    int    `json:"usableSlots"`
	Relevant       bool   `json:"relevant"`
	WeeklyEstimate int64  `json:"weeklyEstimate"`
	PeakPerHour    int64  `json:"peakPerHour"`
	PeakHow        int    `json:"peakHow"`
}

func (b *Baseline) KeysSummaryNL(limit int) []KeySummary {
	type acc struct {
		KeySummary
		weekly, peak float64
	}
	per := make(map[string]*acc)
	for bk, arr := range b.buckets {
		i := strings.LastIndex(bk, "|")
		if i < 0 {
			continue
		}
		name := bk[:i]
		how, _ := strconv.Atoi(bk[i+1:])
		sorted := make([]float64, len(arr))
		for j, v := range arr {
			sorted[j] = float64(v)
		}
		sort.Float64s(sorted)
		med := median(sorted)
		e := per[name]
		if e == nil {
			e = &acc{KeySummary: KeySummary{Key: name}}
			per[name] = e
		}
		e.Samples += len(arr)
		if len(arr) >= b.cfg.MinSamplesPerBucket {
			e.UsableSlots++
		}
		e.weekly += med
		if med > e.peak {
			e.peak, e.PeakHow = med, how
		}
	}
	out := make([]KeySummary, 0, len(per))
	for _, e := range per {
		e.Relevant = e.Samples >= RelevantMinSamples
		e.WeeklyEstimate = int64(math.Round(e.weekly))
		e.PeakPerHour = int64(math.Round(e.peak))
		out = append(out, e.KeySummary)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].WeeklyEstimate != out[j].WeeklyEstimate {
			return out[i].WeeklyEstimate > out[j].WeeklyEstimate
		}
		return out[i].Key < out[j].Key
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Profile / KeysSummary : versions thread-safe.
func (b *Baseline) Profile(k string) Profile {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ProfileNL(k)
}

func (b *Baseline) KeysSummary(limit int) []KeySummary {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.KeysSummaryNL(limit)
}

// Cfg : version thread-safe (tailer, boucles de fond et handlers HTTP
// y accedent depuis des goroutines distinctes).
func (b *Baseline) Cfg() Config {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.CfgNL()
}

// SetEnabled : version thread-safe (tailer, boucles de fond et handlers HTTP
// y accedent depuis des goroutines distinctes).
func (b *Baseline) SetEnabled(enable bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.SetEnabledNL(enable)
}

// Observe : version thread-safe (tailer, boucles de fond et handlers HTTP
// y accedent depuis des goroutines distinctes).
func (b *Baseline) Observe(vhost string, t time.Time, metrics Metrics) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ObserveNL(vhost, t, metrics)
}

// LearningDaysElapsed : version thread-safe (tailer, boucles de fond et handlers HTTP
// y accedent depuis des goroutines distinctes).
func (b *Baseline) LearningDaysElapsed() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.LearningDaysElapsedNL()
}

// IsLearning : version thread-safe (tailer, boucles de fond et handlers HTTP
// y accedent depuis des goroutines distinctes).
func (b *Baseline) IsLearning() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.IsLearningNL()
}

// Reference : version thread-safe (tailer, boucles de fond et handlers HTTP
// y accedent depuis des goroutines distinctes).
func (b *Baseline) Reference(vhost string, t time.Time) *Reference {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ReferenceNL(vhost, t)
}

// Check : version thread-safe (tailer, boucles de fond et handlers HTTP
// y accedent depuis des goroutines distinctes).
func (b *Baseline) Check(vhost string, t time.Time, metrics Metrics) *CheckResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.CheckNL(vhost, t, metrics)
}

// Exclude : version thread-safe (tailer, boucles de fond et handlers HTTP
// y accedent depuis des goroutines distinctes).
func (b *Baseline) Exclude(vhost, isoHour string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ExcludeNL(vhost, isoHour)
}

// ExportState : version thread-safe (tailer, boucles de fond et handlers HTTP
// y accedent depuis des goroutines distinctes).
func (b *Baseline) ExportState() State {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ExportStateNL()
}

// Stats : version thread-safe (tailer, boucles de fond et handlers HTTP
// y accedent depuis des goroutines distinctes).
func (b *Baseline) Stats() Stats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.StatsNL()
}

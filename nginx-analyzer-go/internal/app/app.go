// Package app assemble tous les paquets de l'agent (config, parse, tail,
// detect, baseline, store, rules, geoip, botclass, blocklistsources) en un
// seul objet cable, exactement comme server.js le fait au niveau module —
// c'est le pendant Go de la section "construction" de server.js, avant la
// section API HTTP (portee par internal/httpapi) et la section demarrage
// (portee par cmd/analyzer).
package app

import (
	"encoding/json"
	"log"
	"sync"
	"time"

	"nginx-analyzer-go/internal/baseline"
	"nginx-analyzer-go/internal/botclass"
	"nginx-analyzer-go/internal/config"
	"nginx-analyzer-go/internal/detect"
	"nginx-analyzer-go/internal/geoip"
	"nginx-analyzer-go/internal/parse"
	"nginx-analyzer-go/internal/rules"
	"nginx-analyzer-go/internal/store"
	"nginx-analyzer-go/internal/tail"
)

// vhostHourMetrics reproduit l'accumulateur { requests, errors, ips: Set,
// paths: Set } tenu par trackStructure() cote server.js.
type vhostHourMetrics struct {
	Requests int64
	Errors   int64
	IPs      map[string]struct{}
	Paths    map[string]struct{}
}

// countryHourMetrics reproduit son equivalent par pays (vhosts distincts au
// lieu de chemins distincts - voir trackCountryStructure() cote server.js).
type countryHourMetrics struct {
	Requests int64
	Errors   int64
	IPs      map[string]struct{}
	Vhosts   map[string]struct{}
}

// RecentGeoEvent reproduit un element de recentGeoEvents (carte en direct).
type RecentGeoEvent struct {
	Seq      int64  `json:"seq"`
	TS       int64  `json:"ts"`
	Vhost    string `json:"vhost"`
	Country  string `json:"country"`
	IsBot    *bool  `json:"isBot"`
	Category string `json:"category"`
}

// App porte l'etat assemble de l'agent : tout ce que server.js construit au
// niveau module avant de definir ses routes HTTP.
type App struct {
	Cfg *config.Config

	Store           *store.Store
	Rules           *rules.Manager
	Detector        *detect.Detector
	Baseline        *baseline.Baseline
	CountryBaseline *baseline.Baseline

	Tailer          *tail.Tailer
	WafTailer       *tail.Tailer
	BlocklistTailer *tail.Tailer

	hourlyMu            sync.Mutex
	hourlyByHour        *baseline.HourlyAccumulator[string, vhostHourMetrics]
	hourlyCountryByHour *baseline.HourlyAccumulator[string, countryHourMetrics]

	geoMu     sync.Mutex
	recentGeo []RecentGeoEvent
	geoSeq    int64
}

// loadBaselineState relit un *baseline.State depuis la valeur generique
// renvoyee par store.GetState() (JSON deja decode en map[string]any/etc.) -
// un aller-retour JSON est le moyen le plus simple de retomber sur le type
// concret attendu par baseline.New(), sans dupliquer le decodage a la main.
func loadBaselineState(raw any) *baseline.State {
	if raw == nil {
		return nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var st baseline.State
	if err := json.Unmarshal(b, &st); err != nil {
		return nil
	}
	return &st
}

func boolPtr(b bool) *bool { return &b }

// New assemble l'App a partir de la config, exactement comme server.js
// construit store/rulesManager/detector/baseline/countryBaseline/tailers au
// niveau module.
func New(cfg *config.Config) *App {
	// La resolution GeoIP est partagee entre l'analyzer et le dashboard cote
	// Node (meme raisonnement dans lib/geoip.js) - ici, le paquet geoip lit
	// ses propres variables d'environnement au chargement ; on les
	// resynchronise depuis la Config deja chargee pour rester la seule
	// source de verite si jamais les deux divergent (tests, overrides).
	geoip.CityDB = cfg.GeoipCityDB
	geoip.CountryDB = cfg.GeoipCountryDB
	geoip.ASNDB = cfg.GeoipAsnDB

	st := store.New(cfg.DBPath, store.Options{Retention: store.Retention{
		MinuteHours: config.StoreRetentionMinuteHours,
		HourDays:    config.StoreRetentionHourDays,
		DayDays:     config.StoreRetentionDayDays,
	}})

	rulesManager := rules.New(st, map[string]bool{
		"bruteforce":      cfg.RuleBruteforceEnable,
		"scan":            cfg.RuleScanEnable,
		"flood":           cfg.RuleFloodEnable,
		"scraping":        cfg.RuleScrapingEnable,
		"volumetric":      cfg.RuleVolumetricEnable,
		"country_traffic": cfg.RuleCountryTrafficEnable,
	})

	detector := detect.New(detect.Config{
		WindowMs:      int64(cfg.WindowMs),
		BucketMs:      config.DetectorBucketMs,
		PruneEveryMs:  config.DetectorPruneEveryMs,
		MaxTrackedIps: config.DetectorMaxTrackedIps,
		Bruteforce: detect.BruteforceCfg{
			Enable: rulesManager.IsEnabled("bruteforce"), MinFailures: cfg.BfMinFailures,
			Statuses: []int{401, 403}, PathHint: detect.DefaultConfig().Bruteforce.PathHint,
		},
		Scan: detect.ScanCfg{
			Enable: rulesManager.IsEnabled("scan"), MinRequests: cfg.ScanMinRequests,
			MinDistinct: cfg.ScanMinDistinct, MinNotFoundRatio: detect.DefaultConfig().Scan.MinNotFoundRatio,
		},
		Flood: detect.FloodCfg{Enable: rulesManager.IsEnabled("flood"), MinRequests: cfg.FloodMinRequests},
		Scraping: detect.ScrapingCfg{
			Enable: rulesManager.IsEnabled("scraping"), MinRequests: cfg.ScrapeMinRequests,
			MaxDistinct: detect.DefaultConfig().Scraping.MaxDistinct, UAHint: detect.DefaultConfig().Scraping.UAHint,
		},
	})
	detector.SetCustomRules(ToDetectCustomRules(rulesManager.CustomValid()))

	bl := baseline.New(baseline.Config{
		LearningDays: cfg.LearningDays, SigmaThreshold: float64(cfg.SigmaThresh),
		Enable: boolPtr(rulesManager.IsEnabled("volumetric")),
	}, loadBaselineState(st.GetState("baseline")))

	countryBl := baseline.New(baseline.Config{
		LearningDays: cfg.LearningDays, SigmaThreshold: float64(cfg.CountrySigmaThreshold),
		MinAbsoluteRequests: int64(cfg.CountryMinRequests),
		Enable:              boolPtr(rulesManager.IsEnabled("country_traffic")),
	}, loadBaselineState(st.GetState("country_baseline")))

	a := &App{
		Cfg: cfg, Store: st, Rules: rulesManager, Detector: detector,
		Baseline: bl, CountryBaseline: countryBl,
		hourlyByHour:        baseline.NewHourlyAccumulator[string, vhostHourMetrics](0, 0),
		hourlyCountryByHour: baseline.NewHourlyAccumulator[string, countryHourMetrics](0, 0),
	}

	a.Tailer = tail.New(tail.Options{
		Dir: cfg.LogsDir, Pattern: cfg.LogPattern, Store: st, PollMs: cfg.PollMs,
		DetectFormat: parse.DetectFormat,
		ParseLine: func(line, format, defaultVhost string) (any, bool) {
			return parse.ParseLine(line, format, defaultVhost)
		},
		VhostFromFilename: parse.VhostFromFilename,
		OnEntry:           a.onAccessEntry,
	})

	a.WafTailer = tail.New(tail.Options{
		Dir: cfg.LogsDir, Pattern: cfg.WafLogPattern, Store: st, PollMs: cfg.PollMs,
		DetectFormat: parse.WafDetectFormat,
		ParseLine: func(line, format, defaultVhost string) (any, bool) {
			return parse.WafParseLine(line, format, defaultVhost)
		},
		VhostFromFilename: parse.WafVhostFromFilename,
		OnEntry:           a.onWafEntry,
	})

	a.BlocklistTailer = tail.New(tail.Options{
		Dir: cfg.LogsDir, Pattern: cfg.BlocklistLogPattern, Store: st, PollMs: cfg.PollMs,
		DetectFormat: parse.BlocklistDetectFormat,
		ParseLine: func(line, format, defaultVhost string) (any, bool) {
			return parse.BlocklistParseLine(line, format, defaultVhost)
		},
		VhostFromFilename: parse.BlocklistVhostFromFilename,
		OnEntry:           a.onBlocklistEntry,
	})

	return a
}

// Boot reproduit la section "Boot" de server.js (hors server.listen, portee
// par cmd/analyzer) : geoip.init(), les exceptions/vhost-rules initiales, et
// le demarrage des trois tailers.
func (a *App) Boot() {
	if !geoip.Init() {
		log.Println("[nginx-analyzer] GeoIP indisponible - pas de ventilation par pays")
	}
	a.Detector.SetExceptions(ToDetectExceptions(a.Store.ListExceptions("")))
	a.Tailer.Start()
	a.WafTailer.Start()
	a.BlocklistTailer.Start()
}

// Close reproduit le flush a l'arret (store.close() -> store.flush()) - les
// heures en cours ne sont deliberement PAS flushees ici (fix, audit ANA-07) :
// voir hourlyByHour plus haut pour le raisonnement complet.
func (a *App) Close() {
	a.Tailer.Stop()
	a.WafTailer.Stop()
	a.BlocklistTailer.Stop()
	a.Store.Close()
}

// ToDetectExceptions convertit []store.Exception en []detect.Exception -
// exporte pour que internal/httpapi puisse relire les exceptions apres une
// ecriture (POST/DELETE /api/exceptions) sans dupliquer la conversion.
func ToDetectExceptions(list []store.Exception) []detect.Exception {
	out := make([]detect.Exception, len(list))
	for i, e := range list {
		out[i] = detect.Exception{Vhost: e.Vhost, IP: e.IP}
	}
	return out
}

// ToDetectCustomRules convertit []rules.ValidRule (deja resolu/valide par
// internal/rules) en []detect.CustomRule - le detecteur ne connait rien du
// YAML, seulement des regles deja validees. Exporte pour le meme besoin que
// ToDetectExceptions, depuis PUT /api/rules/custom.
func ToDetectCustomRules(list []rules.ValidRule) []detect.CustomRule {
	out := make([]detect.CustomRule, len(list))
	for i, r := range list {
		enable := r.Enable
		out[i] = detect.CustomRule{
			ID: r.ID, Name: r.Name, Enable: &enable, Severity: r.Severity,
			Description: r.Description, WindowMinutes: r.WindowMinutes, MinMatches: r.MinMatches,
			PathHint: r.PathHint, UAHint: r.UAHint, StatusIn: r.StatusIn, MethodIn: r.MethodIn,
			Global: r.Scope == "global", MinIPs: r.MinIPs,
		}
	}
	return out
}

// ToDetectVhostCfg convertit la map renvoyee par rules.Manager.SetVhostRules()
// en map[string]detect.VhostCfg - exporte pour POST /api/vhost-rules.
func ToDetectVhostCfg(m map[string]rules.VhostRuleConfig) map[string]detect.VhostCfg {
	out := make(map[string]detect.VhostCfg, len(m))
	for k, v := range m {
		enabled := v.Enabled
		out[k] = detect.VhostCfg{Enabled: &enabled, Ignore: v.Ignore, PathsIgnore: v.PathsIgnore}
	}
	return out
}

// RecentGeoSince reproduit le filtrage de /api/traffic/recent : par sinceSeq
// (curseur insensible a l'horloge, fix ANA-09) si fourni, sinon par un
// cutoff d'age (since explicite ou RecentGeoMaxAgeMs par defaut), puis
// filtre optionnellement par vhost. Renvoie aussi geoSeq courant, pour que
// currentSeq dans la reponse HTTP ne soit jamais affecte par le filtrage.
func (a *App) RecentGeoSince(sinceSeq, since int64, vhost string) ([]RecentGeoEvent, int64) {
	a.geoMu.Lock()
	defer a.geoMu.Unlock()
	var filtered []RecentGeoEvent
	if sinceSeq != 0 {
		for _, e := range a.recentGeo {
			if e.Seq > sinceSeq {
				filtered = append(filtered, e)
			}
		}
	} else {
		cutoff := since
		if cutoff == 0 {
			cutoff = nowMs() - config.RecentGeoMaxAgeMs
		}
		for _, e := range a.recentGeo {
			if e.TS > cutoff {
				filtered = append(filtered, e)
			}
		}
	}
	if vhost != "" {
		vf := filtered[:0]
		for _, e := range filtered {
			if e.Vhost == vhost {
				vf = append(vf, e)
			}
		}
		filtered = vf
	}
	return filtered, a.geoSeq
}

// Botclass est expose comme fonction de paquet plutot que par une methode
// d'App puisqu'elle est sans etat - garde ici comme point d'entree unique
// pour rester coherent avec le style server.js (const { isBot, category } =
// botclass.classifyAgent(entry.ua)).
var classifyAgent = botclass.ClassifyAgent

var nowMs = func() int64 { return time.Now().UnixMilli() }

func msToTime(ms int64) time.Time { return time.UnixMilli(ms) }

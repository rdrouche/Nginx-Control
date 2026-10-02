// Package config lit la configuration de l'agent depuis les variables d environnement,
// avec une parite exacte vis a vis de nginx-analyzer/server.js (helpers str/int/bool).
package config

import (
	"os"
	"regexp"
	"strconv"
	"strings"
)

// str reproduit exactement server.js: trim + retrait d un seul niveau de guillemets encadrants.
func str(name, def string) string {
	v, ok := os.LookupEnv(name)
	if !ok {
		v = def
	}
	v = strings.TrimSpace(v)
	if len(v) >= 2 {
		first, last := v[0], v[len(v)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			v = v[1 : len(v)-1]
		}
	}
	return v
}

// intEnv reproduit int(name, def): parseInt en base 10, retombe sur def si non fini.
func intEnv(name string, def int) int {
	s := str(name, "")
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}

// boolEnv reproduit bool(name, def): chaine vide => def, sinon v === 'true' || v === '1'.
func boolEnv(name string, def bool) bool {
	v, ok := os.LookupEnv(name)
	if !ok {
		return def
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return def
	}
	return v == "true" || v == "1"
}

// Config est le pendant exact de l objet CONFIG construit dans server.js.
type Config struct {
	Port    int
	LogsDir string
	// LogPattern est compile depuis LogPatternRaw.
	LogPattern    *regexp.Regexp
	LogPatternRaw string

	DBPath string

	PollMs     int
	FlushMs    int
	EvaluateMs int
	RollupMs   int

	Token string

	LearningDays int
	SigmaThresh  int
	AlertRetDays int

	WafLogPattern    *regexp.Regexp
	WafLogPatternRaw string
	WafRetentionDays int

	BlocklistLogPattern    *regexp.Regexp
	BlocklistLogPatternRaw string
	BlocklistRetentionDays int

	CountrySigmaThreshold int
	CountryMinRequests    int

	RuleBruteforceEnable     bool
	RuleScanEnable           bool
	RuleFloodEnable          bool
	RuleScrapingEnable       bool
	RuleVolumetricEnable     bool
	RuleCountryTrafficEnable bool

	WindowMs int

	BfMinFailures     int
	ScanMinRequests   int
	ScanMinDistinct   int
	FloodMinRequests  int
	ScrapeMinRequests int
	// IgnoreStatus : codes HTTP exclus de la detection (DETECT_IGNORE_STATUS), ex. 444.
	IgnoreStatus map[int]bool

	GeoipCityDB    string
	GeoipCountryDB string
	GeoipAsnDB     string
}

// mustCompile compile une regexp, et si echec (config utilisateur invalide), retombe sur def.
func mustCompile(pattern, fallback string) *regexp.Regexp {
	re, err := regexp.Compile(pattern)
	if err != nil {
		re = regexp.MustCompile(fallback)
	}
	return re
}

// Load construit la Config a partir des variables d environnement, avec les memes
// valeurs par defaut que server.js.
func Load() *Config {
	c := &Config{}

	c.Port = intEnv("PORT", 9100)
	c.LogsDir = str("LOGS_DIR", "/nginx/logs")
	c.LogPatternRaw = str("LOG_PATTERN", `(^|[._])access\.log$`)
	c.LogPattern = mustCompile(c.LogPatternRaw, `(^|[._])access\.log$`)

	c.DBPath = str("DB_PATH", "/analyzer/state.db")

	c.PollMs = intEnv("POLL_MS", 1000)
	c.FlushMs = intEnv("FLUSH_MS", 10000)
	c.EvaluateMs = intEnv("EVALUATE_MS", 30000)
	c.RollupMs = intEnv("ROLLUP_MS", 3600000)

	c.Token = str("ANALYZER_TOKEN", "")

	c.LearningDays = intEnv("LEARNING_DAYS", 21)
	c.SigmaThresh = intEnv("SIGMA_THRESHOLD", 6)
	c.AlertRetDays = intEnv("ALERT_RETENTION_DAYS", 90)

	c.WafLogPatternRaw = str("WAF_LOG_PATTERN", `\.waf\.log$`)
	c.WafLogPattern = mustCompile(c.WafLogPatternRaw, `\.waf\.log$`)
	c.WafRetentionDays = intEnv("WAF_RETENTION_DAYS", 60)

	c.BlocklistLogPatternRaw = str("BLOCKLIST_LOG_PATTERN", `^blocklist-hits\.log$`)
	c.BlocklistLogPattern = mustCompile(c.BlocklistLogPatternRaw, `^blocklist-hits\.log$`)
	c.BlocklistRetentionDays = intEnv("BLOCKLIST_RETENTION_DAYS", 60)

	c.CountrySigmaThreshold = intEnv("COUNTRY_SIGMA_THRESHOLD", 6)
	c.CountryMinRequests = intEnv("COUNTRY_MIN_REQUESTS", 300)

	c.RuleBruteforceEnable = boolEnv("RULE_BRUTEFORCE_ENABLE", true)
	c.RuleScanEnable = boolEnv("RULE_SCAN_ENABLE", true)
	c.RuleFloodEnable = boolEnv("RULE_FLOOD_ENABLE", true)
	c.RuleScrapingEnable = boolEnv("RULE_SCRAPING_ENABLE", true)
	c.RuleVolumetricEnable = boolEnv("RULE_VOLUMETRIC_ENABLE", true)
	c.RuleCountryTrafficEnable = boolEnv("RULE_COUNTRY_TRAFFIC_ENABLE", true)

	c.WindowMs = intEnv("WINDOW_MS", 300000)

	c.BfMinFailures = intEnv("BF_MIN_FAILURES", 15)
	c.ScanMinRequests = intEnv("SCAN_MIN_REQUESTS", 40)
	c.ScanMinDistinct = intEnv("SCAN_MIN_DISTINCT", 25)
	c.FloodMinRequests = intEnv("FLOOD_MIN_REQUESTS", 600)
	c.ScrapeMinRequests = intEnv("SCRAPE_MIN_REQUESTS", 300)
	c.IgnoreStatus = ParseIgnoreStatus(str("DETECT_IGNORE_STATUS", ""))

	c.GeoipCityDB = str("GEOIP_CITY_DB", "/geoip/GeoLite2-City.mmdb")
	c.GeoipCountryDB = str("GEOIP_COUNTRY_DB", "/geoip/GeoLite2-Country.mmdb")
	c.GeoipAsnDB = str("GEOIP_ASN_DB", "/geoip/GeoLite2-ASN.mmdb")

	return c
}

// Constantes non configurables (parite avec server.js / detect.js / store.js), gardees ici
// comme point de reference unique pour le reste du portage.
const (
	HourlyCloseIntervalMs = 5 * 60000
	HourlyCloseDelayMs    = 3600000
	RecentGeoMax          = 500
	RecentGeoMaxAgeMs     = 5 * 60000

	StoreRetentionMinuteHours = 24
	StoreRetentionHourDays    = 30
	StoreRetentionDayDays     = 365

	DetectorBucketMs       = 10000
	DetectorPruneEveryMs   = 60000
	DetectorMaxTrackedIps  = 50000
	MaxCustomWindowMinutes = 24 * 60
	MaxBlocklistWindowMin  = 20160 // 14 jours
	MaxBlocklistRemedMin   = 43200 // 30 jours
	MaxPartialBytes        = 65536
	HeadSigBytes           = 64
	RawMaxLen              = 16384
	ReadJSONBodyMaxBytes   = 2000000
)

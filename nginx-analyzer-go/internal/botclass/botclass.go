// Package botclass classe un agent utilisateur (User-Agent) comme humain ou
// robot, et dans quelle categorie de robot.
//
// Reprend deliberement les memes listes de motifs que nginx lui-meme utilise
// deja pour bloquer/autoriser du trafic (good-bots.conf, ia-bots.conf,
// bad-bots.conf) plutot que d'inventer une classification separee : ce que le
// dashboard appelle un "bot" doit correspondre a ce que nginx traite deja
// comme tel, sinon les deux se contrediraient sur le meme trafic sans raison.
package botclass

import (
	"regexp"
	"strings"
	"sync"
)

var goodBots = compileAll(
	`googlebot`, `bingbot`, `adidxbot`,
	`duckduckbot`, `qwantify`, `baiduspider`, `yandexbot`, `yeti`,
	`facebookexternalhit`, `twitterbot`, `pinterestbot`,
)

var aiBots = compileAll(
	`Applebot-Extended`, `GPTBot`, `CCBot`, `Cohere-ai`, `ChatGPT-User`,
	`OAI-SearchBot`, `ClaudeBot`, `Claude-web`, `Google-Extended`,
	`GoogleOther`, `ImagesiftBot`, `Meta-ExternalAgent`, `PerplexityBot`,
	`YouBot`, `FacebookBot`,
)

var badBots = compileAll(
	`AhrefsBot`, `Amazonbot`, `Bytespider`, `DataForSeoBot`, `DotBot`,
	`MJ12bot`, `PetalBot`, `Rogerbot`, `SemrushBot`, `Seomoz`, `Sogou`,
	`VelenPublicWebCrawler`, `YanBot`, `Shodan`, `Censys`, `Nmap`,
	`ZmEu`, `Masscan`,
)

// genericBotHint reproduit GENERIC_BOT_HINT : tout ce qui s'auto-declare
// automatise sans figurer sur l'une des trois listes nommees ci-dessus - un
// signal generique nettement negatif, distinct de "certainement malveillant"
// ou "certainement un crawler connu".
var genericBotHint = regexp.MustCompile(`(?i)bot|crawler|spider|scrapy|python-requests|curl|wget|go-http-client|java/|libwww|httpclient|okhttp|axios/|node-fetch`)

func compileAll(patterns ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		out[i] = regexp.MustCompile("(?i)" + p)
	}
	return out
}

func matchesAny(list []*regexp.Regexp, ua string) bool {
	for _, re := range list {
		if re.MatchString(ua) {
			return true
		}
	}
	return false
}

// Result reproduit { isBot, category }. IsBot est un *bool car category
// null cote JS ('good'|'ai'|'bad'|'unknown'|'human'|null) correspond a un
// isBot a trois etats (null|true|false), et un agent absent (aucun en-tete)
// doit rester distinct de "humain" plutot que d'etre confondu avec false.
type Result struct {
	IsBot    *bool
	Category string // "good" | "ai" | "bad" | "unknown" | "human" | "" (absent)
}

func boolPtr(b bool) *bool { return &b }

// Cache de classification. Les User-Agent se repetent massivement (quelques
// centaines de valeurs pour des millions de lignes) alors que la classification
// evalue des dizaines d'expressions regulieres : sans cache, regexp de Go (non
// JIT, contrairement a V8) representait ~50 % du CPU d'ingestion. Borne pour ne
// jamais grossir sans limite face a des UA aleatoires (reset complet, simple et
// sans effet sur la correction : la classification est une fonction pure).
const classifyCacheMax = 8192

var (
	classifyMu    sync.Mutex
	classifyCache = make(map[string]Result, 1024)
)

// ClassifyAgent replique classifyAgent() : classifie une chaine User-Agent.
func ClassifyAgent(ua string) Result {
	if ua == "" {
		return Result{IsBot: nil, Category: ""}
	}
	classifyMu.Lock()
	r, ok := classifyCache[ua]
	classifyMu.Unlock()
	if ok {
		return r
	}
	r = classifyAgentUncached(ua)
	classifyMu.Lock()
	if len(classifyCache) >= classifyCacheMax {
		classifyCache = make(map[string]Result, 1024)
	}
	classifyCache[strings.Clone(ua)] = r
	classifyMu.Unlock()
	return r
}

func classifyAgentUncached(ua string) Result {
	if matchesAny(goodBots, ua) {
		return Result{IsBot: boolPtr(true), Category: "good"}
	}
	if matchesAny(aiBots, ua) {
		return Result{IsBot: boolPtr(true), Category: "ai"}
	}
	if matchesAny(badBots, ua) {
		return Result{IsBot: boolPtr(true), Category: "bad"}
	}
	if genericBotHint.MatchString(ua) {
		return Result{IsBot: boolPtr(true), Category: "unknown"}
	}
	return Result{IsBot: boolPtr(false), Category: "human"}
}

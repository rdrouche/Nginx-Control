package challenge

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

// BotRule décrit un robot « légitime » (moteur de recherche) : l'user-agent
// seul est falsifiable, donc l'adresse doit en plus passer la vérification DNS
// inverse confirmée (FCrDNS) : IP → nom → IP, avec un nom du domaine officiel.
type BotRule struct {
	Name     string
	UA       *regexp.Regexp
	Suffixes []string // ex. ".googlebot.com" (toujours précédés d'un point)
}

// DefaultBotRules : robots d'indexation qui publient une vérification DNS inverse.
func DefaultBotRules() []BotRule {
	mk := func(name, ua string, suf ...string) BotRule {
		return BotRule{Name: name, UA: regexp.MustCompile(ua), Suffixes: suf}
	}
	return []BotRule{
		mk("googlebot", `(?i)googlebot|google-inspectiontool|googleother|storebot-google|adsbot-google|mediapartners-google|apis-google|google-read-aloud`, ".googlebot.com", ".google.com", ".googleusercontent.com"),
		mk("bingbot", `(?i)bingbot|bingpreview|msnbot|adidxbot`, ".search.msn.com"),
		mk("applebot", `(?i)applebot`, ".applebot.apple.com"),
		mk("yandex", `(?i)yandex`, ".yandex.ru", ".yandex.net", ".yandex.com"),
		mk("baidu", `(?i)baiduspider`, ".baidu.com", ".baidu.jp"),
	}
}

var botNameRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

// ParseExtraBotRules lit "nom|regex-ua|.suffixe1,.suffixe2;nom2|…" (NC_GOODBOTS_EXTRA).
func ParseExtraBotRules(s string) ([]BotRule, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var out []BotRule
	for _, item := range strings.Split(s, ";") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		p := strings.SplitN(item, "|", 3)
		if len(p) != 3 {
			return nil, fmt.Errorf("NC_GOODBOTS_EXTRA : « %s » doit être nom|regex|.suffixe[,.suffixe]", item)
		}
		name := strings.TrimSpace(p[0])
		if !botNameRE.MatchString(name) {
			return nil, fmt.Errorf("NC_GOODBOTS_EXTRA : nom invalide « %s »", name)
		}
		re, err := regexp.Compile(strings.TrimSpace(p[1]))
		if err != nil || strings.TrimSpace(p[1]) == "" {
			return nil, fmt.Errorf("NC_GOODBOTS_EXTRA : expression invalide pour « %s »", name)
		}
		var suf []string
		for _, x := range strings.Split(p[2], ",") {
			x = strings.ToLower(strings.TrimSpace(x))
			if x == "" {
				continue
			}
			if !strings.HasPrefix(x, ".") || len(x) < 4 || strings.ContainsAny(x, " /\\") {
				return nil, fmt.Errorf("NC_GOODBOTS_EXTRA : suffixe « %s » invalide (attendu .exemple.com)", x)
			}
			suf = append(suf, x)
		}
		if len(suf) == 0 {
			return nil, fmt.Errorf("NC_GOODBOTS_EXTRA : aucun suffixe pour « %s »", name)
		}
		out = append(out, BotRule{Name: name, UA: re, Suffixes: suf})
		if len(out) > 30 {
			return nil, errors.New("NC_GOODBOTS_EXTRA : 30 règles maximum")
		}
	}
	return out, nil
}

// BotVerifier vérifie qu'une requête vient réellement d'un robot connu.
// Résultats mis en cache (24 h si vérifié, 15 min sinon), recherches DNS
// bornées en durée et en parallélisme : un attaquant qui falsifie l'user-agent
// depuis de nombreuses adresses ne peut pas saturer le résolveur.
type BotVerifier struct {
	rules      []BotRule
	lookupAddr func(ctx context.Context, ip string) ([]string, error)
	lookupHost func(ctx context.Context, name string) ([]string, error)
	mu         sync.Mutex
	cache      map[string]botEntry
	sem        chan struct{}
	now        func() time.Time
}

type botEntry struct {
	ok  bool
	exp time.Time
}

// NewBotVerifier construit un vérificateur avec le résolveur du système.
func NewBotVerifier(rules []BotRule) *BotVerifier {
	r := net.DefaultResolver
	return &BotVerifier{
		rules: rules, lookupAddr: r.LookupAddr, lookupHost: r.LookupHost,
		cache: map[string]botEntry{}, sem: make(chan struct{}, 16), now: time.Now,
	}
}

// Verify renvoie (vrai, nom du robot) si l'user-agent correspond à une règle ET
// que l'adresse est confirmée par DNS inverse.
func (v *BotVerifier) Verify(ua, ip string) (bool, string) {
	if v == nil || ua == "" || net.ParseIP(ip) == nil {
		return false, ""
	}
	var rule *BotRule
	for i := range v.rules {
		if v.rules[i].UA.MatchString(ua) {
			rule = &v.rules[i]
			break
		}
	}
	if rule == nil {
		return false, ""
	}
	key := rule.Name + "|" + ip
	now := v.now()
	v.mu.Lock()
	if e, ok := v.cache[key]; ok && now.Before(e.exp) {
		v.mu.Unlock()
		return e.ok, rule.Name
	}
	v.mu.Unlock()

	select {
	case v.sem <- struct{}{}:
		defer func() { <-v.sem }()
	default:
		return false, rule.Name // résolveur occupé : on challenge plutôt que d'attendre
	}
	ok, definitive := v.fcrdns(rule, ip)
	if definitive {
		ttl := 15 * time.Minute
		if ok {
			ttl = 24 * time.Hour
		}
		v.mu.Lock()
		if len(v.cache) >= 50000 {
			for k, e := range v.cache {
				if !now.Before(e.exp) {
					delete(v.cache, k)
				}
			}
		}
		if len(v.cache) < 50000 {
			v.cache[key] = botEntry{ok: ok, exp: now.Add(ttl)}
		}
		v.mu.Unlock()
	}
	return ok, rule.Name
}

// fcrdns : IP → noms (suffixe officiel requis) → adresses ; l'IP doit y figurer.
// definitive=false quand l'échec vient d'une erreur DNS (à ne pas mettre en cache).
func (v *BotVerifier) fcrdns(rule *BotRule, ip string) (ok, definitive bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	names, err := v.lookupAddr(ctx, ip)
	if err != nil && len(names) == 0 {
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			return false, true
		}
		return false, false
	}
	want := net.ParseIP(ip)
	for _, n := range names {
		n = strings.ToLower(strings.TrimSuffix(n, "."))
		if !hasSuffix(n, rule.Suffixes) {
			continue
		}
		addrs, err := v.lookupHost(ctx, n)
		if err != nil && len(addrs) == 0 {
			continue
		}
		for _, a := range addrs {
			if p := net.ParseIP(a); p != nil && p.Equal(want) {
				return true, true
			}
		}
	}
	return false, true
}

func hasSuffix(name string, suffixes []string) bool {
	for _, s := range suffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

package detect

import (
	"fmt"
	"sort"
	"strings"

	"nginx-analyzer-go/internal/parse"
)

// Regles personnalisees « scope: global » (v12.62.0) : UNE alerte de campagne par
// regle, avec des preuves agregees sur toutes les adresses (miroir de
// nginx-analyzer/lib/detect.js : _recordCampaignDetail / _campaignScan /
// _campaignAlert). Le blocage (dashboard) lit Evidence.Campaign.IPs.

// MaxCampaignIPs plafonne les adresses listees dans une alerte de campagne.
const MaxCampaignIPs = 3000

// campDetail : ce qu'un seau retient d'une regle globale (borne : quelques valeurs distinctes).
type campDetail struct {
	paths    map[string]int
	uas      map[string]int
	statuses map[int]int
	vhosts   map[string]struct{}
	last     int64
}

type campaignState struct {
	emittedAt int64
	ips       int
}

// CountedPath / CountedUA : une ligne d'un classement (JSON : {path,count} / {ua,count}).
type CountedPath struct {
	Path  string
	Count int
}
type CountedUA struct {
	UA    string
	Count int
}

// CampaignSample : un exemple par adresse.
type CampaignSample struct {
	IP     string
	Path   *string
	Status *int
	UA     *string
	TS     int64
}

// CampaignIP : adresse et nombre de correspondances (JSON : [ip, count]).
type CampaignIP struct {
	IP    string
	Count int
}

// CampaignEvidence : les preuves d'une campagne distribuee.
type CampaignEvidence struct {
	Vhosts            []string
	WindowMinutes     int
	FirstSeen         int64
	LastSeen          int64
	RequestsPerMinute float64
	TopPaths          []CountedPath
	TopUserAgents     []CountedUA
	Statuses          map[int]int
	Samples           []CampaignSample
	IPs               []CampaignIP
	IPsTruncated      bool
	Renewal           bool
}

func bumpCapped(m map[string]int, k string, cap int) {
	if k == "" {
		return
	}
	if _, ok := m[k]; ok || len(m) < cap {
		m[k]++
	}
}

func recordCampaignDetail(b *bucket, ruleID int, entry parse.AccessEntry, now int64) {
	if b.gm == nil {
		b.gm = make(map[int]*campDetail)
	}
	d := b.gm[ruleID]
	if d == nil {
		d = &campDetail{paths: map[string]int{}, uas: map[string]int{}, statuses: map[int]int{}, vhosts: map[string]struct{}{}}
		b.gm[ruleID] = d
	}
	if now > d.last {
		d.last = now
	}
	if entry.Path != nil {
		bumpCapped(d.paths, *entry.Path, 5)
	}
	if entry.UA != nil {
		bumpCapped(d.uas, *entry.UA, 3)
	}
	d.statuses[entry.Status]++
	if entry.Vhost != "" {
		d.vhosts[entry.Vhost] = struct{}{}
	}
}

type countedKey struct {
	key   string
	count int
}

// sortedCounts : compte decroissant, puis cle croissante (meme ordre que Node).
func sortedCounts(m map[string]int) []countedKey {
	out := make([]countedKey, 0, len(m))
	for k, c := range m {
		out = append(out, countedKey{k, c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].count != out[j].count {
			return out[i].count > out[j].count
		}
		return out[i].key < out[j].key
	})
	return out
}

func sortedStatusCounts(m map[int]int) []countedKey {
	conv := make(map[string]int, len(m))
	for k, c := range m {
		conv[fmt.Sprintf("%d", k)] = c
	}
	return sortedCounts(conv)
}

type campaignIPInfo struct {
	ip     string
	count  int
	last   int64
	sample CampaignSample
}

type campaignScan struct {
	windowMs int64
	ips      []campaignIPInfo
	total    int
	paths    map[string]int
	uas      map[string]int
	statuses map[int]int
	vhosts   map[string]struct{}
	first    int64
	last     int64
}

func (d *Detector) campaignScan(rule CustomRule, now int64) *campaignScan {
	windowMs := int64(ClampCustomWindowMinutes(rule.WindowMinutes)) * 60_000
	cutoffIdx := d.bucketIdx(now - windowMs)
	sc := &campaignScan{windowMs: windowMs, paths: map[string]int{}, uas: map[string]int{}, statuses: map[int]int{}, vhosts: map[string]struct{}{}}
	first := int64(-1)
	for ip, st := range d.ips {
		count := 0
		var ipLast int64
		ipVhosts := map[string]struct{}{}
		ipPaths, ipUAs := map[string]int{}, map[string]int{}
		ipStatuses := map[int]int{}
		for idx, b := range st.buckets {
			if idx < cutoffIdx {
				continue
			}
			n := b.custom[rule.ID]
			if n == 0 {
				continue
			}
			count += n
			det := b.gm[rule.ID]
			if det == nil {
				continue
			}
			if det.last > ipLast {
				ipLast = det.last
			}
			if det.last != 0 && (first < 0 || det.last < first) {
				first = det.last
			}
			for v := range det.vhosts {
				ipVhosts[v] = struct{}{}
			}
			for k, c := range det.paths {
				ipPaths[k] += c
			}
			for k, c := range det.uas {
				ipUAs[k] += c
			}
			for k, c := range det.statuses {
				ipStatuses[k] += c
			}
		}
		if count == 0 {
			continue
		}
		if d.isExcludedForVhosts(ip, ipVhosts) || d.ruleSuppressedForVhosts(ipVhosts, rule.ID) {
			continue
		}
		sc.total += count
		if ipLast > sc.last {
			sc.last = ipLast
		}
		for v := range ipVhosts {
			sc.vhosts[v] = struct{}{}
		}
		for k, c := range ipPaths {
			sc.paths[k] += c
		}
		for k, c := range ipUAs {
			sc.uas[k] += c
		}
		for k, c := range ipStatuses {
			sc.statuses[k] += c
		}
		smp := CampaignSample{IP: ip, TS: ipLast}
		if kc := sortedCounts(ipPaths); len(kc) > 0 {
			p := kc[0].key
			smp.Path = &p
		}
		if kc := sortedCounts(ipUAs); len(kc) > 0 {
			u := kc[0].key
			smp.UA = &u
		}
		if kc := sortedStatusCounts(ipStatuses); len(kc) > 0 {
			var code int
			fmt.Sscanf(kc[0].key, "%d", &code)
			smp.Status = &code
		}
		sc.ips = append(sc.ips, campaignIPInfo{ip: ip, count: count, last: ipLast, sample: smp})
	}
	if len(sc.ips) == 0 {
		return nil
	}
	sort.Slice(sc.ips, func(i, j int) bool {
		a, b := sc.ips[i], sc.ips[j]
		if a.count != b.count {
			return a.count > b.count
		}
		if a.last != b.last {
			return a.last > b.last
		}
		return a.ip < b.ip
	})
	if first < 0 {
		first = sc.last
	}
	sc.first = first
	return sc
}

func (d *Detector) campaignAlert(rule CustomRule, sc *campaignScan, windowMinutes int, renewal bool) Alert {
	nIPs := len(sc.ips)
	listed := nIPs
	if listed > MaxCampaignIPs {
		listed = MaxCampaignIPs
	}
	ips := make([]CampaignIP, listed)
	for i := 0; i < listed; i++ {
		ips[i] = CampaignIP{IP: sc.ips[i].ip, Count: sc.ips[i].count}
	}
	spanMin := float64(sc.last-sc.first) / 60_000
	if spanMin < 1 {
		spanMin = 1
	}
	vhosts := make([]string, 0, len(sc.vhosts))
	for v := range sc.vhosts {
		vhosts = append(vhosts, v)
	}
	sort.Strings(vhosts)
	vhost := ""
	if len(vhosts) == 1 {
		vhost = vhosts[0]
	}
	trunc := func(s string, n int) string {
		if r := []rune(s); len(r) > n {
			return string(r[:n])
		}
		return s
	}
	var topPaths []CountedPath
	for _, kc := range sortedCounts(sc.paths) {
		if len(topPaths) == 10 {
			break
		}
		topPaths = append(topPaths, CountedPath{trunc(kc.key, 300), kc.count})
	}
	var topUAs []CountedUA
	for _, kc := range sortedCounts(sc.uas) {
		if len(topUAs) == 5 {
			break
		}
		topUAs = append(topUAs, CountedUA{trunc(kc.key, 300), kc.count})
	}
	nSamples := nIPs
	if nSamples > 10 {
		nSamples = 10
	}
	samples := make([]CampaignSample, nSamples)
	for i := 0; i < nSamples; i++ {
		samples[i] = sc.ips[i].sample
	}
	sev := rule.Severity
	if sev == "" {
		sev = "medium"
	}
	what := rule.Description
	if what == "" {
		what = fmt.Sprintf(`Regle personnalisee "%s"`, rule.Name)
	}
	suffix := ""
	if vhost != "" {
		suffix += " sur " + vhost
	}
	if len(topPaths) > 0 {
		suffix += " — ex. " + trunc(topPaths[0].Path, 120)
	}
	if renewal {
		suffix += " (mise a jour)"
	}
	ev := Evidence{
		Vhost: vhost, FirstSeen: sc.first, LastSeen: sc.last,
		RuleID: rule.ID, RuleName: rule.Name, Matches: sc.total, GlobalMatches: sc.total, GlobalIPs: nIPs,
		Campaign: &CampaignEvidence{
			Vhosts: vhosts, WindowMinutes: windowMinutes, FirstSeen: sc.first, LastSeen: sc.last,
			RequestsPerMinute: float64(int(float64(sc.total)/spanMin*10+0.5)) / 10,
			TopPaths:          topPaths, TopUserAgents: topUAs, Statuses: sc.statuses,
			Samples: samples, IPs: ips, IPsTruncated: nIPs > listed, Renewal: renewal,
		},
	}
	return Alert{
		Type: fmt.Sprintf("custom_%d", rule.ID),
		Explanation: Explanation{
			ID: rule.ID, What: what,
			Why:    "Campagne repartie sur de nombreuses adresses : chacune reste sous les seuils par IP, c est leur total qui est anormal.",
			Legit:  "Un pic de trafic reel (lien partage, evenement) peut produire un motif proche : verifiez les chemins, les user-agents et la repartition des IP ci-dessous.",
			Action: "Controler les preuves (chemins, user-agents, codes) ; si la campagne est confirmee, activer le blocage de la regle (blocklist) ou proteger la ressource (authentification, limite de debit).",
		},
		Severity: sev,
		Summary: fmt.Sprintf(`Regle "%s" (campagne distribuee) : %d correspondance(s) depuis %d IP sur les dernieres %d min%s`,
			rule.Name, sc.total, nIPs, windowMinutes, strings.TrimRight(suffix, " ")),
		Evidence: ev,
	}
}

// evaluateCampaigns : une alerte par regle globale a l'entree, mise a jour quand le
// nombre d'IP grandit de 50 % ou apres une fenetre complete tant que la campagne dure.
func (d *Detector) evaluateCampaigns(now int64) []Alert {
	var alerts []Alert
	live := map[int]struct{}{}
	for _, rule := range d.customRules {
		if !rule.Global || !rule.enabledForEvaluate() {
			continue
		}
		sc := d.campaignScan(rule, now)
		minIPs := rule.MinIPs
		if minIPs <= 0 {
			minIPs = 5
		}
		if sc == nil || sc.total < rule.MinMatches || len(sc.ips) < minIPs {
			continue
		}
		live[rule.ID] = struct{}{}
		st, had := d.campaigns[rule.ID]
		grown := had && float64(len(sc.ips)) >= float64(st.ips)*1.5
		stale := had && now-st.emittedAt >= sc.windowMs
		if had && !grown && !stale {
			continue
		}
		d.campaigns[rule.ID] = campaignState{emittedAt: now, ips: len(sc.ips)}
		alerts = append(alerts, d.campaignAlert(rule, sc, ClampCustomWindowMinutes(rule.WindowMinutes), had))
	}
	for id := range d.campaigns {
		if _, ok := live[id]; !ok {
			delete(d.campaigns, id)
		}
	}
	return alerts
}

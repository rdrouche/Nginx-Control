package app

import (
	"fmt"

	"nginx-analyzer-go/internal/baseline"
	"nginx-analyzer-go/internal/blocklistsources"
	"nginx-analyzer-go/internal/config"
	"nginx-analyzer-go/internal/detect"
	"nginx-analyzer-go/internal/geoip"
	"nginx-analyzer-go/internal/parse"
	"nginx-analyzer-go/internal/store"
)

const maxTrackedSetSize = 20_000
const maxTrackedVhostSetSize = 5_000

// onAccessEntry replique le callback onEntry() du tailer d'acces principal
// dans server.js : alimente le detecteur, le suivi structurel horaire (par
// vhost puis, si geolocalisable, par pays), le stockage du trafic brut, la
// classification bot, la carte en direct, et la detection "approx" des hits
// de blocklist derives du log d'acces principal.
func (a *App) onAccessEntry(raw any) {
	entry, ok := raw.(parse.AccessEntry)
	if !ok {
		return
	}
	// Statut ignore (ex. 444, deja bloque par un autre mecanisme) : ni regles ni baseline ;
	// le trafic reste enregistre plus bas (statistiques, hits de blocklist).
	ignoredStatus := a.Cfg.IgnoreStatus[entry.Status]
	if !ignoredStatus {
		a.Detector.Add(entry)
		a.trackStructure(entry)
	}

	country := geoip.CountryOf(entry.IP)
	if country != "" && !ignoredStatus {
		a.trackCountryStructure(entry, country)
	}
	a.Store.Record(store.Entry{Ts: entry.TS, Vhost: entry.Vhost, Status: entry.Status, Method: derefStr(entry.Method), Bytes: entry.Bytes}, country)

	ua := ""
	if entry.UA != nil {
		ua = *entry.UA
	}
	result := classifyAgent(ua)
	a.Store.RecordBot(store.Entry{Ts: entry.TS, Vhost: entry.Vhost, Status: entry.Status, Method: derefStr(entry.Method), Bytes: entry.Bytes}, result.Category, country)

	if country != "" {
		a.geoMu.Lock()
		a.geoSeq++
		ev := RecentGeoEvent{Seq: a.geoSeq, TS: entry.TS, Vhost: entry.Vhost, Country: country, IsBot: result.IsBot, Category: result.Category}
		a.recentGeo = append(a.recentGeo, ev)
		if len(a.recentGeo) > config.RecentGeoMax {
			a.recentGeo = a.recentGeo[len(a.recentGeo)-config.RecentGeoMax:]
		}
		a.geoMu.Unlock()
	}

	// hit_logging_method "approx" (nginx-dashboard/lib/blocklist-yaml.js) :
	// pas de blocklist-hits.log dedie - l'operateur a demande a l'analyzer de
	// deriver les hits du log d'acces principal qu'il tail deja.
	if blocklistsources.GetMode() == "approx" && blocklistsources.HasSources() {
		if len(blocklistsources.SourcesContaining(entry.IP)) > 0 {
			a.Store.RecordBlocklistHit(store.BlocklistHitInput{
				Ts: entry.TS, IP: entry.IP, Vhost: entry.Vhost,
				Method: derefStr(entry.Method), URI: derefStr(entry.Path), Status: entry.Status,
			})
		}
	}
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// onWafEntry replique le callback onEntry() du tailer WAF.
func (a *App) onWafEntry(raw any) {
	e, ok := raw.(parse.WafEntry)
	if !ok {
		return
	}
	msgs := make([]store.WafMessage, len(e.Messages))
	for i, m := range e.Messages {
		msgs[i] = store.WafMessage{RuleID: derefStr(m.RuleID), Message: derefStr(m.Message), Severity: m.Severity, Tags: m.Tags}
	}
	a.Store.RecordWaf(store.WafRecordInput{
		Ts: e.TS, Vhost: e.Vhost, IP: derefStr(e.IP), Method: derefStr(e.Method), URI: derefStr(e.URI),
		Status: derefInt(e.Status), Blocked: e.Blocked, Severity: e.Severity, RuleIDs: e.RuleIDs,
		Messages: msgs, UniqueID: derefStr(e.UniqueID), Engine: derefStr(e.Engine), Raw: e.Raw,
	})
}

func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// onBlocklistEntry replique le callback onEntry() du tailer de blocklist
// dedie ("Method 1").
func (a *App) onBlocklistEntry(raw any) {
	e, ok := raw.(parse.BlocklistEntry)
	if !ok {
		return
	}
	a.Store.RecordBlocklistHit(store.BlocklistHitInput{
		Ts: e.TS, IP: derefStr(e.IP), Vhost: derefStr(e.Vhost), Method: derefStr(e.Method), URI: derefStr(e.URI), Status: e.Status,
	})
}

// trackStructure replique trackStructure() : signaux structurels par vhost
// pour l'heure en cours, en plus du volume, pour que la baseline distingue
// une audience d'un flood.
func (a *App) trackStructure(entry parse.AccessEntry) {
	a.hourlyMu.Lock()
	defer a.hourlyMu.Unlock()
	a.hourlyByHour.Add(entry.TS, entry.Vhost,
		func() *vhostHourMetrics {
			return &vhostHourMetrics{IPs: make(map[string]struct{}), Paths: make(map[string]struct{})}
		},
		func(m *vhostHourMetrics) {
			m.Requests++
			if entry.Status >= 400 {
				m.Errors++
			}
			if len(m.IPs) < maxTrackedSetSize {
				m.IPs[entry.IP] = struct{}{}
			}
			// entry.Path est nil pour une requete "-" toute simple - pas un
			// chemin distinct a suivre pour le signal distinctPaths.
			if entry.Path != nil && len(m.Paths) < maxTrackedSetSize {
				m.Paths[*entry.Path] = struct{}{}
			}
		})
}

// trackCountryStructure replique trackCountryStructure() : meme idee,
// agregee par pays - le trafic de chaque vhost depuis un pays donne compte
// dans le volume horaire de ce pays. Les vhosts distincts touches tiennent
// lieu de chemins distincts.
func (a *App) trackCountryStructure(entry parse.AccessEntry, country string) {
	a.hourlyMu.Lock()
	defer a.hourlyMu.Unlock()
	a.hourlyCountryByHour.Add(entry.TS, country,
		func() *countryHourMetrics {
			return &countryHourMetrics{IPs: make(map[string]struct{}), Vhosts: make(map[string]struct{})}
		},
		func(m *countryHourMetrics) {
			m.Requests++
			if entry.Status >= 400 {
				m.Errors++
			}
			if len(m.IPs) < maxTrackedSetSize {
				m.IPs[entry.IP] = struct{}{}
			}
			if len(m.Vhosts) < maxTrackedVhostSetSize {
				m.Vhosts[entry.Vhost] = struct{}{}
			}
		})
}

// checkResultToEvidence aplati un baseline.CheckResult (plus un champ
// supplementaire) en map[string]any, pour store.AlertInput.Evidence -
// reproduit le spread JS `{ ...result, vhost }` / `{ ...result, vhost:
// undefined, country, distinctVhosts }`.
func checkResultToEvidence(r *baseline.CheckResult, extra map[string]any) map[string]any {
	m := map[string]any{
		"learning":     r.Learning,
		"daysElapsed":  r.DaysElapsed,
		"daysRequired": r.DaysRequired,
		"anomaly":      r.Anomaly,
		"vhost":        r.Vhost,
		"hour":         r.Hour,
		"observed":     r.Observed,
		"expected":     r.Expected,
		"deviation":    r.Deviation,
		"samples":      r.Samples,
		"structure": map[string]any{
			"distinctIps":   r.Structure.DistinctIps,
			"distinctPaths": r.Structure.DistinctPaths,
			"errorRatio":    r.Structure.ErrorRatio,
			"looksOrganic":  r.Structure.LooksOrganic,
		},
		"severity": r.Severity,
		"summary":  r.Summary,
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// flushHourlyBucket replique flushHourlyBucket() : alimente la baseline par
// vhost avec les signaux structurels d'une heure terminee, et remonte une
// alerte volumetrique en cas d'anomalie.
func (a *App) flushHourlyBucket(hourMs int64, byVhost map[string]*vhostHourMetrics) {
	hourT := msToTime(hourMs)
	for vhost, m := range byVhost {
		metrics := baseline.Metrics{
			Requests: m.Requests, Errors: m.Errors,
			DistinctIps: int64(len(m.IPs)), DistinctPaths: int64(len(m.Paths)),
		}
		result := a.Baseline.Check(vhost, hourT, metrics)
		// L'apprentissage continue meme regle desactivee/vhost exclu
		// (Observe() ci-dessous, hors de cette condition) - seule l'alerte
		// est retenue, pour que reactiver la regle plus tard ne reparte pas
		// de zero.
		if result != nil && result.Anomaly && a.Baseline.Cfg().Enabled() &&
			!a.Rules.RuleSuppressedForVhost(vhost, detect.RuleVolumetric) {
			a.Store.AddAlert(store.AlertInput{
				Type: "volumetric", Severity: result.Severity, Summary: result.Summary,
				Evidence: checkResultToEvidence(result, map[string]any{"vhost": vhost}),
			})
			fmt.Printf("[alert] volumetric %s: %s\n", vhost, result.Summary)
		}
		a.Baseline.Observe(vhost, hourT, metrics)
	}
	a.Store.SetState("baseline", a.Baseline.ExportState())
}

// countrySummary replique countrySummary() : formulation dediee au pays
// ("depuis FR") plutot que la formulation par vhost ("sur FR") que
// produirait baseline.Check() lui-meme.
func countrySummary(r *baseline.CheckResult, country string) string {
	if r.Structure.LooksOrganic {
		return fmt.Sprintf("Trafic inhabituel depuis %s : %d requetes contre %d attendues, mais la structure ressemble a une audience reelle",
			country, r.Observed, r.Expected)
	}
	return fmt.Sprintf("Pic anormal depuis %s : %d requetes contre %d attendues (%.3f ecarts), reparti sur peu de vhosts et/ou d adresses",
		country, r.Observed, r.Expected, r.Deviation)
}

// flushHourlyCountryBucket replique flushHourlyCountryBucket().
func (a *App) flushHourlyCountryBucket(hourMs int64, byCountry map[string]*countryHourMetrics) {
	hourT := msToTime(hourMs)
	for country, m := range byCountry {
		metrics := baseline.Metrics{
			Requests: m.Requests, Errors: m.Errors,
			DistinctIps: int64(len(m.IPs)), DistinctPaths: int64(len(m.Vhosts)),
		}
		result := a.CountryBaseline.Check(country, hourT, metrics)
		if result != nil && result.Anomaly && a.CountryBaseline.Cfg().Enabled() {
			summary := countrySummary(result, country)
			a.Store.AddAlert(store.AlertInput{
				Type: "country_traffic", Severity: result.Severity, Summary: summary,
				Evidence: checkResultToEvidence(result, map[string]any{
					"vhost": nil, "country": country, "distinctVhosts": len(m.Vhosts),
				}),
			})
			fmt.Printf("[alert] country_traffic %s: %s\n", country, summary)
		}
		a.CountryBaseline.Observe(country, hourT, metrics)
	}
	a.Store.SetState("country_baseline", a.CountryBaseline.ExportState())
}

// evidenceToMap aplati un detect.Evidence en map[string]any, pour
// store.AlertInput.Evidence - reproduit la forme de base()/{...base(), ...}
// cote detect.js. Seuls les champs specifiques a la regle qui a declenche
// (authFailures, notFound, requestsPerSecond, ruleId/ruleName/matches) sont
// ajoutes quand ils sont pertinents.
func evidenceToMap(ev detect.Evidence) map[string]any {
	samples := make([]map[string]any, len(ev.Samples))
	for i, s := range ev.Samples {
		samples[i] = map[string]any{"ts": s.TS, "status": s.Status}
		if s.Method != nil {
			samples[i]["method"] = *s.Method
		} else {
			samples[i]["method"] = nil
		}
		if s.Path != nil {
			samples[i]["path"] = *s.Path
		} else {
			samples[i]["path"] = nil
		}
	}
	var vhost any
	if ev.Vhost != "" {
		vhost = ev.Vhost
	}
	m := map[string]any{
		"ip": ev.IP, "vhost": vhost,
		"firstSeen": ev.FirstSeen, "lastSeen": ev.LastSeen,
		"requests": ev.Requests, "distinctPaths": ev.DistinctPaths,
		"userAgents": ev.UserAgents, "statuses": ev.Statuses, "samples": samples,
	}
	if ev.AuthFailures != 0 {
		m["authFailures"] = ev.AuthFailures
	}
	if ev.NotFound != 0 {
		m["notFound"] = ev.NotFound
	}
	if ev.RequestsPerSecond != 0 {
		m["requestsPerSecond"] = ev.RequestsPerSecond
	}
	if ev.RuleID != 0 {
		m["ruleId"] = ev.RuleID
		m["ruleName"] = ev.RuleName
		m["matches"] = ev.Matches
		if ev.GlobalIPs != 0 {
			m["globalMatches"] = ev.GlobalMatches
			m["globalIps"] = ev.GlobalIPs
		}
	}
	if c := ev.Campaign; c != nil {
		campaignEvidence(m, c)
	}
	return m
}

// alertToInput convertit un detect.Alert en store.AlertInput - le champ
// Explanation n'est deliberement pas transmis : addAlert() cote Node ne le
// persiste jamais non plus (voir lib/store.js), le texte explicatif ne
// survit que dans le "summary" redige au moment de la detection.
func alertToInput(a detect.Alert) store.AlertInput {
	return store.AlertInput{
		Type: a.Type, Severity: a.Severity, Summary: a.Summary,
		Evidence: evidenceToMap(a.Evidence),
	}
}

// CloseFinishedHourlyBuckets replique closeFinishedHourlyBuckets() +
// closeFinishedHourlyCountryBuckets() : ferme toute heure terminee depuis
// plus d'une heure (voir HourlyAccumulator), appele sur un minuteur
// independant de l'arrivee des entrees (voir internal/app/background.go).
func (a *App) CloseFinishedHourlyBuckets(now int64) {
	a.hourlyMu.Lock()
	closedVhost := a.hourlyByHour.CloseFinished(now)
	closedCountry := a.hourlyCountryByHour.CloseFinished(now)
	a.hourlyMu.Unlock()
	for _, c := range closedVhost {
		a.flushHourlyBucket(c.Hour, c.ByKey)
	}
	for _, c := range closedCountry {
		a.flushHourlyCountryBucket(c.Hour, c.ByKey)
	}
}

// campaignEvidence ajoute les preuves d'une campagne distribuee (miroir de
// _campaignAlert dans nginx-analyzer/lib/detect.js : memes cles JSON).
func campaignEvidence(m map[string]any, c *detect.CampaignEvidence) {
	m["campaign"] = true
	m["ip"] = nil
	paths := make([]map[string]any, len(c.TopPaths))
	for i, p := range c.TopPaths {
		paths[i] = map[string]any{"path": p.Path, "count": p.Count}
	}
	uas := make([]map[string]any, len(c.TopUserAgents))
	for i, u := range c.TopUserAgents {
		uas[i] = map[string]any{"ua": u.UA, "count": u.Count}
	}
	samples := make([]map[string]any, len(c.Samples))
	for i, s := range c.Samples {
		x := map[string]any{"ip": s.IP, "path": nil, "status": nil, "ua": nil, "ts": s.TS}
		if s.Path != nil {
			x["path"] = *s.Path
		}
		if s.Status != nil {
			x["status"] = *s.Status
		}
		if s.UA != nil {
			x["ua"] = *s.UA
		}
		samples[i] = x
	}
	ips := make([][]any, len(c.IPs))
	for i, x := range c.IPs {
		ips[i] = []any{x.IP, x.Count}
	}
	m["vhosts"] = c.Vhosts
	m["windowMinutes"] = c.WindowMinutes
	m["firstSeen"] = c.FirstSeen
	m["lastSeen"] = c.LastSeen
	m["requestsPerMinute"] = c.RequestsPerMinute
	m["topPaths"] = paths
	m["topUserAgents"] = uas
	m["statuses"] = c.Statuses
	m["samples"] = samples
	m["ips"] = ips
	m["ipsTruncated"] = c.IPsTruncated
	m["renewal"] = c.Renewal
	delete(m, "requests")
	delete(m, "distinctPaths")
	delete(m, "userAgents")
}

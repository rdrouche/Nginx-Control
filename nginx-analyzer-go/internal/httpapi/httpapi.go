// Package httpapi porte la section API HTTP de server.js : ~40 routes qui
// exposent l'App (internal/app) au dashboard. Chaque poignee de main est une
// traduction directe du bloc `if (p === ...)` correspondant dans server.js,
// dans le meme ordre, pour rester facile a comparer route par route.
package httpapi

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"nginx-analyzer-go/internal/app"
	"nginx-analyzer-go/internal/baseline"
	"nginx-analyzer-go/internal/blocklistsources"
	"nginx-analyzer-go/internal/cidr"
	"nginx-analyzer-go/internal/config"
	"nginx-analyzer-go/internal/detect"
	"nginx-analyzer-go/internal/geoip"
	"nginx-analyzer-go/internal/parse"
	"nginx-analyzer-go/internal/rules"
	"nginx-analyzer-go/internal/store"
	"nginx-analyzer-go/internal/tail"
)

var bootTime = time.Now()

func nowMs() int64 { return time.Now().UnixMilli() }

// send reproduit send(res, code, data).
func send(w http.ResponseWriter, code int, data any) {
	body, err := json.Marshal(emptyNilSlices(data))
	if err != nil {
		body = []byte(`{"error":"encode failure"}`)
		code = 500
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// readJSONBody reproduit readJsonBody() : au-dela de config.ReadJSONBodyMaxBytes,
// renvoie {} plutot que de tenter un JSON invalide/tronque.
func readJSONBody(r *http.Request) map[string]any {
	limited := io.LimitReader(r.Body, config.ReadJSONBodyMaxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil || len(data) > config.ReadJSONBodyMaxBytes {
		return map[string]any{}
	}
	if len(data) == 0 {
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return map[string]any{}
	}
	return m
}

// clampLimit reproduit clampLimit() : une limite negative ou non-finie ne
// doit jamais degenerer en "toute la table" (fix, audit report).
func clampLimit(raw string, def, max int) int {
	return clampLimitMin(raw, def, max, 1)
}

func clampLimitMin(raw string, def, max, min int) int {
	if raw == "" {
		return def
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return def
	}
	n := int(f) // troncature vers zero, comme Math.trunc()
	if n < min {
		n = min
	}
	if n > max {
		n = max
	}
	return n
}

// numOrZero reproduit la coercion JS `+value || 0` (chaine vide/invalide -> 0).
func numOrZero(raw string) int64 {
	if raw == "" {
		return 0
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	return int64(f)
}

func numOrZeroInt(raw string) int {
	return int(numOrZero(raw))
}

// windowParams reproduit le helper window(url).
func windowParams(q url.Values) (from, to int64) {
	to = numOrZero(q.Get("to"))
	if to == 0 {
		to = nowMs()
	}
	hours := numOrZero(q.Get("hours"))
	if hours == 0 {
		hours = 24
	}
	from = numOrZero(q.Get("from"))
	if from == 0 {
		from = to - hours*3_600_000
	}
	return
}

// tokensMatch reproduit tokensMatch() : comparaison a temps constant.
func tokensMatch(a, b string) bool {
	ba, bb := []byte(a), []byte(b)
	if len(ba) != len(bb) {
		return false
	}
	return subtle.ConstantTimeCompare(ba, bb) == 1
}

func strOrNull(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func triStateQuery(q url.Values, key string) *bool {
	v := q.Get(key)
	switch v {
	case "1":
		t := true
		return &t
	case "0":
		f := false
		return &f
	default:
		return nil
	}
}

// ─── Conversion domaine -> forme JSON de l'API ────────────────────────────

func alertJSON(a store.Alert) map[string]any {
	return map[string]any{
		"id": a.ID, "ts": a.Ts, "type": a.Type, "severity": a.Severity,
		"ip": strOrNull(a.IP), "vhost": strOrNull(a.Vhost), "summary": a.Summary,
		"evidence": a.Evidence, "acked": a.Acked,
	}
}

func listAlertsJSON(r store.ListAlertsResult) map[string]any {
	alerts := make([]map[string]any, len(r.Alerts))
	for i, a := range r.Alerts {
		alerts[i] = alertJSON(a)
	}
	return map[string]any{"alerts": alerts, "total": r.Total, "fromDb": r.FromDB}
}

func exceptionJSON(e store.Exception) map[string]any {
	return map[string]any{
		"id": e.ID, "vhost": e.Vhost, "ip": e.IP, "reason": e.Reason,
		"created": e.Created, "author": e.Author,
	}
}

func wafEventJSON(e store.WafEvent) map[string]any {
	msgs := make([]map[string]any, len(e.Messages))
	for i, m := range e.Messages {
		msgs[i] = map[string]any{"ruleId": m.RuleID, "message": m.Message, "severity": m.Severity, "tags": m.Tags}
	}
	return map[string]any{
		"id": e.ID, "ts": e.Ts, "vhost": nullStr(e.Vhost), "ip": nullStr(e.IP), "method": nullStr(e.Method),
		"uri": nullStr(e.URI), "status": nullInt(e.Status), "blocked": e.Blocked, "severity": nullStr(e.Severity),
		"ruleIds": e.RuleIDs, "messages": msgs, "uniqueId": nullStr(e.UniqueID), "engine": nullStr(e.Engine),
	}
}

func wafEventDetailJSON(e store.WafEvent) map[string]any {
	m := wafEventJSON(e)
	m["raw"] = e.Raw
	ruleDetails := make([]map[string]any, len(e.RuleIDs))
	for i, id := range e.RuleIDs {
		category, why := parse.Categorize(id)
		var refURL any
		if u := parse.ReferenceURL(id); u != nil {
			refURL = *u
		}
		ruleDetails[i] = map[string]any{"ruleId": id, "category": category, "why": why, "referenceUrl": refURL}
	}
	m["rules"] = ruleDetails
	return m
}

func hourlyMetricJSON(list []store.HourlyMetric) []map[string]any {
	out := make([]map[string]any, len(list))
	for i, h := range list {
		out[i] = map[string]any{"hour": h.Hour, "ts": h.Ts, "requests": h.Requests, "bytes": h.Bytes, "errors": h.Errors}
	}
	return out
}

func countryStatJSON(list []store.CountryStat) []map[string]any {
	out := make([]map[string]any, len(list))
	for i, c := range list {
		out[i] = map[string]any{"country": c.Country, "requests": c.Requests, "bytes": c.Bytes, "errors": c.Errors}
	}
	return out
}

func vhostStatJSON(list []store.VhostStat) []map[string]any {
	out := make([]map[string]any, len(list))
	for i, v := range list {
		out[i] = map[string]any{"vhost": v.Vhost, "requests": v.Requests, "bytes": v.Bytes, "errors": v.Errors}
	}
	return out
}

func botCategoryStatJSON(list []store.BotCategoryStat) []map[string]any {
	out := make([]map[string]any, len(list))
	for i, b := range list {
		out[i] = map[string]any{"category": b.Category, "requests": b.Requests}
	}
	return out
}

func botPivotJSON(list []store.BotPivotRow, keyName string) []map[string]any {
	out := make([]map[string]any, len(list))
	for i, r := range list {
		out[i] = map[string]any{keyName: r.Key, "human": r.Human, "bots": r.Bots, "total": r.Total}
	}
	return out
}

func seriesPointJSON(list []store.SeriesPoint) []map[string]any {
	out := make([]map[string]any, len(list))
	for i, p := range list {
		out[i] = map[string]any{"bucket": p.Bucket, "ts": p.Ts, "requests": p.Requests, "bytes": p.Bytes, "errors": p.Errors}
	}
	return out
}

func wafTopRuleJSON(list []store.WafTopRule) []map[string]any {
	out := make([]map[string]any, len(list))
	for i, r := range list {
		out[i] = map[string]any{"ruleId": r.RuleID, "count": r.Count, "example": r.Example}
	}
	return out
}

func wafTopIPJSON(list []store.WafTopIP) []map[string]any {
	out := make([]map[string]any, len(list))
	for i, r := range list {
		out[i] = map[string]any{"ip": r.IP, "count": r.Count, "blocked": r.Blocked}
	}
	return out
}

func wafSeriesJSON(list []store.WafSeriesPoint) []map[string]any {
	out := make([]map[string]any, len(list))
	for i, p := range list {
		out[i] = map[string]any{"ts": p.Ts, "count": p.Count, "blocked": p.Blocked}
	}
	return out
}

func blocklistSummaryJSON(sum store.BlocklistHitsSummary, bySource []map[string]any) map[string]any {
	top := make([]map[string]any, len(sum.TopIPs))
	for i, t := range sum.TopIPs {
		top[i] = map[string]any{"ip": t.IP, "count": t.Count}
	}
	return map[string]any{
		"totalHits": sum.TotalHits, "uniqueIps": sum.UniqueIPs, "topIps": top, "bySource": bySource,
	}
}

func blocklistIPHistoryJSON(h store.BlocklistIPHistory) map[string]any {
	var first, last any
	if h.FirstSeen != nil {
		first = *h.FirstSeen
	}
	if h.LastSeen != nil {
		last = *h.LastSeen
	}
	return map[string]any{"ip": h.IP, "count": h.Count, "firstSeen": first, "lastSeen": last}
}

func explanationJSON(e detect.Explanation) map[string]any {
	return map[string]any{"id": e.ID, "what": e.What, "why": e.Why, "legit": e.Legit, "action": e.Action}
}

func blocklistConfigJSON(c rules.BlocklistConfig) map[string]any {
	var threshold, remediationMinutes any
	if c.Threshold != nil {
		threshold = *c.Threshold
	}
	if c.RemediationMinutes != nil {
		remediationMinutes = *c.RemediationMinutes
	}
	return map[string]any{
		"threshold": threshold, "windowMinutes": c.WindowMinutes,
		"remediation": c.Remediation, "remediationMinutes": remediationMinutes,
		"remediationType": c.RemediationType,
	}
}

func catalogJSON(c rules.Catalog) map[string]any {
	builtins := make([]map[string]any, len(c.Builtins))
	for i, b := range c.Builtins {
		builtins[i] = map[string]any{
			"key": b.Key, "id": b.ID, "enabled": b.Enabled, "custom": b.Custom,
			"explanation": explanationJSON(b.Explanation), "config": b.Config,
			"blocklist": blocklistConfigJSON(b.Blocklist),
		}
	}
	custom := make([]map[string]any, len(c.Custom))
	for i, cr := range c.Custom {
		var pathHint, uaHint any
		if cr.PathHint != "" {
			pathHint = cr.PathHint
		}
		if cr.UAHint != "" {
			uaHint = cr.UAHint
		}
		custom[i] = map[string]any{
			"key": cr.Key, "id": cr.ID, "name": cr.Name, "enabled": cr.Enabled, "custom": cr.Custom,
			"severity": cr.Severity, "description": cr.Description, "windowMinutes": cr.WindowMinutes,
			"minMatches": cr.MinMatches, "scope": cr.Scope, "minIps": minIPsJSON(cr.MinIPs), "pathHint": pathHint, "uaHint": uaHint,
			"statusIn": cr.StatusIn, "methodIn": cr.MethodIn, "blocklist": blocklistConfigJSON(cr.Blocklist),
		}
	}
	return map[string]any{
		"builtins": builtins, "custom": custom, "customYaml": c.CustomYaml, "customErrors": c.CustomErrors,
		"processing": map[string]any{
			"aggregation": c.Processing.Aggregation, "edgeTriggered": c.Processing.EdgeTriggered,
			"vhostOptOut": c.Processing.VhostOptOut, "customRules": c.Processing.CustomRules,
		},
	}
}

func blocklistRuleJSON(r rules.BlocklistRule) map[string]any {
	var remediationMinutes any
	if r.RemediationMinutes != nil {
		remediationMinutes = *r.RemediationMinutes
	}
	return map[string]any{
		"id": r.ID, "key": r.Key, "name": r.Name, "custom": r.Custom,
		"threshold": r.Threshold, "windowMinutes": r.WindowMinutes,
		"remediation": r.Remediation, "remediationMinutes": remediationMinutes,
		"remediationType": r.RemediationType,
	}
}

func baselineStatsJSON(s baseline.Stats) map[string]any {
	return map[string]any{
		"learning": s.Learning, "daysElapsed": s.DaysElapsed, "daysRequired": s.DaysRequired,
		"bucketsTracked": s.BucketsTracked, "bucketsUsable": s.BucketsUsable,
		"vhostsTracked": s.VhostsTracked, "totalSlots": s.TotalSlots, "coverage": s.Coverage,
		"startedAt": s.StartedAt.Format("2006-01-02T15:04:05.000Z"), "keysTracked": s.KeysTracked, "sporadicKeys": s.SporadicKeys,
	}
}

func recentGeoEventJSON(e app.RecentGeoEvent) map[string]any {
	var isBot any
	if e.IsBot != nil {
		isBot = *e.IsBot
	}
	var category any
	if e.Category != "" {
		category = e.Category
	}
	return map[string]any{
		"seq": e.Seq, "ts": e.TS, "vhost": e.Vhost, "country": e.Country,
		"isBot": isBot, "category": category,
	}
}

func memoryMB() float64 {
	rss := readRSSBytes()
	return math.Round(float64(rss)/1048576*10) / 10
}

// readRSSBytes lit la RSS reelle du processus depuis /proc/self/status
// (Linux, la seule plateforme de deploiement de cet agent), avec un repli
// sur les statistiques du runtime Go si /proc n'est pas disponible (autre
// OS, ex. lors d'un `go test` local) - equivalent de
// process.memoryUsage().rss cote Node.
func readRSSBytes() int64 {
	data, err := os.ReadFile("/proc/self/status")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "VmRSS:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if kb, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
						return kb * 1024
					}
				}
			}
		}
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return int64(ms.Sys)
}

// ─── Route handlers ────────────────────────────────────────────────────────

// NewHandler reproduit le http.createServer(...) de server.js : construit le
// routeur complet pour une *app.App deja assemblee et demarree.
func NewHandler(a *app.App) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				send(w, 500, map[string]any{"error": errString(rec)})
			}
		}()
		p := r.URL.Path
		q := r.URL.Query()
		cfg := a.Cfg

		if p == "/api/health" {
			send(w, 200, map[string]any{"ok": true, "uptime": time.Since(bootTime).Seconds()})
			return
		}

		if cfg.Token != "" && !tokensMatch(r.Header.Get("X-Analyzer-Token"), cfg.Token) {
			send(w, 401, map[string]any{"error": "unauthorized"})
			return
		}

		switch {
		case p == "/api/status":
			handleStatus(w, a)
			return

		case p == "/api/alerts" && r.Method == http.MethodGet:
			acked := triStateQuery(q, "acked")
			res := a.Store.ListAlerts(store.ListAlertsOptions{
				Limit: clampLimit(q.Get("limit"), 100, 500), Offset: maxInt(0, numOrZeroInt(q.Get("offset"))),
				Type: q.Get("type"), Severity: q.Get("severity"), Since: numOrZero(q.Get("since")),
				SinceID: numOrZero(q.Get("sinceId")), Order: orderOf(q.Get("order")), Acked: acked,
			})
			send(w, 200, listAlertsJSON(res))
			return

		case strings.HasPrefix(p, "/api/alerts/") && strings.HasSuffix(p, "/ack") && r.Method == http.MethodPost:
			parts := strings.Split(p, "/")
			var id int64
			if len(parts) > 3 {
				id, _ = strconv.ParseInt(parts[3], 10, 64)
			}
			send(w, 200, map[string]any{"ok": a.Store.AckAlert(id)})
			return

		case p == "/api/alerts/ack-all" && r.Method == http.MethodPost:
			n := a.Store.AckAllAlerts(store.AckAllAlertsOptions{
				Type: q.Get("type"), Severity: q.Get("severity"), Vhost: q.Get("vhost"), OnlyUnacked: true,
			})
			send(w, 200, map[string]any{"updated": n})
			return

		case p == "/api/alerts/clear" && r.Method == http.MethodPost:
			n := a.Store.ClearAlerts(store.ClearAlertsOptions{Type: q.Get("type"), Severity: q.Get("severity"), Vhost: q.Get("vhost")})
			send(w, 200, map[string]any{"deleted": n})
			return

		case p == "/api/traffic/series":
			from, to := windowParams(q)
			grain := q.Get("grain")
			if grain == "" {
				grain = "minute"
			}
			send(w, 200, map[string]any{"grain": grain, "series": seriesPointJSON(a.Store.Series(grain, from, to, q.Get("vhost")))})
			return

		case p == "/api/traffic/countries":
			from, to := windowParams(q)
			send(w, 200, map[string]any{"countries": countryStatJSON(a.Store.ByCountry(from, to, q.Get("vhost")))})
			return

		case p == "/api/traffic/bots":
			from, to := windowParams(q)
			rows := a.Store.ByBotCategory(from, to, q.Get("vhost"))
			var total, bots int64
			for _, row := range rows {
				total += row.Requests
				if row.Category != "human" {
					bots += row.Requests
				}
			}
			send(w, 200, map[string]any{"total": total, "human": total - bots, "bots": bots, "byCategory": botCategoryStatJSON(rows)})
			return

		case p == "/api/traffic/bots/vhosts":
			from, to := windowParams(q)
			send(w, 200, map[string]any{"vhosts": botPivotJSON(a.Store.BotByVhost(from, to), "vhost")})
			return

		case p == "/api/traffic/bots/countries":
			from, to := windowParams(q)
			send(w, 200, map[string]any{"countries": botPivotJSON(a.Store.BotByCountry(from, to, q.Get("vhost")), "country")})
			return

		case p == "/api/traffic/recent":
			handleRecent(w, a, q)
			return

		case p == "/api/traffic/vhosts":
			from, to := windowParams(q)
			send(w, 200, map[string]any{"vhosts": vhostStatJSON(a.Store.ByVhost(from, to))})
			return

		case p == "/api/exceptions" && r.Method == http.MethodGet:
			list := a.Store.ListExceptions(q.Get("vhost"))
			out := make([]map[string]any, len(list))
			for i, e := range list {
				out[i] = exceptionJSON(e)
			}
			send(w, 200, map[string]any{"exceptions": out})
			return

		case p == "/api/exceptions" && r.Method == http.MethodPost:
			vhost, ip := q.Get("vhost"), q.Get("ip")
			if vhost == "" || ip == "" {
				send(w, 400, map[string]any{"error": "vhost and ip required"})
				return
			}
			res := a.Store.AddException(store.AddExceptionInput{Vhost: vhost, IP: ip, Reason: q.Get("reason"), Author: q.Get("author")})
			a.Detector.SetExceptions(app.ToDetectExceptions(a.Store.ListExceptions("")))
			code := 200
			if !res.OK {
				code = 400
			}
			send(w, code, map[string]any{"ok": res.OK, "error": strOrNull(res.Error)})
			return

		case strings.HasPrefix(p, "/api/exceptions/") && r.Method == http.MethodDelete:
			parts := strings.Split(p, "/")
			var id int64
			if len(parts) > 3 {
				id, _ = strconv.ParseInt(parts[3], 10, 64)
			}
			ok := a.Store.RemoveException(id)
			a.Detector.SetExceptions(app.ToDetectExceptions(a.Store.ListExceptions("")))
			send(w, 200, map[string]any{"ok": ok})
			return

		case p == "/api/rules" && r.Method == http.MethodGet:
			dc := a.Detector.Cfg()
			catalog := a.Rules.Catalog(detect.Explanations, rules.Thresholds{
				WindowMs:   dc.WindowMs,
				Bruteforce: &rules.BruteforceThresholds{MinFailures: dc.Bruteforce.MinFailures},
				Scan: &rules.ScanThresholds{
					MinRequests: dc.Scan.MinRequests, MinDistinct: dc.Scan.MinDistinct, MinNotFoundRatio: dc.Scan.MinNotFoundRatio,
				},
				Flood:    &rules.FloodThresholds{MinRequests: dc.Flood.MinRequests},
				Scraping: &rules.ScrapingThresholds{MinRequests: dc.Scraping.MinRequests, MaxDistinct: dc.Scraping.MaxDistinct},
				Volumetric: &rules.VolumetricThresholds{
					LearningDays: a.Baseline.Cfg().LearningDays, SigmaThreshold: a.Baseline.Cfg().SigmaThreshold,
					MinAbsoluteRequests: a.Baseline.Cfg().MinAbsoluteRequests,
				},
				CountryTraffic: &rules.VolumetricThresholds{
					LearningDays: a.CountryBaseline.Cfg().LearningDays, SigmaThreshold: a.CountryBaseline.Cfg().SigmaThreshold,
					MinAbsoluteRequests: a.CountryBaseline.Cfg().MinAbsoluteRequests,
				},
			})
			send(w, 200, catalogJSON(catalog))
			return

		case p == "/api/rules/toggle" && r.Method == http.MethodPost:
			key := q.Get("key")
			enable := q.Get("enable") != "0" && q.Get("enable") != "false"
			if !a.Rules.Toggle(key, enable) {
				send(w, 400, map[string]any{"error": "Regle inconnue : " + key})
				return
			}
			switch key {
			case "bruteforce", "scan", "flood", "scraping":
				a.Detector.SetRuleEnabled(key, enable)
			case "volumetric":
				a.Baseline.SetEnabled(enable)
			case "country_traffic":
				a.CountryBaseline.SetEnabled(enable)
			}
			send(w, 200, map[string]any{"ok": true, "key": key, "enabled": enable})
			return

		case p == "/api/rules/blocklist-config" && r.Method == http.MethodGet:
			list := a.Rules.ListBlocklistRules()
			out := make([]map[string]any, len(list))
			for i, br := range list {
				out[i] = blocklistRuleJSON(br)
			}
			send(w, 200, map[string]any{"rules": out})
			return

		case p == "/api/rules/blocklist" && r.Method == http.MethodPost:
			key := q.Get("key")
			body := readJSONBody(r)
			remediation, _ := body["remediation"].(bool)
			result := a.Rules.SetBlocklistConfig(key, rules.BlocklistConfigInput{
				Threshold: floatPtrFromBody(body, "threshold"), WindowMinutes: floatPtrFromBody(body, "windowMinutes"),
				Remediation: remediation, RemediationMinutes: floatPtrFromBody(body, "remediationMinutes"),
				RemediationType: remediationTypeFromBody(body),
			})
			if !result.OK {
				send(w, 400, map[string]any{"ok": false, "errors": result.Errors, "value": nil})
				return
			}
			send(w, 200, map[string]any{"ok": true, "key": key, "value": blocklistConfigJSON(result.Value)})
			return

		case p == "/api/rules/custom" && r.Method == http.MethodGet:
			yaml := a.Rules.CustomYaml()
			if yaml == "" {
				yaml = rules.Template()
			}
			send(w, 200, map[string]any{"yaml": yaml, "errors": a.Rules.CustomErrors()})
			return

		case p == "/api/rules/custom" && r.Method == http.MethodPut:
			body := readJSONBody(r)
			yamlText, _ := body["yaml"].(string)
			result := a.Rules.SetCustomYaml(yamlText)
			if !result.OK {
				send(w, 400, map[string]any{"ok": false, "errors": result.Errors})
				return
			}
			a.Detector.SetCustomRules(app.ToDetectCustomRules(a.Rules.CustomValid()))
			send(w, 200, map[string]any{"ok": true, "count": result.Count})
			return

		case p == "/api/vhost-rules" && r.Method == http.MethodPost:
			body := readJSONBody(r)
			vhostsRaw, _ := body["vhosts"].(map[string]any)
			input := make(map[string]rules.VhostRuleInput, len(vhostsRaw))
			for name, v := range vhostsRaw {
				vm, _ := v.(map[string]any)
				// JS: `cfg.enabled !== false` - seul un false explicite desactive ;
				// un champ absent vaut true.
				enabled := true
				if b, ok := vm["enabled"].(bool); ok {
					enabled = b
				}
				var ignore []int
				if arr, ok := vm["ignore"].([]any); ok {
					for _, x := range arr {
						if n, ok := jsNumber(x); ok {
							ignore = append(ignore, n)
						}
					}
				}
				// pathsIgnore : { "<id>": ["/a", "/b*"] } - cles non numeriques ignorees.
				var pathsIgnore map[int][]string
				if pm, ok := vm["pathsIgnore"].(map[string]any); ok {
					pathsIgnore = make(map[int][]string, len(pm))
					for k, lv := range pm {
						id, err := strconv.Atoi(k)
						if err != nil {
							continue
						}
						arr, _ := lv.([]any)
						for _, x := range arr {
							pathsIgnore[id] = append(pathsIgnore[id], anyToString(x))
						}
					}
				}
				input[name] = rules.VhostRuleInput{Enabled: enabled, Ignore: ignore, PathsIgnore: pathsIgnore}
			}
			m := a.Rules.SetVhostRules(input)
			a.Detector.SetVhostRules(app.ToDetectVhostCfg(m))
			send(w, 200, map[string]any{"ok": true, "count": len(m)})
			return

		case p == "/api/blocklist-sources" && r.Method == http.MethodPost:
			body := readJSONBody(r)
			mode, _ := body["mode"].(string)
			blocklistsources.SetMode(mode)
			sourcesRaw, _ := body["sources"].(map[string]any)
			sources := make(map[string]blocklistsources.Source, len(sourcesRaw))
			for name, v := range sourcesRaw {
				vm, _ := v.(map[string]any)
				var ips []string
				if arr, ok := vm["ips"].([]any); ok {
					for _, x := range arr {
						if s, ok := x.(string); ok {
							ips = append(ips, s)
						}
					}
				}
				sources[name] = blocklistsources.Source{IPs: ips}
			}
			blocklistsources.SetSources(sources)
			send(w, 200, map[string]any{"ok": true, "mode": blocklistsources.GetMode()})
			return

		case p == "/api/baseline":
			send(w, 200, baselineStatsJSON(a.Baseline.Stats()))
			return

		case p == "/api/baseline/keys":
			bl := a.Baseline
			if r.URL.Query().Get("type") == "country" {
				bl = a.CountryBaseline
			}
			send(w, 200, map[string]any{"keys": bl.KeysSummary(100)})
			return
		case p == "/api/baseline/profile":
			bl := a.Baseline
			if r.URL.Query().Get("type") == "country" {
				bl = a.CountryBaseline
			}
			k := r.URL.Query().Get("key")
			if k == "" || len(k) > 253 {
				send(w, 400, map[string]any{"error": "key required"})
				return
			}
			send(w, 200, bl.Profile(k))
			return
		case p == "/api/baseline/country":
			send(w, 200, baselineStatsJSON(a.CountryBaseline.Stats()))
			return

		case p == "/api/waf/events" && r.Method == http.MethodGet:
			res := a.Store.ListWaf(store.ListWafOptions{
				Limit: clampLimit(q.Get("limit"), 100, 500), Offset: maxInt(0, numOrZeroInt(q.Get("offset"))),
				Vhost: q.Get("vhost"), Severity: q.Get("severity"), Blocked: triStateQuery(q, "blocked"),
				Since: numOrZero(q.Get("since")),
			})
			out := make([]map[string]any, len(res.Events))
			for i, e := range res.Events {
				out[i] = wafEventJSON(e)
			}
			send(w, 200, map[string]any{"events": out, "total": res.Total, "fromDb": res.FromDB})
			return

		case strings.HasPrefix(p, "/api/waf/events/") && r.Method == http.MethodGet:
			parts := strings.Split(p, "/")
			var id int64
			if len(parts) > 4 {
				id, _ = strconv.ParseInt(parts[4], 10, 64)
			}
			ev := a.Store.GetWafEvent(id)
			if ev == nil {
				send(w, 404, map[string]any{"error": "Not found"})
				return
			}
			send(w, 200, wafEventDetailJSON(*ev))
			return

		case p == "/api/waf/top-rules":
			from, to := windowParams(q)
			send(w, 200, map[string]any{"rules": wafTopRuleJSON(a.Store.WafTopRules(from, to, q.Get("vhost"), 0))})
			return

		case p == "/api/waf/top-ips":
			from, to := windowParams(q)
			send(w, 200, map[string]any{"ips": wafTopIPJSON(a.Store.WafTopIps(from, to, q.Get("vhost")))})
			return

		case p == "/api/waf/series":
			from, to := windowParams(q)
			send(w, 200, map[string]any{"series": wafSeriesJSON(a.Store.WafSeries(from, to, q.Get("vhost")))})
			return

		case p == "/api/waf/clear" && r.Method == http.MethodPost:
			n := a.Store.ClearWaf(store.ClearWafOptions{Vhost: q.Get("vhost"), Severity: q.Get("severity"), Blocked: triStateQuery(q, "blocked")})
			send(w, 200, map[string]any{"deleted": n})
			return

		case p == "/api/blocklist-hits/summary":
			from, to := windowParams(q)
			limit := clampLimitMin(q.Get("limit"), 500, 5000, 1)
			summary := a.Store.BlocklistHitsSummary(from, to, limit)
			bySourceCounts := map[string]int{}
			var order []string
			for _, t := range summary.TopIPs {
				for _, name := range blocklistsources.SourcesContaining(t.IP) {
					if _, ok := bySourceCounts[name]; !ok {
						order = append(order, name)
					}
					bySourceCounts[name] += t.Count
				}
			}
			bySource := make([]map[string]any, 0, len(order))
			for _, name := range order {
				bySource = append(bySource, map[string]any{"name": name, "hits": bySourceCounts[name]})
			}
			sortBySourceHitsDesc(bySource)
			send(w, 200, blocklistSummaryJSON(summary, bySource))
			return

		case p == "/api/blocklist-hits/check":
			ip := q.Get("ip")
			if ip == "" || !cidr.IsValidPattern(ip) {
				send(w, 400, map[string]any{"error": "ip invalide"})
				return
			}
			from, to := windowParams(q)
			send(w, 200, blocklistIPHistoryJSON(a.Store.BlocklistHitsForIp(ip, from, to)))
			return

		case p == "/api/blocklist-hits/clear" && r.Method == http.MethodPost:
			n := a.Store.ClearBlocklistHits()
			send(w, 200, map[string]any{"deleted": n})
			return

		case p == "/api/baseline/exclude" && r.Method == http.MethodPost:
			vhost, hour := q.Get("vhost"), q.Get("hour")
			if vhost == "" || hour == "" {
				send(w, 400, map[string]any{"error": "vhost and hour required"})
				return
			}
			a.Baseline.Exclude(vhost, hour)
			a.Store.SetState("baseline", a.Baseline.ExportState())
			send(w, 200, map[string]any{"ok": true})
			return

		case p == "/api/baseline/country/exclude" && r.Method == http.MethodPost:
			country, hour := q.Get("country"), q.Get("hour")
			if country == "" || hour == "" {
				send(w, 400, map[string]any{"error": "country and hour required"})
				return
			}
			a.CountryBaseline.Exclude(country, hour)
			a.Store.SetState("country_baseline", a.CountryBaseline.ExportState())
			send(w, 200, map[string]any{"ok": true})
			return
		}

		send(w, 404, map[string]any{"error": "Not found"})
	})
}

func handleStatus(w http.ResponseWriter, a *app.App) {
	tailStats, tailFollowing := a.Tailer.Status()
	wafStats, wafFollowing := a.WafTailer.Status()
	blStats, blFollowing := a.BlocklistTailer.Status()

	var wafWarnings []map[string]any
	for _, f := range wafFollowing {
		if f.SuspectFormat {
			wafWarnings = append(wafWarnings, map[string]any{"file": f.File, "vhost": f.Vhost, "lines": f.Lines, "dropped": f.Dropped})
		}
	}

	send(w, 200, map[string]any{
		"version": "1.0.0",
		"config": map[string]any{
			"logsDir": a.Cfg.LogsDir, "dbPath": a.Cfg.DBPath,
			"learningDays": a.Cfg.LearningDays, "sigma": a.Cfg.SigmaThresh,
			"countrySigma": a.Cfg.CountrySigmaThreshold, "countryMinRequests": a.Cfg.CountryMinRequests,
		},
		"tail":                    tailStatusJSON(tailStats, tailFollowing),
		"wafTail":                 tailStatusJSON(wafStats, wafFollowing),
		"blocklistTail":           tailStatusJSON(blStats, blFollowing),
		"blocklistSources":        map[string]any{"mode": blocklistsources.GetMode(), "synced": blocklistsources.HasSources()},
		"wafWarnings":             wafWarnings,
		"accessLogPatternWarning": tailStats.Files == 0,
		"waf":                     wafStatsJSON(a.Store.WafStats()),
		"detector":                detectorStatsJSON(a.Detector.Stats()),
		"baseline":                baselineStatsJSON(a.Baseline.Stats()),
		"countryBaseline":         baselineStatsJSON(a.CountryBaseline.Stats()),
		"store":                   storeStatsJSON(a.Store.Stats()),
		"geoip":                   geoipStatusJSON(geoip.Status()),
		"memoryMb":                memoryMB(),
	})
}

func tailStatusJSON(s tail.Stats, following []tail.FollowingStatus) map[string]any {
	fs := make([]map[string]any, len(following))
	for i, f := range following {
		fs[i] = map[string]any{
			"file": f.File, "vhost": f.Vhost, "format": f.Format, "offset": f.Offset,
			"lines": f.Lines, "parsed": f.Parsed, "dropped": f.Dropped, "suspectFormat": f.SuspectFormat,
		}
	}
	return map[string]any{
		"lines": s.Lines, "parsed": s.Parsed, "dropped": s.Dropped, "rotations": s.Rotations, "files": s.Files,
		"following": fs,
	}
}

func wafStatsJSON(s store.WafStats) map[string]any {
	return map[string]any{"rows": s.Rows, "persistent": s.Persistent}
}

func detectorStatsJSON(s detect.Stats) map[string]any {
	return map[string]any{"trackedIps": s.TrackedIps, "activeAlerts": s.ActiveAlerts}
}

func storeStatsJSON(s store.Stats) map[string]any {
	m := map[string]any{"persistent": s.Persistent, "pending": s.Pending}
	if s.Persistent {
		m["rows"] = s.Rows
		m["alerts"] = s.Alerts
		m["dbBytes"] = s.DBBytes
	}
	return m
}

func geoipStatusJSON(s geoip.StatusInfo) map[string]any {
	var db any
	if s.Database != "" {
		db = s.Database
	}
	return map[string]any{"available": s.Available, "database": db, "cached": s.Cached}
}

func handleRecent(w http.ResponseWriter, a *app.App, q url.Values) {
	sinceSeq := numOrZero(q.Get("sinceSeq"))
	since := numOrZero(q.Get("since"))
	limit := clampLimit(q.Get("limit"), 200, config.RecentGeoMax)
	vhost := q.Get("vhost")

	events, currentSeq := a.RecentGeoSince(sinceSeq, since, vhost)
	if len(events) > limit {
		events = events[len(events)-limit:]
	}
	out := make([]map[string]any, len(events))
	for i, e := range events {
		out[i] = recentGeoEventJSON(e)
	}
	send(w, 200, map[string]any{
		"events": out, "geoipAvailable": geoip.Status().Available,
		"serverTime": nowMs(), "currentSeq": currentSeq,
	})
}

func errString(r any) string {
	if e, ok := r.(error); ok {
		return e.Error()
	}
	if s, ok := r.(string); ok {
		return s
	}
	return "internal error"
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func orderOf(v string) string {
	if v == "asc" {
		return "asc"
	}
	return "desc"
}

func floatPtrFromBody(body map[string]any, key string) *float64 {
	v, ok := body[key]
	if !ok || v == nil {
		return nil
	}
	if f, ok := v.(float64); ok {
		return &f
	}
	return nil
}

func sortBySourceHitsDesc(list []map[string]any) {
	for i := 1; i < len(list); i++ {
		for j := i; j > 0; j-- {
			hi, _ := list[j]["hits"].(int)
			hj, _ := list[j-1]["hits"].(int)
			if hi > hj {
				list[j], list[j-1] = list[j-1], list[j]
			} else {
				break
			}
		}
	}
}

// jsNumber reproduit Number(x) pour les valeurs issues d'un JSON : nombre tel
// quel, chaine numerique convertie, le reste (NaN cote JS) est ignore.
func jsNumber(x any) (int, bool) {
	switch v := x.(type) {
	case float64:
		return int(v), true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, false
		}
		return int(f), true
	}
	return 0, false
}

// nullStr / nullInt : cote Node, une colonne absente est `null` (e.x ?? null) ;
// les types du domaine Go n'ont que la valeur zero, que l'on remappe en null.
func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullInt(n int) any {
	if n == 0 {
		return nil
	}
	return n
}

// emptyNilSlices parcourt une reponse et remplace toute slice nil par une slice
// vide : encoding/json ecrit `null` pour une slice nil, alors que le JS ecrit
// `[]` - et le dashboard fait `.length`/`.map` sur ces champs. Fait une fois,
// ici, plutot que champ par champ (evite les regressions a chaque nouvelle route).
func emptyNilSlices(v any) any {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return v
	}
	return walkNil(rv).Interface()
}

func walkNil(v reflect.Value) reflect.Value {
	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			return v
		}
		return walkNil(v.Elem())
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return v // []byte : JSON base64, inchange
		}
		if v.IsNil() {
			return reflect.MakeSlice(v.Type(), 0, 0)
		}
		k := v.Type().Elem().Kind()
		if k == reflect.Map || k == reflect.Slice || k == reflect.Interface {
			for i := 0; i < v.Len(); i++ {
				v.Index(i).Set(walkNil(v.Index(i)))
			}
		}
	case reflect.Map:
		if v.IsNil() {
			return v
		}
		k := v.Type().Elem().Kind()
		if k == reflect.Map || k == reflect.Slice || k == reflect.Interface {
			for _, key := range v.MapKeys() {
				v.SetMapIndex(key, walkNil(v.MapIndex(key)))
			}
		}
	}
	return v
}

// anyToString : valeur JSON -> chaine pour les motifs paths-ignore ; tout ce
// qui n est pas une chaine est ecarte par SanitizePathsIgnore (pas de "/").
func anyToString(x any) string {
	if s, ok := x.(string); ok {
		return s
	}
	return ""
}

// minIPsJSON : null hors scope global (parite avec le moteur Node).
func minIPsJSON(n int) any {
	if n <= 0 {
		return nil
	}
	return n
}

// remediationTypeFromBody : "" si absent/null ; une valeur non textuelle devient
// une valeur invalide (refusee par la validation, comme String(x) cote Node).
func remediationTypeFromBody(body map[string]any) string {
	v, present := body["remediationType"]
	if !present || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return "invalide"
}

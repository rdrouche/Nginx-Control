package main

import (
	"log"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Label schema — same "nginx-control.*" family and spirit as Partie 1's
// Docker labels (features/docker-autoconfig.js on the dashboard side), with
// the one necessary difference documented in the design doc: a location's
// target is a plain reachable `scheme://host:port` this agent's OWN host can
// already reach directly (`.target`), never a bare Docker container name —
// there is no "same Docker network as nginx" trick available here, since
// nginx runs on a different host entirely. `.proxy_pass` is accepted as an
// alias of `.target` purely for muscle-memory continuity with Partie 1's own
// label name; both are treated identically by this agent.
//
//	nginx-control.enable=true
//	nginx-control.vhost.server_name=app.example.com
//	nginx-control.vhost.mode=direct|tunnel|relay            (default: direct)
//	nginx-control.vhost.relay_scheme=http|https             (default: http, mode=relay uniquement)
//	nginx-control.vhost.listen=8443
//	nginx-control.vhost.ssl_certificate=none|snippet|auto|certbot_http|certbot_dns
//	nginx-control.vhost.ssl_certificate.snippet=<file>
//	nginx-control.vhost.http_to_https_auto=true
//	nginx-control.vhost.server.snippet01=<file>            (01, 02, ...)
//	nginx-control.vhost.location01=/                       (01, 02, ...)
//	nginx-control.vhost.location01.target=http://host:port (ou .proxy_pass)
//	nginx-control.vhost.location01.snippet01=<file>
//	nginx-control.vhost.location01.monitor.enable=false
//	nginx-control.monitor.enable=true
//	nginx-control.monitor.interval=30s
//	nginx-control.monitor.valid_http_code=200,301,302
//	nginx-control.diagnostic.enable=false
//	nginx-control.vhost.analyze.enable=false
//	nginx-control.vhost.analyze.ignore_rules=1,2,4
//	nginx-control.publish=dmz,lan                          (multi-master, defaut: toutes les cibles — voir targets.go/README.md)
const labelPrefix = "nginx-control."

var locationKeyRE = regexp.MustCompile(`^nginx-control\.vhost\.location(\d+)$`)

// Fix (audit report, Basse/"Agent Go"): only the literal "true" (any case)
// used to be recognized — every other common Docker-label boolean spelling
// ("yes", "1", used by plenty of other Docker-labels-driven tools operators
// may be copying habits from) silently read as false, with no warning at
// all: a container meant to opt in with nginx-control.enable=yes was simply
// invisible to this agent. "false"/"no"/"0" all still mean false (the
// zero-value default already covers "absent" and everything else); only
// these two spellings are ambiguous enough to warn about, since they most
// likely indicate a real typo rather than an intentional third value.
func boolLabel(labels map[string]string, key string, def bool) bool {
	v, ok := labels[key]
	if !ok {
		return def
	}
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "true", "yes", "1":
		return true
	case "false", "no", "0", "":
		return false
	default:
		log.Printf("[labels] %s=%q non reconnu, traite comme %v (valeurs valides : true/false, yes/no, 1/0)", key, v, def)
		return def
	}
}

// Fix (audit report, Basse/"Agent Go"): an unparseable value (a typo, an
// empty string left over from a template substitution) used to silently
// collapse to 0, exactly the same zero-value Go itself uses for "this
// field was never set" — combined with VhostSpec.Listen's `omitempty` json
// tag, the manifest sent to the dashboard ends up with NO "listen" field at
// all, indistinguishable from the operator never having set the label in
// the first place. The dashboard then quietly applies its own default
// (443/80 depending on SSL) with no trace anywhere that the operator's
// actual value was thrown away. Logged here instead, at the one place that
// actually still has the original string to show.
func intLabel(labels map[string]string, key string) int {
	v, ok := labels[key]
	if !ok {
		return 0
	}
	trimmed := strings.TrimSpace(v)
	n, err := strconv.Atoi(trimmed)
	if err != nil {
		log.Printf("[labels] %s=%q invalide (entier attendu), ignore — voir la valeur par defaut cote dashboard", key, v)
		return 0
	}
	return n
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func intCSV(s string) []int {
	out := []int{}
	for _, tok := range splitCSV(s) {
		if n, err := strconv.Atoi(tok); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// numberedSnippets collects "<prefix>NN" -> value for NN = 01, 02, ... under
// a given prefix, e.g. "nginx-control.vhost.server.snippet" ->
// [".snippet01 value", ".snippet02 value", ...], in index order.
func numberedSnippets(labels map[string]string, prefix string) []string {
	type kv struct {
		n int
		v string
	}
	var found []kv
	re := regexp.MustCompile("^" + regexp.QuoteMeta(prefix) + `(\d+)$`)
	for k, v := range labels {
		if m := re.FindStringSubmatch(k); m != nil {
			n, _ := strconv.Atoi(m[1])
			found = append(found, kv{n, v})
		}
	}
	sort.Slice(found, func(i, j int) bool { return found[i].n < found[j].n })
	out := make([]string, 0, len(found))
	for _, f := range found {
		out = append(out, f.v)
	}
	return out
}

// vhostFromLabels builds one VhostSpec from a single container's labels,
// plus the (possibly nil) list of multi-master target names this container
// asked to be published to (nginx-control.publish=, see targets.go's
// publishesTo() for how nil/"all" is interpreted). Returns (nil, nil, false)
// if this container does not opt in (nginx-control.enable != true) or
// declares no usable location.
func vhostFromLabels(labels map[string]string) (*VhostSpec, []string, bool) {
	if !boolLabel(labels, labelPrefix+"enable", false) {
		return nil, nil, false
	}
	serverName := strings.TrimSpace(labels[labelPrefix+"vhost.server_name"])
	if serverName == "" {
		return nil, nil, false
	}
	publish := splitCSV(strings.ToLower(labels[labelPrefix+"publish"]))

	mode := strings.ToLower(strings.TrimSpace(labels[labelPrefix+"vhost.mode"]))
	if mode != "tunnel" && mode != "relay" {
		mode = "direct"
	}
	relayScheme := strings.ToLower(strings.TrimSpace(labels[labelPrefix+"vhost.relay_scheme"]))
	if relayScheme != "https" {
		relayScheme = "http"
	}

	v := &VhostSpec{
		ServerName:            serverName,
		Mode:                  mode,
		RelayScheme:           relayScheme,
		Listen:                intLabel(labels, labelPrefix+"vhost.listen"),
		SSLCertificate:        strings.ToLower(strings.TrimSpace(labels[labelPrefix+"vhost.ssl_certificate"])),
		SSLCertificateSnippet: strings.TrimSpace(labels[labelPrefix+"vhost.ssl_certificate.snippet"]),
		HTTPToHTTPSAuto:       boolLabel(labels, labelPrefix+"vhost.http_to_https_auto", false),
		ServerSnippets:        numberedSnippets(labels, labelPrefix+"vhost.server.snippet"),
		Diagnostic:            DiagnosticSpec{Enable: boolLabel(labels, labelPrefix+"diagnostic.enable", true)},
		Analyze: AnalyzeSpec{
			Enable:      boolLabel(labels, labelPrefix+"vhost.analyze.enable", true),
			IgnoreRules: intCSV(labels[labelPrefix+"vhost.analyze.ignore_rules"]),
		},
		Monitor: MonitorSpec{
			Enable:        boolLabel(labels, labelPrefix+"monitor.enable", false),
			Interval:      strings.TrimSpace(labels[labelPrefix+"monitor.interval"]),
			ValidHTTPCode: strings.TrimSpace(labels[labelPrefix+"monitor.valid_http_code"]),
		},
	}

	// Locations: nginx-control.vhost.location01=/  + .target/.proxy_pass +
	// .snippetNN + .monitor.enable, discovered by scanning for the base key
	// (bare "locationNN") and reading its numbered siblings directly.
	//
	// Fix v12.22.0 (audit finding GO-11) : cette boucle collectait autrefois
	// seulement l entier n (via strconv.Atoi), puis RECONSTRUISAIT la clé de
	// base avec pad2(n) — donc "location1" (n=1, sans zero en tete) devenait
	// "location01" une fois reconstruit, une clé qui n existe pas dans les
	// labels reels : path restait vide et toute la location, silencieusement,
	// disparaissait (et le vhost entier avec elle si c etait la seule). En
	// plus, "location01" et "location1" ensemble donnaient le meme n=1 et
	// produisaient un doublon. On garde desormais le suffixe BRUT (m[1], tel
	// qu ecrit dans le label) pour reconstruire la clé, et on deduplique par
	// valeur entiere (la premiere variante rencontree gagne).
	type locIdx struct {
		n      int
		suffix string
	}
	seenIdx := map[int]bool{}
	var indices []locIdx
	for k := range labels {
		if m := locationKeyRE.FindStringSubmatch(k); m != nil {
			n, _ := strconv.Atoi(m[1])
			if seenIdx[n] {
				continue
			}
			seenIdx[n] = true
			indices = append(indices, locIdx{n, m[1]})
		}
	}
	sort.Slice(indices, func(i, j int) bool { return indices[i].n < indices[j].n })
	for _, idx := range indices {
		base := labelPrefix + "vhost.location" + idx.suffix
		path := strings.TrimSpace(labels[base])
		if path == "" {
			continue
		}
		target := strings.TrimSpace(labels[base+".target"])
		if target == "" {
			target = strings.TrimSpace(labels[base+".proxy_pass"])
		}
		if target == "" {
			continue // pas de cible utilisable, on ignore cette location plutot que d envoyer un manifeste casse
		}
		// Fix (audit report, Basse/"Agent Go"): the dashboard's own
		// AGENT_TARGET_RE (lib/agent-manifest.js) only ever matches a bare
		// "scheme://host[:port]" — no trailing slash, no path at all. A
		// target label written with one anyway (an easy, common copy-paste
		// habit from a proxy_pass value, where a trailing "/" changes the
		// URI-rewriting behavior) used to be sent to the dashboard exactly
		// as typed, failing that regex and rejecting the WHOLE manifest —
		// every other, otherwise-valid vhost from this same agent rolled
		// back with it. A single trailing slash is trimmed here rather than
		// treated as a hard error: it is unambiguous (this agent's own
		// AGENT_TARGET_RE-equivalent shape never expects one) and this is
		// the one place that still has the raw label value to fix it from.
		if trimmed := strings.TrimSuffix(target, "/"); trimmed != target {
			log.Printf("[labels] %s : barre oblique finale retiree (%q -> %q)", base, target, trimmed)
			target = trimmed
		}
		loc := LocationSpec{
			Path:          path,
			Target:        target,
			Snippets:      numberedSnippets(labels, base+".snippet"),
			MonitorIgnore: !boolLabel(labels, base+".monitor.enable", true),
		}
		v.Locations = append(v.Locations, loc)
	}
	if len(v.Locations) == 0 {
		return nil, nil, false
	}
	return v, publish, true
}

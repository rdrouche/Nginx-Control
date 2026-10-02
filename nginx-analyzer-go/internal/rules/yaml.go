// Package rules porte lib/rules-yaml.js et lib/rules-manager.js : le sous-
// ensemble YAML minimal pour les regles de detection personnalisees, et la
// gestion centralisee de l'etat des regles (integrees + personnalisees +
// opt-out par vhost) pour la modale "Regles" du dashboard.
//
// Le projet est deliberement sans dependance npm (meme regle que les
// lecteurs YAML plats du dashboard), donc une vraie bibliotheque YAML n'est
// pas une option ici. Plutot que d'ecrire un analyseur YAML general - une
// specification notoirement profonde, dont presque rien n'est necessaire ici
// - ce fichier ne supporte qu'une seule forme : une cle racine `rules:`
// portant une liste de maps plates (valeurs scalaires uniquement, aucune
// imbrication a l'interieur d'une regle). C'est tout ce dont une regle de
// detection a besoin, et c'est aussi exactement la forme qu'utilisent un
// fichier de scenario CrowdSec ou le propre `analyzer.yml` de ce projet.
package rules

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// RawRule est une regle telle que parsee, avant validation : cles YAML
// brutes (snake_case) vers valeurs scalaires deja typees par parseScalar
// (nil, bool, float64, string, ou []any).
type RawRule map[string]any

var reEscape = regexp.MustCompile(`\\(.)`)

// unescapeDoubleQuoted reproduit unescapeDoubleQuoted() : une chaine entre
// guillemets doubles etait rendue avec ses guillemets retires mais ses
// echappements backslash intacts. L'exemple documente du projet,
// `path_hint: "(wp-admin|phpmyadmin|\\.env)"`, doit se compiler vers la
// source regex `(wp-admin|phpmyadmin|\.env)` (un seul backslash litteral
// avant le point) comme le ferait n'importe quelle chaine YAML entre
// guillemets doubles. Seuls les echappements utiles a une source regex sont
// traites (`\\`, `\"`, et les echappements d'espacement courants) ; un `\x`
// non reconnu est laisse comme `x`, conformement au comportement standard
// YAML/JSON pour une sequence d'echappement.
func unescapeDoubleQuoted(s string) string {
	return reEscape.ReplaceAllStringFunc(s, func(m string) string {
		c := m[1]
		switch c {
		case 'n':
			return "\n"
		case 't':
			return "\t"
		case 'r':
			return "\r"
		case '"':
			return "\""
		case '\\':
			return "\\"
		default:
			return string(c)
		}
	})
}

var (
	reInt    = regexp.MustCompile(`^-?\d+(\.\d+)?$`)
	reArray  = regexp.MustCompile(`^\[.*\]$`)
	reDquote = regexp.MustCompile(`^".*"$`)
	reSquote = regexp.MustCompile(`^'.*'$`)
)

// parseScalar reproduit parseScalar() : null, booleen, nombre, chaine
// entre guillemets, tableau en ligne, ou chaine nue.
func parseScalar(raw string) any {
	v := strings.TrimSpace(raw)
	if v == "" || v == "~" || strings.ToLower(v) == "null" {
		return nil
	}
	if strings.ToLower(v) == "true" {
		return true
	}
	if strings.ToLower(v) == "false" {
		return false
	}
	if reInt.MatchString(v) {
		n, err := strconv.ParseFloat(v, 64)
		if err == nil {
			return n
		}
	}
	if reArray.MatchString(v) {
		inner := strings.TrimSpace(v[1 : len(v)-1])
		if inner == "" {
			return []any{}
		}
		parts := strings.Split(inner, ",")
		out := make([]any, len(parts))
		for i, p := range parts {
			out[i] = parseScalar(strings.TrimSpace(p))
		}
		return out
	}
	if reDquote.MatchString(v) {
		return unescapeDoubleQuoted(v[1 : len(v)-1])
	}
	// Simple-quoted: le seul echappement YAML dans '...' est '' pour un
	// guillemet litteral.
	if reSquote.MatchString(v) {
		return strings.ReplaceAll(v[1:len(v)-1], "''", "'")
	}
	return v
}

var (
	reRulesKey = regexp.MustCompile(`^rules\s*:\s*$`)
	reItem     = regexp.MustCompile(`^  - ([A-Za-z_]+)\s*:\s*(.*)$`)
	reField    = regexp.MustCompile(`^    ([A-Za-z_]+)\s*:\s*(.*)$`)
)

// ParseRulesYaml reproduit parseRulesYaml() : parse le texte YAML brut en
// (rules, errors). `rules` contient chaque element qui a parse comme une map
// plate (non valide champ par champ - voir ValidateRule pour cela) ;
// `errors` contient les problemes de syntaxe numerotes par ligne. Les deux
// peuvent etre non vides en meme temps : une regle malformee n'empeche pas
// le reste du fichier de parser.
func ParseRulesYaml(text string) (rulesOut []RawRule, errors []string) {
	current := RawRule(nil)
	sawRulesKey := false
	lines := strings.Split(text, "\n")

	flush := func() {
		if current != nil {
			rulesOut = append(rulesOut, current)
		}
	}

	for i, line := range lines {
		lineNo := i + 1
		raw := strings.TrimSuffix(line, "\r")
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if reRulesKey.MatchString(raw) {
			sawRulesKey = true
			continue
		}
		if m := reItem.FindStringSubmatch(raw); m != nil {
			flush()
			current = RawRule{}
			current[m[1]] = parseScalar(m[2])
			continue
		}
		if m := reField.FindStringSubmatch(raw); m != nil && current != nil {
			current[m[1]] = parseScalar(m[2])
			continue
		}
		errors = append(errors, fmt.Sprintf("Ligne %d : syntaxe non reconnue — %q", lineNo, trimmed))
	}
	flush()
	if !sawRulesKey && len(rulesOut) == 0 && len(errors) == 0 && strings.TrimSpace(text) != "" {
		errors = append(errors, `Cle racine "rules:" introuvable — le fichier doit commencer par "rules:" suivi d une liste`)
	}
	return rulesOut, errors
}

var severities = map[string]bool{"low": true, "medium": true, "high": true}

// Bornes du mecanisme "Blocklist a la CrowdSec" par regle (v12.50.0), memes
// valeurs que MAX_BLOCKLIST_WINDOW_MINUTES / MAX_BLOCKLIST_REMEDIATION_MINUTES.
const (
	MaxBlocklistWindowMinutes      = 14 * 24 * 60
	MaxBlocklistRemediationMinutes = 30 * 24 * 60
)

func asFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case string:
		n, err := strconv.ParseFloat(x, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

func asString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

func asBool(v any) (bool, bool) {
	b, ok := v.(bool)
	return b, ok
}

func asSlice(v any) ([]any, bool) {
	s, ok := v.([]any)
	return s, ok
}

// ValidateRule reproduit validateRule() : valide une regle deja parsee.
// Renvoie une liste de messages d'erreur (vide = valide).
func ValidateRule(r RawRule, seenIDs map[int]bool) []string {
	var errs []string
	label := fmt.Sprintf("regle %v", r["id"])
	if name, ok := asString(r["name"]); ok && name != "" {
		label = fmt.Sprintf("regle %q", name)
	}

	idOK := false
	idVal := 0
	if idF, ok := asFloat(r["id"]); ok && idF == float64(int(idF)) {
		idVal = int(idF)
		idOK = true
	}
	if !idOK || idVal < 100 {
		errs = append(errs, fmt.Sprintf(`%s : "id" doit etre un entier >= 100 (0-99 sont reserves aux regles integrees)`, label))
	} else if seenIDs[idVal] {
		errs = append(errs, fmt.Sprintf(`%s : id %d deja utilise par une autre regle`, label, idVal))
	}

	name, hasName := asString(r["name"])
	validName := regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	if !hasName || name == "" || !validName.MatchString(name) {
		errs = append(errs, fmt.Sprintf(`%s : "name" est requis (lettres/chiffres/underscore/tiret uniquement)`, label))
	}

	if sev, ok := asString(r["severity"]); ok {
		if !severities[sev] {
			errs = append(errs, fmt.Sprintf(`%s : "severity" doit etre low, medium ou high`, label))
		}
	} else if r["severity"] != nil {
		errs = append(errs, fmt.Sprintf(`%s : "severity" doit etre low, medium ou high`, label))
	}

	if mm, ok := asFloat(r["min_matches"]); !ok || mm <= 0 {
		errs = append(errs, fmt.Sprintf(`%s : "min_matches" est requis et doit etre un nombre > 0`, label))
	}

	if r["window_minutes"] != nil {
		if wm, ok := asFloat(r["window_minutes"]); !ok || wm <= 0 {
			errs = append(errs, fmt.Sprintf(`%s : "window_minutes" doit etre un nombre > 0`, label))
		}
	}

	if r["scope"] != nil {
		if sc, ok := asString(r["scope"]); !ok || (sc != "ip" && sc != "global") {
			errs = append(errs, fmt.Sprintf(`%s : "scope" doit etre ip (defaut, comptage par IP) ou global (toutes IP confondues)`, label))
		}
	}
	if r["min_ips"] != nil {
		if v, ok := asFloat(r["min_ips"]); !ok || v < 1 || v != float64(int(v)) {
			errs = append(errs, fmt.Sprintf(`%s : "min_ips" doit etre un entier >= 1 (nombre d'IP distinctes, scope: global)`, label))
		}
	}

	for _, field := range []string{"path_hint", "ua_hint"} {
		if r[field] != nil {
			if s, ok := asString(r[field]); ok {
				if _, err := regexp.Compile(s); err != nil {
					errs = append(errs, fmt.Sprintf(`%s : %q n est pas une expression reguliere valide (%s)`, label, field, err.Error()))
				}
			}
		}
	}

	for _, field := range []string{"status_in", "method_in"} {
		if r[field] != nil {
			if _, ok := asSlice(r[field]); !ok {
				errs = append(errs, fmt.Sprintf(`%s : %q doit etre une liste, ex: [401, 403]`, label, field))
			}
		}
	}

	if r["blocklist_threshold"] != nil {
		if v, ok := asFloat(r["blocklist_threshold"]); !ok || v < 1 {
			errs = append(errs, fmt.Sprintf(`%s : "blocklist_threshold" doit etre un entier >= 1 (ou absent pour desactiver)`, label))
		}
	}
	if r["blocklist_window_minutes"] != nil {
		if v, ok := asFloat(r["blocklist_window_minutes"]); !ok || v < 1 {
			errs = append(errs, fmt.Sprintf(`%s : "blocklist_window_minutes" doit etre un entier >= 1`, label))
		}
	}
	if r["blocklist_remediation_minutes"] != nil {
		if v, ok := asFloat(r["blocklist_remediation_minutes"]); !ok || v < 1 {
			errs = append(errs, fmt.Sprintf(`%s : "blocklist_remediation_minutes" doit etre un entier >= 1 (ou absent pour ne pas fixer de duree propre)`, label))
		}
	}

	if v := r["blocklist_remediation_type"]; v != nil {
		if sv, ok := asString(v); !ok || !ValidRemediationType(sv) {
			errs = append(errs, fmt.Sprintf(`%s : "blocklist_remediation_type" doit valoir block ou challenge`, label))
		}
	}

	if idOK {
		seenIDs[idVal] = true
	}
	return errs
}

// ValidRule reproduit un element de `valid` renvoye par parseAndValidate() :
// une regle normalisee, avec ses defauts appliques - ce qui serait remis au
// Detector (internal/detect.CustomRule, une fois l'orchestrateur HTTP
// cable a l'etape 7/8).
type ValidRule struct {
	ID                          int
	Name                        string
	Enable                      bool
	Severity                    string
	Description                 string
	WindowMinutes               int
	MinMatches                  int
	Scope                       string // "ip" (defaut) ou "global"
	MinIPs                      int    // scope global : defaut 5 ; 0 sinon
	PathHint                    *regexp.Regexp
	PathHintRaw                 string
	UAHint                      *regexp.Regexp
	UAHintRaw                   string
	StatusIn                    []int
	MethodIn                    []string
	BlocklistThreshold          *int
	BlocklistWindowMinutes      int
	BlocklistRemediation        bool
	BlocklistRemediationMinutes *int
	BlocklistRemediationType    string // "block" (defaut) ou "challenge" (v12.63.0)
}

// ValidRemediationType : block | challenge.
func ValidRemediationType(t string) bool { return t == "block" || t == "challenge" }

func clampInt(v float64, max int) int {
	n := int(v + 0.5) // Math.round pour des valeurs positives
	if n > max {
		n = max
	}
	return n
}

// ParseAndValidate reproduit parseAndValidate() : parse + valide en un seul
// passage.
func ParseAndValidate(text string) (raw []RawRule, errors []string, valid []ValidRule) {
	raw, errors = ParseRulesYaml(text)
	seenIDs := make(map[int]bool)
	for _, r := range raw {
		ruleErrors := ValidateRule(r, seenIDs)
		if len(ruleErrors) > 0 {
			errors = append(errors, ruleErrors...)
			continue
		}
		idF, _ := asFloat(r["id"])
		name, _ := asString(r["name"])
		enable := true
		if b, ok := asBool(r["enable"]); ok {
			enable = b
		}
		severity := "medium"
		if s, ok := asString(r["severity"]); ok && s != "" {
			severity = s
		}
		description := ""
		if s, ok := asString(r["description"]); ok {
			description = s
		}
		windowMinutes := 5
		if wm, ok := asFloat(r["window_minutes"]); ok && wm != 0 {
			windowMinutes = int(wm)
		}
		minMatches, _ := asFloat(r["min_matches"])
		scope, minIPs := "ip", 0
		if sc, ok := asString(r["scope"]); ok && sc == "global" {
			scope, minIPs = "global", 5
			if v, ok := asFloat(r["min_ips"]); ok && v >= 1 {
				minIPs = int(v)
			}
		}

		var pathHint *regexp.Regexp
		pathHintRaw := ""
		if s, ok := asString(r["path_hint"]); ok && s != "" {
			pathHintRaw = s
			pathHint, _ = regexp.Compile("(?i)" + s)
		}
		var uaHint *regexp.Regexp
		uaHintRaw := ""
		if s, ok := asString(r["ua_hint"]); ok && s != "" {
			uaHintRaw = s
			uaHint, _ = regexp.Compile("(?i)" + s)
		}

		// Correctif (audit): `status_in: ["401"]` (un code de statut entre
		// guillemets) survivait comme la CHAINE "401", alors que entry.status
		// (internal/detect) est toujours un nombre - les chaines
		// numeriques sont converties en nombre ici pour que les deux
		// ecritures se comportent de facon identique.
		var statusIn []int
		if arr, ok := asSlice(r["status_in"]); ok {
			for _, v := range arr {
				if f, ok := asFloat(v); ok {
					statusIn = append(statusIn, int(f))
				}
			}
		}
		var methodIn []string
		if arr, ok := asSlice(r["method_in"]); ok {
			for _, v := range arr {
				if s, ok := asString(v); ok {
					methodIn = append(methodIn, strings.ToUpper(s))
				} else if f, ok := asFloat(v); ok {
					methodIn = append(methodIn, strings.ToUpper(strconv.FormatFloat(f, 'f', -1, 64)))
				}
			}
		}

		var blocklistThreshold *int
		if v, ok := asFloat(r["blocklist_threshold"]); ok && v >= 1 {
			n := int(v + 0.5)
			blocklistThreshold = &n
		}
		blocklistWindowMinutes := 1440
		if v, ok := asFloat(r["blocklist_window_minutes"]); ok && v >= 1 {
			blocklistWindowMinutes = int(v + 0.5)
		}
		if blocklistWindowMinutes > MaxBlocklistWindowMinutes {
			blocklistWindowMinutes = MaxBlocklistWindowMinutes
		}
		blocklistRemediation := false
		if b, ok := asBool(r["blocklist_remediation"]); ok {
			blocklistRemediation = b
		}
		var blocklistRemediationMinutes *int
		if v, ok := asFloat(r["blocklist_remediation_minutes"]); ok && v >= 1 {
			n := clampInt(v, MaxBlocklistRemediationMinutes)
			blocklistRemediationMinutes = &n
		}

		blocklistRemediationType := "block"
		if sv, ok := asString(r["blocklist_remediation_type"]); ok && sv == "challenge" {
			blocklistRemediationType = "challenge"
		}

		valid = append(valid, ValidRule{
			ID: int(idF), Name: name, Enable: enable, Severity: severity, Description: description,
			WindowMinutes: windowMinutes, MinMatches: int(minMatches), Scope: scope, MinIPs: minIPs,
			PathHint: pathHint, PathHintRaw: pathHintRaw, UAHint: uaHint, UAHintRaw: uaHintRaw,
			StatusIn: statusIn, MethodIn: methodIn,
			BlocklistThreshold: blocklistThreshold, BlocklistWindowMinutes: blocklistWindowMinutes,
			BlocklistRemediation: blocklistRemediation, BlocklistRemediationMinutes: blocklistRemediationMinutes,
			BlocklistRemediationType: blocklistRemediationType,
		})
	}
	return raw, errors, valid
}

// StringifyRules reproduit stringifyRules() : serialise une liste de regles
// normalisees (ou d'objets bruts parses) en texte YAML, pour le contenu par
// defaut de l'editeur.
func StringifyRules(entries []map[string]any) string {
	if len(entries) == 0 {
		return "rules: []\n"
	}
	get := func(m map[string]any, keys ...string) any {
		for _, k := range keys {
			if v, ok := m[k]; ok && v != nil {
				return v
			}
		}
		return nil
	}
	toStr := func(v any) string {
		if v == nil {
			return ""
		}
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprintf("%v", v)
	}
	toBoolDefaultTrue := func(v any) bool {
		if b, ok := v.(bool); ok {
			return b
		}
		return v == nil // absent -> traite comme "pas explicitement false" -> true
	}
	toBoolDefaultFalse := func(v any) bool {
		b, _ := v.(bool)
		return b
	}
	joinInts := func(v any) string {
		arr, ok := v.([]any)
		if !ok {
			if ints, ok := v.([]int); ok {
				parts := make([]string, len(ints))
				for i, n := range ints {
					parts[i] = strconv.Itoa(n)
				}
				return strings.Join(parts, ", ")
			}
			return ""
		}
		parts := make([]string, len(arr))
		for i, x := range arr {
			parts[i] = toStr(x)
		}
		return strings.Join(parts, ", ")
	}
	joinStrings := func(v any) string {
		if arr, ok := v.([]any); ok {
			parts := make([]string, len(arr))
			for i, x := range arr {
				parts[i] = toStr(x)
			}
			return strings.Join(parts, ", ")
		}
		if arr, ok := v.([]string); ok {
			return strings.Join(arr, ", ")
		}
		return ""
	}

	lines := []string{"rules:"}
	for _, r := range entries {
		id := get(r, "id")
		name := get(r, "name")
		enable := toBoolDefaultTrue(get(r, "enable"))
		severity := toStr(get(r, "severity"))
		if severity == "" {
			severity = "medium"
		}
		description := toStr(get(r, "description"))
		windowMinutes := get(r, "window_minutes", "windowMinutes")
		minMatches := get(r, "min_matches", "minMatches")
		pathHint := toStr(get(r, "path_hint", "pathHintRaw"))
		uaHint := toStr(get(r, "ua_hint", "uaHintRaw"))
		statusIn := get(r, "status_in", "statusIn")
		methodIn := get(r, "method_in", "methodIn")
		blocklistThreshold := get(r, "blocklist_threshold", "blocklistThreshold")
		blocklistWindowMinutes := get(r, "blocklist_window_minutes", "blocklistWindowMinutes")
		blocklistRemediation := toBoolDefaultFalse(get(r, "blocklist_remediation", "blocklistRemediation"))
		blocklistRemediationMinutes := get(r, "blocklist_remediation_minutes", "blocklistRemediationMinutes")
		blocklistRemediationType := toStr(get(r, "blocklist_remediation_type", "blocklistRemediationType"))

		wm := toStr(windowMinutes)
		if wm == "" {
			wm = "5"
		}
		bwm := toStr(blocklistWindowMinutes)
		if bwm == "" {
			bwm = "1440"
		}

		lines = append(lines,
			fmt.Sprintf("  - id: %s", toStr(id)),
			fmt.Sprintf("    name: %s", toStr(name)),
			fmt.Sprintf("    enable: %v", enable),
			fmt.Sprintf("    severity: %s", severity),
			fmt.Sprintf("    description: \"%s\"", strings.ReplaceAll(description, `"`, `\"`)),
			fmt.Sprintf("    window_minutes: %s", wm),
			fmt.Sprintf("    min_matches: %s", toStr(minMatches)),
		)
		if toStr(get(r, "scope")) == "global" {
			mi := toStr(get(r, "min_ips", "minIps", "MinIPs"))
			if mi == "" || mi == "0" {
				mi = "5"
			}
			lines = append(lines, "    scope: global", fmt.Sprintf("    min_ips: %s", mi))
		}
		if pathHint != "" {
			lines = append(lines, fmt.Sprintf(`    path_hint: "%s"`, pathHint))
		} else {
			lines = append(lines, "    path_hint: null")
		}
		if uaHint != "" {
			lines = append(lines, fmt.Sprintf(`    ua_hint: "%s"`, uaHint))
		} else {
			lines = append(lines, "    ua_hint: null")
		}
		lines = append(lines,
			fmt.Sprintf("    status_in: [%s]", joinInts(statusIn)),
			fmt.Sprintf("    method_in: [%s]", joinStrings(methodIn)),
		)
		if blocklistThreshold != nil {
			lines = append(lines, fmt.Sprintf("    blocklist_threshold: %s", toStr(blocklistThreshold)))
		} else {
			lines = append(lines, "    blocklist_threshold: null")
		}
		lines = append(lines, fmt.Sprintf("    blocklist_window_minutes: %s", bwm))
		lines = append(lines, fmt.Sprintf("    blocklist_remediation: %v", blocklistRemediation))
		if blocklistRemediationMinutes != nil {
			lines = append(lines, fmt.Sprintf("    blocklist_remediation_minutes: %s", toStr(blocklistRemediationMinutes)))
		} else {
			lines = append(lines, "    blocklist_remediation_minutes: null")
		}
		if blocklistRemediationType == "challenge" {
			lines = append(lines, "    blocklist_remediation_type: challenge")
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

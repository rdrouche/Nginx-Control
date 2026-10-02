// Package parse contient les parseurs de lignes de log, sans etat, portes depuis
// nginx-analyzer/lib/parse.js, parse-waf.js et parse-blocklist.js avec parite exacte.
package parse

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// AccessEntry est le pendant exact de l objet retourne par parseLine() dans parse.js.
type AccessEntry struct {
	Vhost   string
	IP      string
	User    *string
	TS      int64 // epoch ms
	TSValid bool  // false si le timestamp n a pas pu etre parse (equiv. ts===null en JS)
	Method  *string
	Path    *string
	Status  int
	Bytes   int64
	Referer *string
	UA      *string
}

var months = map[string]time.Month{
	"Jan": time.January, "Feb": time.February, "Mar": time.March, "Apr": time.April,
	"May": time.May, "Jun": time.June, "Jul": time.July, "Aug": time.August,
	"Sep": time.September, "Oct": time.October, "Nov": time.November, "Dec": time.December,
}

// requestField reproduit REQUEST_FIELD : soit "METHOD path ..." soit un simple "-".
const requestField = `"(?:(?P<method>[A-Z_]+)\s+(?P<path>\S+)[^"]*|(?P<dash>-))"`

var (
	reVhost    = regexp.MustCompile(`^(?P<vhost>\S+)\s+(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+` + requestField + `\s+(?P<status>\d{3})\s+(?P<bytes>\d+|-)\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"`)
	reCombined = regexp.MustCompile(`^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+` + requestField + `\s+(?P<status>\d{3})\s+(?P<bytes>\d+|-)\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"`)

	reIPv4    = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)
	reIPv6ish = regexp.MustCompile(`^[0-9a-fA-F:]+$`)

	// DD/Mon/YYYY:HH:MM:SS [+-]ZZZZ (offset optionnel), parite avec le regex JS
	// /^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?/ (pas ancre en fin de chaine).
	reTime = regexp.MustCompile(`^(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?`)
)

// LooksLikeIP reproduit looksLikeIp() de parse.js.
func LooksLikeIP(s string) bool {
	if reIPv4.MatchString(s) {
		return true
	}
	if strings.Contains(s, ":") && reIPv6ish.MatchString(s) {
		return true
	}
	return false
}

// ParseTime reproduit parseTime() : renvoie (epochMs, ok).
func ParseTime(s string) (int64, bool) {
	m := reTime.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	day, _ := strconv.Atoi(m[1])
	mon, ok := months[m[2]]
	if !ok {
		return 0, false
	}
	year, _ := strconv.Atoi(m[3])
	hour, _ := strconv.Atoi(m[4])
	min, _ := strconv.Atoi(m[5])
	sec, _ := strconv.Atoi(m[6])
	offsetStr := m[7] // +-ZZZZ, peut etre absent

	utc := time.Date(year, mon, day, hour, min, sec, 0, time.UTC)

	if offsetStr == "" {
		return utc.UnixMilli(), true
	}

	sign := -1 // offset[0] === '-' ? 1 : -1  -> ici on l applique en soustrayant sign*offsetMin
	if offsetStr[0] == '-' {
		sign = 1
	}
	offH, _ := strconv.Atoi(offsetStr[1:3])
	offM, _ := strconv.Atoi(offsetStr[3:5])
	offsetMin := offH*60 + offM

	adjusted := utc.Add(time.Duration(sign*offsetMin) * time.Minute)
	return adjusted.UnixMilli(), true
}

// namedGroups extrait les groupes nommes d un match en map[nom]valeur ("" si absent).
func namedGroups(re *regexp.Regexp, match []string) map[string]string {
	out := make(map[string]string, len(match))
	for i, name := range re.SubexpNames() {
		if i == 0 || name == "" {
			continue
		}
		if i < len(match) {
			out[name] = match[i]
		}
	}
	return out
}

// DetectFormat reproduit detectFormat() : "vhost" ou "combined".
func DetectFormat(sampleLines []string) string {
	vhostCount, combinedCount := 0, 0
	for _, line := range sampleLines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		firstTok := line
		if idx := strings.IndexAny(line, " \t"); idx >= 0 {
			firstTok = line[:idx]
		}
		looksVhostish := firstTok == "-" || (!LooksLikeIP(firstTok) && strings.Contains(firstTok, "."))
		if looksVhostish && reVhost.MatchString(line) {
			vhostCount++
		} else if reCombined.MatchString(line) {
			combinedCount++
		}
	}
	if vhostCount > combinedCount {
		return "vhost"
	}
	return "combined"
}

// strPtrOrNil renvoie nil pour la valeur "-" ; sinon un pointeur vers une COPIE
// de la chaine (voir le commentaire de ParseLine sur le clonage).
func strPtrOrNil(s, dashValue string) *string {
	if s == dashValue {
		return nil
	}
	v := strings.Clone(s)
	return &v
}

// ParseLine reproduit parseLine(line, format, defaultVhost) de parse.js.
//
// Memoire : le tailer passe des sous-chaines d'un chunk de log entier (plusieurs
// Mo) ; tout champ de l'entree qui serait conserve (cle de map d'IP, ensemble de
// chemins/UA, echantillons...) retiendrait le chunk complet en vie. Les champs
// de l'entree sont donc des copies independantes (quelques petites allocations
// de courte duree par ligne, sans commune mesure avec le chunk retenu).
// Renvoie (entry, ok) ; ok=false <=> la ligne doit etre comptee "dropped".
func ParseLine(line, format, defaultVhost string) (AccessEntry, bool) {
	if len(line) < 20 {
		return AccessEntry{}, false
	}

	var re *regexp.Regexp
	if format == "vhost" {
		re = reVhost
	} else {
		re = reCombined
	}

	m := re.FindStringSubmatch(line)
	if m == nil {
		return AccessEntry{}, false
	}
	g := namedGroups(re, m)

	vhost := defaultVhost
	if format == "vhost" {
		if g["vhost"] == "-" {
			vhost = defaultVhost
		} else {
			vhost = strings.Clone(g["vhost"])
		}
	}

	ts, tsOk := ParseTime(g["time"])
	if !tsOk {
		return AccessEntry{}, false
	}

	status, _ := strconv.Atoi(g["status"])

	var bytes int64
	if g["bytes"] == "-" {
		bytes = 0
	} else {
		bytes, _ = strconv.ParseInt(g["bytes"], 10, 64)
	}

	var method, path *string
	if g["dash"] != "-" {
		mv := strings.Clone(g["method"])
		pv := strings.Clone(g["path"])
		method = &mv
		path = &pv
	}

	entry := AccessEntry{
		Vhost:   vhost,
		IP:      strings.Clone(g["ip"]),
		User:    strPtrOrNil(g["user"], "-"),
		TS:      ts,
		TSValid: tsOk,
		Method:  method,
		Path:    path,
		Status:  status,
		Bytes:   bytes,
		Referer: strPtrOrNil(g["referer"], "-"),
		UA:      strPtrOrNil(g["ua"], "-"),
	}
	return entry, true
}

var reVhostFromAccessFilename = regexp.MustCompile(`\.(access|error)\.log(\.\d+)?(\.gz)?$`)
var reLogSuffix = regexp.MustCompile(`\.log$`)

// VhostFromFilename reproduit vhostFromFilename() de parse.js.
func VhostFromFilename(filename string) string {
	v := reVhostFromAccessFilename.ReplaceAllString(filename, "")
	v = reLogSuffix.ReplaceAllString(v, "")
	return v
}

// NormalizePath reproduit normalizePath() de parse.js.
func NormalizePath(p string) string {
	if idx := strings.IndexByte(p, '?'); idx >= 0 {
		return p[:idx]
	}
	return p
}

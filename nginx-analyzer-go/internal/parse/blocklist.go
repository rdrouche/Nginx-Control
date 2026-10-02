package parse

import (
	"regexp"
	"strconv"
	"strings"
)

// BlocklistEntry reproduit l objet retourne par parseLine() dans parse-blocklist.js.
type BlocklistEntry struct {
	TS      int64
	TSValid bool
	IP      *string
	Vhost   *string
	Method  *string
	URI     *string
	Status  int
}

var reBlocklistLine = regexp.MustCompile(`^(\S+) (\S+) (\S+) "([^"]*)" (\d{3})\s*$`)

// BlocklistDetectFormat reproduit detectFormat() de parse-blocklist.js: toujours "blocklist".
func BlocklistDetectFormat(sampleLines []string) string {
	return "blocklist"
}

// BlocklistVhostFromFilename reproduit vhostFromFilename(): toujours "" (pas de vhost par nom
// de fichier, c est un fichier global unique ; l equivalent JS renvoie null).
func BlocklistVhostFromFilename(filename string) string {
	return ""
}

// BlocklistParseLine reproduit parseLine() de parse-blocklist.js.
func BlocklistParseLine(line, format, defaultVhost string) (BlocklistEntry, bool) {
	if len(line) < 10 {
		return BlocklistEntry{}, false
	}
	trimmed := strings.TrimSpace(line)
	m := reBlocklistLine.FindStringSubmatch(trimmed)
	if m == nil {
		return BlocklistEntry{}, false
	}
	timeStr, ip, host, request, statusStr := m[1], m[2], m[3], m[4], m[5]

	// ISO8601, ex: 2026-09-10T12:00:00+00:00
	ts, tsOk := parseISO8601(timeStr)
	if !tsOk {
		return BlocklistEntry{}, false
	}

	var vhost *string
	if host != "" && host != "-" {
		v := host
		vhost = &v
	} else if defaultVhost != "" {
		v := defaultVhost
		vhost = &v
	}

	var ipPtr *string
	if ip != "" {
		v := ip
		ipPtr = &v
	}

	reqParts := strings.Split(request, " ")
	var method, uri *string
	if len(reqParts) >= 2 {
		m0, u0 := reqParts[0], reqParts[1]
		method, uri = &m0, &u0
	}

	status, _ := strconv.Atoi(statusStr)

	return BlocklistEntry{
		TS: ts, TSValid: tsOk,
		IP: ipPtr, Vhost: vhost,
		Method: method, URI: uri, Status: status,
	}, true
}

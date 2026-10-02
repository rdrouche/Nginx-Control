package config

import (
	"regexp"
	"strconv"
)

var ignoreSplit = regexp.MustCompile(`[\s,;]+`)

// ParseIgnoreStatus lit DETECT_IGNORE_STATUS ("444,403") : codes 100-599 uniquement,
// le reste est ignore. Pendant exact de nginx-analyzer/lib/ignore-status.js.
func ParseIgnoreStatus(raw string) map[int]bool {
	out := map[int]bool{}
	for _, part := range ignoreSplit.Split(raw, -1) {
		if len(part) != 3 {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 100 || n > 599 {
			continue
		}
		out[n] = true
	}
	return out
}

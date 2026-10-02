package parse

import "time"

// parseISO8601 reproduit Date.parse() sur une chaine ISO8601 telle que produite par nginx's
// $time_iso8601 (ex: 2026-09-10T12:00:00+00:00).
func parseISO8601(s string) (int64, bool) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UnixMilli(), true
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UnixMilli(), true
	}
	return 0, false
}

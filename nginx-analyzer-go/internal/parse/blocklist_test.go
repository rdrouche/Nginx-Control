package parse

import "testing"

const blocklistLine = `2026-09-24T10:15:03+00:00 203.0.113.5 example.com "GET /wp-login.php HTTP/1.1" 403`

func TestBlocklistDetectFormatAlways(t *testing.T) {
	if got := BlocklistDetectFormat(nil); got != "blocklist" {
		t.Errorf("got %q", got)
	}
}

func TestBlocklistVhostFromFilenameGlobal(t *testing.T) {
	if got := BlocklistVhostFromFilename("blocklist-hits.log"); got != "" {
		t.Errorf("attendu vide (equivalent null), got %q", got)
	}
}

func TestBlocklistParseLineBaseFields(t *testing.T) {
	r, ok := BlocklistParseLine(blocklistLine, "blocklist", "")
	if !ok {
		t.Fatal("expected ok")
	}
	if r.IP == nil || *r.IP != "203.0.113.5" {
		t.Errorf("ip = %v", r.IP)
	}
	if r.Vhost == nil || *r.Vhost != "example.com" {
		t.Errorf("vhost = %v", r.Vhost)
	}
	if r.Method == nil || *r.Method != "GET" {
		t.Errorf("method = %v", r.Method)
	}
	if r.URI == nil || *r.URI != "/wp-login.php" {
		t.Errorf("uri = %v", r.URI)
	}
	if r.Status != 403 {
		t.Errorf("status = %d", r.Status)
	}
	if r.TS == 0 || !r.TSValid {
		t.Errorf("ts should be a valid number, got %d valid=%v", r.TS, r.TSValid)
	}
}

func TestBlocklistHostDashFallsBackToDefault(t *testing.T) {
	l := `2026-09-24T10:15:03+00:00 203.0.113.5 - "GET / HTTP/1.1" 403`
	r, ok := BlocklistParseLine(l, "blocklist", "defaut.fr")
	if !ok || r.Vhost == nil || *r.Vhost != "defaut.fr" {
		t.Errorf("vhost = %v ok=%v", r.Vhost, ok)
	}
}

func TestBlocklistParseLineRobustness(t *testing.T) {
	cases := []string{
		"",
		`2026-09-24T10:15:03+00:00 203.0.113.5 example.com "GET /`,
		"n importe quoi",
		`pas-une-date 203.0.113.5 example.com "GET / HTTP/1.1" 403`,
	}
	for _, c := range cases {
		if _, ok := BlocklistParseLine(c, "blocklist", ""); ok {
			t.Errorf("attendu drop pour %q", c)
		}
	}
}

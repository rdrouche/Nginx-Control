package parse

import (
	"testing"
	"time"
)

const combinedLine = `203.0.113.5 - - [09/Sep/2026:10:00:00 +0200] "GET /index.html HTTP/1.1" 200 1234 "https://ref.example" "Mozilla/5.0"`
const vhostLine = `example.com 203.0.113.5 - - [09/Sep/2026:10:00:00 +0200] "GET /index.html HTTP/1.1" 200 1234 "-" "curl/8.5.0"`

func TestParseLineCombinedFields(t *testing.T) {
	r, ok := ParseLine(combinedLine, "combined", "site.fr")
	if !ok {
		t.Fatal("expected ok")
	}
	if r.IP != "203.0.113.5" {
		t.Errorf("ip = %q", r.IP)
	}
	if r.Method == nil || *r.Method != "GET" {
		t.Errorf("method = %v", r.Method)
	}
	if r.Path == nil || *r.Path != "/index.html" {
		t.Errorf("path = %v", r.Path)
	}
	if r.Status != 200 {
		t.Errorf("status = %d", r.Status)
	}
	if r.Bytes != 1234 {
		t.Errorf("bytes = %d", r.Bytes)
	}
	if r.UA == nil || *r.UA != "Mozilla/5.0" {
		t.Errorf("ua = %v", r.UA)
	}
	if r.Vhost != "site.fr" {
		t.Errorf("vhost = %q (doit venir du nom de fichier)", r.Vhost)
	}
}

func TestParseLineVhostFormat(t *testing.T) {
	r, ok := ParseLine(vhostLine, "vhost", "")
	if !ok {
		t.Fatal("expected ok")
	}
	if r.Vhost != "example.com" {
		t.Errorf("vhost = %q", r.Vhost)
	}
	if r.IP != "203.0.113.5" {
		t.Errorf("ip = %q", r.IP)
	}
	if r.Status != 200 {
		t.Errorf("status = %d", r.Status)
	}
	if r.Referer != nil {
		t.Errorf("referer should be nil, got %v", r.Referer)
	}
	if r.User != nil {
		t.Errorf("user should be nil, got %v", r.User)
	}
}

func TestDetectFormat(t *testing.T) {
	if got := DetectFormat([]string{combinedLine, combinedLine}); got != "combined" {
		t.Errorf("combined reconnu: got %q", got)
	}
	if got := DetectFormat([]string{vhostLine, vhostLine}); got != "vhost" {
		t.Errorf("vhost reconnu: got %q", got)
	}
	if got := DetectFormat([]string{vhostLine, vhostLine, combinedLine}); got != "vhost" {
		t.Errorf("majorite l emporte: got %q", got)
	}
	if got := DetectFormat([]string{"", "  ", combinedLine}); got != "combined" {
		t.Errorf("lignes vides ignorees: got %q", got)
	}
	if got := DetectFormat([]string{}); got != "combined" {
		t.Errorf("echantillon vide -> combined par defaut: got %q", got)
	}
}

func TestParseTime(t *testing.T) {
	ts, ok := ParseTime("09/Sep/2026:10:00:00 +0200")
	if !ok {
		t.Fatal("expected ok")
	}
	got := time.UnixMilli(ts).UTC().Format(time.RFC3339)
	if got != "2026-09-09T08:00:00Z" {
		t.Errorf("fuseau applique: got %s", got)
	}

	ts, ok = ParseTime("09/Sep/2026:10:00:00 -0500")
	if !ok {
		t.Fatal("expected ok")
	}
	got = time.UnixMilli(ts).UTC().Format(time.RFC3339)
	if got != "2026-09-09T15:00:00Z" {
		t.Errorf("fuseau negatif: got %s", got)
	}

	if _, ok := ParseTime("09/Sep/2026:10:00:00"); !ok {
		t.Error("sans fuseau doit rester valide")
	}

	if _, ok := ParseTime("pas une date"); ok {
		t.Error("date invalide -> doit echouer")
	}
	if _, ok := ParseTime("09/Xyz/2026:10:00:00 +0200"); ok {
		t.Error("mois invalide -> doit echouer")
	}
}

func TestParseLineRobustness(t *testing.T) {
	cases := []string{
		"",
		"203.0.113.5 - - [09/Sep",
		"n importe quoi",
		`203.0.113.5 - - [09/Sep/2026:10:00:00 +0200] "GET / HTTP/1.1" ABC 1 "-" "-"`,
		`203.0.113.5 - - [09/Sep/2026:10:00:00 +0200] "GET / HTTP/1.1 200 1 "-" "-"`,
	}
	for _, line := range cases {
		if _, ok := ParseLine(line, "combined", ""); ok {
			t.Errorf("attendu drop pour %q", line)
		}
	}
}

func TestParseLineEdgeCases(t *testing.T) {
	r, ok := ParseLine(`203.0.113.5 - - [09/Sep/2026:10:00:00 +0200] "GET / HTTP/1.1" 304 - "-" "-"`, "combined", "")
	if !ok {
		t.Fatal("expected ok")
	}
	if r.Bytes != 0 {
		t.Errorf("octets a tiret -> 0: got %d", r.Bytes)
	}

	r, ok = ParseLine(`203.0.113.5 - - [09/Sep/2026:10:00:00 +0200] "PROPFIND /x HTTP/1.1" 405 0 "-" "-"`, "combined", "")
	if !ok || r.Method == nil || *r.Method != "PROPFIND" {
		t.Errorf("methode inhabituelle: got %v ok=%v", r.Method, ok)
	}

	r, ok = ParseLine(`2001:db8::1 - - [09/Sep/2026:10:00:00 +0200] "GET / HTTP/1.1" 200 1 "-" "-"`, "combined", "")
	if !ok || r.IP != "2001:db8::1" {
		t.Errorf("IPv6 acceptee: got %q ok=%v", r.IP, ok)
	}
}

func TestVhostFromFilename(t *testing.T) {
	if got := VhostFromFilename("forge.rdr-it.com.access.log"); got != "forge.rdr-it.com" {
		t.Errorf("got %q", got)
	}
	if got := VhostFromFilename("site.access.log.1"); got != "site" {
		t.Errorf("got %q", got)
	}
}

func TestNormalizePath(t *testing.T) {
	if got := NormalizePath("/search?q=x&p=2"); got != "/search" {
		t.Errorf("got %q", got)
	}
	if got := NormalizePath("/plain"); got != "/plain" {
		t.Errorf("got %q", got)
	}
}

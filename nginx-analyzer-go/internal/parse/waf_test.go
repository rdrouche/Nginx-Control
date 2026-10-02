package parse

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type wafMsgIn struct {
	Message string         `json:"message"`
	Details wafDetailInput `json:"details"`
}
type wafDetailInput struct {
	RuleID   string   `json:"ruleId,omitempty"`
	Severity string   `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

func wafLine(t *testing.T, overrides map[string]any, messages []wafMsgIn) string {
	t.Helper()
	tx := map[string]any{
		"client_ip":  "203.0.113.5",
		"time_stamp": "Wed Sep 10 12:00:00 2026",
		"request":    map[string]any{"method": "GET", "uri": "/login"},
		"response":   map[string]any{"http_code": 403},
		"unique_id":  "abc123",
		"messages":   messages,
	}
	for k, v := range overrides {
		tx[k] = v
	}
	b, err := json.Marshal(map[string]any{"transaction": tx})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestWafParseLineBaseFields(t *testing.T) {
	line := wafLine(t, nil, nil)
	r, ok := WafParseLine(line, "json", "site.fr")
	if !ok {
		t.Fatal("expected ok")
	}
	if r.Vhost != "site.fr" {
		t.Errorf("vhost = %q", r.Vhost)
	}
	if r.IP == nil || *r.IP != "203.0.113.5" {
		t.Errorf("ip = %v", r.IP)
	}
	if r.Method == nil || *r.Method != "GET" {
		t.Errorf("method = %v", r.Method)
	}
	if r.URI == nil || *r.URI != "/login" {
		t.Errorf("uri = %v", r.URI)
	}
	if r.Status == nil || *r.Status != 403 {
		t.Errorf("status = %v", r.Status)
	}
	if r.UniqueID == nil || *r.UniqueID != "abc123" {
		t.Errorf("uniqueId = %v", r.UniqueID)
	}
}

func TestWafBlocked(t *testing.T) {
	r, ok := WafParseLine(wafLine(t, nil, nil), "json", "")
	if !ok || !r.Blocked {
		t.Error("403 -> bloque")
	}
	r, ok = WafParseLine(wafLine(t, map[string]any{"response": map[string]any{"http_code": 200}}, nil), "json", "")
	if !ok || r.Blocked {
		t.Error("200 -> non bloque")
	}
}

func TestWafRulesAndMessages(t *testing.T) {
	msgs := []wafMsgIn{
		{Message: "SQL Injection", Details: wafDetailInput{RuleID: "942100", Severity: "2", Tags: []string{"attack-sqli"}}},
		{Message: "XSS attempt", Details: wafDetailInput{RuleID: "941100", Severity: "2", Tags: []string{"attack-xss"}}},
	}
	r, ok := WafParseLine(wafLine(t, nil, msgs), "json", "")
	if !ok {
		t.Fatal("expected ok")
	}
	if len(r.RuleIDs) != 2 || r.RuleIDs[0] != "942100" || r.RuleIDs[1] != "941100" {
		t.Errorf("ruleIds = %v", r.RuleIDs)
	}
	if len(r.Messages) != 2 || r.Messages[0].Message == nil || *r.Messages[0].Message != "SQL Injection" {
		t.Errorf("messages = %+v", r.Messages)
	}
}

func TestWafDuplicateRulesDeduped(t *testing.T) {
	msgs := []wafMsgIn{
		{Message: "a", Details: wafDetailInput{RuleID: "942100", Severity: "2"}},
		{Message: "b", Details: wafDetailInput{RuleID: "942100", Severity: "4"}},
	}
	r, ok := WafParseLine(wafLine(t, nil, msgs), "json", "")
	if !ok || len(r.RuleIDs) != 1 || r.RuleIDs[0] != "942100" {
		t.Errorf("ruleIds = %v", r.RuleIDs)
	}
}

func TestWafWorstSeverityRetained(t *testing.T) {
	msgs := []wafMsgIn{
		{Message: "a", Details: wafDetailInput{RuleID: "1", Severity: "5"}},
		{Message: "b", Details: wafDetailInput{RuleID: "2", Severity: "2"}},
	}
	r, ok := WafParseLine(wafLine(t, nil, msgs), "json", "")
	if !ok || r.Severity != "critical" {
		t.Errorf("severity = %v", r.Severity)
	}
}

func TestWafNoMessages(t *testing.T) {
	r, ok := WafParseLine(wafLine(t, nil, []wafMsgIn{}), "json", "")
	if !ok || r.Severity != "unknown" || len(r.RuleIDs) != 0 {
		t.Errorf("severity=%v ruleIds=%v", r.Severity, r.RuleIDs)
	}
}

func TestNormalizeSeverityTable(t *testing.T) {
	cases := map[string]string{
		"0": "critical", "2": "critical", "3": "error", "4": "warning",
		"5": "notice", "6": "info", "7": "info",
		"CRITICAL": "critical", "warning": "warning", "DEBUG": "info",
	}
	for raw, want := range cases {
		if got := normalizeSeverity(raw); got != want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", raw, got, want)
		}
	}
	if got := normalizeSeverity(""); got != "unknown" {
		t.Errorf("empty -> unknown, got %q", got)
	}
	if got := normalizeSeverity("n importe quoi"); got != "unknown" {
		t.Errorf("invalid -> unknown, got %q", got)
	}
}

func TestWafParseLineRobustness(t *testing.T) {
	cases := []string{
		"n importe quoi",
		`{"transaction":{`,
		`{"foo":"bar"}`,
		`{"transaction":{"client_ip":"1.2.3.4"}}`,
		"",
		"{}",
	}
	for _, c := range cases {
		if _, ok := WafParseLine(c, "json", ""); ok {
			t.Errorf("attendu drop pour %q", c)
		}
	}
}

func TestWafVhostFromFilename(t *testing.T) {
	if got := WafVhostFromFilename("example.com.waf.log"); got != "example.com" {
		t.Errorf("got %q", got)
	}
	if got := WafVhostFromFilename("site.fr.waf.log.1"); got != "site.fr" {
		t.Errorf("got %q", got)
	}
	if got := WafVhostFromFilename("site.fr.waf.log.1.gz"); got != "site.fr" {
		t.Errorf("got %q", got)
	}
}

func TestWafDetectFormatAlwaysJSON(t *testing.T) {
	if got := WafDetectFormat([]string{"n importe quoi"}); got != "json" {
		t.Errorf("got %q", got)
	}
}

func TestWafRealModsecV3Structure(t *testing.T) {
	raw := `{"transaction":{"client_ip":"89.91.226.61","time_stamp":"Fri Sep 11 08:49:48 2026",` +
		`"unique_id":"178911658855.650745","request":{"method":"POST","uri":"/pro/LUD/ils/RecordManagementService.svc/CheckIn"},` +
		`"response":{"body":"","http_code":200},` +
		`"producer":{"modsecurity":"ModSecurity v3.0.12 (Linux)","connector":"ModSecurity-nginx v1.0.4","secrules_engine":"DetectionOnly","components":["OWASP_CRS/4.30.0-dev"]},` +
		`"messages":[{"message":"Request content type is not allowed by policy","details":{"ruleId":"920420","severity":"2","tags":["attack-protocol"]}},` +
		`{"message":"Inbound Anomaly Score Exceeded (Total Score: 5)","details":{"ruleId":"949110","severity":"0","tags":["anomaly-evaluation"]}}]}}`
	r, ok := WafParseLine(raw, "json", "mediatheque.ville-bourges.fr")
	if !ok {
		t.Fatal("expected ok")
	}
	if r.Status == nil || *r.Status != 200 {
		t.Errorf("status doit venir de response.http_code: %v", r.Status)
	}
	if len(r.RuleIDs) != 2 || r.RuleIDs[0] != "920420" || r.RuleIDs[1] != "949110" {
		t.Errorf("ruleIds = %v", r.RuleIDs)
	}
	if len(r.Messages) != 2 {
		t.Errorf("messages len = %d", len(r.Messages))
	}
	if r.Severity != "critical" {
		t.Errorf("severity la plus severe (0=critical) attendue, got %v", r.Severity)
	}
}

func TestWafNoMessagesFieldAbsent(t *testing.T) {
	raw := `{"transaction":{"client_ip":"1.2.3.4","time_stamp":"Fri Sep 11 08:49:48 2026","request":{"method":"GET","uri":"/"},"response":{"http_code":200}}}`
	r, ok := WafParseLine(raw, "json", "")
	if !ok || len(r.RuleIDs) != 0 || r.Severity != "unknown" {
		t.Errorf("ruleIds=%v severity=%v", r.RuleIDs, r.Severity)
	}
}

func TestWafRawLinePreserved(t *testing.T) {
	raw := wafLine(t, nil, nil)
	r, ok := WafParseLine(raw, "json", "")
	if !ok || r.Raw != raw {
		t.Errorf("raw line not preserved")
	}
}

func TestWafRawLineTruncated(t *testing.T) {
	bigTag := strings.Repeat("x", 20000)
	raw := wafLine(t, nil, []wafMsgIn{{Message: "m", Details: wafDetailInput{RuleID: "1", Severity: "2", Tags: []string{bigTag}}}})
	r, ok := WafParseLine(raw, "json", "")
	if !ok {
		t.Fatal("expected ok")
	}
	if len(r.Raw) > rawMaxLen+20 {
		t.Errorf("raw too long: %d", len(r.Raw))
	}
	if !strings.HasSuffix(r.Raw, "(tronque)") {
		t.Errorf("raw should be truncated with marker, got suffix %q", r.Raw[len(r.Raw)-20:])
	}
}

func TestWafEngineExposed(t *testing.T) {
	raw := `{"transaction":{"client_ip":"1.2.3.4","time_stamp":"Wed Sep 10 12:00:00 2026","request":{"method":"GET","uri":"/"},"response":{"http_code":200},"producer":{"secrules_engine":"DetectionOnly"},"messages":[]}}`
	r, ok := WafParseLine(raw, "json", "")
	if !ok || r.Engine == nil || *r.Engine != "DetectionOnly" {
		t.Errorf("engine = %v ok=%v", r.Engine, ok)
	}
}

func TestWafEngineAbsent(t *testing.T) {
	r, ok := WafParseLine(wafLine(t, nil, nil), "json", "")
	if !ok || r.Engine != nil {
		t.Errorf("engine should be nil, got %v", r.Engine)
	}
}

func TestCategorize(t *testing.T) {
	cases := map[string]string{
		"920420": "Conformite du protocole",
		"930100": "Traversee de repertoire",
		"932100": "Execution de commande",
		"941100": "XSS",
		"942100": "Injection SQL",
		"949110": "Evaluation du score",
		"980100": "Correlation",
	}
	for id, want := range cases {
		if got, _ := Categorize(id); got != want {
			t.Errorf("Categorize(%q) = %q, want %q", id, got, want)
		}
	}
	if got, _ := Categorize("123456"); got != "Regle personnalisee" {
		t.Errorf("got %q", got)
	}
}

func TestReferenceURL(t *testing.T) {
	u := ReferenceURL("942100")
	if u == nil || !strings.HasPrefix(*u, "https://github.com/search") || !strings.Contains(*u, "942100") {
		t.Errorf("got %v", u)
	}
	if ReferenceURL("") != nil {
		t.Error("empty ruleId -> nil")
	}
}

func TestWafTimestampFormatsParity(t *testing.T) {
	want := time.Date(2026, 9, 30, 15, 37, 39, 0, time.UTC).UnixMilli()
	for _, ts := range []string{
		"Wed, 30 Sep 2026 15:37:39 GMT",
		"Wed, 30 Sep 2026 15:37:39 +0000",
		"2026-09-30T15:37:39Z",
		"30/Sep/2026:15:37:39 +0000",
	} {
		got, ok := parseTimestamp(ts)
		if !ok || got != want {
			t.Errorf("parseTimestamp(%q) = %d,%v ; attendu %d", ts, got, ok, want)
		}
	}
}

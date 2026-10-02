package parse

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// strconvAtoi reproduit parseInt(s, 10) de JS: lit un prefixe numerique eventuellement signe
// et ignore le reste, plutot que d exiger que toute la chaine soit numerique comme strconv.Atoi.
func strconvAtoi(s string) (int, error) {
	i := 0
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		i++
	}
	start := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == start {
		return 0, strconv.ErrSyntax
	}
	return strconv.Atoi(s[:i])
}

func urlQueryEscape(s string) string { return url.QueryEscape(s) }

// WafMessage reproduit un element de tx.messages apres normalisation.
type WafMessage struct {
	RuleID   *string
	Message  *string
	Severity string
	Tags     []string
}

// WafEntry reproduit l objet retourne par parseLine() dans parse-waf.js.
type WafEntry struct {
	TS       int64
	TSValid  bool
	Vhost    string
	IP       *string
	Method   *string
	URI      *string
	Status   *int
	Blocked  bool
	Severity string
	RuleIDs  []string
	Messages []WafMessage
	UniqueID *string
	Engine   *string
	Raw      string
}

var severityMap = map[string]string{
	"0": "critical", "1": "critical", "2": "critical",
	"3": "error",
	"4": "warning",
	"5": "notice",
	"6": "info", "7": "info",
	"EMERGENCY": "critical", "ALERT": "critical", "CRITICAL": "critical",
	"ERROR":   "error",
	"WARNING": "warning",
	"NOTICE":  "notice",
	"INFO":    "info", "DEBUG": "info",
}

var severityRank = map[string]int{
	"critical": 0, "error": 1, "warning": 2, "notice": 3, "info": 4, "unknown": 5,
}

// normalizeSeverity reproduit normalizeSeverity() de parse-waf.js: trim + majuscule puis lookup.
func normalizeSeverity(v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	if v == "" {
		return "unknown"
	}
	if s, ok := severityMap[v]; ok {
		return s
	}
	return "unknown"
}

// worstSeverity reproduit worstSeverity(): la severite au rang numerique le plus bas,
// en partant de 'unknown' comme la moins severe (parite exacte avec le JS).
func worstSeverity(labels []string) string {
	worst := "unknown"
	for _, l := range labels {
		r, ok := severityRank[l]
		if !ok {
			continue
		}
		if r < severityRank[worst] {
			worst = l
		}
	}
	return worst
}

var reWafVhostFromFilename = regexp.MustCompile(`\.waf\.log(\.\d+)?(\.gz)?$`)

// WafVhostFromFilename reproduit vhostFromFilename() de parse-waf.js.
func WafVhostFromFilename(filename string) string {
	v := reWafVhostFromFilename.ReplaceAllString(filename, "")
	v = reLogSuffix.ReplaceAllString(v, "")
	return v
}

// WafDetectFormat reproduit detectFormat() de parse-waf.js: toujours "json".
func WafDetectFormat(sampleLines []string) string {
	return "json"
}

// modsecTimeLayouts, essayes dans l ordre, dans le fuseau LOCAL du process (comme Date.parse()
// en l absence de TZ explicite dans la chaine — parite avec parseTimestamp() de parse-waf.js,
// dont le format nominal ModSecurity par defaut est "Mon Jan 2 15:04:05 2006").
var modsecTimeLayouts = []string{
	"Mon Jan 2 15:04:05 2006",
	time.RFC3339,
	"02/Jan/2006:15:04:05 -0700",
	// Date.parse() de JS accepte aussi ces formes (toUTCString(), RFC 2822, ISO sans T).
	time.RFC1123Z,
	time.RFC1123,
	"2006-01-02 15:04:05",
}

// parseTimestamp reproduit parseTimestamp() de parse-waf.js: Date.parse() interprete dans le
// fuseau local du runtime pour un format sans indication de zone.
func parseTimestamp(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	for _, layout := range modsecTimeLayouts {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t.UnixMilli(), true
		}
	}
	return 0, false
}

type wafRawMessageDetail struct {
	RuleID   json.Number `json:"ruleId"`
	Message  string      `json:"message"`
	Severity string      `json:"severity"`
	Tags     []string    `json:"tags"`
}
type wafRawMessage struct {
	Message string              `json:"message"`
	Details wafRawMessageDetail `json:"details"`
}
type wafRawRequest struct {
	Method string `json:"method"`
	URI    string `json:"uri"`
}
type wafRawResponse struct {
	HTTPCode *int `json:"http_code"`
}
type wafRawProducer struct {
	SecrulesEngine string `json:"secrules_engine"`
}
type wafRawTx struct {
	TimeStamp  string          `json:"time_stamp"`
	ClientIP   string          `json:"client_ip"`
	RemoteAddr string          `json:"remote_address"`
	Request    *wafRawRequest  `json:"request"`
	Response   *wafRawResponse `json:"response"`
	Producer   *wafRawProducer `json:"producer"`
	Messages   []wafRawMessage `json:"messages"`
	UniqueID   string          `json:"unique_id"`
	ID         string          `json:"id"`
}
type wafRawRoot struct {
	Transaction *wafRawTx `json:"transaction"`
}

const rawMaxLen = 16 * 1024

func strOrNil(s string) *string {
	if s == "" {
		return nil
	}
	v := s
	return &v
}

// crsCategory reproduit un tuple de CRS_CATEGORIES.
type crsCategory struct {
	lo, hi   int
	category string
	why      string
}

var crsCategories = []crsCategory{
	{900, 900, "Initialisation", "Configuration interne du jeu de regles, sans rapport avec une attaque."},
	{901, 901, "Test", "Regles de verification internes au CRS."},
	{905, 905, "Verification", "Verifications de bon fonctionnement du moteur."},
	{910, 910, "Reputation IP", "Adresse presente sur une liste de reputation (IP connue malveillante)."},
	{911, 911, "Methode HTTP", "Methode HTTP non autorisee par la politique."},
	{912, 912, "DoS", "Signal de deni de service applicatif."},
	{913, 913, "Scanner", "Signature d un outil de scan automatise connu."},
	{920, 921, "Conformite du protocole", "La requete ne respecte pas les regles du protocole HTTP (en-tetes, encodage, format)."},
	{930, 930, "Traversee de repertoire", "Tentative d acces a des fichiers hors de la racine web (Local File Inclusion)."},
	{931, 931, "Inclusion distante", "Tentative de faire charger un fichier depuis une source externe (Remote File Inclusion)."},
	{932, 932, "Execution de commande", "Tentative d execution de commande systeme (Remote Code Execution)."},
	{933, 933, "Injection PHP", "Tentative d injection de code PHP."},
	{934, 934, "Attaque generique", "Motif d attaque generique, non specifique a un langage."},
	{941, 941, "XSS", "Tentative d injection de script cote client (Cross-Site Scripting)."},
	{942, 942, "Injection SQL", "Motif caracteristique d une injection SQL."},
	{943, 943, "Fixation de session", "Tentative de manipulation de l identifiant de session."},
	{944, 944, "Attaque Java", "Motif d attaque visant une application Java."},
	{949, 949, "Evaluation du score", "Regle d agregation : le score cumule d anomalie depasse le seuil de blocage."},
	{950, 959, "Fuite de donnees", "La reponse du serveur semble contenir des informations sensibles (erreurs, traces, donnees internes)."},
	{980, 980, "Correlation", "Regle de synthese reliant plusieurs signaux d une meme transaction."},
}

const genericCategory = "Regle personnalisee"
const genericWhy = "Cette regle ne correspond pas a une plage connue de l OWASP Core Rule Set — probablement une regle ajoutee localement."

// Categorize reproduit categorize() de parse-waf.js.
func Categorize(ruleID string) (category, why string) {
	prefix := ruleID
	if len(prefix) > 3 {
		prefix = prefix[:3]
	}
	if n, err := strconvAtoi(prefix); err == nil {
		for _, c := range crsCategories {
			if n >= c.lo && n <= c.hi {
				return c.category, c.why
			}
		}
	}
	return genericCategory, genericWhy
}

// ReferenceURL reproduit referenceUrl() de parse-waf.js.
func ReferenceURL(ruleID string) *string {
	if ruleID == "" {
		return nil
	}
	u := "https://github.com/search?q=repo%3Acoreruleset%2Fcoreruleset+%22" + urlQueryEscape(ruleID) + "%22&type=code"
	return &u
}

// WafParseLine reproduit parseLine() de parse-waf.js.
func WafParseLine(line, format, defaultVhost string) (WafEntry, bool) {
	if len(line) < 2 {
		return WafEntry{}, false
	}
	var root wafRawRoot
	if err := json.Unmarshal([]byte(line), &root); err != nil {
		return WafEntry{}, false
	}
	if root.Transaction == nil {
		return WafEntry{}, false
	}
	tx := root.Transaction

	ts, tsOk := parseTimestamp(tx.TimeStamp)
	if !tsOk {
		return WafEntry{}, false
	}

	messages := make([]WafMessage, 0, len(tx.Messages))
	ruleIDsSeen := map[string]bool{}
	var ruleIDs []string
	var severities []string
	for i, m := range tx.Messages {
		if i >= 50 {
			break
		}
		var ruleID *string
		if m.Details.RuleID != "" {
			s := m.Details.RuleID.String()
			ruleID = &s
		}
		msg := strOrNil(m.Message)
		if ruleID == nil && msg == nil {
			continue
		}
		sev := normalizeSeverity(m.Details.Severity)
		tags := m.Details.Tags
		if len(tags) > 10 {
			tags = tags[:10]
		}
		messages = append(messages, WafMessage{RuleID: ruleID, Message: msg, Severity: sev, Tags: tags})
		severities = append(severities, sev)
		if ruleID != nil && *ruleID != "" && !ruleIDsSeen[*ruleID] {
			ruleIDsSeen[*ruleID] = true
			ruleIDs = append(ruleIDs, *ruleID)
		}
	}

	sev := worstSeverity(severities)

	var httpCode *int
	if tx.Response != nil {
		httpCode = tx.Response.HTTPCode
	}
	blocked := httpCode != nil && *httpCode == 403

	ip := strOrNil(tx.ClientIP)
	if ip == nil {
		ip = strOrNil(tx.RemoteAddr)
	}
	var method, uri *string
	if tx.Request != nil {
		method = strOrNil(tx.Request.Method)
		uri = strOrNil(tx.Request.URI)
	}
	var engine *string
	if tx.Producer != nil {
		engine = strOrNil(tx.Producer.SecrulesEngine)
	}
	uniqueID := strOrNil(tx.UniqueID)
	if uniqueID == nil {
		uniqueID = strOrNil(tx.ID)
	}

	msgsForEntry := messages
	if len(msgsForEntry) > 10 {
		msgsForEntry = msgsForEntry[:10]
	}

	raw := line
	if len(raw) > rawMaxLen {
		raw = raw[:rawMaxLen] + "…(tronque)"
	}

	return WafEntry{
		TS: ts, TSValid: tsOk,
		Vhost: defaultVhost, IP: ip,
		Method: method, URI: uri,
		Status: httpCode, Blocked: blocked, Severity: sev,
		RuleIDs: ruleIDs, Messages: msgsForEntry,
		UniqueID: uniqueID, Engine: engine, Raw: raw,
	}, true
}

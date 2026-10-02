package rules

import (
	"strconv"
	"strings"
	"sync"

	"nginx-analyzer-go/internal/detect"
)

// BuiltinKeys reproduit BUILTIN_KEYS = Object.keys(RULE_IDS) : l'ordre
// d'insertion de detect.RULE_IDS cote Node, reproduit ici a la main puisque
// les maps Go n'ont pas d'ordre stable.
var BuiltinKeys = []string{"bruteforce", "scan", "flood", "scraping", "volumetric", "country_traffic"}

func ruleIDFor(key string) int {
	switch key {
	case "bruteforce":
		return detect.RuleBruteforce
	case "scan":
		return detect.RuleScan
	case "flood":
		return detect.RuleFlood
	case "scraping":
		return detect.RuleScraping
	case "volumetric":
		return detect.RuleVolumetric
	case "country_traffic":
		return detect.RuleCountryTraffic
	default:
		return 0
	}
}

func isBuiltinKey(key string) bool {
	for _, k := range BuiltinKeys {
		if k == key {
			return true
		}
	}
	return false
}

// BlocklistConfig reproduit BLOCKLIST_DEFAULTS / la forme { threshold,
// windowMinutes, remediation, remediationMinutes }.
type BlocklistConfig struct {
	Threshold          *int
	WindowMinutes      int
	Remediation        bool
	RemediationMinutes *int
	RemediationType    string // "block" | "challenge" (v12.63.0)
}

// DefaultBlocklistConfig reproduit BLOCKLIST_DEFAULTS : par la meme
// convention de securite que le reste du mecanisme "Blocklist a la
// CrowdSec" - une regle ne contribue a la blocklist automatique que si
// l'operateur lui a explicitement donne un threshold, et ne bloque
// reellement (remediation) que si celui-ci vaut litteralement true.
func DefaultBlocklistConfig() BlocklistConfig {
	return BlocklistConfig{Threshold: nil, WindowMinutes: 1440, Remediation: false, RemediationMinutes: nil, RemediationType: "block"}
}

// BlocklistConfigInput reproduit l'argument brut de setBlocklistConfig() /
// normalizeBlocklistConfig() - des pointeurs pour distinguer "absent" de
// "zero".
type BlocklistConfigInput struct {
	Threshold          *float64
	WindowMinutes      *float64
	Remediation        bool
	RemediationMinutes *float64
	RemediationType    string // "" = absent -> block
}

// NormalizeResult reproduit { ok, errors, value } de normalizeBlocklistConfig().
type NormalizeResult struct {
	OK     bool
	Errors []string
	Value  BlocklistConfig
}

// normalizeBlocklistConfig replique normalizeBlocklistConfig() : valide +
// borne la config blocklist d'une regle integree.
func normalizeBlocklistConfig(in BlocklistConfigInput) NormalizeResult {
	var errs []string
	var threshold *int
	if in.Threshold != nil {
		if *in.Threshold < 1 {
			errs = append(errs, `"threshold" doit etre un entier >= 1 (ou absent/null pour desactiver)`)
		} else {
			n := int(*in.Threshold + 0.5)
			threshold = &n
		}
	}
	windowMinutes := 1440
	if in.WindowMinutes != nil {
		if *in.WindowMinutes < 1 {
			errs = append(errs, `"windowMinutes" doit etre un entier >= 1`)
		} else {
			n := int(*in.WindowMinutes + 0.5)
			if n > MaxBlocklistWindowMinutes {
				n = MaxBlocklistWindowMinutes
			}
			windowMinutes = n
		}
	}
	var remediationMinutes *int
	if in.RemediationMinutes != nil {
		if *in.RemediationMinutes < 1 {
			errs = append(errs, `"remediationMinutes" doit etre un entier >= 1 (ou absent/null)`)
		} else {
			n := int(*in.RemediationMinutes + 0.5)
			if n > MaxBlocklistRemediationMinutes {
				n = MaxBlocklistRemediationMinutes
			}
			remediationMinutes = &n
		}
	}
	remediationType := "block"
	if in.RemediationType != "" {
		if !ValidRemediationType(in.RemediationType) {
			errs = append(errs, `"remediationType" doit valoir block ou challenge`)
		} else {
			remediationType = in.RemediationType
		}
	}
	if len(errs) > 0 {
		return NormalizeResult{OK: false, Errors: errs}
	}
	return NormalizeResult{OK: true, Value: BlocklistConfig{
		Threshold: threshold, WindowMinutes: windowMinutes, Remediation: in.Remediation, RemediationMinutes: remediationMinutes,
		RemediationType: remediationType,
	}}
}

// Store est le sous-ensemble de *store.Store dont RulesManager a besoin
// (getState/setState generique) - une interface plutot qu'une dependance
// directe pour rester testable sans SQLite, comme fakeStore() cote Node.
type Store interface {
	GetState(key string) any
	SetState(key string, value any)
}

// ruleState reproduit this.state[key] = { enabled, blocklist }.
type ruleState struct {
	Enabled   bool            `json:"enabled"`
	Blocklist BlocklistConfig `json:"blocklist"`
}

// VhostRuleConfig reproduit un element de la map vhostRules : { enabled, ignore }.
type VhostRuleConfig struct {
	Enabled bool
	Ignore  map[int]struct{}
	// PathsIgnore : # nginx-control-analyze-rule-{ID}-paths-ignore (v12.54.0).
	PathsIgnore map[int][]string
}

// Manager porte la classe RulesManager.
type Manager struct {
	mu          sync.Mutex
	store       Store
	state       map[string]ruleState
	customYaml  string
	customRaw   []RawRule
	customErrs  []string
	customValid []ValidRule
	vhostRules  map[string]VhostRuleConfig
}

// New reproduit le constructeur. envDefaults : etat enable/disable derive
// des variables d'environnement, utilise seulement si rien n'a encore ete
// persiste.
func New(store Store, envDefaults map[string]bool) *Manager {
	m := &Manager{store: store, state: make(map[string]ruleState), vhostRules: make(map[string]VhostRuleConfig)}

	persisted, _ := store.GetState("rule_state").(map[string]any)
	for _, key := range BuiltinKeys {
		enabled := true
		blocklistPersisted := map[string]any{}
		if persisted != nil {
			if p, ok := persisted[key]; ok {
				// Correctif/migration (v12.50.0) : rule_state[key] etait un
				// booleen brut (enable/disable uniquement). Une valeur
				// persistee d'avant v12.50.0 (booleen nu) est transparemment
				// mise a niveau vers la nouvelle forme au chargement, pour
				// qu'un choix enable/disable existant ne soit jamais perdu.
				switch v := p.(type) {
				case bool:
					enabled = v
				case map[string]any:
					if e, ok := v["enabled"]; ok {
						if b, ok := e.(bool); ok {
							enabled = b
						}
					} else if def, ok := envDefaults[key]; ok {
						enabled = def
					}
					if bl, ok := v["blocklist"].(map[string]any); ok {
						blocklistPersisted = bl
					}
				default:
					if def, ok := envDefaults[key]; ok {
						enabled = def
					}
				}
			} else if def, ok := envDefaults[key]; ok {
				enabled = def
			}
		} else if def, ok := envDefaults[key]; ok {
			enabled = def
		}
		norm := normalizeBlocklistConfig(blocklistInputFromPersisted(blocklistPersisted))
		bl := DefaultBlocklistConfig()
		if norm.OK {
			bl = norm.Value
		}
		m.state[key] = ruleState{Enabled: enabled, Blocklist: bl}
	}

	customRaw, _ := store.GetState("custom_rules_yaml").(string)
	m.customYaml = customRaw
	raw, errs, valid := ParseAndValidate(m.customYaml)
	m.customRaw = raw
	m.customErrs = errs
	m.customValid = valid

	return m
}

func blocklistInputFromPersisted(m map[string]any) BlocklistConfigInput {
	in := BlocklistConfigInput{}
	if v, ok := m["threshold"]; ok {
		if f, ok := asFloat(v); ok {
			in.Threshold = &f
		}
	}
	if v, ok := m["windowMinutes"]; ok {
		if f, ok := asFloat(v); ok {
			in.WindowMinutes = &f
		}
	}
	if v, ok := m["remediation"].(bool); ok {
		in.Remediation = v
	}
	if v, ok := m["remediationMinutes"]; ok {
		if f, ok := asFloat(v); ok {
			in.RemediationMinutes = &f
		}
	}
	if v, ok := m["remediationType"].(string); ok {
		in.RemediationType = v
	}
	return in
}

// IsEnabled replique isEnabled().
func (m *Manager) IsEnabledNL(key string) bool {
	if s, ok := m.state[key]; ok {
		return s.Enabled
	}
	return true
}

// Toggle replique toggle() : bascule une regle integree et persiste. Renvoie
// false pour une cle inconnue.
func (m *Manager) ToggleNL(key string, enable bool) bool {
	if !isBuiltinKey(key) {
		return false
	}
	s := m.state[key]
	s.Enabled = enable
	m.state[key] = s
	m.persistRuleState()
	return true
}

// GetBlocklistConfig replique getBlocklistConfig().
func (m *Manager) GetBlocklistConfigNL(key string) *BlocklistConfig {
	if !isBuiltinKey(key) {
		return nil
	}
	c := m.state[key].Blocklist
	return &c
}

// SetBlocklistConfig replique setBlocklistConfig() : rejete en bloc en cas
// d'erreur de validation, jamais une application partielle.
func (m *Manager) SetBlocklistConfigNL(key string, in BlocklistConfigInput) NormalizeResult {
	if !isBuiltinKey(key) {
		return NormalizeResult{OK: false, Errors: []string{"Regle inconnue : " + key}}
	}
	result := normalizeBlocklistConfig(in)
	if !result.OK {
		return result
	}
	s := m.state[key]
	s.Blocklist = result.Value
	m.state[key] = s
	m.persistRuleState()
	return result
}

func (m *Manager) persistRuleState() {
	out := make(map[string]any, len(m.state))
	for k, v := range m.state {
		bl := map[string]any{
			"windowMinutes":   v.Blocklist.WindowMinutes,
			"remediation":     v.Blocklist.Remediation,
			"remediationType": v.Blocklist.RemediationType,
		}
		if v.Blocklist.Threshold != nil {
			bl["threshold"] = *v.Blocklist.Threshold
		} else {
			bl["threshold"] = nil
		}
		if v.Blocklist.RemediationMinutes != nil {
			bl["remediationMinutes"] = *v.Blocklist.RemediationMinutes
		} else {
			bl["remediationMinutes"] = nil
		}
		out[k] = map[string]any{"enabled": v.Enabled, "blocklist": bl}
	}
	m.store.SetState("rule_state", out)
}

// BlocklistRule reproduit un element de listBlocklistRules().
type BlocklistRule struct {
	ID                 int
	Key                string
	Name               string
	Custom             bool
	Threshold          int
	WindowMinutes      int
	Remediation        bool
	RemediationMinutes *int
	RemediationType    string
}

// ListBlocklistRules replique listBlocklistRules() : liste unifiee de
// chaque regle (integree + personnalisee) ayant opte dans le mecanisme
// "Blocklist a la CrowdSec" - tout ce dont le dashboard a besoin pour
// calculer les IP suspectes, sans avoir a distinguer integree/personnalisee.
func (m *Manager) ListBlocklistRulesNL() []BlocklistRule {
	var out []BlocklistRule
	for _, key := range BuiltinKeys {
		bl := m.GetBlocklistConfigNL(key)
		if bl.Threshold == nil {
			continue
		}
		out = append(out, BlocklistRule{
			ID: ruleIDFor(key), Key: key, Name: key, Custom: false,
			Threshold: *bl.Threshold, WindowMinutes: bl.WindowMinutes,
			Remediation: bl.Remediation, RemediationMinutes: bl.RemediationMinutes,
			RemediationType: bl.RemediationType,
		})
	}
	for _, r := range m.customValid {
		if r.BlocklistThreshold == nil {
			continue
		}
		out = append(out, BlocklistRule{
			ID: r.ID, Key: "custom_" + itoa(r.ID), Name: r.Name, Custom: true,
			Threshold: *r.BlocklistThreshold, WindowMinutes: r.BlocklistWindowMinutes,
			Remediation: r.BlocklistRemediation, RemediationMinutes: r.BlocklistRemediationMinutes,
			RemediationType: r.BlocklistRemediationType,
		})
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// SetCustomYamlResult reproduit { ok, errors, count } de setCustomYaml().
type SetCustomYamlResult struct {
	OK     bool
	Errors []string
	Count  int
}

// SetCustomYaml replique setCustomYaml() : remplace les regles
// personnalisees a partir du texte YAML brut.
func (m *Manager) SetCustomYamlNL(text string) SetCustomYamlResult {
	_, errs, valid := ParseAndValidate(text)
	if len(errs) > 0 {
		return SetCustomYamlResult{OK: false, Errors: errs}
	}
	m.customYaml = text
	m.customValid = valid
	m.store.SetState("custom_rules_yaml", text)
	return SetCustomYamlResult{OK: true, Count: len(valid)}
}

// CustomYaml expose le texte YAML personnalise courant (getter, pas dans le
// JS d'origine mais necessaire ici puisque Go n'a pas de proprietes
// publiques sur un champ non exporte).
func (m *Manager) CustomYamlNL() string       { return m.customYaml }
func (m *Manager) CustomErrorsNL() []string   { return m.customErrs }
func (m *Manager) CustomValidNL() []ValidRule { return m.customValid }

// VhostRuleInput reproduit un element de l'argument `vhosts` de setVhostRules().
type VhostRuleInput struct {
	Enabled     bool
	Ignore      []int
	PathsIgnore map[int][]string
}

// Limites defensives, identiques a sanitizePathsIgnore() cote Node.
const (
	MaxPathsIgnorePerRule = 50
	MaxPathIgnoreLen      = 256
)

// SanitizePathsIgnore replique sanitizePathsIgnore() : motifs "/..." uniquement
// (exact, ou prefixe si fini par "*"), dedoublonnes, bornes. Un id negatif ou
// une liste vide est ecarte.
func SanitizePathsIgnore(raw map[int][]string) map[int][]string {
	out := make(map[int][]string)
	for id, list := range raw {
		if id < 0 {
			continue
		}
		var pats []string
		for _, v := range list {
			pat := strings.TrimSpace(v)
			if len(pat) < 1 || len(pat) > MaxPathIgnoreLen || pat[0] != '/' {
				continue
			}
			dup := false
			for _, e := range pats {
				if e == pat {
					dup = true
					break
				}
			}
			if !dup {
				pats = append(pats, pat)
			}
			if len(pats) >= MaxPathsIgnorePerRule {
				break
			}
		}
		if len(pats) > 0 {
			out[id] = pats
		}
	}
	return out
}

// SetVhostRules replique setVhostRules() : remplace la map d'opt-out par vhost.
func (m *Manager) SetVhostRulesNL(vhosts map[string]VhostRuleInput) map[string]VhostRuleConfig {
	out := make(map[string]VhostRuleConfig, len(vhosts))
	for name, cfg := range vhosts {
		ignore := make(map[int]struct{}, len(cfg.Ignore))
		for _, id := range cfg.Ignore {
			ignore[id] = struct{}{}
		}
		out[strings.ToLower(name)] = VhostRuleConfig{Enabled: cfg.Enabled, Ignore: ignore, PathsIgnore: SanitizePathsIgnore(cfg.PathsIgnore)}
	}
	m.vhostRules = out
	return out
}

// VhostDisabled replique vhostDisabled() : vrai quand un vhost a
// completement opte hors de l'analyse (# nginx-control-analyze: off).
func (m *Manager) VhostDisabledNL(vhost string) bool {
	if vhost == "" {
		return false
	}
	cfg, ok := m.vhostRules[strings.ToLower(vhost)]
	return ok && !cfg.Enabled
}

// RuleSuppressedForVhost replique ruleSuppressedForVhost() : vrai quand cet
// identifiant de regle precis est ignore pour ce vhost (l'opt-out complet du
// vhost compte aussi).
func (m *Manager) RuleSuppressedForVhostNL(vhost string, ruleID int) bool {
	if vhost == "" {
		return false
	}
	cfg, ok := m.vhostRules[strings.ToLower(vhost)]
	if !ok {
		return false
	}
	if !cfg.Enabled {
		return true
	}
	_, ignored := cfg.Ignore[ruleID]
	return ignored
}

// Template replique le template statique de l'editeur (static template()).
func Template() string {
	return StringifyRules([]map[string]any{{
		"id": 100, "name": "exemple_admin_probe", "enable": false, "severity": "medium",
		"description":    "Exemple desactive par defaut — dupliquez et adaptez.",
		"window_minutes": 5, "min_matches": 10,
		"path_hint": "(wp-admin|phpmyadmin|\\.env)", "ua_hint": nil,
		"status_in": []any{}, "method_in": []any{},
	}})
}

// Thresholds reproduit l'argument optionnel `thresholds` de catalog() :
// la configuration numerique reelle avec laquelle chaque regle integree
// tourne actuellement, pour que la modale affiche des chiffres reels
// ("600 requetes / 5 min") plutot que seulement le texte statique
// what/why/legit/action, qui ne change jamais meme quand un operateur
// ajuste les variables d'environnement ANALYZER_*.
type Thresholds struct {
	WindowMs       int64
	Bruteforce     *BruteforceThresholds
	Scan           *ScanThresholds
	Flood          *FloodThresholds
	Scraping       *ScrapingThresholds
	Volumetric     *VolumetricThresholds
	CountryTraffic *VolumetricThresholds
}

type BruteforceThresholds struct{ MinFailures int }
type ScanThresholds struct {
	MinRequests      int
	MinDistinct      int
	MinNotFoundRatio float64
}
type FloodThresholds struct{ MinRequests int }
type ScrapingThresholds struct {
	MinRequests int
	MaxDistinct int
}
type VolumetricThresholds struct {
	LearningDays        int
	SigmaThreshold      float64
	MinAbsoluteRequests int64
}

// Explanation reutilise directement detect.Explanation : ce paquet importe
// deja internal/detect pour RULE_IDS, inutile de dupliquer le type.
type Explanation = detect.Explanation

// BuiltinCatalogEntry reproduit un element `builtins` de catalog().
type BuiltinCatalogEntry struct {
	Key         string
	ID          int
	Enabled     bool
	Custom      bool
	Explanation Explanation
	Config      map[string]any // nil = pas de config connue (retro-compatibilite : jamais une exception)
	Blocklist   BlocklistConfig
}

// CustomCatalogEntry reproduit un element `custom` de catalog().
type CustomCatalogEntry struct {
	Key           string
	ID            int
	Name          string
	Enabled       bool
	Custom        bool
	Severity      string
	Description   string
	WindowMinutes int
	MinMatches    int
	Scope         string // "ip" | "global"
	MinIPs        int    // scope global ; 0 sinon
	PathHint      string
	UAHint        string
	StatusIn      []int
	MethodIn      []string
	Blocklist     BlocklistConfig
}

// ProcessingInfo reproduit buildProcessingInfo() : documentation vivante
// (pas de configuration) de COMMENT le moteur traite les regles.
type ProcessingInfo struct {
	Aggregation   string
	EdgeTriggered string
	VhostOptOut   string
	CustomRules   string
}

// Catalog reproduit la valeur de retour de catalog().
type Catalog struct {
	Builtins     []BuiltinCatalogEntry
	Custom       []CustomCatalogEntry
	CustomYaml   string
	CustomErrors []string
	Processing   ProcessingInfo
}

func formatNum(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// Catalog replique catalog() : catalogue complet pour la modale "Regles" du
// dashboard - integrees + personnalisees, chacune avec son etat actif.
func (m *Manager) CatalogNL(explanations map[string]Explanation, thresholds Thresholds) Catalog {
	var windowMinutes *float64
	if thresholds.WindowMs != 0 {
		v := float64(thresholds.WindowMs) / 60_000
		windowMinutes = &v
	}

	builtins := make([]BuiltinCatalogEntry, 0, len(BuiltinKeys))
	for _, key := range BuiltinKeys {
		var config map[string]any
		switch key {
		case "bruteforce":
			if thresholds.Bruteforce != nil {
				config = map[string]any{"windowMinutes": ptrOrNil(windowMinutes), "minFailures": thresholds.Bruteforce.MinFailures}
			}
		case "scan":
			if thresholds.Scan != nil {
				config = map[string]any{
					"windowMinutes": ptrOrNil(windowMinutes), "minRequests": thresholds.Scan.MinRequests,
					"minDistinct":             thresholds.Scan.MinDistinct,
					"minNotFoundRatioPercent": int(thresholds.Scan.MinNotFoundRatio*100 + 0.5),
				}
			}
		case "flood":
			if thresholds.Flood != nil {
				config = map[string]any{"windowMinutes": ptrOrNil(windowMinutes), "minRequests": thresholds.Flood.MinRequests}
			}
		case "scraping":
			if thresholds.Scraping != nil {
				config = map[string]any{
					"windowMinutes": ptrOrNil(windowMinutes), "minRequests": thresholds.Scraping.MinRequests,
					"maxDistinct": thresholds.Scraping.MaxDistinct,
				}
			}
		case "volumetric":
			if thresholds.Volumetric != nil {
				config = map[string]any{
					"learningDays": thresholds.Volumetric.LearningDays, "sigmaThreshold": thresholds.Volumetric.SigmaThreshold,
					"minAbsoluteRequests": thresholds.Volumetric.MinAbsoluteRequests,
				}
			}
		case "country_traffic":
			if thresholds.CountryTraffic != nil {
				config = map[string]any{
					"learningDays": thresholds.CountryTraffic.LearningDays, "sigmaThreshold": thresholds.CountryTraffic.SigmaThreshold,
					"minAbsoluteRequests": thresholds.CountryTraffic.MinAbsoluteRequests,
				}
			}
		}
		bl := m.GetBlocklistConfigNL(key)
		builtins = append(builtins, BuiltinCatalogEntry{
			Key: key, ID: ruleIDFor(key), Enabled: m.IsEnabledNL(key), Custom: false,
			Explanation: explanations[key], Config: config, Blocklist: *bl,
		})
	}

	custom := make([]CustomCatalogEntry, 0, len(m.customValid))
	for _, r := range m.customValid {
		custom = append(custom, CustomCatalogEntry{
			Key: "custom_" + itoa(r.ID), ID: r.ID, Name: r.Name, Enabled: r.Enable, Custom: true,
			Severity: r.Severity, Description: r.Description, WindowMinutes: r.WindowMinutes, MinMatches: r.MinMatches,
			Scope: r.Scope, MinIPs: r.MinIPs,
			PathHint: r.PathHintRaw, UAHint: r.UAHintRaw, StatusIn: r.StatusIn, MethodIn: r.MethodIn,
			Blocklist: BlocklistConfig{
				Threshold: r.BlocklistThreshold, WindowMinutes: r.BlocklistWindowMinutes,
				Remediation: r.BlocklistRemediation, RemediationMinutes: r.BlocklistRemediationMinutes,
				RemediationType: r.BlocklistRemediationType,
			},
		})
	}

	return Catalog{
		Builtins: builtins, Custom: custom, CustomYaml: m.customYaml, CustomErrors: m.customErrs,
		Processing: buildProcessingInfo(windowMinutes),
	}
}

func ptrOrNil(v *float64) any {
	if v == nil {
		return nil
	}
	return *v
}

// buildProcessingInfo replique la methode statique du meme nom : texte
// explicatif (pas de configuration ici, juste de la documentation vivante)
// sur COMMENT le moteur traite les regles.
func buildProcessingInfo(windowMinutes *float64) ProcessingInfo {
	w := 5.0
	if windowMinutes != nil && *windowMinutes != 0 {
		w = *windowMinutes
	}
	wStr := formatNum(w)
	return ProcessingInfo{
		Aggregation:   "Chaque regle integree (brute-force, scan, flood, aspiration) compte par adresse IP source, sur une fenetre glissante de " + wStr + " min decoupee en petits intervalles (10 s) : seule l activite des " + wStr + " dernieres minutes compte, jamais un cumul depuis le debut.",
		EdgeTriggered: "Une alerte se declenche au moment ou le seuil est franchi (transition), pas a chaque evaluation tant que le seuil reste depasse : un episode continu ne produit qu'une seule alerte, pas une rafale toutes les 30 s.",
		VhostOptOut:   "L'opt-out par vhost (# nginx-control-analyze-ignore-rules / # nginx-control-analyze: off) s'applique par regle et par vhost. Si l'IP suspecte a touche PLUSIEURS vhosts pendant la fenetre, la regle n'est ignoree que si TOUS ces vhosts l'ont individuellement ignoree — un seul vhost qui n'a pas opte pour l'ignore-rule suffit a garder l'alerte visible, pour ne jamais masquer une attaque reelle sur ce vhost-la au pretexte qu'un autre partage la meme adresse IP.",
		CustomRules:   "Les regles personnalisees (id >= 100) suivent exactement le meme moteur (comptage par IP, fenetre glissante propre a chaque regle, declenchement par transition, meme opt-out par vhost) — seul le critere de correspondance (chemin, agent, code HTTP, methode) et le seuil sont definis par vous.",
	}
}

// IsEnabled : version thread-safe (ingestion, handlers HTTP concurrents).
func (m *Manager) IsEnabled(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.IsEnabledNL(key)
}

// Toggle : version thread-safe (ingestion, handlers HTTP concurrents).
func (m *Manager) Toggle(key string, enable bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ToggleNL(key, enable)
}

// GetBlocklistConfig : version thread-safe (ingestion, handlers HTTP concurrents).
func (m *Manager) GetBlocklistConfig(key string) *BlocklistConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.GetBlocklistConfigNL(key)
}

// SetBlocklistConfig : version thread-safe (ingestion, handlers HTTP concurrents).
func (m *Manager) SetBlocklistConfig(key string, in BlocklistConfigInput) NormalizeResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.SetBlocklistConfigNL(key, in)
}

// ListBlocklistRules : version thread-safe (ingestion, handlers HTTP concurrents).
func (m *Manager) ListBlocklistRules() []BlocklistRule {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ListBlocklistRulesNL()
}

// SetCustomYaml : version thread-safe (ingestion, handlers HTTP concurrents).
func (m *Manager) SetCustomYaml(text string) SetCustomYamlResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.SetCustomYamlNL(text)
}

// CustomYaml : version thread-safe (ingestion, handlers HTTP concurrents).
func (m *Manager) CustomYaml() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.CustomYamlNL()
}

// CustomErrors : version thread-safe (ingestion, handlers HTTP concurrents).
func (m *Manager) CustomErrors() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.CustomErrorsNL()
}

// CustomValid : version thread-safe (ingestion, handlers HTTP concurrents).
func (m *Manager) CustomValid() []ValidRule {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.CustomValidNL()
}

// SetVhostRules : version thread-safe (ingestion, handlers HTTP concurrents).
func (m *Manager) SetVhostRules(vhosts map[string]VhostRuleInput) map[string]VhostRuleConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.SetVhostRulesNL(vhosts)
}

// VhostDisabled : version thread-safe (ingestion, handlers HTTP concurrents).
func (m *Manager) VhostDisabled(vhost string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.VhostDisabledNL(vhost)
}

// RuleSuppressedForVhost : version thread-safe (ingestion, handlers HTTP concurrents).
func (m *Manager) RuleSuppressedForVhost(vhost string, ruleID int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.RuleSuppressedForVhostNL(vhost, ruleID)
}

// Catalog : version thread-safe (ingestion, handlers HTTP concurrents).
func (m *Manager) Catalog(explanations map[string]Explanation, thresholds Thresholds) Catalog {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.CatalogNL(explanations, thresholds)
}

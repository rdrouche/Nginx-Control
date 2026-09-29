package main

// Manifest types mirror nginx-dashboard/lib/agent-manifest.js's JSON schema
// EXACTLY (field names, casing, defaults) — this file has no business logic
// of its own beyond what a manifest vhost needs to say; all validation is
// re-done authoritatively on the dashboard side (lib/agent-manifest.js), the
// same distrust any client of a network API deserves. Keeping the two in
// sync by hand (rather than generating one from the other) is a deliberate,
// small cost: this is the only place in the whole project where the same
// shape is described twice, and a mismatch is caught immediately by the
// dashboard's own validation rejecting the push with a clear error.

type MonitorSpec struct {
	Enable        bool   `json:"enable"`
	Interval      string `json:"interval,omitempty"`
	ValidHTTPCode string `json:"validHttpCode,omitempty"`
}

type DiagnosticSpec struct {
	Enable bool `json:"enable"`
}

type AnalyzeSpec struct {
	Enable      bool  `json:"enable"`
	IgnoreRules []int `json:"ignoreRules,omitempty"`
}

type LocationSpec struct {
	Path          string   `json:"path"`
	Target        string   `json:"target"`
	Snippets      []string `json:"snippets,omitempty"`
	MonitorIgnore bool     `json:"monitorIgnore,omitempty"`
}

type VhostSpec struct {
	ServerName            string         `json:"serverName"`
	Mode                  string         `json:"mode,omitempty"`        // "direct" (defaut) | "tunnel" | "relay"
	RelayScheme           string         `json:"relayScheme,omitempty"` // "http" (defaut) | "https" — utilise seulement si Mode=="relay"
	Listen                int            `json:"listen,omitempty"`
	SSLCertificate        string         `json:"sslCertificate,omitempty"`
	SSLCertificateSnippet string         `json:"sslCertificateSnippet,omitempty"`
	HTTPToHTTPSAuto       bool           `json:"httpToHttpsAuto,omitempty"`
	ServerSnippets        []string       `json:"serverSnippets,omitempty"`
	Locations             []LocationSpec `json:"locations"`
	Monitor               MonitorSpec    `json:"monitor,omitempty"`
	Diagnostic            DiagnosticSpec `json:"diagnostic,omitempty"`
	Analyze               AnalyzeSpec    `json:"analyze,omitempty"`
}

type MetricsSpec struct {
	CPUPercent       *float64 `json:"cpuPercent,omitempty"`
	MemPercent       *float64 `json:"memPercent,omitempty"`
	MemTotalMb       *float64 `json:"memTotalMb,omitempty"`
	UptimeSec        *float64 `json:"uptimeSec,omitempty"`
	NetRxBytesPerSec *float64 `json:"netRxBytesPerSec,omitempty"`
	NetTxBytesPerSec *float64 `json:"netTxBytesPerSec,omitempty"`
}

// RelaySpec is the envelope-level `relay: { http, https }` block (mode
// "relay", v12.20.0) : l'adresse `scheme://host:port` du/des port(s) fixes
// que CET agent expose lui-meme via relay.go — jamais une adresse tierce.
// Omis entierement si l agent n a pas de listener relay actif (voir
// startRelay() dans relay.go, appele seulement si --relay-http-listen ou
// --relay-https-listen est fourni).
type RelaySpec struct {
	HTTP  string `json:"http,omitempty"`
	HTTPS string `json:"https,omitempty"`
}

type Manifest struct {
	ProtocolVersion int          `json:"protocolVersion"`
	Vhosts          []VhostSpec  `json:"vhosts"`
	Metrics         *MetricsSpec `json:"metrics,omitempty"`
	Relay           *RelaySpec   `json:"relay,omitempty"`
}

// CurrentProtocolVersion must track lib/agent-manifest.js's
// CURRENT_PROTOCOL_VERSION. A dashboard that no longer supports it responds
// with a clear top-level "protocolVersion non supportee" error (see
// pushManifest()) rather than silently misinterpreting the payload.
const CurrentProtocolVersion = 1

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// Mode "relay" (v12.20.0) — reponse au probleme souleve par l'operateur :
// le mode "direct" ouvre un port par vhost/container cote dashboard->agent,
// ce qui devient penible des que l'agent vit dans un VLAN separe (un port a
// ouvrir a chaque nouveau service, potentiellement un port ALEATOIRE si
// jamais ce choix etait fait cote allocation dynamique). Le mode "relay"
// resout ca en ouvrant, cote agent, UN SEUL port HTTP et/ou UN SEUL port
// HTTPS fixes ; nginx fait un simple proxy_pass direct vers cette adresse
// unique (voir generateAgentVhostContent() cote dashboard, branche isRelay)
// et c'est CET agent qui route localement par Host+path vers le vrai
// backend (meme table de routage que le mode tunnel, voir
// resolveLocalTarget() dans tunnel.go — routes.byHost couvre les deux
// modes).
//
// Difference cle avec le mode tunnel : ici, nginx parle DIRECTEMENT a
// l'agent en HTTP(S) reel (net/http/httputil.ReverseProxy), pas de saut par
// le dashboard ni de JSON tamponne sur WebSocket — un vrai flux HTTP,
// streaming compris. Le mode tunnel reste necessaire pour un agent
// injoignable en entree (NAT sortant uniquement) ; le mode relay suppose au
// contraire qu'un port fixe PEUT etre ouvert vers l'agent (juste UN SEUL,
// pas un par service).

// relayHandler builds the reverse proxy that serves BOTH relay listeners
// (HTTP and HTTPS — see startRelay()). Its own scheme (how nginx reaches
// THIS agent) is entirely independent of the backend's scheme (how this
// agent reaches the real local service, i.e. each location's `.target`) :
// nothing here assumes the two match, so any combination works by
// construction — e.g. a frontal HTTPS client -> nginx -> this relay over
// plain HTTP (trusted internal hop) -> a Docker backend itself over HTTPS.
// See the README, section "Chaines de schemas supportees", for the full
// matrix. insecureBackendTLS controls ONLY the last hop (agent -> backend) :
// when true, a backend `.target` of `https://...` is reached without
// verifying its certificate — needed in practice for an internal Docker
// service serving a self-signed cert, which is the common case (unlike the
// relay's OWN listener certificate, which nginx already treats as
// self-signed via `proxy_ssl_verify off;`, this one nginx never sees at
// all).
func relayHandler(insecureBackendTLS bool) http.Handler {
	var transport http.RoundTripper
	if insecureBackendTLS {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		transport = t
	}
	return &httputil.ReverseProxy{
		Transport: transport, // nil -> http.DefaultTransport (verification TLS normale)
		Director: func(req *http.Request) {
			host := req.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			target, ok := resolveLocalTarget(host, req.URL.Path)
			if !ok {
				// Laisse passer tel quel : RoundTrip echouera proprement
				// (URL invalide/hote inconnu) plutot que de router au hasard.
				req.URL.Scheme = "http"
				req.URL.Host = "127.0.0.1:0"
				return
			}
			u, err := url.Parse(target)
			if err != nil {
				req.URL.Scheme = "http"
				req.URL.Host = "127.0.0.1:0"
				return
			}
			req.URL.Scheme = u.Scheme
			req.URL.Host = u.Host
			// Host d'origine (server_name du vhost distant) preserve pour le
			// backend local, exactement comme le ferait un proxy_pass nginx
			// sans "proxy_set_header Host" personnalise cote agent.
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[relay] %s %s : %v", r.Method, r.URL.Path, err)
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("relay: cible locale injoignable\n"))
		},
	}
}

// startRelay launches the HTTP and/or HTTPS relay listeners requested on the
// command line (main.go). Either can be empty to skip it — an operator
// might want only one of the two, exactly as the user's request phrased it
// ("port unique ou deux (http et https si necessaire de differencier)").
// insecureBackendTLS is passed straight to relayHandler() — see its comment,
// it governs the agent -> backend hop only, never the nginx -> agent hop
// (that one is a plain HTTP or HTTPS listener, chosen by which of
// httpListen/httpsListen is set). Blocks until ctx is cancelled; listener
// errors are logged, not fatal (a relay problem should not take down the
// manifest-push loop, which keeps working for direct/tunnel vhosts
// regardless).
func startRelay(ctx context.Context, httpListen, httpsListen, certFile, keyFile string, insecureBackendTLS bool) {
	handler := relayHandler(insecureBackendTLS)

	if httpListen != "" {
		// Fix (audit report, Basse/"Agent Go"): no ReadHeaderTimeout at all
		// means a client that opens the connection and then trickles its
		// request headers in one byte at a time (or never finishes them)
		// ties up a goroutine and a file descriptor indefinitely — the
		// classic slowloris pattern. This listener is meant to be reached
		// only by nginx over a private hop (see this file's own header
		// comment), but it is still a real network listener with no other
		// protection in front of it, so it gets the same floor any
		// internet-facing net/http server would.
		srv := &http.Server{Addr: httpListen, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
		go runRelayServer(ctx, srv, "http", func() error { return srv.ListenAndServe() })
	}

	if httpsListen != "" {
		cert, err := loadOrGenerateCert(certFile, keyFile)
		if err != nil {
			log.Printf("[relay] impossible de preparer le certificat HTTPS : %v — le listener https ne demarre pas", err)
		} else {
			srv := &http.Server{
				Addr:              httpsListen,
				Handler:           handler,
				TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}},
				ReadHeaderTimeout: 10 * time.Second, // meme raison que le listener http ci-dessus
			}
			go runRelayServer(ctx, srv, "https", func() error { return srv.ListenAndServeTLS("", "") })
		}
	}
}

func runRelayServer(ctx context.Context, srv *http.Server, label string, listenAndServe func() error) {
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	log.Printf("[relay] listener %s demarre sur %s", label, srv.Addr)
	if err := listenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("[relay] listener %s arrete : %v", label, err)
	}
}

// loadOrGenerateCert reads an operator-supplied cert/key pair when both are
// given, or generates a throwaway self-signed one otherwise (stdlib only :
// crypto/tls, crypto/x509, crypto/rsa, encoding/pem — same zero-dependency
// discipline as the rest of this binary). A self-signed cert is expected and
// documented: nginx's side of this hop sets `proxy_ssl_verify off;` (see
// lib/agent-manifest.js's generateAgentVhostContent(), mode relay/https
// branch) unless the operator supplies a real one and re-enables
// verification themselves via a server snippet.
func loadOrGenerateCert(certFile, keyFile string) (tls.Certificate, error) {
	if certFile != "" && keyFile != "" {
		return tls.LoadX509KeyPair(certFile, keyFile)
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generation de la cle privee : %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generation du numero de serie : %w", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "nginx-control-agent (auto-signe)"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
		DNSNames:              []string{"*"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("creation du certificat : %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("assemblage du certificat auto-signe : %w", err)
	}
	log.Printf("[relay] certificat HTTPS auto-signe genere en memoire (valide 10 ans, CN=%s) — fournir --relay-https-cert/--relay-https-key pour un vrai certificat", "nginx-control-agent")
	return cert, nil
}

// relayAdvertised resolves what this agent should tell the dashboard its
// relay address is, for a given scheme : the explicit --relay-*-advertise
// flag if given (mandatory in practice — an agent behind NAT/VLAN cannot
// reliably guess which of its addresses is reachable from nginx), else
// empty (meaning: do not advertise this scheme at all).
func relayAdvertised(advertise string) string {
	return strings.TrimSpace(advertise)
}

// validateAdvertiseAddr fails fast on the single most common misconfiguration
// (retour utilisateur) : RELAY_HTTP_ADVERTISE/RELAY_HTTPS_ADVERTISE holding a
// bare port number (e.g. "8080") instead of the "scheme://host:port" address
// nginx must actually connect to — an easy mistake given the neighboring
// RELAY_HTTP_HOST_PORT/RELAY_HTTPS_HOST_PORT are themselves bare numbers.
// Unlike RELAY_*_LISTEN (fixable automatically by normalizeListenAddr() in
// main.go, since ":<port>" unambiguously means "all interfaces"), there is
// no safe default HOST to guess here — an agent behind NAT/VLAN cannot know
// which of its own addresses nginx can actually reach — so this fails the
// agent's startup immediately with an explicit message, instead of letting
// it start normally and silently push a manifest the dashboard will reject
// (vhost by vhost, every cycle, forever) — see
// nginx-dashboard/lib/agent-manifest.js#AGENT_TARGET_RE for the equivalent
// check applied dashboard-side once such a manifest actually arrives.
func validateAdvertiseAddr(flagName, value string) error {
	if value == "" {
		return nil
	}
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Path != "" || u.RawQuery != "" {
		return fmt.Errorf(`%s=%q invalide : attendu "http://host:port" ou "https://host:port" (l'adresse a laquelle NGINX doit joindre ce relais), pas juste un numero de port`, flagName, value)
	}
	return nil
}

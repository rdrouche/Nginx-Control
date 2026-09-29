// Command nginx-control-agent is the reference "Partie 2" remote agent for
// nginx-dashboard : it reads nginx-control.* Docker labels on its OWN
// Docker host (see labels.go for the exact schema), builds the JSON
// manifest nginx-dashboard/lib/agent-manifest.js expects, and pushes it on
// an interval. It also carries the "mode 3" tunnel client (tunnel.go) for
// any vhost declared with `nginx-control.vhost.mode=tunnel`.
//
// Zero third-party dependencies — same discipline as the dashboard itself
// (nginx-dashboard's own package.json has none). Everything here is Go
// standard library.
//
// See README.md for a full walkthrough (enrollment, approval, running).
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// buildVersion is overwritten at build time via -ldflags "-X main.buildVersion=..."
// (see Dockerfile) — purely informational (logged at startup), never
// compared against anything: protocol compatibility is decided by
// CurrentProtocolVersion (manifest.go), not by this string.
var buildVersion = "dev"

// envOr/envOrBool/envOrDuration let every flag also be set via an
// environment variable of the same intent — the ENV names documented in
// Dockerfile (RELAY_HTTP_LISTEN, DASHBOARD_URL, etc.), one level up from the
// CLI flag names. An explicit flag on the command line always wins (Go's
// own flag.Parse() semantics: whatever default we pass here is just that,
// a default) ; this only changes what the default IS, using the
// environment when a flag is omitted entirely. This is what lets one Docker
// image (see Dockerfile's ENTRYPOINT) be reused unchanged across
// deployments that only vary by a .env file (see compose.yml/sample.env in
// this same folder) — no flag translation script needed.
func envOr(name, def string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return def
}
func envOrBool(name string, def bool) bool {
	v, ok := os.LookupEnv(name)
	if !ok {
		return def
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return b
}
// normalizeListenAddr tolerates the extremely common footgun of giving a
// bare port number (RELAY_HTTP_LISTEN=8080) instead of Go's net.Listen
// syntax (":8080") — every other port-shaped setting in this project
// (PORT, RELAY_HTTP_HOST_PORT, ...) is just a number, so writing one here
// too is a natural mistake, and Go's net.Listen() rejects it outright
// ("missing port in address") because a lone "8080" parses as a HOSTNAME
// with no port, not a port with no host. Only a value made entirely of
// digits is touched (":8080", "0.0.0.0:8080", "[::]:8080" etc. are already
// valid and pass through unchanged) — logged once so the operator still
// notices their .env is slightly off, without the agent refusing to start
// over it.
func normalizeListenAddr(v string) string {
	if v == "" {
		return v
	}
	isDigits := true
	for _, r := range v {
		if r < '0' || r > '9' {
			isDigits = false
			break
		}
	}
	if isDigits {
		log.Printf("[agent] adresse d'ecoute %q sans hote:port explicite, interpretee comme \":%s\" (toutes les interfaces) — pour eviter cet avertissement, ecrire directement \":%s\"", v, v, v)
		return ":" + v
	}
	return v
}

func envOrDuration(name string, def time.Duration) time.Duration {
	v, ok := os.LookupEnv(name)
	if !ok {
		return def
	}
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return d
}

func main() {
	dashboardURL := flag.String("dashboard-url", envOr("DASHBOARD_URL", ""), "URL de base du dashboard (ex: https://dashboard.example.com) [obligatoire] (env: DASHBOARD_URL)")
	hostname := flag.String("hostname", envOr("AGENT_HOSTNAME", ""), "Nom d'hote propose lors de l'enrolement (defaut : hostname systeme) (env: AGENT_HOSTNAME)")
	fingerprint := flag.String("fingerprint", envOr("AGENT_FINGERPRINT", ""), "Empreinte libre affichee a l'operateur (ex: numero de serie, id machine) (env: AGENT_FINGERPRINT)")
	stateFile := flag.String("state-file", envOr("STATE_FILE", "./nginx-control-agent-state.json"), "Fichier local ou persister agentId/token (env: STATE_FILE)")
	tokenFile := flag.String("token-file", envOr("TOKEN_FILE", ""), "Fichier relu a chaque cycle contenant le jeton Bearer (alternative a --token / au jeton sauvegarde dans --state-file) (env: TOKEN_FILE)")
	tokenFlag := flag.String("token", envOr("TOKEN", ""), "Jeton Bearer fourni directement (ecrase --token-file et l'etat sauvegarde) (env: TOKEN)")
	// ─── Multi-master (v12.21.0) ─────────────────────────────────────────────
	// --targets-file remplace --dashboard-url (et les flags associes) par une
	// LISTE de cibles independantes (voir targets.go et README.md) — un seul
	// agent peut alors pousser vers plusieurs Nginx Control (typiquement
	// DMZ + LAN), chaque conteneur decidant lesquelles recevoir via l etiquette
	// nginx-control.publish=. Fournir les deux a la fois est une erreur (voir
	// plus bas) : melanger les deux formes de configuration serait ambigu sur
	// laquelle gagne.
	targetsFile := flag.String("targets-file", envOr("TARGETS_FILE", ""), "Fichier JSON listant plusieurs cibles Nginx Control (multi-master) — remplace --dashboard-url/--state-file/--token(-file) (env: TARGETS_FILE)")
	dockerSocket := flag.String("docker-socket", envOr("DOCKER_SOCKET", "/var/run/docker.sock"), "Chemin du socket Docker local (env: DOCKER_SOCKET)")
	pollInterval := flag.Duration("poll-interval", envOrDuration("POLL_INTERVAL", 30*time.Second), "Intervalle entre deux pushs de manifeste (env: POLL_INTERVAL)")
	insecureSkipVerify := flag.Bool("insecure-skip-verify", envOrBool("INSECURE_SKIP_VERIFY", false), "Ne pas verifier le certificat TLS du dashboard (tests uniquement, jamais en production) (env: INSECURE_SKIP_VERIFY)")
	tunnelEnable := flag.Bool("tunnel", envOrBool("TUNNEL_ENABLE", true), "Maintenir une connexion tunnel (mode 3) si au moins un vhost declare mode=tunnel (env: TUNNEL_ENABLE)")
	once := flag.Bool("once", envOrBool("ONCE", false), "Ne pousser qu'un seul manifeste puis quitter (utile pour tester) (env: ONCE)")

	// ─── Mode "relay" (port unique/double, v12.20.0) ────────────────────────
	// Voir relay.go pour le detail. --relay-*-listen ouvre le listener local ;
	// --relay-*-advertise est l'adresse que le DASHBOARD doit ecrire dans le
	// proxy_pass nginx genere (jamais la meme chose si l'agent est derriere
	// un NAT/VLAN — l'agent ne peut pas deviner son adresse cote nginx).
	relayHTTPListen := flag.String("relay-http-listen", envOr("RELAY_HTTP_LISTEN", ""), "Adresse d'ecoute locale du relais HTTP (mode relay), ex: :8080 — vide = relais HTTP desactive (env: RELAY_HTTP_LISTEN)")
	relayHTTPAdvertise := flag.String("relay-http-advertise", envOr("RELAY_HTTP_ADVERTISE", ""), "Adresse scheme://host:port que le dashboard doit utiliser dans proxy_pass pour joindre le relais HTTP [obligatoire si --relay-http-listen est fourni] (env: RELAY_HTTP_ADVERTISE)")
	relayHTTPSListen := flag.String("relay-https-listen", envOr("RELAY_HTTPS_LISTEN", ""), "Adresse d'ecoute locale du relais HTTPS (mode relay), ex: :8443 — vide = relais HTTPS desactive (env: RELAY_HTTPS_LISTEN)")
	relayHTTPSAdvertise := flag.String("relay-https-advertise", envOr("RELAY_HTTPS_ADVERTISE", ""), "Adresse scheme://host:port que le dashboard doit utiliser dans proxy_pass pour joindre le relais HTTPS [obligatoire si --relay-https-listen est fourni] (env: RELAY_HTTPS_ADVERTISE)")
	relayHTTPSCert := flag.String("relay-https-cert", envOr("RELAY_HTTPS_CERT", ""), "Certificat TLS pour le relais HTTPS (PEM) — omis: certificat auto-signe genere en memoire (env: RELAY_HTTPS_CERT)")
	relayHTTPSKey := flag.String("relay-https-key", envOr("RELAY_HTTPS_KEY", ""), "Cle privee TLS pour le relais HTTPS (PEM) — requis si --relay-https-cert est fourni (env: RELAY_HTTPS_KEY)")
	// Cote AVAL du relais (agent -> backend Docker local), independant du
	// cote AMONT (nginx -> agent) choisi par --relay-http-listen/--relay-https-listen
	// ci-dessus : un .target de location en https:// (voir labels.go/manifest.go)
	// peut tres bien pointer vers un service Docker au certificat auto-signe.
	// Sans ce flag, ReverseProxy verifie ce certificat comme n'importe quel
	// client TLS standard et le rejette — voir le README, section "Chaines de
	// schemas supportees", pour le detail des combinaisons couvertes.
	relayBackendInsecureSkipVerify := flag.Bool("relay-backend-insecure-skip-verify", envOrBool("RELAY_BACKEND_INSECURE_SKIP_VERIFY", false), "Ne pas verifier le certificat TLS d'un backend local https:// joint par le relais (utile pour un service Docker interne en certificat auto-signe) (env: RELAY_BACKEND_INSECURE_SKIP_VERIFY)")
	flag.Parse()

	log.Printf("[agent] nginx-control-agent %s", buildVersion)

	// Fix (retour utilisateur) : "listen tcp: address 8080: missing port in
	// address" — voir normalizeListenAddr() ci-dessus pour le detail du
	// piege et pourquoi il est si facile a reproduire ici precisement.
	*relayHTTPListen = normalizeListenAddr(*relayHTTPListen)
	*relayHTTPSListen = normalizeListenAddr(*relayHTTPSListen)

	if *relayHTTPListen != "" && *relayHTTPAdvertise == "" {
		fmt.Fprintln(os.Stderr, "erreur: --relay-http-advertise est obligatoire des que --relay-http-listen est fourni")
		os.Exit(2)
	}
	if *relayHTTPSListen != "" && *relayHTTPSAdvertise == "" {
		fmt.Fprintln(os.Stderr, "erreur: --relay-https-advertise est obligatoire des que --relay-https-listen est fourni")
		os.Exit(2)
	}
	// Fix (retour utilisateur) : contrairement a --relay-*-listen, une valeur
	// invalide ici (ex: un numero de port nu, comme "8080") ne peut pas etre
	// corrigee automatiquement (aucun hote a deviner) — voir
	// validateAdvertiseAddr() dans relay.go pour le detail. L agent refuse
	// desormais de demarrer avec un message explicite, plutot que de pousser
	// indefiniment un manifeste que le dashboard rejettera systematiquement.
	if err := validateAdvertiseAddr("--relay-http-advertise", *relayHTTPAdvertise); err != nil {
		fmt.Fprintln(os.Stderr, "erreur: "+err.Error())
		os.Exit(2)
	}
	if err := validateAdvertiseAddr("--relay-https-advertise", *relayHTTPSAdvertise); err != nil {
		fmt.Fprintln(os.Stderr, "erreur: "+err.Error())
		os.Exit(2)
	}
	if (*relayHTTPSCert == "") != (*relayHTTPSKey == "") {
		fmt.Fprintln(os.Stderr, "erreur: --relay-https-cert et --relay-https-key doivent etre fournis ensemble (ou aucun des deux, pour un certificat auto-signe)")
		os.Exit(2)
	}

	// ─── Resolution des cibles : soit --targets-file (multi-master), soit les
	// flags --dashboard-url/--state-file/--token(-file) historiques (une seule
	// cible, au nom vide — comportement identique a avant cette version). ────
	var targets []targetConfig
	if *targetsFile != "" {
		if *dashboardURL != "" {
			fmt.Fprintln(os.Stderr, "erreur: --targets-file et --dashboard-url sont mutuellement exclusifs (lequel doit gagner serait ambigu)")
			os.Exit(2)
		}
		t, err := loadTargetsFile(*targetsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur: --targets-file invalide (%s) : %v\n", *targetsFile, err)
			os.Exit(2)
		}
		targets = t
		log.Printf("[agent] mode multi-master : %d cible(s) chargee(s) depuis %s", len(targets), *targetsFile)
	} else {
		if *dashboardURL == "" {
			fmt.Fprintln(os.Stderr, "erreur: --dashboard-url est obligatoire (ou --targets-file pour plusieurs cibles)")
			os.Exit(2)
		}
		targets = []targetConfig{{
			Name: "", DashboardURL: strings.TrimRight(*dashboardURL, "/"),
			StateFile: *stateFile, TokenFile: *tokenFile, Token: *tokenFlag,
			InsecureSkipVerify: *insecureSkipVerify,
		}}
	}

	if *hostname == "" {
		h, err := os.Hostname()
		if err != nil || h == "" {
			h = "agent-inconnu"
		}
		*hostname = h
	}

	ctx, cancel := context.WithCancel(context.Background())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; log.Println("[agent] arret demande"); cancel() }()

	dockerCli := newDockerClient(*dockerSocket)

	// Contrairement au tunnel (qui n'a de sens que si un vhost mode=tunnel
	// existe), le(s) listener(s) relay demarrent immediatement des que
	// l'operateur les a demandes en ligne de commande : le port doit etre
	// ouvert et stable avant meme qu'un manifeste valide ne soit pousse,
	// puisque c'est justement l'adresse que le manifeste va annoncer. Un seul
	// jeu de listeners relay pour tout le processus, meme en multi-master :
	// c'est le meme hote physique, donc la meme adresse joignable quelle que
	// soit la cible qui finit par y faire un proxy_pass (voir targets.go).
	if *relayHTTPListen != "" || *relayHTTPSListen != "" {
		startRelay(ctx, *relayHTTPListen, *relayHTTPSListen, *relayHTTPSCert, *relayHTTPSKey, *relayBackendInsecureSkipVerify)
	}
	var relaySpec *RelaySpec
	if http := relayAdvertised(*relayHTTPAdvertise); http != "" {
		if relaySpec == nil {
			relaySpec = &RelaySpec{}
		}
		relaySpec.HTTP = http
	}
	if https := relayAdvertised(*relayHTTPSAdvertise); https != "" {
		if relaySpec == nil {
			relaySpec = &RelaySpec{}
		}
		relaySpec.HTTPS = https
	}

	// Une seule cible : execute la boucle directement dans main(), exactement
	// comme avant cette version (aucune goroutine supplementaire, aucun
	// changement de comportement/log pour l'usage historique). Plusieurs
	// cibles : chacune tourne dans sa propre goroutine, independamment (son
	// propre enrolement, son propre jeton, son propre intervalle de push —
	// seuls le socket Docker et le(s) listener(s) relay sont partages), et
	// main() attend qu'elles se terminent toutes (pertinent surtout avec
	// --once) avant de rendre la main.
	if len(targets) == 1 {
		ok := runTarget(ctx, targets[0], dockerCli, *hostname, *fingerprint, *pollInterval, *once, *tunnelEnable, relaySpec)
		// Fix (audit report, Basse/"Agent Go"): --once used to always exit 0
		// regardless of runTarget()'s outcome — a caller scripting around
		// this flag (a health check, a CI smoke test, a one-shot cron job)
		// could never actually detect a failed enrollment or a rejected
		// push from the exit code alone. Only meaningful with --once: the
		// normal polling loop runs until the process is killed, so there is
		// no single "final" result to report here otherwise.
		if *once && !ok {
			os.Exit(1)
		}
		return
	}
	var failed int32
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func(t targetConfig) {
			defer wg.Done()
			if !runTarget(ctx, t, dockerCli, *hostname, *fingerprint, *pollInterval, *once, *tunnelEnable, relaySpec) {
				atomic.AddInt32(&failed, 1)
			}
		}(t)
	}
	wg.Wait()
	// Same reasoning as the single-target branch above: only relevant with
	// --once, and "any target failed" is enough to make the whole run count
	// as a failure (a caller polling --once for a health signal across
	// several targets needs to know if EVEN ONE of them didn't succeed).
	if *once && failed > 0 {
		os.Exit(1)
	}
}

// runTarget porte l'enrolement + la boucle de push pour UNE cible (voir
// targetConfig dans targets.go). Le routage local (setLocalRoutes(), utilise
// par relay.go/tunnel.go pour savoir vers quel backend rediriger une requete
// entrante par Host) recoit systematiquement la liste COMPLETE des vhosts
// lus sur ce Docker local, jamais seulement ceux publies vers CETTE cible :
// un agent en multi-master reste un seul hote physique, et une requete qui
// arrive par le relais ou le tunnel doit pouvoir etre routee quelle que soit
// la cible dont elle provient. Seul le manifeste ENVOYE a chaque Nginx
// Control est filtre par publishesTo() — le routage local, lui, ne filtre
// jamais.
// runTarget's bool return (fix, audit report Basse/"Agent Go" — "--once
// renvoie le code 0 meme en cas d echec") reports whether this target's run
// actually succeeded: with --once, main() now aggregates every target's
// result and calls os.Exit(1) if any failed, instead of always exiting 0
// regardless of what happened (an enrollment that never completed, a push
// that errored, a token still missing — all silently indistinguishable from
// success to a caller/orchestrator scripting around `--once`'s exit code).
// A context cancellation (external shutdown, not this target's own doing)
// is never treated as a failure.
func runTarget(ctx context.Context, t targetConfig, dockerCli *dockerClient, hostname, fingerprint string, pollInterval time.Duration, once, tunnelEnable bool, relaySpec *RelaySpec) bool {
	logPrefix := "[agent]"
	if t.Name != "" {
		logPrefix = fmt.Sprintf("[agent:%s]", t.Name)
	}

	st := loadState(t.StateFile)

	// Fix v12.22.0 (audit finding GO-08) : un client HTTP PAR CIBLE, avec sa
	// PROPRE config TLS — auparavant seul le tunnel (dialTunnel) respectait
	// --insecure-skip-verify ; enroll() et pushManifest() utilisaient
	// http.DefaultClient, qui verifie toujours le certificat serveur, meme
	// quand l operateur avait explicitement demande de ne pas le faire (ou
	// l inverse : en multi-master, une cible pouvait vouloir des reglages TLS
	// differents de l autre, impossible a exprimer avec un seul client
	// partage). Fix v12.22.0 (audit finding GO-09) : Timeout explicite —
	// avant ce correctif, un dashboard qui ne repond plus (mais accepte la
	// connexion TCP) bloquait la boucle de CETTE cible indefiniment.
	httpClient := &http.Client{Timeout: 30 * time.Second}
	if strings.HasPrefix(t.DashboardURL, "https://") && t.InsecureSkipVerify {
		httpClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}

	// ─── Enrolement (une seule fois par cible — l agentId est persiste) ──────
	//
	// Fix v12.22.0 (audit finding GO-04, regression v12.21.0) : un
	// log.Fatalf() ici arretait TOUT le processus des qu UNE cible etait
	// injoignable au demarrage — en multi-master, un dashboard LAN eteint
	// empechait alors indefiniment la cible DMZ (parfaitement joignable, sur
	// sa propre goroutine) de jamais recevoir le moindre push : le processus
	// redemarrait en boucle (le superviseur du conteneur le relance), et
	// l enrolement de la cible DMZ n etait jamais retente puisque le
	// processus mourait avant. Desormais : un enrolement rate est retente
	// avec un backoff exponentiel plafonne, uniquement pour CETTE cible ;
	// les autres cibles de main() continuent sans etre affectees.
	if st.AgentID == "" {
		enrollBackoff := time.Second
		const maxEnrollBackoff = time.Minute
		for st.AgentID == "" {
			select {
			case <-ctx.Done():
				return true
			default:
			}
			id, err := enroll(ctx, httpClient, t.DashboardURL, hostname, fingerprint)
			if err != nil {
				log.Printf("%s enrolement impossible, nouvelle tentative dans %s : %v", logPrefix, enrollBackoff, err)
				if once {
					return false
				}
				if !sleepOrDone(ctx, enrollBackoff) {
					return true
				}
				if enrollBackoff < maxEnrollBackoff {
					enrollBackoff *= 2
				}
				continue
			}
			st.AgentID = id
			if err := saveState(t.StateFile, st); err != nil {
				log.Printf("%s attention: impossible de sauvegarder l etat local (%v) — l enrolement sera repete au prochain demarrage", logPrefix, err)
			}
			log.Printf("%s enrole avec l id %s — en attente d approbation par un operateur (page \"Hotes distants\" du dashboard)", logPrefix, id)
		}
	}

	token := resolveToken(t.Token, t.TokenFile, st.Token)

	// Fix v12.22.0 (audit finding GO-07) : le tunnel recevait auparavant la
	// VALEUR du jeton au demarrage (capturee une fois). Apres une rotation de
	// jeton (nouveau fichier --token-file, ou reapprobation), le TUNNEL
	// restait en 401 jusqu au redemarrage complet de l agent, meme si les
	// pushs de manifeste (qui relisent le jeton a chaque cycle, plus bas)
	// utilisaient deja le bon. currentToken() est relue par runTunnel() a
	// CHAQUE tentative de reconnexion.
	var tokenMu sync.Mutex
	currentToken := func() string {
		tokenMu.Lock()
		defer tokenMu.Unlock()
		return token
	}
	setCurrentToken := func(tok string) {
		tokenMu.Lock()
		token = tok
		tokenMu.Unlock()
	}

	// Fix v12.22.0 (audit finding GO-10) : un etat de metriques ("echantillon
	// precedent") propre a CETTE cible — voir metrics_linux.go#MetricsState.
	metricsState := NewMetricsState()

	var tunnelStarted bool
	startTunnelOnce := func() {
		if tunnelStarted || !tunnelEnable {
			return
		}
		tunnelStarted = true
		go runTunnel(ctx, t.DashboardURL, currentToken, t.InsecureSkipVerify, t.Name)
	}

	for {
		select {
		case <-ctx.Done():
			return true
		default:
		}

		tok := resolveToken(t.Token, t.TokenFile, currentToken())
		if tok != currentToken() {
			setCurrentToken(tok)
		}
		if tok == "" {
			log.Printf("%s pas encore de jeton — approuvez l agent %s dans le dashboard puis fournissez le jeton via --token, --token-file (ou le champ \"token\"/\"tokenFile\" de --targets-file), ou en le collant dans %s (\"token\": \"agt_...\")", logPrefix, st.AgentID, t.StateFile)
			if once {
				return false
			}
			if !sleepOrDone(ctx, pollInterval) {
				return true
			}
			continue
		}
		if tok != st.Token {
			st.Token = tok
			_ = saveState(t.StateFile, st)
		}
		startTunnelOnce()

		cycleOK := true
		entries, err := buildVhosts(ctx, dockerCli)
		if err != nil {
			log.Printf("%s lecture des labels Docker impossible : %v", logPrefix, err)
			cycleOK = false
		} else {
			// setLocalRoutes recoit la liste COMPLETE des entrees (vhost +
			// sa liste Publish) — jamais seulement celles publiees vers
			// CETTE cible : voir le commentaire de routeEntry dans
			// tunnel.go (fix GO-06) pour pourquoi le filtrage par cible se
			// fait a la LECTURE de la table (resolveTunnelTarget), pas ici.
			setLocalRoutes(entries)

			// Fix (retour utilisateur) : declaree comme un nil slice, cette
			// variable restait "vhosts": null une fois encodee en JSON des
			// que zero container ne correspondait (aucun label
			// nginx-control.enable=true trouve, ou aucun ne publie vers CETTE
			// cible en multi-master) — Go n encode un slice vide en "[]" QUE
			// s il n est pas nil. Cote dashboard, validateManifest() exige
			// `Array.isArray(body.vhosts)`, qui est false pour null : chaque
			// cycle echouait alors avec "vhosts est requis et doit etre un
			// tableau", en boucle, meme si "zero vhost a publier pour le
			// moment" est un etat parfaitement valide (agent qui vient de
			// demarrer, ou dont tous les containers labellises sont
			// temporairement arretes).
			vhosts := []VhostSpec{}
			for _, e := range entries {
				if publishesTo(e.Publish, t.Name) {
					vhosts = append(vhosts, e.Vhost)
				}
			}
			manifest := Manifest{ProtocolVersion: CurrentProtocolVersion, Vhosts: vhosts, Metrics: collectMetrics(metricsState), Relay: relaySpec}
			rejected, err := pushManifest(ctx, httpClient, t.DashboardURL, tok, logPrefix, manifest)
			if err != nil {
				log.Printf("%s push du manifeste echoue : %v", logPrefix, err)
				cycleOK = false
			}
			// Fix (audit report, Basse/"Agent Go"): only skip updating this
			// target's rejection set when the push never actually reached
			// the dashboard (pushManifest returns nil in that one case —
			// see its own comment) — the PREVIOUS state (from the last push
			// that did complete) stays authoritative rather than being
			// wiped by a request that told us nothing new. Every other
			// outcome (success, partial rejection, whole-manifest failure)
			// replaces it wholesale, even on an empty `vhosts` push (an
			// agent whose containers all stopped correctly clears its own
			// prior rejections along with everything else).
			if err == nil || rejected != nil {
				setRejectionsForTarget(t.Name, rejected)
			}
		}

		if once {
			return cycleOK
		}
		if !sleepOrDone(ctx, pollInterval) {
			return true
		}
	}
}

func sleepOrDone(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// resolveToken applies the priority order documented in --help: an explicit
// --token flag wins, then a --token-file re-read every cycle (so an operator
// can approve, then just drop the token into a file without restarting the
// agent), then whatever was last persisted to --state-file.
func resolveToken(flagToken, tokenFile, fallback string) string {
	if flagToken != "" {
		return flagToken
	}
	if tokenFile != "" {
		if data, err := os.ReadFile(tokenFile); err == nil {
			t := strings.TrimSpace(string(data))
			if t != "" {
				return t
			}
		}
	}
	return fallback
}

func buildVhosts(ctx context.Context, d *dockerClient) ([]vhostEntry, error) {
	containers, err := d.listRunningContainers(ctx)
	if err != nil {
		return nil, err
	}
	var entries []vhostEntry
	for _, c := range containers {
		if v, publish, ok := vhostFromLabels(c.Labels); ok {
			entries = append(entries, vhostEntry{Vhost: *v, Publish: publish})
		}
	}
	return entries, nil
}

// ─── HTTP vers le dashboard (enrolement + push du manifeste) ───────────────

func enroll(ctx context.Context, client *http.Client, dashboardURL, hostname, fingerprint string) (string, error) {
	body, _ := json.Marshal(map[string]string{"hostname": hostname, "fingerprint": fingerprint})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dashboardURL+"/api/agent/enroll", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("%d : %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var out struct {
		AgentID string `json:"agentId"`
		Status  string `json:"status"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("reponse illisible : %w", err)
	}
	return out.AgentID, nil
}

// pushManifest returns the list of server names REJECTED by this push (fix,
// audit report Basse/"Agent Go" — "les routes locales incluent les vhosts
// refuses par le dashboard") alongside the usual error. Callers must feed
// this straight into setRejectionsForTarget() so the local routing table
// (tunnel.go) never keeps serving a vhost the dashboard just turned down —
// see that function's own header comment for the full reasoning, including
// why a whole-manifest failure (testFailed, or any other `out.OK == false`)
// means EVERY vhost in `m` counts as rejected: the dashboard rolled all of
// them back together, not just the one — if any — actually named in
// out.Error.
// logPrefix (fix, audit report Basse/"Agent Go" — "pushManifest journalise
// avec le prefixe [agent] au lieu de celui de la cible") identifies which
// target's push these two log lines are about, in multi-master mode: every
// OTHER log line in this file already uses the caller's own per-target
// prefix ("[agent:dmz]", say — see runTarget()'s logPrefix) instead of the
// generic "[agent]" these two used unconditionally, making a rejected vhost
// or a "manifest applied" line impossible to attribute to the right target
// when several are running in the same process.
func pushManifest(ctx context.Context, client *http.Client, dashboardURL, token, logPrefix string, m Manifest) ([]string, error) {
	allNames := func() []string {
		names := make([]string, 0, len(m.Vhosts))
		for _, v := range m.Vhosts {
			names = append(names, v.ServerName)
		}
		return names
	}

	body, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dashboardURL+"/api/agent/manifest", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		// Push not even delivered: keep the PREVIOUS rejection state as-is
		// (nil here means "don't touch it" — see the caller) rather than
		// guessing either way from a request that never reached the
		// dashboard at all.
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("jeton refuse (401) — a-t-il ete revoque ? reponse : %s", strings.TrimSpace(string(data)))
	}

	var out struct {
		OK     bool `json:"ok"`
		Vhosts []struct {
			ServerName string   `json:"serverName"`
			OK         bool     `json:"ok"`
			Errors     []string `json:"errors"`
		} `json:"vhosts"`
		Error      string `json:"error"`
		TestFailed bool   `json:"testFailed"`
	}
	if json.Unmarshal(data, &out) != nil {
		return nil, fmt.Errorf("reponse illisible (%d) : %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	for _, v := range out.Vhosts {
		if !v.OK {
			log.Printf("%s vhost %q rejete : %s", logPrefix, v.ServerName, strings.Join(v.Errors, "; "))
		}
	}
	if !out.OK {
		if out.TestFailed {
			return allNames(), fmt.Errorf("nginx -t a echoue cote dashboard, manifeste annule : %s", out.Error)
		}
		return allNames(), fmt.Errorf("push refuse : %s", out.Error)
	}
	log.Printf("%s manifeste applique (%d vhost(s) valides sur %d)", logPrefix, countOK(out.Vhosts), len(out.Vhosts))
	var rejected []string
	for _, v := range out.Vhosts {
		if !v.OK {
			rejected = append(rejected, v.ServerName)
		}
	}
	return rejected, nil
}

func countOK(vhosts []struct {
	ServerName string   `json:"serverName"`
	OK         bool     `json:"ok"`
	Errors     []string `json:"errors"`
}) int {
	n := 0
	for _, v := range vhosts {
		if v.OK {
			n++
		}
	}
	return n
}

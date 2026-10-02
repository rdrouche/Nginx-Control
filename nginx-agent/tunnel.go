package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Client-side counterpart of nginx-dashboard/lib/ws-lite.js +
// features/agent-tunnel.js (mode 3, tunnel NAT sortant). Same deliberate
// MVP scope as the server side: single-frame messages only (no
// fragmentation), one JSON control message per WebSocket text frame, whole
// HTTP bodies buffered rather than streamed. See lib/ws-lite.js's own header
// comment for the full rationale — duplicated here in spirit, not in code,
// since this is a different language.

const wsMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xa
)

// Fix v12.22.0 (audit finding GO-05) : ni ping envoye par l agent, ni read
// deadline — une session TCP coupee silencieusement par un NAT/pare-feu
// restait "connectee" indefiniment du point de vue de l agent (readFrame
// bloque pour toujours), pendant que le dashboard affichait l agent en
// ligne alors que tout repondait 502. pingInterval/readDeadline reprennent
// exactement les valeurs documentees par le correctif propose.
const (
	pingInterval = 30 * time.Second
	readDeadline = 2 * pingInterval
)

// wsConn couple la connexion TCP/TLS brute a un mutex d ecriture.
//
// Fix v12.22.0 (audit finding GO-01, reproduit) : avant ce correctif,
// writeFrame() emettait l en-tete de trame et le payload en DEUX appels
// conn.Write() distincts, sans aucune exclusion mutuelle entre elles. Une
// page qui charge une dizaine de ressources en parallele suffisait a
// entrelacer les octets de plusieurs trames sur le meme flux TCP (chaque
// requete tourne dans sa propre goroutine, voir handleTunnelRequest) : le
// parseur cote dashboard (lib/ws-lite.js) recevait alors un flux
// incoherent, fermait le tunnel, et toutes les requetes en cours finissaient
// en 502. Desormais : un seul buffer (en-tete + payload assembles), un seul
// Write(), sous writeMu — TOUTE ecriture sur la connexion (trames de
// donnees, pings/pongs, reponses HTTP) passe par writeFrame(wc, ...).
type wsConn struct {
	conn    net.Conn
	writeMu sync.Mutex
}

// routes couvre les DEUX modes qui font du routage local par Host+path cote
// agent (voir resolveLocalTarget()) : "tunnel" (saut WebSocket via le
// dashboard, pour un agent injoignable en entree) et "relay" (le proxy_pass
// nginx pointe directement sur le port fixe expose par relay.go).
//
// Fix v12.22.0 (audit finding GO-06, consequence du design multi-master
// v12.21.0) : chaque route porte desormais son Mode et la liste Publish du
// conteneur d origine (telle que lue par nginx-control.publish=), pour que
// le mode tunnel puisse etre filtre PAR CIBLE (voir resolveTunnelTarget() et
// hasTunnelVhosts() ci-dessous) — un dashboard DMZ compromis ne peut plus
// faire relayer, via son propre tunnel, une requete vers un vhost publie
// uniquement en LAN. Le mode relay, lui, reste un routage PARTAGE et non
// filtre par cible (resolveLocalTarget()) : c est un unique port physique
// expose par cet agent, la meme limite que le rapport d audit documente
// explicitement plutot que de la "corriger" par un listener par cible (hors
// scope, cf. rapport-bugs-v12.21.0.md, GO-06).
type routeEntry struct {
	Locations []LocationSpec
	Publish   []string
	Mode      string
}

type tunnelRoutes struct {
	mu     sync.RWMutex
	byHost map[string]routeEntry
}

var routes = &tunnelRoutes{byHost: map[string]routeEntry{}}

// Fix (audit report, Basse/"Agent Go"): setLocalRoutes() (below) builds its
// table straight from this agent's OWN Docker labels, entirely independent
// of whether the dashboard actually ACCEPTED each vhost — a manifest push
// can be rejected as a whole (nginx -t failed, rolled back) or per-vhost (a
// server_name conflict, an invalid field), and this agent used to keep
// routing traffic for those exact server names anyway (into a container
// that, from nginx's actual point of view, has no vhost at all). rejections
// is keyed by target name (a vhost can be accepted by one target's
// dashboard and rejected by another's — see targets.go's multi-master
// design) and rebuilt wholesale on every push (see setRejectionsForTarget())
// so a since-fixed vhost stops being excluded on the very next successful
// push, never accumulating stale entries.
var rejectionsMu sync.RWMutex
var rejectionsByTarget = map[string]map[string]bool{}

// setRejectionsForTarget replaces the full rejection set for one target —
// called once per push (success, partial failure, or whole-manifest
// failure alike, see pushManifest()'s own comment for how each maps to a
// server-name list).
func setRejectionsForTarget(targetName string, rejectedServerNames []string) {
	set := make(map[string]bool, len(rejectedServerNames))
	for _, name := range rejectedServerNames {
		set[strings.ToLower(strings.TrimSpace(name))] = true
	}
	rejectionsMu.Lock()
	rejectionsByTarget[targetName] = set
	rejectionsMu.Unlock()
}

// rejectedForTarget : was `host` rejected by THIS target's most recent
// push? Used by resolveTunnelTarget(), already filtered per-target for
// other reasons (fix GO-06) — the natural place to also apply this one.
func rejectedForTarget(host, targetName string) bool {
	rejectionsMu.RLock()
	defer rejectionsMu.RUnlock()
	return rejectionsByTarget[targetName][host]
}

// rejectedByAnyTarget : was `host` rejected by ANY target's most recent
// push? Used by resolveLocalTarget(), which — like relay mode itself (see
// routeEntry's own comment) — is intentionally NOT filtered per target: a
// relay listener is one shared physical port, so a vhost invalid for one
// dashboard is treated as invalid for the shared routing table too, rather
// than silently served to whichever target happened to accept it.
func rejectedByAnyTarget(host string) bool {
	rejectionsMu.RLock()
	defer rejectionsMu.RUnlock()
	for _, set := range rejectionsByTarget {
		if set[host] {
			return true
		}
	}
	return false
}

// setLocalRoutes reconstruit la table de routage locale a partir du dernier
// manifeste construit sur ce Docker local — la liste COMPLETE des
// conteneurs (voir main.go#runTarget : jamais seulement ceux publies vers
// UNE cible, le routage local doit rester capable de servir n importe quelle
// cible qui le demande, seul le FILTRAGE par cible se fait a la lecture, pas
// a l ecriture de cette table).
func setLocalRoutes(entries []vhostEntry) {
	m := map[string]routeEntry{}
	for _, e := range entries {
		v := e.Vhost
		if v.Mode != "tunnel" && v.Mode != "relay" {
			continue
		}
		re := routeEntry{Locations: v.Locations, Publish: e.Publish, Mode: v.Mode}
		for _, name := range strings.Fields(strings.ReplaceAll(v.ServerName, ",", " ")) {
			m[strings.ToLower(name)] = re
		}
	}
	routes.mu.Lock()
	routes.byHost = m
	routes.mu.Unlock()
}

// hasTunnelVhosts : est-ce que la cible nommee targetName a au moins un
// vhost mode=tunnel publie vers elle ? (fix GO-06 : filtre desormais par
// cible, voir routeEntry ci-dessus — auparavant un seul booleen global,
// vrai des qu UNE cible quelconque avait un vhost tunnel, faisait tourner
// runTunnel() pour toutes les cibles sans distinction.)
func hasTunnelVhosts(targetName string) bool {
	routes.mu.RLock()
	defer routes.mu.RUnlock()
	for _, re := range routes.byHost {
		if re.Mode == "tunnel" && publishesTo(re.Publish, targetName) {
			return true
		}
	}
	return false
}

// Fix (audit report, Basse/"Agent Go"): an exact-match location ("= /", the
// only modifier the dashboard's own LOCATION_RE — lib/agent-manifest.js —
// actually accepts alongside a bare prefix) used to be treated as an
// ordinary prefix here, stripped of its "=" and compared with
// strings.HasPrefix() exactly like every other location. nginx's real
// semantics are the opposite: "=" means an EXACT match, resolved before any
// prefix search even starts, and it wins outright when the request path
// matches it exactly — never merely "a slightly better prefix candidate".
// Second half of the same finding: on a tie between two prefix locations of
// the SAME length (a duplicate path in the manifest, or two different
// modifiers on the same literal path), the loop's `>=` meant the LAST one
// in iteration order silently overwrote the first — nginx's own location
// selection is deterministic and never depends on declaration order for a
// tie like this; using `>` instead makes the first one win, matching "the
// earliest, only-if-strictly-better" rule the rest of this function already
// follows for everything else.
func bestLocationMatch(locs []LocationSpec, path string) (string, bool) {
	// Pass 1 : correspondance exacte ("=") — priorite absolue, comme nginx.
	for _, loc := range locs {
		p := strings.TrimSpace(loc.Path)
		if strings.HasPrefix(p, "=") {
			exact := strings.TrimSpace(strings.TrimPrefix(p, "="))
			if exact == path {
				return loc.Target, loc.Target != ""
			}
		}
	}
	// Pass 2 : prefixe le plus long parmi les locations restantes (sans
	// modificateur, ou ~/~*/^~ traites de maniere identique — semantique
	// simplifiee et volontaire, portee MVP documentee dans ce fichier et le
	// README : aucun vrai support des expressions regulieres).
	best := ""
	bestTarget := ""
	for _, loc := range locs {
		p := strings.TrimSpace(loc.Path)
		if strings.HasPrefix(p, "=") {
			continue // deja traite au pass 1, jamais un candidat de prefixe ici
		}
		clean := strings.TrimLeft(p, "~^ ")
		if strings.HasPrefix(path, clean) && len(clean) > len(best) {
			best = clean
			bestTarget = loc.Target
		}
	}
	return bestTarget, bestTarget != ""
}

// resolveLocalTarget : routage NON filtre par cible, utilise par relay.go
// uniquement (mode relay — port physique unique et partage, voir le
// commentaire de routeEntry ci-dessus pour pourquoi ce mode reste hors du
// filtrage GO-06).
func resolveLocalTarget(host, path string) (string, bool) {
	hostLower := strings.ToLower(host)
	routes.mu.RLock()
	re, ok := routes.byHost[hostLower]
	routes.mu.RUnlock()
	if !ok || rejectedByAnyTarget(hostLower) {
		return "", false
	}
	return bestLocationMatch(re.Locations, path)
}

// resolveTunnelTarget : routage FILTRE par cible (fix GO-06), utilise par
// handleTunnelRequest() — seule une route mode=tunnel explicitement publiee
// vers targetName (ou publiee vers "toutes les cibles", cf. publishesTo())
// est resolue ; toute autre route (relay, ou tunnel publiee vers une AUTRE
// cible) est traitee comme absente pour CETTE connexion tunnel.
func resolveTunnelTarget(host, path, targetName string) (string, bool) {
	hostLower := strings.ToLower(host)
	routes.mu.RLock()
	re, ok := routes.byHost[hostLower]
	routes.mu.RUnlock()
	if !ok || re.Mode != "tunnel" || !publishesTo(re.Publish, targetName) || rejectedForTarget(hostLower, targetName) {
		return "", false
	}
	return bestLocationMatch(re.Locations, path)
}

// ─── Handshake ──────────────────────────────────────────────────────────────

func dialTunnel(ctx context.Context, dashboardURL, token string, insecureSkipVerify bool) (*wsConn, *bufio.Reader, error) {
	u, err := url.Parse(dashboardURL)
	if err != nil {
		return nil, nil, fmt.Errorf("URL de dashboard invalide : %w", err)
	}
	// Fix (audit report, Basse/"Agent Go"): u.Host for an IPv6 literal
	// written WITHOUT an explicit port (e.g. "https://[::1]") is exactly
	// "[::1]" — which itself contains colons (the address's own), so the
	// old `!strings.Contains(host, ":")` check to decide "no port yet, add
	// the default" never fired for this case, silently passing a
	// port-less "[::1]" to net.Dial's "tcp" address, which requires
	// "host:port" and rejects it outright. u.Hostname()/u.Port() are the
	// net/url-provided, bracket-aware equivalent of this same decision
	// (Hostname() strips the brackets, Port() is "" when absent regardless
	// of how many colons the address itself contains) — net.JoinHostPort()
	// then re-adds brackets correctly for IPv6, none needed for IPv4/a
	// hostname.
	hostname := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	host := net.JoinHostPort(hostname, port)

	var conn net.Conn
	// Fix v12.22.0 (audit finding GO-05, partie deadline) : une deadline de
	// connexion couvre desormais aussi le handshake TCP/TLS lui-meme, pas
	// seulement la lecture des trames une fois connecte (voir plus bas dans
	// runTunnel) — un dial qui reste bloque (reseau filtrant qui droppe sans
	// RST) ne doit pas non plus geler cette goroutine indefiniment.
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if u.Scheme == "https" {
		conn, err = tls.DialWithDialer(dialer, "tcp", host, &tls.Config{InsecureSkipVerify: insecureSkipVerify, ServerName: hostname})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", host)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("connexion au dashboard impossible : %w", err)
	}
	// TCP keepalive sur le dialer sous-jacent (fix GO-05) : pertinent
	// seulement pour le cas non-TLS (net.Dialer.DialContext renvoie deja un
	// *net.TCPConn), le cas TLS est enveloppe par *tls.Conn mais reste
	// construit sur le meme dialer — le SO_KEEPALIVE du systeme s applique
	// aux deux, avec l intervalle par defaut de l OS ; le ping applicatif
	// ci-dessous (pingInterval) est la protection principale, independante
	// de l OS.
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	keyBytes := make([]byte, 16)
	_, _ = rand.Read(keyBytes)
	key := base64.StdEncoding.EncodeToString(keyBytes)

	req := "GET /api/agent/tunnel HTTP/1.1\r\n" +
		"Host: " + u.Host + "\r\n" +
		"User-Agent: " + userAgent + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Authorization: Bearer " + token + "\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, nil, err
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	if !strings.Contains(statusLine, "101") {
		// Consomme le reste des en-tetes pour un message d erreur lisible.
		var body strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil || strings.TrimSpace(line) == "" {
				break
			}
			body.WriteString(line)
		}
		conn.Close()
		return nil, nil, fmt.Errorf("handshake refuse : %s", strings.TrimSpace(statusLine))
	}
	acceptHeader := ""
	for {
		line, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
			break
		}
		if h := strings.SplitN(line, ":", 2); len(h) == 2 && strings.EqualFold(strings.TrimSpace(h[0]), "Sec-WebSocket-Accept") {
			acceptHeader = strings.TrimSpace(h[1])
		}
	}
	// Fix v12.22.0 (basse, section 5 du rapport) : Sec-WebSocket-Accept
	// n etait auparavant jamais verifie. Ca reste defensif (dashboard et
	// agent viennent du meme projet, cote serveur lib/ws-lite.js applique
	// deja la RFC), mais un serveur qui repond 101 sans le bon accept n est
	// justement PAS ce dashboard-la (proxy mal configure, MITM) : autant
	// echouer proprement plutot que de continuer a l aveugle.
	if acceptHeader != "" && acceptHeader != wsAcceptKey(key) {
		conn.Close()
		return nil, nil, fmt.Errorf("Sec-WebSocket-Accept invalide (attendu different de la reponse) — handshake abandonne")
	}
	_ = conn.SetDeadline(time.Time{}) // le handshake est termine, readDeadline prend le relais dans runTunnel
	return &wsConn{conn: conn}, reader, nil
}

// ─── Frames ─────────────────────────────────────────────────────────────────

// writeFrame writes one MASKED client->server frame (mandatory per RFC 6455
// for the client direction — lib/ws-lite.js's FrameParser rejects an
// unmasked client frame outright). Fix v12.22.0 (GO-01): header and payload
// are assembled into ONE buffer and sent with a SINGLE Write(), under wc's
// write mutex — see wsConn's own header comment.
func writeFrame(wc *wsConn, opcode byte, payload []byte) error {
	maskKey := make([]byte, 4)
	_, _ = rand.Read(maskKey)
	masked := make([]byte, len(payload))
	for i, b := range payload {
		masked[i] = b ^ maskKey[i%4]
	}

	var frame bytes.Buffer
	frame.WriteByte(0x80 | opcode)
	n := len(payload)
	switch {
	case n < 126:
		frame.WriteByte(0x80 | byte(n))
	case n < 65536:
		frame.WriteByte(0x80 | 126)
		_ = binary.Write(&frame, binary.BigEndian, uint16(n))
	default:
		frame.WriteByte(0x80 | 127)
		_ = binary.Write(&frame, binary.BigEndian, uint64(n))
	}
	frame.Write(maskKey)
	frame.Write(masked)

	wc.writeMu.Lock()
	defer wc.writeMu.Unlock()
	_, err := wc.conn.Write(frame.Bytes())
	return err
}

// readFrame reads one server->client frame. Per RFC 6455 the server never
// masks, but this reader tolerates a masked frame too (defensive, costs
// nothing) rather than assuming a well-behaved peer.
func readFrame(r *bufio.Reader) (opcode byte, payload []byte, err error) {
	head := make([]byte, 2)
	if _, err = io.ReadFull(r, head); err != nil {
		return
	}
	fin := head[0]&0x80 != 0
	opcode = head[0] & 0x0f
	masked := head[1]&0x80 != 0
	length := uint64(head[1] & 0x7f)
	if !fin {
		return 0, nil, fmt.Errorf("trame fragmentee non supportee (FIN=0)")
	}
	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err = io.ReadFull(r, ext); err != nil {
			return
		}
		length = uint64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err = io.ReadFull(r, ext); err != nil {
			return
		}
		length = binary.BigEndian.Uint64(ext)
	}
	const maxFrame = 8 * 1024 * 1024
	if length > maxFrame {
		return 0, nil, fmt.Errorf("trame trop volumineuse (%d octets)", length)
	}
	var maskKey []byte
	if masked {
		maskKey = make([]byte, 4)
		if _, err = io.ReadFull(r, maskKey); err != nil {
			return
		}
	}
	payload = make([]byte, length)
	if _, err = io.ReadFull(r, payload); err != nil {
		return
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	return opcode, payload, nil
}

// ─── Protocole applicatif (voir features/agent-tunnel.js) ─────────────────

type tunnelHTTPRequest struct {
	Type       string            `json:"type"`
	ID         string            `json:"id"`
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	Headers    map[string]string `json:"headers"`
	BodyBase64 string            `json:"bodyBase64"`
}

// tunnelHTTPResponse.Headers est desormais map[string][]string (fix GO-03) :
// voir handleTunnelRequest() pour le pourquoi. features/agent-tunnel.js cote
// dashboard passe deja ces valeurs telles quelles a res.writeHead(), qui
// accepte nativement un tableau par en-tete (aucun changement necessaire de
// ce cote-la).
type tunnelHTTPResponse struct {
	Type       string              `json:"type"`
	ID         string              `json:"id"`
	Status     int                 `json:"status"`
	Headers    map[string][]string `json:"headers"`
	BodyBase64 string              `json:"bodyBase64"`
}

type tunnelHTTPError struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Message string `json:"message"`
}

// Fix v12.22.0 (audit finding GO-02) : http.Client sans CheckRedirect suit
// lui-meme les redirections du backend local. Un `POST /login` qui renvoie
// 302 + Set-Cookie se voyait alors suivi par l agent, qui ne renvoyait au
// navigateur que la reponse FINALE (200) — la redirection elle-meme (et
// l URL qu elle porte) n atteignait jamais le client. Pire : si cette
// redirection pointe vers une URL absolue PUBLIQUE, c est l agent lui-meme
// qui irait la chercher. http.ErrUseLastResponse fait strictement ce qu un
// vrai reverse proxy fait : renvoyer la reponse de redirection telle quelle,
// au navigateur de decider.
var localHTTPClient = &http.Client{
	Timeout:       25 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
}

// Fix v12.22.0 (audit finding GO-12) : le corps de reponse etait tronque a
// maxTunnelResponseBody sans jamais le signaler, alors que le Content-Length
// D ORIGINE (non corrige) restait dans les en-tetes transmis au navigateur —
// soit une attente indefinie (le navigateur attend des octets qui ne
// viendront jamais), soit un fichier corrompu silencieusement. On lit
// desormais UN OCTET DE PLUS que la limite : s il est present, la reponse
// est refusee explicitement (http-error / 502 cote dashboard) plutot que
// livree tronquee.
const maxTunnelResponseBody = 5 * 1024 * 1024

func handleTunnelRequest(wc *wsConn, msg tunnelHTTPRequest, targetName string) {
	host := msg.Headers["host"]
	// Fix v12.22.0 (audit finding GO-06) : resolveTunnelTarget() (et non plus
	// resolveLocalTarget()) filtre desormais par la cible a laquelle CETTE
	// connexion tunnel appartient — voir son propre commentaire plus haut.
	target, ok := resolveTunnelTarget(host, msg.Path, targetName)
	if !ok {
		_ = writeJSONFrame(wc, tunnelHTTPError{Type: "http-error", ID: msg.ID,
			Message: fmt.Sprintf("aucune location locale ne correspond a %s%s", host, msg.Path)})
		return
	}

	var body io.Reader
	if msg.BodyBase64 != "" {
		raw, err := base64.StdEncoding.DecodeString(msg.BodyBase64)
		if err == nil {
			body = bytes.NewReader(raw)
		}
	}
	targetURL := strings.TrimRight(target, "/") + msg.Path
	httpReq, err := http.NewRequest(msg.Method, targetURL, body)
	if err != nil {
		_ = writeJSONFrame(wc, tunnelHTTPError{Type: "http-error", ID: msg.ID, Message: err.Error()})
		return
	}
	for k, v := range msg.Headers {
		if strings.EqualFold(k, "host") {
			continue
		}
		httpReq.Header.Set(k, v)
	}

	resp, err := localHTTPClient.Do(httpReq)
	if err != nil {
		_ = writeJSONFrame(wc, tunnelHTTPError{Type: "http-error", ID: msg.ID,
			Message: fmt.Sprintf("cible locale injoignable (%s) : %v", target, err)})
		return
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxTunnelResponseBody+1))
	if err == nil && len(respBody) > maxTunnelResponseBody {
		_ = writeJSONFrame(wc, tunnelHTTPError{Type: "http-error", ID: msg.ID,
			Message: fmt.Sprintf("reponse locale trop volumineuse (> %d octets), refusee plutot que tronquee", maxTunnelResponseBody)})
		return
	}

	// Fix v12.22.0 (audit finding GO-03) : resp.Header.Get(k) ne gardait que
	// la PREMIERE valeur de chaque en-tete — un backend qui envoie deux
	// Set-Cookie (session + preference, par exemple) n en laissait passer
	// qu un seul, cassant l authentification ou la session cote navigateur.
	// map[string][]string preserve les deux.
	headers := map[string][]string{}
	for k, vs := range resp.Header {
		headers[k] = append([]string(nil), vs...)
	}
	_ = writeJSONFrame(wc, tunnelHTTPResponse{
		Type: "http-response", ID: msg.ID, Status: resp.StatusCode,
		Headers: headers, BodyBase64: base64.StdEncoding.EncodeToString(respBody),
	})
}

func writeJSONFrame(wc *wsConn, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writeFrame(wc, opText, data)
}

// runTunnel maintains one long-lived tunnel connection for ONE target,
// reconnecting with a capped exponential backoff on any disconnect — never
// gives up permanently, since an agent behind NAT has no other way back in.
// Blocks until ctx is cancelled.
//
// tokenFunc (fix GO-07) is called fresh on every dial attempt, rather than
// capturing a single token value for the whole function's lifetime : after a
// token rotation (approve -> revoke -> re-approve, or --token-file updated),
// the very next reconnect now authenticates with the CURRENT token instead
// of being stuck in a 401 loop with the token that was current when
// runTunnel first started, until the whole agent process was restarted.
//
// targetName (fix GO-06) identifies which target's routes this connection
// may serve — see hasTunnelVhosts()/resolveTunnelTarget().
func runTunnel(ctx context.Context, dashboardURL string, tokenFunc func() string, insecureSkipVerify bool, targetName string) {
	backoff := time.Second
	const maxBackoff = 30 * time.Second
	// See the "connection only counts as stable" comment further down.
	const minStableConnection = 10 * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if !hasTunnelVhosts(targetName) {
			// Rien a publier en mode tunnel pour l instant (aucun vhost du
			// manifeste courant, publie vers CETTE cible, n a mode=tunnel) —
			// pas la peine d ouvrir de connexion. Reevalue periodiquement :
			// un manifeste ulterieur peut tres bien ajouter un vhost tunnel
			// en cours de route.
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}

		wc, reader, err := dialTunnel(ctx, dashboardURL, tokenFunc(), insecureSkipVerify)
		if err != nil {
			log.Printf("[tunnel] connexion echouee, nouvelle tentative dans %s : %v", backoff, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < maxBackoff {
				backoff *= 2
			}
			continue
		}
		log.Printf("[tunnel] connecte")
		connectedAt := time.Now()

		func() {
			defer wc.conn.Close()

			// Fix v12.22.0 (audit finding GO-05) : ping applicatif toutes les
			// pingInterval, et une read deadline (renouvelee a chaque trame
			// recue, y compris les pongs) de 2x cet intervalle — une session
			// coupee par un NAT/pare-feu sans RST fait desormais echouer
			// readFrame au bout de readDeadline au lieu de bloquer pour
			// toujours.
			pingCtx, stopPing := context.WithCancel(ctx)
			defer stopPing()
			go func() {
				ticker := time.NewTicker(pingInterval)
				defer ticker.Stop()
				for {
					select {
					case <-pingCtx.Done():
						return
					case <-ticker.C:
						if err := writeFrame(wc, opPing, nil); err != nil {
							return
						}
					}
				}
			}()

			for {
				_ = wc.conn.SetReadDeadline(time.Now().Add(readDeadline))
				opcode, payload, err := readFrame(reader)
				if err != nil {
					log.Printf("[tunnel] connexion perdue : %v", err)
					return
				}
				switch opcode {
				case opClose:
					return
				case opPing:
					_ = writeFrame(wc, opPong, payload)
				case opPong:
					// rien a faire — juste garder la connexion vivante et
					// reculer la read deadline (deja fait ci-dessus).
				case opText:
					var msg tunnelHTTPRequest
					if json.Unmarshal(payload, &msg) == nil && msg.Type == "http-request" {
						go handleTunnelRequest(wc, msg, targetName)
					}
				}
			}
		}()

		// Fix (audit report, Basse/"Agent Go"): backoff used to be reset to
		// its 1s floor unconditionally right after a successful connect
		// (before this fix), with no regard for how long that connection
		// actually lasted. The dashboard itself replaces an agent's tunnel
		// connection the instant a NEW one authenticates with the same
		// token (see features/agent-tunnel.js#handleUpgrade, "Une
		// reconnexion du meme agent remplace proprement la precedente") —
		// two agent PROCESSES sharing one token (a misconfiguration, or a
		// leaked/duplicated token file) would each keep kicking the other
		// off and instantly reconnecting at the reset 1s floor, a tight
		// loop hammering the dashboard with reconnects. A connection only
		// "counts" as stable, resetting backoff to the 1s floor, once it
		// has stayed up for at least minStableConnection; anything shorter
		// keeps escalating backoff exactly like a failed dial would.
		if time.Since(connectedAt) >= minStableConnection {
			backoff = time.Second
			select {
			case <-ctx.Done():
				return
			default:
			}
		} else {
			if backoff < maxBackoff {
				backoff *= 2
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
		}
	}
}

// wsAcceptKey computes the RFC 6455 Sec-WebSocket-Accept value for a given
// client key — used both to build the request's own expectations
// (dialTunnel's defensive verification, see its header comment) and kept
// here for documentation/tests parity with lib/ws-lite.js's acceptKeyFor().
func wsAcceptKey(key string) string {
	h := sha1.Sum([]byte(key + wsMagic))
	return base64.StdEncoding.EncodeToString(h[:])
}

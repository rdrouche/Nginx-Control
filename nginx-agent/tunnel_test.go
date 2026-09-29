package main

import (
	"bufio"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// readOneClientFrame decodes one frame written by writeFrame() (always
// MASKED, client->server direction) from the other end of a net.Pipe —
// readFrame() already tolerates a masked frame defensively (see its own
// header comment), so it doubles as the test decoder here.
func readOneClientFrame(t *testing.T, conn net.Conn) (byte, []byte) {
	t.Helper()
	opcode, payload, err := readFrame(bufio.NewReader(conn))
	if err != nil {
		t.Fatalf("decodage de la trame : %v", err)
	}
	return opcode, payload
}

// Fix v12.22.0 (audit finding GO-01, reproduit) : writeFrame() doit produire
// UN SEUL appel Write() sur la connexion (en-tete + payload assembles dans
// un seul buffer), jamais deux appels distincts — c'est precisement ce qui
// permettait a deux frames ecrites par deux goroutines concurrentes de voir
// leurs octets entrelaces sur le flux TCP.
type countingConn struct {
	net.Conn
	mu     sync.Mutex
	writes int
}

func (c *countingConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.writes++
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func TestWriteFrame_SingleWriteCall(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	cc := &countingConn{Conn: client}
	wc := &wsConn{conn: cc}

	done := make(chan struct{})
	go func() {
		_ = writeFrame(wc, opText, []byte("hello"))
		close(done)
	}()

	opcode, payload := readOneClientFrame(t, server)
	<-done
	if opcode != opText || string(payload) != "hello" {
		t.Fatalf("trame decodee incorrecte : opcode=%d payload=%q", opcode, payload)
	}
	if cc.writes != 1 {
		t.Fatalf("writeFrame doit faire EXACTEMENT un appel Write() (en-tete+payload assembles), obtenu %d", cc.writes)
	}
}

// Fix v12.22.0 (audit finding GO-01) : plusieurs goroutines qui ecrivent des
// frames CONCURREMMENT sur la meme wsConn ne doivent jamais produire un flux
// corrompu — chaque frame lue de l autre cote doit correspondre exactement a
// l un des payloads envoyes, sans melange d octets entre deux d entre elles.
func TestWriteFrame_ConcurrentWritesDoNotInterleave(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	wc := &wsConn{conn: client}

	const n = 50
	payloads := make([][]byte, n)
	for i := range payloads {
		// Des tailles variees (dont certaines > 125 et > 65535 octets rares
		// en pratique mais on reste raisonnable ici) pour exercer les trois
		// branches de longueur de writeFrame.
		size := 10 + i*37
		p := make([]byte, size)
		for j := range p {
			p[j] = byte((i + j) % 256)
		}
		payloads[i] = p
	}

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(p []byte) {
			defer wg.Done()
			_ = writeFrame(wc, opText, p)
		}(payloads[i])
	}
	go func() { wg.Wait() }()

	received := make(map[int]bool, n)
	reader := bufio.NewReader(server)
	for i := 0; i < n; i++ {
		_, payload, err := readFrame(reader)
		if err != nil {
			t.Fatalf("lecture de la trame #%d : %v (flux probablement corrompu/entrelace)", i, err)
		}
		found := -1
		for idx, want := range payloads {
			if received[idx] {
				continue
			}
			if len(want) == len(payload) && string(want) == string(payload) {
				found = idx
				break
			}
		}
		if found == -1 {
			t.Fatalf("trame #%d (%d octets) ne correspond a AUCUN payload attendu non encore recu — flux corrompu", i, len(payload))
		}
		received[found] = true
	}
	if len(received) != n {
		t.Fatalf("attendu %d trames distinctes recues, obtenu %d", n, len(received))
	}
}

// setSingleTunnelRoute is a small test helper: registers one tunnel route
// (published to every target, i.e. Publish == nil) pointing at target.
func setSingleTunnelRoute(host, target string) {
	setLocalRoutes([]vhostEntry{{
		Vhost: VhostSpec{
			ServerName: host, Mode: "tunnel",
			Locations: []LocationSpec{{Path: "/", Target: target}},
		},
	}})
}

// Fix v12.22.0 (audit finding GO-02) : un backend local qui repond par une
// redirection (302 + Set-Cookie, typique d'un POST /login) doit voir cette
// redirection transmise TELLE QUELLE au dashboard (puis au navigateur) — pas
// suivie silencieusement par l'agent lui-meme.
func TestHandleTunnelRequest_DoesNotFollowRedirects(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=abc123; HttpOnly")
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	}))
	defer backend.Close()
	setSingleTunnelRoute("redir.example.com", backend.URL)
	t.Cleanup(func() { setLocalRoutes(nil) })

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	wc := &wsConn{conn: client}

	go handleTunnelRequest(wc, tunnelHTTPRequest{
		ID: "r1", Method: "POST", Path: "/login",
		Headers: map[string]string{"host": "redir.example.com"},
	}, "")

	_, payload := readOneClientFrame(t, server)
	var resp tunnelHTTPResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		t.Fatalf("reponse illisible : %v (%s)", err, payload)
	}
	if resp.Type != "http-response" {
		t.Fatalf("attendu http-response, obtenu %q (la redirection a-t-elle ete suivie et transformee en erreur ?)", resp.Type)
	}
	if resp.Status != http.StatusFound {
		t.Fatalf("attendu 302 transmis tel quel (jamais suivi par l'agent), obtenu %d", resp.Status)
	}
	if loc := resp.Headers["Location"]; len(loc) != 1 || loc[0] != "/dashboard" {
		t.Fatalf("en-tete Location manquant ou incorrect : %v", resp.Headers["Location"])
	}
}

// Fix v12.22.0 (audit finding GO-03) : plusieurs Set-Cookie du backend
// doivent TOUS atteindre le dashboard (map[string][]string), pas seulement
// le premier (l'ancien map[string]string ne gardait que resp.Header.Get(k)).
func TestHandleTunnelRequest_PreservesMultipleSetCookie(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		w.WriteHeader(200)
	}))
	defer backend.Close()
	setSingleTunnelRoute("cookies.example.com", backend.URL)
	t.Cleanup(func() { setLocalRoutes(nil) })

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	wc := &wsConn{conn: client}

	go handleTunnelRequest(wc, tunnelHTTPRequest{
		ID: "r2", Method: "GET", Path: "/",
		Headers: map[string]string{"host": "cookies.example.com"},
	}, "")

	_, payload := readOneClientFrame(t, server)
	var resp tunnelHTTPResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		t.Fatalf("reponse illisible : %v", err)
	}
	cookies := resp.Headers["Set-Cookie"]
	if len(cookies) != 2 {
		t.Fatalf("attendu 2 Set-Cookie preserves, obtenu %d : %v", len(cookies), cookies)
	}
}

// Fix v12.22.0 (audit finding GO-12) : une reponse locale au-dela de
// maxTunnelResponseBody doit etre REFUSEE explicitement (http-error), jamais
// tronquee silencieusement avec un Content-Length d'origine trompeur.
func TestHandleTunnelRequest_OversizedBodyRejectedNotTruncated(t *testing.T) {
	oversized := make([]byte, maxTunnelResponseBody+1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(oversized)
	}))
	defer backend.Close()
	setSingleTunnelRoute("big.example.com", backend.URL)
	t.Cleanup(func() { setLocalRoutes(nil) })

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	wc := &wsConn{conn: client}

	go handleTunnelRequest(wc, tunnelHTTPRequest{
		ID: "r3", Method: "GET", Path: "/",
		Headers: map[string]string{"host": "big.example.com"},
	}, "")

	_, payload := readOneClientFrame(t, server)
	var errMsg tunnelHTTPError
	if err := json.Unmarshal(payload, &errMsg); err != nil {
		t.Fatalf("message illisible : %v", err)
	}
	if errMsg.Type != "http-error" {
		t.Fatalf("attendu un http-error explicite pour une reponse surdimensionnee, obtenu type=%q (reponse tronquee silencieusement ?)", errMsg.Type)
	}
}

// Fix v12.22.0 (audit finding GO-06) : handleTunnelRequest() doit refuser de
// router une requete pour un vhost non publie vers la cible passee — voir
// aussi TestSetLocalRoutes_TunnelIsolatedPerTarget dans labels_test.go pour
// la couverture de resolveTunnelTarget()/hasTunnelVhosts() elles-memes ; ce
// test verifie le comportement de bout en bout au niveau du handler.
func TestHandleTunnelRequest_RefusesVhostNotPublishedToThisTarget(t *testing.T) {
	setLocalRoutes([]vhostEntry{{
		Vhost:   VhostSpec{ServerName: "dmz-only.example.com", Mode: "tunnel", Locations: []LocationSpec{{Path: "/", Target: "http://127.0.0.1:1"}}},
		Publish: []string{"dmz"},
	}})
	t.Cleanup(func() { setLocalRoutes(nil) })

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	wc := &wsConn{conn: client}

	go handleTunnelRequest(wc, tunnelHTTPRequest{
		ID: "r4", Method: "GET", Path: "/",
		Headers: map[string]string{"host": "dmz-only.example.com"},
	}, "lan") // cette connexion tunnel appartient a la cible "lan", pas "dmz"

	_, payload := readOneClientFrame(t, server)
	var errMsg tunnelHTTPError
	if err := json.Unmarshal(payload, &errMsg); err != nil {
		t.Fatalf("message illisible : %v", err)
	}
	if errMsg.Type != "http-error" {
		t.Fatalf("attendu un refus (http-error) : la route n est publiee que vers dmz, pas vers lan")
	}
}

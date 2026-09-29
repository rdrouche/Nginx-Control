package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// End-to-end smoke test of the relay mode's actual network path: a fake
// local backend, the relay's HTTP and HTTPS listeners, and a real client
// request through each — closest thing to the manual E2E verification done
// for tunnel mode (v12.19.0), but automated since it needs no external
// dashboard/agent enrollment round-trip (relay traffic never goes through
// the dashboard at all — that is the whole point of the mode).
func TestRelay_HTTPAndHTTPS_RouteToLocalBackend(t *testing.T) {
	setLocalRoutes(vhostsAsEntries([]VhostSpec{
		{ServerName: "relay-test.example.com", Mode: "relay", Locations: []LocationSpec{
			{Path: "/", Target: "http://127.0.0.1:19281"},
		}},
	}, nil))
	t.Cleanup(func() { setLocalRoutes(nil) })

	backend := &http.Server{Addr: "127.0.0.1:19281", Handler: http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("hello-from-backend")) })}
	go backend.ListenAndServe()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = backend.Shutdown(ctx)
	})
	waitListening(t, "127.0.0.1:19281")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	startRelay(ctx, "127.0.0.1:19282", "127.0.0.1:19283", "", "", false)
	waitListening(t, "127.0.0.1:19282")
	waitListening(t, "127.0.0.1:19283")

	// HTTP hop
	req, _ := http.NewRequest("GET", "http://127.0.0.1:19282/", nil)
	req.Host = "relay-test.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("requete HTTP via le relais : %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "hello-from-backend" {
		t.Fatalf("reponse inattendue : %d %q", resp.StatusCode, body)
	}

	// HTTPS hop — certificat auto-signe genere en memoire, verification
	// desactivee cote client de test exactement comme nginx le fera via
	// `proxy_ssl_verify off;` (voir generateAgentVhostContent()).
	httpsClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	reqs, _ := http.NewRequest("GET", "https://127.0.0.1:19283/", nil)
	reqs.Host = "relay-test.example.com"
	resps, err := httpsClient.Do(reqs)
	if err != nil {
		t.Fatalf("requete HTTPS via le relais : %v", err)
	}
	bodys, _ := io.ReadAll(resps.Body)
	resps.Body.Close()
	if resps.StatusCode != 200 || string(bodys) != "hello-from-backend" {
		t.Fatalf("reponse HTTPS inattendue : %d %q", resps.StatusCode, bodys)
	}
}

func TestRelay_UnknownHost_502(t *testing.T) {
	setLocalRoutes(nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	startRelay(ctx, "127.0.0.1:19284", "", "", "", false)
	waitListening(t, "127.0.0.1:19284")

	req, _ := http.NewRequest("GET", "http://127.0.0.1:19284/", nil)
	req.Host = "personne-ne-me-connait.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("requete : %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("attendu 502 pour un hote inconnu du relais, obtenu %d", resp.StatusCode)
	}
}

// Chaine de schemas "HTTPS (frontal) -> HTTP (relais agent) -> HTTPS
// (backend Docker, certificat auto-signe)" — exactement le cas souleve pour
// confirmer que le relais ne suppose jamais que son propre schema d'ecoute
// et celui du backend local se correspondent. httptest.NewTLSServer() sert
// un certificat auto-signe, comme le ferait un vrai service Docker interne
// qui ne passe pas par une CA connue.
func TestRelay_HTTPSBackend_InsecureSkipVerify(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("hello-from-https-backend")) }))
	t.Cleanup(backend.Close)

	setLocalRoutes(vhostsAsEntries([]VhostSpec{
		{ServerName: "relay-https-backend.example.com", Mode: "relay", Locations: []LocationSpec{
			{Path: "/", Target: backend.URL}, // backend.URL est deja "https://127.0.0.1:PORT"
		}},
	}, nil))
	t.Cleanup(func() { setLocalRoutes(nil) })

	t.Run("sans le flag -> certificat auto-signe rejete (502)", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		startRelay(ctx, "127.0.0.1:19285", "", "", "", false)
		waitListening(t, "127.0.0.1:19285")

		req, _ := http.NewRequest("GET", "http://127.0.0.1:19285/", nil)
		req.Host = "relay-https-backend.example.com"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("requete : %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("attendu 502 (certificat backend auto-signe non verifiable), obtenu %d", resp.StatusCode)
		}
	})

	t.Run("avec le flag -> certificat auto-signe accepte, reponse relayee", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		startRelay(ctx, "127.0.0.1:19286", "", "", "", true)
		waitListening(t, "127.0.0.1:19286")

		req, _ := http.NewRequest("GET", "http://127.0.0.1:19286/", nil)
		req.Host = "relay-https-backend.example.com"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("requete : %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 || string(body) != "hello-from-https-backend" {
			t.Fatalf("reponse inattendue : %d %q", resp.StatusCode, body)
		}
	})
}

func waitListening(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("rien n ecoute sur %s apres le delai d attente", addr)
}

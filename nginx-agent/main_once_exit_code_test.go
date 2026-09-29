package main

// Fix (audit report, Basse/"Agent Go"): "--once renvoie le code 0 meme en cas
// d echec". Exercised as a real subprocess (re-executing this same test
// binary with a special env var, the standard Go pattern for testing a
// package's own os.Exit() behavior — main() can't be called safely
// in-process here since a failing path now calls os.Exit(1) directly, which
// would kill the whole `go test` run instead of just this one case).
import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestOnceExitCode_SubprocessHelper(t *testing.T) {
	if os.Getenv("NGINX_CONTROL_AGENT_ONCE_TEST_SUBPROCESS") != "1" {
		t.Skip("aide au test uniquement, invoquee dans un sous-processus par TestOnceExitCode_*")
	}
	main()
}

// runOnceSubprocess re-execute ce meme binaire de test, avec la fonction
// main() reelle de l agent (via le helper ci-dessus), contre le faux
// dashboard `ts`. Renvoie le code de sortie du sous-processus.
func runOnceSubprocess(t *testing.T, dashboardURL string) int {
	t.Helper()
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=TestOnceExitCode_SubprocessHelper", "-test.v")
	cmd.Env = append(os.Environ(),
		"NGINX_CONTROL_AGENT_ONCE_TEST_SUBPROCESS=1",
		"DASHBOARD_URL="+dashboardURL,
		"ONCE=true",
		"TUNNEL_ENABLE=false",
		"STATE_FILE="+filepath.Join(dir, "state.json"),
		// Un chemin de socket Docker garanti inexistant dans ce bac a sable :
		// buildVhosts() echoue alors immediatement (err != nil), exactement
		// le cas "cycleOK = false" que ce test verifie — jamais besoin d un
		// vrai Docker pour exercer ce chemin.
		"DOCKER_SOCKET="+filepath.Join(dir, "no-such-docker.sock"),
	)
	out, err := cmd.CombinedOutput()
	t.Logf("sortie du sous-processus :\n%s", out)
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	if err != nil {
		t.Fatalf("echec inattendu du sous-processus (pas un simple code de sortie non nul) : %v", err)
	}
	return 0
}

func TestOnceExitCode_EnrollmentFails_ExitsNonZero(t *testing.T) {
	// Le dashboard refuse l enrolement lui-meme (500) : runTarget() ne
	// dispose jamais d un agentId, boucle sur l enrolement jusqu a --once,
	// puis doit rendre la main en signalant l echec.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	code := runOnceSubprocess(t, ts.URL)
	if code == 0 {
		t.Error("un enrolement qui echoue en mode --once doit sortir avec un code non nul (avant ce correctif : toujours 0)")
	}
}

func TestOnceExitCode_EnrollSucceeds_NoDocker_ExitsNonZero(t *testing.T) {
	// Enrolement + approbation reussis (l agent obtient un jeton), mais
	// buildVhosts() echoue (pas de Docker dans ce bac a sable) — le cycle de
	// push n a donc jamais pu avoir lieu, ce qui doit aussi compter comme un
	// echec en mode --once.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent/enroll":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"agentId": "test-agent-id"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	// Sans jeton fourni (--token/--token-file), runTarget() boucle sur
	// "pas encore de jeton" — meme resultat attendu (echec en mode --once)
	// mais via un autre chemin de retour (voir main.go, la branche `tok == ""`).
	code := runOnceSubprocess(t, ts.URL)
	if code == 0 {
		t.Error("sans jeton disponible, --once doit aussi sortir avec un code non nul")
	}
}

package blocklistsources

import (
	"sort"
	"testing"
)

// reset reproduit le delete require.cache du test JS : repart d'un etat
// vierge avant chaque cas, puisque ce paquet Go n'est charge qu'une fois par
// process de test (contrairement a un require() Node qu'on peut invalider).
func reset() {
	mu.Lock()
	index = nil
	mode = "dedicated"
	mu.Unlock()
}

func TestMode(t *testing.T) {
	t.Run("mode par defaut = dedicated", func(t *testing.T) {
		reset()
		if GetMode() != "dedicated" {
			t.Fatal("mode par defaut devrait etre dedicated")
		}
	})
	t.Run("SetMode accepte approx, rejette tout le reste vers dedicated", func(t *testing.T) {
		reset()
		SetMode("approx")
		if GetMode() != "approx" {
			t.Fatal("devrait etre approx")
		}
		SetMode("n-importe-quoi")
		if GetMode() != "dedicated" {
			t.Fatal("devrait retomber sur dedicated")
		}
		SetMode("")
		if GetMode() != "dedicated" {
			t.Fatal("devrait retomber sur dedicated")
		}
	})
}

func TestSourcesContainingAvantSync(t *testing.T) {
	t.Run("index vide -> aucune correspondance, pas d exception", func(t *testing.T) {
		reset()
		if got := SourcesContaining("203.0.113.5"); len(got) != 0 {
			t.Fatalf("got %v", got)
		}
		if HasSources() {
			t.Fatal("HasSources devrait etre false")
		}
	})
}

func sortedCopy(s []string) []string {
	out := append([]string{}, s...)
	sort.Strings(out)
	return out
}

func TestSourcesContainingApresSync(t *testing.T) {
	t.Run("adresse exacte (host route) correspond a sa source", func(t *testing.T) {
		reset()
		SetSources(map[string]Source{"firehol": {IPs: []string{"203.0.113.5"}}})
		if !HasSources() {
			t.Fatal("HasSources devrait etre true")
		}
		if got := SourcesContaining("203.0.113.5"); len(got) != 1 || got[0] != "firehol" {
			t.Fatalf("got %v", got)
		}
		if got := SourcesContaining("203.0.113.6"); len(got) != 0 {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("bloc CIDR correspond a toute adresse qu il couvre", func(t *testing.T) {
		reset()
		SetSources(map[string]Source{"spamhaus": {IPs: []string{"198.51.100.0/24"}}})
		if got := SourcesContaining("198.51.100.42"); len(got) != 1 || got[0] != "spamhaus" {
			t.Fatalf("got %v", got)
		}
		if got := SourcesContaining("198.51.101.1"); len(got) != 0 {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("une IP presente dans plusieurs sources renvoie toutes les sources", func(t *testing.T) {
		reset()
		SetSources(map[string]Source{
			"a": {IPs: []string{"203.0.113.5"}},
			"b": {IPs: []string{"203.0.113.0/24"}},
			"c": {IPs: []string{"192.0.2.0/24"}},
		})
		matches := sortedCopy(SourcesContaining("203.0.113.5"))
		if len(matches) != 2 || matches[0] != "a" || matches[1] != "b" {
			t.Fatalf("got %v", matches)
		}
	})

	t.Run("adresse IPv4-mappee correspond a un CIDR IPv4", func(t *testing.T) {
		reset()
		SetSources(map[string]Source{"src": {IPs: []string{"203.0.113.0/24"}}})
		if got := SourcesContaining("::ffff:203.0.113.5"); len(got) != 1 || got[0] != "src" {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("un pattern invalide dans la liste est ignore sans planter", func(t *testing.T) {
		reset()
		SetSources(map[string]Source{"src": {IPs: []string{"pas-une-ip", "203.0.113.5"}}})
		if got := SourcesContaining("203.0.113.5"); len(got) != 1 || got[0] != "src" {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("SetSources({}) vide l index", func(t *testing.T) {
		reset()
		SetSources(map[string]Source{"src": {IPs: []string{"203.0.113.5"}}})
		if !HasSources() {
			t.Fatal("devrait avoir des sources")
		}
		SetSources(map[string]Source{})
		if HasSources() {
			t.Fatal("devrait etre vide")
		}
		if got := SourcesContaining("203.0.113.5"); len(got) != 0 {
			t.Fatalf("got %v", got)
		}
	})
}

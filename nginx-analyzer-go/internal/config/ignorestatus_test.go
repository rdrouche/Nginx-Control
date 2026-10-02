package config

import "testing"

func TestParseIgnoreStatus(t *testing.T) {
	m := ParseIgnoreStatus("444, 403;abc 99 600 4444 502")
	for _, ok := range []int{444, 403, 502} {
		if !m[ok] {
			t.Fatalf("%d attendu", ok)
		}
	}
	if len(m) != 3 {
		t.Fatalf("seuls 3 codes valides attendus : %v", m)
	}
	if len(ParseIgnoreStatus("")) != 0 {
		t.Fatal("vide : aucun code")
	}
}

package geoip

import (
	"os"
	"testing"
)

const testDB = "testdata/test-country.mmdb"

func TestMain(m *testing.M) {
	CountryDB = testDB
	CityDB = "/nexiste/pas.mmdb"
	ASNDB = "/nexiste/pas.mmdb"
	os.Exit(m.Run())
}

func TestBaseDeTestPresente(t *testing.T) {
	t.Run("le fichier existe", func(t *testing.T) {
		if _, err := os.Stat(testDB); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("Init detecte la base", func(t *testing.T) {
		if !Init() {
			t.Fatal("Init() devrait detecter la base de test")
		}
	})
}

func TestResolutionJeuDeTestMaxMind(t *testing.T) {
	cases := []struct{ ip, cc string }{
		{"81.2.69.160", "GB"},
		{"2.125.160.216", "GB"},
		{"89.160.20.112", "SE"},
		{"67.43.156.1", "BT"},
	}
	for _, c := range cases {
		t.Run(c.ip+" -> "+c.cc, func(t *testing.T) {
			if got := CountryOf(c.ip); got != c.cc {
				t.Fatalf("CountryOf(%q) = %q, want %q", c.ip, got, c.cc)
			}
		})
	}
	t.Run("une IP absente de la base -> vide, sans exception", func(t *testing.T) {
		if got := CountryOf("8.8.8.8"); got != "" {
			t.Fatalf("got %q", got)
		}
	})
}

func TestResolutionIPv6(t *testing.T) {
	t.Run("adresse IPv6 native -> JP", func(t *testing.T) {
		r := MmdbLookup(testDB, "2001:218::")
		country, _ := r["country"].(map[string]any)
		if country == nil || country["iso_code"] != "JP" {
			t.Fatalf("r = %+v", r)
		}
	})
	t.Run("adresse IPv6 native -> SE", func(t *testing.T) {
		r := MmdbLookup(testDB, "2001:220::")
		country, _ := r["country"].(map[string]any)
		if country == nil || country["iso_code"] != "SE" {
			t.Fatalf("r = %+v", r)
		}
	})
	t.Run("adresse IPv4-mappee donne le meme resultat que l IPv4 nue", func(t *testing.T) {
		a := CountryOf("::ffff:89.160.20.112")
		b := CountryOf("89.160.20.112")
		if a != b {
			t.Fatalf("%q != %q", a, b)
		}
	})
	t.Run("adresse IPv6 sans correspondance -> nil, sans exception", func(t *testing.T) {
		if r := MmdbLookup(testDB, "2003::"); r != nil {
			t.Fatalf("got %+v", r)
		}
	})
	t.Run("adresse IPv6 malformee -> nil, sans exception", func(t *testing.T) {
		if r := MmdbLookup(testDB, ":::"); r != nil {
			t.Fatalf("got %+v", r)
		}
		if r := MmdbLookup(testDB, "::ffff:999.1.1.1"); r != nil {
			t.Fatalf("got %+v", r)
		}
	})
}

func TestRobustesse(t *testing.T) {
	t.Run("adresse malformee", func(t *testing.T) {
		for _, bad := range []string{"pas-une-ip", "999.1.1.1", "", "1.2.3"} {
			if got := CountryOf(bad); got != "" {
				t.Fatalf("CountryOf(%q) = %q", bad, got)
			}
		}
	})
	t.Run("base inexistante", func(t *testing.T) {
		if r := MmdbLookup("/nexiste/pas.mmdb", "8.8.8.8"); r != nil {
			t.Fatalf("got %+v", r)
		}
	})
	t.Run("fichier non-MMDB", func(t *testing.T) {
		tmp := t.TempDir() + "/pas-une-base.mmdb"
		if err := os.WriteFile(tmp, []byte("ceci n est pas une base"), 0o644); err != nil {
			t.Fatal(err)
		}
		if r := MmdbLookup(tmp, "8.8.8.8"); r != nil {
			t.Fatalf("got %+v", r)
		}
	})
}

func TestCache(t *testing.T) {
	t.Run("deux appels identiques donnent le meme resultat", func(t *testing.T) {
		a := CountryOf("81.2.69.160")
		b := CountryOf("81.2.69.160")
		if a != b {
			t.Fatalf("%q != %q", a, b)
		}
		if Status().Cached <= 0 {
			t.Fatal("le cache doit se remplir")
		}
	})
}

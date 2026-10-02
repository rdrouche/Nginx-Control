package store

import (
	"path/filepath"
	"testing"
	"time"
)

func hit(o BlocklistHitInput, tNow int64) BlocklistHitInput {
	if o.Ts == 0 {
		o.Ts = tNow
	}
	if o.IP == "" {
		o.IP = "203.0.113.5"
	}
	if o.Vhost == "" {
		o.Vhost = "site.fr"
	}
	if o.Method == "" {
		o.Method = "GET"
	}
	if o.URI == "" {
		o.URI = "/wp-login.php"
	}
	if o.Status == 0 {
		o.Status = 403
	}
	return o
}

func TestBlocklistStore(t *testing.T) {
	tmp := t.TempDir()
	s := New(filepath.Join(tmp, "b.db"))
	defer s.Close()
	tNow := time.Now().UnixMilli()

	t.Run("un hit se relit dans le resume", func(t *testing.T) {
		s.RecordBlocklistHit(hit(BlocklistHitInput{}, tNow))
		sum := s.BlocklistHitsSummary(tNow-1000, tNow+1000, 0)
		if sum.TotalHits != 1 || sum.UniqueIPs != 1 {
			t.Fatalf("sum: %+v", sum)
		}
		if len(sum.TopIPs) == 0 || sum.TopIPs[0].IP != "203.0.113.5" || sum.TopIPs[0].Count != 1 {
			t.Fatalf("topIps: %+v", sum.TopIPs)
		}
	})

	t.Run("plusieurs hits cumules, IP distinctes comptees a part", func(t *testing.T) {
		s.RecordBlocklistHit(hit(BlocklistHitInput{}, tNow))
		s.RecordBlocklistHit(hit(BlocklistHitInput{IP: "198.51.100.9"}, tNow))
		sum := s.BlocklistHitsSummary(tNow-1000, tNow+1000, 0)
		if sum.TotalHits != 3 || sum.UniqueIPs != 2 {
			t.Fatalf("sum: %+v", sum)
		}
		var top *BlocklistTopIP
		for i := range sum.TopIPs {
			if sum.TopIPs[i].IP == "203.0.113.5" {
				top = &sum.TopIPs[i]
			}
		}
		if top == nil || top.Count != 2 {
			t.Fatalf("top: %+v", top)
		}
	})

	t.Run("hors fenetre temporelle -> ignore", func(t *testing.T) {
		sum := s.BlocklistHitsSummary(tNow+10_000, tNow+20_000, 0)
		if sum.TotalHits != 0 {
			t.Fatalf("attendu 0, obtenu %d", sum.TotalHits)
		}
	})

	t.Run("blocklistHitsForIp compte et borne", func(t *testing.T) {
		r := s.BlocklistHitsForIp("203.0.113.5", tNow-1000, tNow+1000)
		if r.Count != 2 {
			t.Fatalf("count: %d", r.Count)
		}
		if r.FirstSeen == nil || r.LastSeen == nil {
			t.Fatal("firstSeen/lastSeen ne doivent pas etre nil")
		}
	})

	t.Run("IP jamais vue -> compte 0", func(t *testing.T) {
		r := s.BlocklistHitsForIp("192.0.2.1", tNow-1000, tNow+1000)
		if r.Count != 0 || r.FirstSeen != nil {
			t.Fatalf("r: %+v", r)
		}
	})

	t.Run("purgeBlocklistHits ne supprime que les plus vieux", func(t *testing.T) {
		before := s.BlocklistHitsSummary(tNow-1000, tNow+1000, 0).TotalHits
		if before == 0 {
			t.Fatal("attendu des hits existants")
		}
		deleted := s.PurgeBlocklistHits(tNow - 500)
		if deleted != 0 {
			t.Fatalf("rien de plus vieux que T-500 dans ce jeu de test, obtenu %d", deleted)
		}
	})

	t.Run("clearBlocklistHits vide completement", func(t *testing.T) {
		deleted := s.ClearBlocklistHits()
		if deleted < 3 {
			t.Fatalf("attendu >= 3, obtenu %d", deleted)
		}
		if s.BlocklistHitsSummary(tNow-1000, tNow+1000, 0).TotalHits != 0 {
			t.Fatal("la table devrait etre vide")
		}
	})
}

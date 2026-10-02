package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExceptions(t *testing.T) {
	tmp := t.TempDir()
	s := New(filepath.Join(tmp, "exc.db"))
	defer s.Close()

	t.Run("ajout, liste, filtre par vhost", func(t *testing.T) {
		r := s.AddException(AddExceptionInput{Vhost: "site.fr", IP: "203.0.113.5", Reason: "monitoring", Author: "admin"})
		if !r.OK {
			t.Fatalf("attendu ok, obtenu erreur: %s", r.Error)
		}
		s.AddException(AddExceptionInput{Vhost: "autre.fr", IP: "198.51.100.0/24"})
		all := s.ListExceptions("")
		if len(all) != 2 {
			t.Fatalf("attendu 2, obtenu %d", len(all))
		}
		scoped := s.ListExceptions("site.fr")
		if len(scoped) != 1 || scoped[0].IP != "203.0.113.5" {
			t.Fatalf("scoped: %+v", scoped)
		}
	})

	t.Run("motif invalide rejete", func(t *testing.T) {
		r := s.AddException(AddExceptionInput{Vhost: "site.fr", IP: "pas-une-ip"})
		if r.OK {
			t.Fatal("un motif invalide doit etre rejete")
		}
	})

	t.Run("champs requis", func(t *testing.T) {
		r := s.AddException(AddExceptionInput{Vhost: "", IP: "1.2.3.4"})
		if r.OK {
			t.Fatal("vhost requis")
		}
	})

	t.Run("upsert sur (vhost, ip)", func(t *testing.T) {
		s.AddException(AddExceptionInput{Vhost: "site.fr", IP: "203.0.113.5", Reason: "raison mise a jour"})
		scoped := s.ListExceptions("site.fr")
		if len(scoped) != 1 || scoped[0].Reason != "raison mise a jour" {
			t.Fatalf("upsert: %+v", scoped)
		}
	})

	t.Run("suppression", func(t *testing.T) {
		all := s.ListExceptions("")
		id := all[0].ID
		if !s.RemoveException(id) {
			t.Fatal("removeException devrait reussir")
		}
		if len(s.ListExceptions("")) != len(all)-1 {
			t.Fatal("une exception en moins attendue")
		}
	})
}

func TestExceptionsSansSQLite(t *testing.T) {
	tmp := t.TempDir()
	blocker := filepath.Join(tmp, "pas-un-dossier")
	os.WriteFile(blocker, []byte("x"), 0o644)
	bad := New(filepath.Join(blocker, "x.db"))
	r := bad.AddException(AddExceptionInput{Vhost: "site.fr", IP: "203.0.113.5"})
	if !r.OK {
		t.Fatalf("attendu ok en mode memoire, obtenu: %s", r.Error)
	}
	if len(bad.ListExceptions("")) != 1 {
		t.Fatal("attendu 1 exception en memoire")
	}
}

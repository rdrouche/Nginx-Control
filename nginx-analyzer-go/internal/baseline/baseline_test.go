package baseline

// La detection volumetrique echoue habituellement de trois facons : elle
// ignore la saisonnalite, elle se laisse empoisonner par une attaque passee,
// et elle confond un succes avec une attaque. Ces tests couvrent les trois -
// portage 1:1 de test/baseline.test.js.

import (
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"
)

// hourOfWeek() bucket par heure LOCALE (voir baseline.go) ; ce fichier
// construit ses dates en UTC et attend des numeros de creneau precis, donc
// TestMain fixe le fuseau du processus de test a UTC pour rester
// deterministe quel que soit le fuseau systeme de la machine qui l execute
// (parite avec `process.env.TZ = 'UTC'` en tete du fichier Node d origine).
func TestMain(m *testing.M) {
	os.Setenv("TZ", "UTC")
	os.Exit(m.Run())
}

var oldStartedAt = time.Now().UnixMilli() - 30*86400000 // apprentissage termine

func m(requests int64, o Metrics) Metrics {
	if o.DistinctIps == 0 {
		o.DistinctIps = (requests + 1) / 2
	}
	if o.DistinctPaths == 0 {
		o.DistinctPaths = (requests + 9) / 10
	}
	o.Requests = requests
	return o
}

// tue(w, h) : mardi h(par defaut 14h) UTC, w semaines apres le 2026-09-08.
func tue(w int, hOpt ...int) time.Time {
	h := 14
	if len(hOpt) > 0 {
		h = hOpt[0]
	}
	return time.Date(2026, 9, 8+7*w, h, 0, 0, 0, time.UTC)
}

func TestStatistiquesRobustes(t *testing.T) {
	t.Run("mediane", func(t *testing.T) {
		if v := median([]float64{1, 2, 3}); v != 2 {
			t.Fatalf("median([1,2,3])=%v", v)
		}
		if v := median([]float64{1, 2, 3, 4}); v != 2.5 {
			t.Fatalf("median([1,2,3,4])=%v", v)
		}
	})
	t.Run("MAD ignore les valeurs extremes", func(t *testing.T) {
		normal := []float64{100, 102, 98, 101, 99}
		avecAttaque := []float64{100, 102, 98, 101, 99, 50000}
		sortedNormal := append([]float64{}, normal...)
		sort64(sortedNormal)
		sortedAttaque := append([]float64{}, avecAttaque...)
		sort64(sortedAttaque)
		madN := mad(normal, median(sortedNormal))
		madA := mad(avecAttaque, median(sortedAttaque))
		if !(madA < madN*3) {
			t.Fatalf("MAD passe de %.1f a %.1f", madN, madA)
		}
	})
	t.Run("heure de la semaine", func(t *testing.T) {
		if v := HourOfWeek(time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)); v != 0 {
			t.Fatalf("lundi 00h: %d", v)
		}
		if v := HourOfWeek(time.Date(2026, 9, 8, 14, 0, 0, 0, time.UTC)); v != 38 {
			t.Fatalf("mardi 14h: %d", v)
		}
	})
}

func sort64(v []float64) {
	for i := 1; i < len(v); i++ {
		j := i
		for j > 0 && v[j-1] > v[j] {
			v[j-1], v[j] = v[j], v[j-1]
			j--
		}
	}
}

func TestPeriodeApprentissage(t *testing.T) {
	t.Run("aucune alerte pendant l apprentissage", func(t *testing.T) {
		b := New(Config{LearningDays: 21}, nil)
		for w := 0; w < 5; w++ {
			b.Observe("site.fr", tue(w), m(100, Metrics{}))
		}
		r := b.Check("site.fr", tue(5), m(100000, Metrics{}))
		if r == nil || !r.Learning {
			t.Fatal("doit signaler l apprentissage, pas alerter")
		}
		if r.Anomaly {
			t.Fatal("ne doit pas etre une anomalie")
		}
	})
	t.Run("l etat indique la progression", func(t *testing.T) {
		b := New(Config{LearningDays: 21}, nil)
		s := b.Stats()
		if !s.Learning {
			t.Fatal("learning devrait etre true")
		}
		if s.DaysRequired != 21 {
			t.Fatalf("daysRequired: %d", s.DaysRequired)
		}
	})
}

func TestSaisonnalite(t *testing.T) {
	t.Run("un creneau creux ne declenche pas sur le trafic d un creneau charge", func(t *testing.T) {
		b := New(Config{}, &State{StartedAt: oldStartedAt})
		for w := 0; w < 6; w++ {
			b.Observe("site.fr", tue(w, 14), m(1000, Metrics{}))
			b.Observe("site.fr", time.Date(2026, 9, 13+7*w, 4, 0, 0, 0, time.UTC), m(20, Metrics{}))
		}
		if r := b.Check("site.fr", tue(6, 14), m(1000, Metrics{})); r != nil {
			t.Fatalf("1000 requetes un mardi 14h devrait etre normal: %+v", r)
		}
		r := b.Check("site.fr", time.Date(2026, 9, 55, 4, 0, 0, 0, time.UTC),
			m(1000, Metrics{DistinctIps: 2, DistinctPaths: 1}))
		if r == nil || !r.Anomaly {
			t.Fatal("un pic hors creneau doit alerter")
		}
	})
}

func TestEchantillonInsuffisant(t *testing.T) {
	t.Run("moins de 3 observations -> silence", func(t *testing.T) {
		b := New(Config{}, &State{StartedAt: oldStartedAt})
		b.Observe("site.fr", tue(0), m(100, Metrics{}))
		b.Observe("site.fr", tue(1), m(100, Metrics{}))
		if r := b.Check("site.fr", tue(2), m(10000, Metrics{})); r != nil {
			t.Fatalf("r: %+v", r)
		}
	})
	t.Run("petit volume ignore", func(t *testing.T) {
		b := New(Config{MinAbsoluteRequests: 100}, &State{StartedAt: oldStartedAt})
		for w := 0; w < 6; w++ {
			b.Observe("site.fr", tue(w), m(2, Metrics{}))
		}
		if r := b.Check("site.fr", tue(6), m(50, Metrics{})); r != nil {
			t.Fatal("50 requetes ne meritent pas une alerte")
		}
	})
}

func TestDetectionEcart(t *testing.T) {
	t.Run("un pic important alerte", func(t *testing.T) {
		b := New(Config{}, &State{StartedAt: oldStartedAt})
		for w := 0; w < 6; w++ {
			b.Observe("site.fr", tue(w), m(1000, Metrics{}))
		}
		r := b.Check("site.fr", tue(6), m(50000, Metrics{DistinctIps: 3, DistinctPaths: 2, Errors: 40000}))
		if r == nil || !r.Anomaly {
			t.Fatal("attendu une anomalie")
		}
		if r.Deviation <= 6 {
			t.Fatalf("deviation: %v", r.Deviation)
		}
		if r.Expected != 1000 {
			t.Fatalf("expected: %d", r.Expected)
		}
	})
	t.Run("une variation normale n alerte pas", func(t *testing.T) {
		b := New(Config{}, &State{StartedAt: oldStartedAt})
		for _, v := range []int64{900, 1100, 950, 1050, 1000, 980} {
			b.Observe("site.fr", tue(0), m(v, Metrics{}))
		}
		if r := b.Check("site.fr", tue(6), m(1150, Metrics{})); r != nil {
			t.Fatalf("r: %+v", r)
		}
	})
}

func TestStructureTranche(t *testing.T) {
	t.Run("une audience reelle est signalee comme telle", func(t *testing.T) {
		b := New(Config{}, &State{StartedAt: oldStartedAt})
		for w := 0; w < 6; w++ {
			b.Observe("site.fr", tue(w), m(1000, Metrics{}))
		}
		r := b.Check("site.fr", tue(6), Metrics{Requests: 20000, DistinctIps: 8000, DistinctPaths: 1500, Errors: 100})
		if r == nil || !r.Anomaly {
			t.Fatal("attendu une anomalie")
		}
		if !r.Structure.LooksOrganic {
			t.Fatal("looksOrganic devrait etre true")
		}
		if r.Severity != "low" {
			t.Fatalf("severity: %s, ne doit pas etre traite comme une attaque", r.Severity)
		}
	})
	t.Run("un flood est signale comme tel", func(t *testing.T) {
		b := New(Config{}, &State{StartedAt: oldStartedAt})
		for w := 0; w < 6; w++ {
			b.Observe("site.fr", tue(w), m(1000, Metrics{}))
		}
		r := b.Check("site.fr", tue(6), Metrics{Requests: 20000, DistinctIps: 4, DistinctPaths: 1, Errors: 15000})
		if r == nil {
			t.Fatal("attendu un resultat")
		}
		if r.Structure.LooksOrganic {
			t.Fatal("looksOrganic devrait etre false")
		}
		if r.Severity != "medium" && r.Severity != "high" {
			t.Fatalf("severity: %s", r.Severity)
		}
	})
}

func TestEmpoisonnementReference(t *testing.T) {
	t.Run("une periode marquee normale n entre pas dans la baseline", func(t *testing.T) {
		b := New(Config{}, &State{StartedAt: oldStartedAt})
		for w := 0; w < 6; w++ {
			b.Observe("site.fr", tue(w), m(1000, Metrics{}))
		}
		spike := tue(6)
		b.Exclude("site.fr", spike.UTC().Format("2006-01-02T15:04:05.000Z"))
		b.Observe("site.fr", spike, m(99999, Metrics{}))
		ref := b.Reference("site.fr", tue(7))
		if ref == nil || ref.Median != 1000 {
			t.Fatalf("le pic exclu ne doit pas deplacer la mediane: %+v", ref)
		}
	})
}

func TestPersistance(t *testing.T) {
	t.Run("l etat survit a un redemarrage", func(t *testing.T) {
		b := New(Config{}, &State{StartedAt: oldStartedAt})
		for w := 0; w < 6; w++ {
			b.Observe("site.fr", tue(w), m(1000, Metrics{}))
		}
		state := b.ExportState()
		// Aller-retour JSON, comme JSON.parse(JSON.stringify(...)) cote Node.
		raw, err := json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		var state2 State
		if err := json.Unmarshal(raw, &state2); err != nil {
			t.Fatal(err)
		}
		b2 := New(Config{}, &state2)
		ref := b2.Reference("site.fr", tue(6))
		if ref == nil || ref.Median != 1000 {
			t.Fatalf("ref: %+v", ref)
		}
		if b2.IsLearning() {
			t.Fatal("la date de depart doit etre conservee")
		}
	})
}

func TestCouverture(t *testing.T) {
	t.Run("coverage rapporte au nombre reel de creneaux possibles", func(t *testing.T) {
		b := New(Config{MinSamplesPerBucket: 1}, &State{StartedAt: oldStartedAt})
		for _, v := range []string{"a.example.com", "b.example.com", "c.example.com"} {
			for h := 0; h < 24; h++ {
				b.Observe(v, tue(0, h), m(100, Metrics{}))
			}
		}
		s := b.Stats()
		if s.VhostsTracked != 3 {
			t.Fatalf("vhostsTracked: %d", s.VhostsTracked)
		}
		if s.BucketsUsable != 72 {
			t.Fatalf("bucketsUsable: %d", s.BucketsUsable)
		}
		if s.TotalSlots != 3*168 {
			t.Fatalf("totalSlots: %d", s.TotalSlots)
		}
		if s.Coverage > 100 {
			t.Fatalf("coverage ne doit jamais depasser 100%%: %v", s.Coverage)
		}
		want := round1(100 * 72 / float64(3*168))
		if s.Coverage != want {
			t.Fatalf("coverage: %v, want %v", s.Coverage, want)
		}
	})
	t.Run("un seul vhost retombe sur le comportement historique", func(t *testing.T) {
		b := New(Config{MinSamplesPerBucket: 1}, &State{StartedAt: oldStartedAt})
		for h := 0; h < 24; h++ {
			b.Observe("site.fr", tue(0, h), m(100, Metrics{}))
		}
		s := b.Stats()
		if s.VhostsTracked != 1 {
			t.Fatalf("vhostsTracked: %d", s.VhostsTracked)
		}
		if s.TotalSlots != 168 {
			t.Fatalf("totalSlots: %d", s.TotalSlots)
		}
		want := round1(100 * 24 / float64(168))
		if s.Coverage != want {
			t.Fatalf("coverage: %v, want %v", s.Coverage, want)
		}
	})
	t.Run("aucun vhost suivi -> pas de division par zero", func(t *testing.T) {
		b := New(Config{}, &State{StartedAt: oldStartedAt})
		s := b.Stats()
		if s.VhostsTracked != 0 {
			t.Fatalf("vhostsTracked: %d", s.VhostsTracked)
		}
		if s.BucketsUsable != 0 {
			t.Fatalf("bucketsUsable: %d", s.BucketsUsable)
		}
		if s.Coverage != 0 {
			t.Fatalf("coverage: %v", s.Coverage)
		}
	})
}

func TestCleSporadiqueEtProfil(t *testing.T) {
	b := New(Config{MinSamplesPerBucket: 1}, &State{StartedAt: oldStartedAt})
	for h := 0; h < 24; h++ {
		b.Observe("site.fr", tue(0, h), m(100, Metrics{}))
	}
	for i := 0; i < 50; i++ {
		b.Observe("scan"+strconv.Itoa(i)+".bot", tue(0, 3), m(2, Metrics{}))
	}
	s := b.Stats()
	if s.VhostsTracked != 1 || s.KeysTracked != 51 || s.SporadicKeys != 50 || s.TotalSlots != 168 {
		t.Fatalf("stats: %+v", s)
	}

	b2 := New(Config{MinSamplesPerBucket: 3}, &State{StartedAt: oldStartedAt})
	for w := 0; w < 3; w++ {
		b2.Observe("site.fr", tue(w, 14), m(int64(1000+w*10), Metrics{}))
	}
	b2.Observe("site.fr", tue(0, 15), m(500, Metrics{}))
	p := b2.Profile("site.fr")
	if len(p.Slots) != 168 {
		t.Fatalf("slots: %d", len(p.Slots))
	}
	s14 := p.Slots[HourOfWeek(tue(0, 14))]
	if !s14.Usable || s14.Median != 1010 || s14.Threshold <= s14.Median {
		t.Fatalf("slot 14h: %+v", s14)
	}
	s15 := p.Slots[HourOfWeek(tue(0, 15))]
	if s15.Usable || s15.Samples != 1 || p.Slots[0].Samples != 0 {
		t.Fatalf("slot 15h: %+v", s15)
	}

	b3 := New(Config{MinSamplesPerBucket: 1}, &State{StartedAt: oldStartedAt})
	for h := 0; h < 24; h++ {
		v := int64(100)
		if h == 14 {
			v = 900
		}
		b3.Observe("gros.fr", tue(0, h), m(v, Metrics{}))
		b3.Observe("petit.fr", tue(0, h), m(10, Metrics{}))
	}
	k := b3.KeysSummary(10)
	if k[0].Key != "gros.fr" || k[0].PeakPerHour != 900 || k[0].PeakHow != HourOfWeek(tue(0, 14)) || !k[0].Relevant {
		t.Fatalf("keys: %+v", k)
	}
}

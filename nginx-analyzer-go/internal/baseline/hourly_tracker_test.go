package baseline

import (
	"reflect"
	"testing"
)

const H = 3_600_000

// T0 = Date.parse('2026-09-09T14:00:00Z'), pile sur une heure ronde.
const T0 = 1789056000000

type counter struct{ n int }

func TestHourlyAccumulator(t *testing.T) {
	t.Run("deux entrees de la meme heure/cle sont cumulees", func(t *testing.T) {
		a := NewHourlyAccumulator[string, counter](0, 0)
		a.Add(T0+1000, "site.fr", func() *counter { return &counter{} }, func(c *counter) { c.n++ })
		a.Add(T0+2000, "site.fr", func() *counter { return &counter{} }, func(c *counter) { c.n++ })
		closed := a.CloseFinished(T0 + 3*H)
		if len(closed) != 1 {
			t.Fatalf("attendu 1 heure fermee, obtenu %d", len(closed))
		}
		if closed[0].Hour != T0 {
			t.Fatalf("hour attendu %d, obtenu %d", T0, closed[0].Hour)
		}
		if closed[0].ByKey["site.fr"].n != 2 {
			t.Fatalf("n attendu 2, obtenu %d", closed[0].ByKey["site.fr"].n)
		}
	})

	t.Run("deux heures differentes ne se melangent jamais", func(t *testing.T) {
		a := NewHourlyAccumulator[string, counter](0, 0)
		a.Add(T0, "site.fr", func() *counter { return &counter{} }, func(c *counter) { c.n++ })        // 14:00
		a.Add(T0+H+1000, "site.fr", func() *counter { return &counter{} }, func(c *counter) { c.n++ }) // 15:00
		a.Add(T0+500, "site.fr", func() *counter { return &counter{} }, func(c *counter) { c.n++ })    // encore 14:00
		a.Add(T0+H+2000, "site.fr", func() *counter { return &counter{} }, func(c *counter) { c.n++ }) // encore 15:00
		closed := a.CloseFinished(T0 + 10*H)
		byHour := map[int64]int{}
		for _, c := range closed {
			byHour[c.Hour] = c.ByKey["site.fr"].n
		}
		if byHour[T0] != 2 {
			t.Fatalf("14:00 attendu 2, obtenu %d", byHour[T0])
		}
		if byHour[T0+H] != 2 {
			t.Fatalf("15:00 attendu 2, obtenu %d", byHour[T0+H])
		}
	})

	t.Run("une heure n est fermee que plus de closeDelayMs apres sa fin", func(t *testing.T) {
		a := NewHourlyAccumulator[string, counter](0, 0)
		a.Add(T0, "site.fr", func() *counter { return &counter{} }, func(c *counter) { c.n++ })
		if closed := a.CloseFinished(T0 + 30*60_000); len(closed) != 0 {
			t.Fatal("encore dans l heure -> rien a fermer")
		}
		if closed := a.CloseFinished(T0 + H + 1000); len(closed) != 0 {
			t.Fatal("heure finie mais dans le delai de fermeture -> encore ouverte")
		}
		closed := a.CloseFinished(T0 + 2*H + 1000)
		if len(closed) != 1 || closed[0].Hour != T0 {
			t.Fatalf("closed: %+v", closed)
		}
	})

	t.Run("une heure fermee est retiree, pas de double comptage", func(t *testing.T) {
		a := NewHourlyAccumulator[string, counter](0, 0)
		a.Add(T0, "site.fr", func() *counter { return &counter{} }, func(c *counter) { c.n++ })
		first := a.CloseFinished(T0 + 2*H + 1000)
		if len(first) != 1 {
			t.Fatalf("first: %+v", first)
		}
		second := a.CloseFinished(T0 + 3*H)
		if len(second) != 0 {
			t.Fatal("la meme heure ne doit plus jamais etre rendue")
		}
	})

	t.Run("les heures sont rendues dans l ordre chronologique", func(t *testing.T) {
		a := NewHourlyAccumulator[string, counter](0, 0)
		a.Add(T0+2*H, "x", func() *counter { return &counter{} }, func(c *counter) { c.n++ })
		a.Add(T0, "x", func() *counter { return &counter{} }, func(c *counter) { c.n++ })
		a.Add(T0+H, "x", func() *counter { return &counter{} }, func(c *counter) { c.n++ })
		closed := a.CloseFinished(T0 + 10*H)
		var hours []int64
		for _, c := range closed {
			hours = append(hours, c.Hour)
		}
		want := []int64{T0, T0 + H, T0 + 2*H}
		if !reflect.DeepEqual(hours, want) {
			t.Fatalf("hours: %v, want %v", hours, want)
		}
	})

	t.Run("openHours reflete les heures pas encore fermees", func(t *testing.T) {
		a := NewHourlyAccumulator[string, counter](0, 0)
		a.Add(T0, "x", func() *counter { return &counter{} }, func(c *counter) { c.n++ })
		a.Add(T0+H, "x", func() *counter { return &counter{} }, func(c *counter) { c.n++ })
		want := []int64{T0, T0 + H}
		if !reflect.DeepEqual(a.OpenHours(), want) {
			t.Fatalf("openHours: %v, want %v", a.OpenHours(), want)
		}
		a.CloseFinished(T0 + 2*H + 1000)
		want2 := []int64{T0 + H}
		if !reflect.DeepEqual(a.OpenHours(), want2) {
			t.Fatalf("openHours apres fermeture: %v, want %v", a.OpenHours(), want2)
		}
	})
}

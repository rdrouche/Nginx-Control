// Package baseline porte lib/baseline.js et lib/hourly-tracker.js : detection
// d'anomalie volumetrique et le mecanisme generique d'accumulation par heure
// qui l'alimente.
package baseline

import "sort"

// HourlyAccumulator porte HourlyAccumulator (fix, audit ANA-07) : accumule
// par (heure, cle) plutot que dans un seul objet "heure courante" partage,
// pour que plusieurs sources (access, WAF, blocklist) avancant chacune a son
// rythme ne se marchent jamais dessus pres d'une frontiere d'heure, et pour
// qu'un redemarrage en cours d'heure ne fasse jamais compter deux fois la
// meme heure reelle : CloseFinished() ne rend une heure que largement apres
// sa fin (closeDelayMs), et l'appelant ne doit jamais forcer la fermeture
// autrement (en particulier : pas a l'arret du process).
type HourlyAccumulator[K comparable, V any] struct {
	hourMs       int64
	closeDelayMs int64
	byHour       map[int64]map[K]*V
}

// NewHourlyAccumulator cree un accumulateur. closeDelayMs=0 et hourMs=0
// retombent sur le defaut JS de 3 600 000 ms (1h) pour les deux.
func NewHourlyAccumulator[K comparable, V any](closeDelayMs, hourMs int64) *HourlyAccumulator[K, V] {
	if hourMs == 0 {
		hourMs = 3_600_000
	}
	if closeDelayMs == 0 {
		closeDelayMs = 3_600_000
	}
	return &HourlyAccumulator[K, V]{
		hourMs:       hourMs,
		closeDelayMs: closeDelayMs,
		byHour:       make(map[int64]map[K]*V),
	}
}

// HourOf replique hourOf().
func (a *HourlyAccumulator[K, V]) HourOf(ts int64) int64 {
	return (ts / a.hourMs) * a.hourMs
}

// Add replique add() : replie une entree dans son creneau heure/cle.
// createFn construit un accumulateur neuf au premier usage ; updateFn le
// modifie en place.
func (a *HourlyAccumulator[K, V]) Add(ts int64, key K, createFn func() *V, updateFn func(*V)) *V {
	h := a.HourOf(ts)
	byKey, ok := a.byHour[h]
	if !ok {
		byKey = make(map[K]*V)
		a.byHour[h] = byKey
	}
	acc, ok := byKey[key]
	if !ok {
		acc = createFn()
		byKey[key] = acc
	}
	updateFn(acc)
	return acc
}

// ClosedHour reproduit un element du tableau [hourTs, Map<key, accumulator>]
// rendu par closeFinished().
type ClosedHour[K comparable, V any] struct {
	Hour  int64
	ByKey map[K]*V
}

// CloseFinished replique closeFinished() : retire et renvoie chaque heure
// terminee depuis plus de closeDelayMs, `[hourTs, byKey][]`, la plus
// ancienne en premier. Peut etre appelee aussi souvent que necessaire - une
// heure pas encore due est simplement laissee en place.
func (a *HourlyAccumulator[K, V]) CloseFinished(now int64) []ClosedHour[K, V] {
	// Une heure couvre [hour, hour+hourMs) et "se termine" a hour+hourMs ;
	// elle n'est fermee qu'une fois cette fin vieille d'au moins closeDelayMs.
	cutoff := now - a.closeDelayMs - a.hourMs
	var closed []ClosedHour[K, V]
	for h, byKey := range a.byHour {
		if h <= cutoff {
			closed = append(closed, ClosedHour[K, V]{Hour: h, ByKey: byKey})
		}
	}
	sort.Slice(closed, func(i, j int) bool { return closed[i].Hour < closed[j].Hour })
	for _, c := range closed {
		delete(a.byHour, c.Hour)
	}
	return closed
}

// OpenHours replique openHours() : heures actuellement ouvertes (pour les
// tests/diagnostics), les plus anciennes en premier.
func (a *HourlyAccumulator[K, V]) OpenHours() []int64 {
	hours := make([]int64, 0, len(a.byHour))
	for h := range a.byHour {
		hours = append(hours, h)
	}
	sort.Slice(hours, func(i, j int) bool { return hours[i] < hours[j] })
	return hours
}

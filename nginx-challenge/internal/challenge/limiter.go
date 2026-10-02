package challenge

import (
	"sync"
	"time"
)

// limiter : fenêtre fixe d'une minute par clé (adresse). Mémoire bornée.
type limiter struct {
	mu    sync.Mutex
	max   int
	win   map[string]*bucket
	now   func() time.Time
	limit int // nombre maximal de clés suivies
}

type bucket struct {
	count int
	reset time.Time
}

func newLimiter(perMinute int) *limiter {
	return &limiter{max: perMinute, win: map[string]*bucket{}, now: time.Now, limit: 100000}
}

// allow renvoie false quand la clé dépasse son quota de la minute.
func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.win[key]
	if b == nil || now.After(b.reset) {
		if len(l.win) >= l.limit {
			for k, v := range l.win {
				if now.After(v.reset) {
					delete(l.win, k)
				}
			}
			if len(l.win) >= l.limit {
				return false
			}
		}
		b = &bucket{reset: now.Add(time.Minute)}
		l.win[key] = b
	}
	b.count++
	return b.count <= l.max
}

// usedSet : jetons déjà résolus (anti-rejeu), purgés à expiration, borné.
type usedSet struct {
	mu  sync.Mutex
	m   map[string]time.Time
	cap int
	now func() time.Time
}

func newUsedSet() *usedSet { return &usedSet{m: map[string]time.Time{}, cap: 50000, now: time.Now} }

// add enregistre le jeton ; false s'il a déjà servi ou si la table est saturée.
func (u *usedSet) add(id string, until time.Time) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	now := u.now()
	if exp, ok := u.m[id]; ok && now.Before(exp) {
		return false
	}
	if len(u.m) >= u.cap {
		for k, v := range u.m {
			if !now.Before(v) {
				delete(u.m, k)
			}
		}
		if len(u.m) >= u.cap {
			return false
		}
	}
	u.m[id] = until
	return true
}

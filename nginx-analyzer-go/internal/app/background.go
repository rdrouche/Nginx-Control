package app

import (
	"log"
	"time"
)

// every reproduit le helper every(ms, fn, label) de server.js : execute fn()
// a intervalle regulier jusqu'a ce que stop soit ferme, en avalant/loggant
// toute panique/erreur plutot que de faire tomber l'agent.
func every(d time.Duration, fn func(), label string, stop <-chan struct{}) {
	t := time.NewTicker(d)
	go func() {
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				safeCall(fn, label)
			}
		}
	}()
}

func safeCall(fn func(), label string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[%s] %v", label, r)
		}
	}()
	fn()
}

// StartBackgroundLoops reproduit la section "Periodic work" de server.js :
// flush, relecture des exceptions, evaluation du detecteur, rollup +
// purges par anciennete, et fermeture des heures terminees.
func (a *App) StartBackgroundLoops(stop <-chan struct{}) {
	every(time.Duration(a.Cfg.FlushMs)*time.Millisecond, func() {
		a.Store.Flush()
	}, "flush", stop)

	// Les exceptions sont relues a chaque evaluation : une exception ajoutee
	// depuis le dashboard doit prendre effet sans redemarrer l'agent.
	every(time.Duration(a.Cfg.EvaluateMs)*time.Millisecond, func() {
		a.Detector.SetExceptions(ToDetectExceptions(a.Store.ListExceptions("")))
	}, "exceptions", stop)

	every(time.Duration(a.Cfg.EvaluateMs)*time.Millisecond, func() {
		for _, alert := range a.Detector.Evaluate(nowMs()) {
			a.Store.AddAlert(alertToInput(alert))
			log.Printf("[alert] %s %s: %s", alert.Type, alert.Evidence.IP, alert.Summary)
		}
	}, "evaluate", stop)

	every(time.Duration(a.Cfg.RollupMs)*time.Millisecond, func() {
		a.Store.Rollup()
		a.Store.PurgeAlerts(nowMs() - int64(a.Cfg.AlertRetDays)*86_400_000)
		a.Store.PurgeWaf(nowMs() - int64(a.Cfg.WafRetentionDays)*86_400_000)
		a.Store.PurgeBlocklistHits(nowMs() - int64(a.Cfg.BlocklistRetentionDays)*86_400_000)
	}, "rollup", stop)

	// Fix (audit ANA-07) : ferme les heures terminees sur son propre
	// minuteur, independant du rythme d'arrivee des entrees.
	every(5*time.Minute, func() {
		a.CloseFinishedHourlyBuckets(nowMs())
	}, "hourly-close", stop)
}

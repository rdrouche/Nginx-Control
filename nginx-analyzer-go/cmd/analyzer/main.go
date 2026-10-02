// Command analyzer est le point d'entree de nginx-analyzer (portage Go) :
// reproduit la section "Boot" de server.js (construction de l'App, demarrage
// des tailers, boucles de fond, ecoute HTTP, arret propre sur signal).
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	// Embarque la base des fuseaux horaires (~450 Ko) : la baseline volumetrique et
	// l'horodatage WAF sans fuseau dependent de TZ (heure LOCALE), et une image
	// minimale n'a pas forcement /usr/share/zoneinfo.
	_ "time/tzdata"

	"nginx-analyzer-go/internal/app"
	"nginx-analyzer-go/internal/config"
	"nginx-analyzer-go/internal/geoip"
	"nginx-analyzer-go/internal/httpapi"
)

// defaultGCPercent : compromis RAM/CPU mesure sur une charge extreme (300 000
// lignes, 50 000 IP suivies) - GOGC=100 (defaut Go) : 272 Mo ; 50 : 200 Mo ;
// 40 : ~180 Mo ; 30 : 158 Mo mais l'ingestion ralentit nettement. Le GC de Go
// laisse sinon le tas grossir jusqu'a 2x le volume vivant. Surchargeable avec
// la variable d'environnement GOGC (et GOMEMLIMIT pour un plafond souple).
const defaultGCPercent = 40

func main() {
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(defaultGCPercent)
	}
	cfg := config.Load()
	log.Printf("[nginx-analyzer] demarrage (%s/%s, %s)", runtime.GOOS, runtime.GOARCH, runtime.Version())
	a := app.New(cfg)

	stop := make(chan struct{})
	a.StartBackgroundLoops(stop)

	// L'API est ouverte AVANT le demarrage des tailers : le dashboard la sonde
	// (timeout 8 s) et doit la trouver joignable meme si la premiere passe de
	// lecture des logs (arriere accumule pendant un arret) est longue. Un port
	// deja pris est fatal et clairement journalise (et non silencieux).
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Port))
	if err != nil {
		log.Fatalf("[nginx-analyzer] impossible d'ecouter sur :%d : %v", cfg.Port, err)
	}
	srv := &http.Server{Handler: httpapi.NewHandler(a)}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("[nginx-analyzer] %v", err)
		}
	}()

	a.Boot()

	go func() {
		log.Printf("[nginx-analyzer] :%d", cfg.Port)
		log.Printf("  Logs      : %s (%s)", cfg.LogsDir, cfg.LogPatternRaw)
		log.Printf("  Base      : %s (%s)", cfg.DBPath, persistenceLabel(a))
		log.Printf("  GeoIP     : %s", geoipLabel())
		bs := a.Baseline.Stats()
		log.Printf("  Baseline  : %s, %.0f%% des creneaux", learningLabel(bs.Learning, bs.DaysElapsed, bs.DaysRequired), bs.Coverage)
		cbs := a.CountryBaseline.Stats()
		log.Printf("  Base.pays : %s, %.0f%% des creneaux", learningLabel(cbs.Learning, cbs.DaysElapsed, cbs.DaysRequired), cbs.Coverage)
		wafStats, _ := a.WafTailer.Status()
		log.Printf("  WAF       : %s (%d fichier(s))", cfg.WafLogPatternRaw, wafStats.Files)
		blStats, _ := a.BlocklistTailer.Status()
		log.Printf("  Blocklist : %s (%d fichier(s))", cfg.BlocklistLogPatternRaw, blStats.Files)

	}()

	// Flush des minutes en attente avant de sortir (store.Close() ->
	// store.Flush()). Les heures en cours ne sont deliberement PAS flushees
	// ici (fix, audit ANA-07) - voir internal/app.App pour le raisonnement
	// complet : perdre le signal structurel d'une heure en cours a un
	// redemarrage est un ecart mineur acceptable ; corrompre la baseline
	// apprise a chaque redemarrage ne l'est pas.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh
	log.Printf("[nginx-analyzer] %s, arret", sig)
	close(stop)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	a.Close()
	os.Exit(0)
}

func persistenceLabel(a *app.App) string {
	if a.Store.Persistent() {
		return "SQLite"
	}
	return "memoire seule"
}

func geoipLabel() string {
	st := geoip.Status()
	if st.Available {
		return st.Database
	}
	return "indisponible"
}

func learningLabel(learning bool, daysElapsed float64, daysRequired int) string {
	if learning {
		return fmt.Sprintf("apprentissage %.0f/%d j", daysElapsed, daysRequired)
	}
	return "active"
}

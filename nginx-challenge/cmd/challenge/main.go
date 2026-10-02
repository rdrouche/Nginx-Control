// Commande nginx-challenge : voir internal/challenge.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"nginx-challenge/internal/challenge"
)

func main() {
	cfg, err := challenge.LoadConfig(os.Getenv)
	if err != nil {
		log.Fatalf("configuration invalide : %v", err)
	}
	if cfg.SecretGenerated {
		log.Printf("ATTENTION : NC_SECRET absent — secret aléatoire tiré au démarrage ; les cookies de vérification seront invalidés à chaque redémarrage (et ne sont pas partagés entre instances).")
	}
	srv, err := challenge.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	hs := &http.Server{
		Addr: cfg.Bind, Handler: srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	go func() {
		log.Printf("nginx-challenge à l'écoute sur %s (difficulté %d bits, cookie %s)", cfg.Bind, cfg.Bits, cfg.CookieTTL)
		if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	flushStop := make(chan struct{})
	flushDone := make(chan struct{})
	go func() { srv.Stats().RunFlusher(flushStop, time.Minute); close(flushDone) }()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = hs.Shutdown(ctx)
	close(flushStop)
	<-flushDone
}

//go:build pprof

// Diagnostic uniquement : `go build -tags pprof ./cmd/analyzer` expose
// /debug/pprof sur 127.0.0.1:6060 (PPROF_ADDR pour changer). Absent du binaire
// de production (aucun import, aucun port ouvert).
package main

import (
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
)

func init() {
	addr := os.Getenv("PPROF_ADDR")
	if addr == "" {
		addr = "127.0.0.1:6060"
	}
	go func() { log.Printf("[pprof] %s", addr); _ = http.ListenAndServe(addr, nil) }()
}

//go:build !linux

package main

// Sur un OS non-Linux (rare pour un hote Docker, mais on ne plante jamais
// pour une simple metrique d observabilite) : aucune metrique n est
// remontee, le manifeste part sans bloc "metrics" — voir
// lib/agent-manifest.js#validateMetrics cote dashboard, qui traite deja
// l absence totale de metriques comme un cas normal.
//
// MetricsState existe aussi sur cette plateforme (type vide) uniquement pour
// que main.go#runTarget compile a l identique quel que soit l OS cible (une
// instance par cible, voir metrics_linux.go pour le pourquoi — fix GO-10).
type MetricsState struct{}

func NewMetricsState() *MetricsState { return &MetricsState{} }

func collectMetrics(*MetricsState) *MetricsSpec { return nil }

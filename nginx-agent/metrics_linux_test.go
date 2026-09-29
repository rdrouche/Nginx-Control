//go:build linux

package main

import (
	"strings"
	"testing"
	"time"
)

// Verifie que rx et tx sont bien lus separement (et non plus agreges puis
// repartis a parts egales, cf. la note dans le document de conception sur
// les "metriques reseau rx/tx separees").
func TestParseNetDev_SeparatesRxAndTx(t *testing.T) {
	// Format reel de /proc/net/dev : deux lignes d en-tete, puis
	// "iface: rx_bytes rx_packets ... (8 colonnes rx) tx_bytes ...".
	// lo est exclue, les autres interfaces sont sommees entre elles.
	fake := strings.Join([]string{
		"Inter-|   Receive                                                |  Transmit",
		" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed",
		"    lo:  1000       10    0    0    0     0          0         0     1000       10    0    0    0     0       0          0",
		"  eth0: 500000     100    0    0    0     0          0         0    20000       50    0    0    0     0       0          0",
		"  eth1: 100000      20    0    0    0     0          0         0     5000       10    0    0    0     0       0          0",
	}, "\n") + "\n"

	rx, tx, err := parseNetDev(strings.NewReader(fake))
	if err != nil {
		t.Fatalf("parseNetDev : %v", err)
	}
	if rx != 600000 {
		t.Fatalf("rx attendu 600000 (lo exclue), obtenu %d", rx)
	}
	if tx != 25000 {
		t.Fatalf("tx attendu 25000 (lo exclue), obtenu %d", tx)
	}
	if rx == tx {
		t.Fatalf("rx et tx ne doivent pas etre egaux par construction dans ce jeu de donnees (regression vers l ancien partage 50/50 ?)")
	}
}

// Verifie que collectMetrics() calcule bien des debits rx/tx distincts entre
// deux echantillons successifs (bout en bout, via la vraie lecture de
// /proc/net/dev de la machine de test — best-effort comme le reste de ce
// fichier : on ne verifie que la coherence interne, pas des valeurs precises).
func TestCollectMetrics_NetRatesIndependent(t *testing.T) {
	ms := NewMetricsState()

	first := collectMetrics(ms)
	if first == nil {
		t.Fatal("premier echantillon nil")
	}
	// Le tout premier appel n a pas de reference : pas de debit rapporte.
	if first.NetRxBytesPerSec != nil || first.NetTxBytesPerSec != nil {
		t.Fatalf("le premier echantillon ne doit rapporter aucun debit (pas de reference precedente)")
	}

	time.Sleep(50 * time.Millisecond)
	second := collectMetrics(ms)
	if second == nil {
		t.Fatal("second echantillon nil")
	}
	// Sur une machine de test reelle le trafic reseau peut etre nul entre les
	// deux echantillons : on verifie seulement que les DEUX champs sont
	// maintenant rapportes (calcules independamment), pas leur valeur.
	if second.NetRxBytesPerSec == nil || second.NetTxBytesPerSec == nil {
		t.Fatalf("le second echantillon doit rapporter rx ET tx (meme si 0)")
	}
}

// Fix v12.22.0 (audit finding GO-10, regression v12.21.0) : deux cibles
// multi-master interrogees quasi simultanement ne doivent plus partager le
// meme etat "echantillon precedent" — chacune a desormais son propre
// *MetricsState (voir main.go#runTarget). Ce test reproduit le scenario a
// l origine du bug : une deuxieme instance qui vient de naitre ne doit
// jamais lire l etat "deja un echantillon" d une autre instance plus
// ancienne.
func TestCollectMetrics_StatesAreIndependentAcrossTargets(t *testing.T) {
	msA := NewMetricsState()
	_ = collectMetrics(msA) // "cible A" a deja un historique...
	time.Sleep(10 * time.Millisecond)
	_ = collectMetrics(msA)

	msB := NewMetricsState() // ...mais "cible B" vient de demarrer.
	firstB := collectMetrics(msB)
	if firstB == nil {
		t.Fatal("premier echantillon de la cible B : nil")
	}
	if firstB.NetRxBytesPerSec != nil || firstB.NetTxBytesPerSec != nil {
		t.Fatalf("le premier echantillon de msB ne doit rapporter aucun debit, meme si msA en a deja un — etat croise entre cibles (regression GO-10)")
	}
}

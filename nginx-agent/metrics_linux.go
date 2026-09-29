//go:build linux

package main

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Linux-only host metrics (Partie 2 "avance" — voir le document de
// conception, section "Metriques"), lues directement dans /proc plutot que
// via une dependance externe (encore une fois, zero dependance au-dela de la
// bibliotheque standard). CPU% et debit reseau sont des MOYENNES entre deux
// appels successifs (un instantane de /proc/stat seul ne veut rien dire :
// ce sont des compteurs cumulatifs depuis le boot).
//
// Fix v12.22.0 (audit finding GO-10, regression v12.21.0) : cet etat
// ("echantillon precedent") vivait autrefois dans des variables de PAQUET,
// partagees par tout le processus. En mono-cible ca ne changeait rien, mais
// en multi-master (v12.21.0) chaque cible appelle collectMetrics() dans sa
// PROPRE boucle, a son propre rythme (--poll-interval peut differer d une
// cible a l autre) — la 2e cible a lire l etat mesurait alors un delta
// d a peine quelques millisecondes (le temps que la 1ere cible vienne de
// mettre a jour ces memes variables), donnant un CPU% ou un debit reseau
// faux ou nul. MetricsState rend cet etat explicite et prive PAR CIBLE (voir
// main.go#runTarget, qui en cree une instance par cible et la reutilise a
// chaque appel).
type MetricsState struct {
	mu             sync.Mutex
	prevCPUIdle    uint64
	prevCPUTotal   uint64
	prevNetRxBytes uint64
	prevNetTxBytes uint64
	prevSampleAt   time.Time
	havePrevSample bool
}

func NewMetricsState() *MetricsState { return &MetricsState{} }

func readProcStatCPU() (idle, total uint64, err error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)[1:]
		var sum uint64
		for i, tok := range fields {
			n, e := strconv.ParseUint(tok, 10, 64)
			if e != nil {
				continue
			}
			sum += n
			if i == 3 { // "idle" est le 4e champ (user nice system idle ...)
				idle = n
			}
		}
		return idle, sum, nil
	}
	return 0, 0, nil
}

func readMemInfo() (totalKb, availKb uint64, err error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, _ := strconv.ParseUint(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			totalKb = val
		case "MemAvailable:":
			availKb = val
		}
	}
	return totalKb, availKb, nil
}

func readUptimeSec() (float64, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, nil
	}
	v, _ := strconv.ParseFloat(fields[0], 64)
	return v, nil
}

// readNetRxTxBytes lit separement les compteurs cumulatifs de reception et
// d emission de toutes les interfaces (hors loopback) dans /proc/net/dev.
// Colonnes du format (apres le nom d interface et son ':') : la 1ere est
// "bytes" recus, la 9e est "bytes" emis (rx_bytes ... rx_compressed
// tx_bytes ...) — memes indices que l ancienne version qui les sommait, mais
// desormais gardes separes plutot que d etre agreges puis repartis a parts
// egales.
func readNetRxTxBytes() (rxTotal, txTotal uint64, err error) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	return parseNetDev(f)
}

// parseNetDev est l analyse pure du contenu de /proc/net/dev, separee de la
// lecture disque pour etre testable sans vrai /proc (voir metrics_linux_test.go).
func parseNetDev(r io.Reader) (rxTotal, txTotal uint64, err error) {
	scanner := bufio.NewScanner(r)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		if lineNo <= 2 {
			continue // deux lignes d en-tete
		}
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		iface := strings.TrimSpace(parts[0])
		if iface == "lo" {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 9 {
			continue
		}
		rx, _ := strconv.ParseUint(fields[0], 10, 64)
		tx, _ := strconv.ParseUint(fields[8], 10, 64)
		rxTotal += rx
		txTotal += tx
	}
	return rxTotal, txTotal, nil
}

func f64ptr(v float64) *float64 { return &v }

// collectMetrics best-effort : toute valeur illisible est simplement omise
// (jamais d erreur fatale pour une simple metrique d observabilite — voir
// lib/agent-manifest.js#validateMetrics cote dashboard, qui accepte deja un
// sous-ensemble partiel). ms est l etat "echantillon precedent" PROPRE A LA
// CIBLE appelante (voir MetricsState ci-dessus, fix GO-10).
func collectMetrics(ms *MetricsState) *MetricsSpec {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	m := &MetricsSpec{}
	now := time.Now()

	if idle, total, err := readProcStatCPU(); err == nil && total > 0 {
		if ms.havePrevSample && total > ms.prevCPUTotal {
			deltaTotal := float64(total - ms.prevCPUTotal)
			deltaIdle := float64(idle - ms.prevCPUIdle)
			if deltaTotal > 0 {
				pct := (1 - deltaIdle/deltaTotal) * 100
				if pct < 0 {
					pct = 0
				}
				if pct > 100 {
					pct = 100
				}
				m.CPUPercent = f64ptr(pct)
			}
		}
		ms.prevCPUIdle, ms.prevCPUTotal = idle, total
	}

	if totalKb, availKb, err := readMemInfo(); err == nil && totalKb > 0 {
		usedPct := (1 - float64(availKb)/float64(totalKb)) * 100
		m.MemPercent = f64ptr(usedPct)
		m.MemTotalMb = f64ptr(float64(totalKb) / 1024)
	}

	if up, err := readUptimeSec(); err == nil {
		m.UptimeSec = f64ptr(up)
	}

	if rxBytes, txBytes, err := readNetRxTxBytes(); err == nil {
		if ms.havePrevSample {
			elapsed := now.Sub(ms.prevSampleAt).Seconds()
			if elapsed > 0 && rxBytes >= ms.prevNetRxBytes && txBytes >= ms.prevNetTxBytes {
				m.NetRxBytesPerSec = f64ptr(float64(rxBytes-ms.prevNetRxBytes) / elapsed)
				m.NetTxBytesPerSec = f64ptr(float64(txBytes-ms.prevNetTxBytes) / elapsed)
			}
		}
		ms.prevNetRxBytes, ms.prevNetTxBytes = rxBytes, txBytes
	}

	ms.prevSampleAt = now
	ms.havePrevSample = true
	return m
}

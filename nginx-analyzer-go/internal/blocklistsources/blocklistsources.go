// Package blocklistsources porte lib/blocklist-sources.js : appartenance
// IP/CIDR par source de blocklist, synchronisee depuis nginx-dashboard
// (v12.29.0) pour que l'analyzer puisse attribuer un hit de blocklist a une
// source precise ("bySource") et, quand hit_logging_method vaut "approx",
// detecter les hits lui-meme directement depuis le(s) access log(s) qu'il
// tail deja plutot que d'exiger un blocklist-hits.log dedie.
//
// Seul le dashboard recupere et valide les sources de blocklist
// (features/blocklists.js) - ce paquet se contente de garder ce qu'il a
// recu en dernier, en memoire, exactement comme SetVhostRules() cote
// internal/rules : pas de persistance, pas de source de verite
// independante. Un analyzer redemarre a un index vide jusqu'au prochain push
// periodique du dashboard - degradation vers "pas encore d'attribution"
// plutot qu'une erreur.
package blocklistsources

import (
	"strings"
	"sync"

	"nginx-analyzer-go/internal/cidr"
)

type sourceEntry struct {
	name   string
	exact  map[string]struct{}
	blocks []*cidr.Block
}

var (
	mu    sync.Mutex
	index []sourceEntry
	mode  = "dedicated" // "dedicated" | "approx" - miroir de hit_logging_method cote nginx-dashboard
)

// Source reproduit la forme { ips: [pattern, ...] } que porte le cache
// blocklist du dashboard par source.
type Source struct {
	IPs []string
}

// SetSources replique setSources(). Les patterns invalides sont ignores
// silencieusement (le dashboard valide deja a la recuperation, mais ce
// paquet ne fait jamais confiance a un appelant qui pourrait changer).
func SetSources(sources map[string]Source) {
	next := make([]sourceEntry, 0, len(sources))
	for name, src := range sources {
		exact := map[string]struct{}{}
		var blocks []*cidr.Block
		for _, pattern := range src.IPs {
			block := cidr.ParseCidr(pattern)
			if block == nil {
				continue
			}
			isHostRoute := (block.Family == 4 && block.Prefix == 32) || (block.Family == 6 && block.Prefix == 128)
			if isHostRoute {
				exact[blockKey(block.Family, block.Bytes)] = struct{}{}
			} else {
				blocks = append(blocks, block)
			}
		}
		next = append(next, sourceEntry{name: name, exact: exact, blocks: blocks})
	}
	mu.Lock()
	index = next
	mu.Unlock()
}

func blockKey(family int, bytes []byte) string {
	parts := make([]string, len(bytes))
	for i, b := range bytes {
		parts[i] = itoa(int(b))
	}
	return itoa(family) + ":" + strings.Join(parts, ".")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// SetMode replique setMode() : tout ce qui n'est pas exactement "approx"
// retombe sur "dedicated".
func SetMode(m string) {
	mu.Lock()
	defer mu.Unlock()
	if m == "approx" {
		mode = "approx"
	} else {
		mode = "dedicated"
	}
}

// GetMode replique getMode().
func GetMode() string {
	mu.Lock()
	defer mu.Unlock()
	return mode
}

// SourcesContaining replique sourcesContaining() : quelles sources
// synchronisees listent actuellement ip. Vide tant que SetSources() n'a
// jamais tourne.
func SourcesContaining(ip string) []string {
	mu.Lock()
	defer mu.Unlock()
	if len(index) == 0 {
		return nil
	}
	addr := cidr.ToBytes(ip)
	if addr == nil {
		return nil
	}
	key := blockKey(addr.Family, addr.Bytes)
	var matches []string
	for _, src := range index {
		if _, ok := src.exact[key]; ok {
			matches = append(matches, src.name)
			continue
		}
		for _, block := range src.blocks {
			if cidr.ContainsParsed(addr, block) {
				matches = append(matches, src.name)
				break
			}
		}
	}
	return matches
}

// HasSources replique hasSources() : vrai des qu'au moins une source a ete
// synchronisee - permet aux appelants d'economiser du travail sinon.
func HasSources() bool {
	mu.Lock()
	defer mu.Unlock()
	return len(index) > 0
}

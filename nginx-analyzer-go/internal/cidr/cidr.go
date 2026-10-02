// Package cidr porte lib/cidr.js : correspondance IP/CIDR pour IPv4 et IPv6, ecrit a la main
// (pas de net.ParseIP/net.ParseCIDR) pour garder une parite exacte avec le comportement du
// Node — en particulier la gestion des adresses IPv4-mappees (::ffff:a.b.c.d) qui doivent
// matcher indifferemment un bloc v4 ou v6, et la tolerance aux espaces superflus.
package cidr

import (
	"regexp"
	"strconv"
	"strings"
)

// Addr est le pendant de { bytes, family } en JS.
type Addr struct {
	Bytes  []byte
	Family int // 4 ou 6
}

// Block est le pendant de { bytes, family, prefix } en JS.
type Block struct {
	Bytes  []byte
	Family int
	Prefix int
}

var reIPv4 = regexp.MustCompile(`^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$`)

// Ipv4ToBytes reproduit ipv4ToBytes().
func Ipv4ToBytes(ip string) []byte {
	m := reIPv4.FindStringSubmatch(ip)
	if m == nil {
		return nil
	}
	bytes := make([]byte, 4)
	for i := 1; i <= 4; i++ {
		part := m[i]
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || n > 255 {
			return nil
		}
		// String(n) !== m[i].replace(/^0+(?=\d)/, '') : rejette un zero non
		// significatif en tete (ex. "01"), mais "0" seul reste valide.
		trimmed := strings.TrimLeft(part, "0")
		if trimmed == "" {
			trimmed = "0"
		}
		if strconv.Itoa(n) != trimmed {
			return nil
		}
		bytes[i-1] = byte(n)
	}
	return bytes
}

var reHexGroup = regexp.MustCompile(`^[0-9a-fA-F]{1,4}$`)

// Ipv6ToBytes reproduit ipv6ToBytes().
func Ipv6ToBytes(ip string) []byte {
	if !strings.Contains(ip, ":") {
		return nil
	}
	head, tail := ip, ""
	dc := strings.Index(ip, "::")
	hasDC := dc != -1
	if hasDC {
		if strings.Index(ip[dc+1:], "::") != -1 {
			return nil
		}
		head = ip[:dc]
		tail = ip[dc+2:]
	}

	parseGroups := func(s string) []string {
		if s == "" {
			return nil
		}
		return strings.Split(s, ":")
	}
	headGroups := parseGroups(head)
	tailGroups := parseGroups(tail)

	expandV4Tail := func(groups []string) ([]string, bool) {
		if len(groups) == 0 {
			return groups, true
		}
		last := groups[len(groups)-1]
		if !strings.Contains(last, ".") {
			return groups, true
		}
		v4 := Ipv4ToBytes(last)
		if v4 == nil {
			return nil, false
		}
		g1 := (uint16(v4[0]) << 8) | uint16(v4[1])
		g2 := (uint16(v4[2]) << 8) | uint16(v4[3])
		out := append(append([]string{}, groups[:len(groups)-1]...),
			strconv.FormatUint(uint64(g1), 16), strconv.FormatUint(uint64(g2), 16))
		return out, true
	}
	var ok bool
	headGroups, ok = expandV4Tail(headGroups)
	if !ok {
		return nil
	}
	tailGroups, ok = expandV4Tail(tailGroups)
	if !ok {
		return nil
	}

	total := len(headGroups) + len(tailGroups)
	if !hasDC && total != 8 {
		return nil
	}
	if hasDC && total >= 8 {
		return nil
	}
	fill := 0
	if hasDC {
		fill = 8 - total
	}
	allGroups := make([]string, 0, 8)
	allGroups = append(allGroups, headGroups...)
	for i := 0; i < fill; i++ {
		allGroups = append(allGroups, "0")
	}
	allGroups = append(allGroups, tailGroups...)
	if len(allGroups) != 8 {
		return nil
	}

	bytes := make([]byte, 0, 16)
	for _, g := range allGroups {
		if !reHexGroup.MatchString(g) {
			return nil
		}
		n, err := strconv.ParseUint(g, 16, 32)
		if err != nil {
			return nil
		}
		bytes = append(bytes, byte((n>>8)&0xff), byte(n&0xff))
	}
	return bytes
}

// ToBytes reproduit toBytes() : renvoie nil si invalide.
func ToBytes(ip string) *Addr {
	if ip == "" {
		return nil
	}
	if v4 := Ipv4ToBytes(ip); v4 != nil {
		return &Addr{Bytes: v4, Family: 4}
	}
	if v6 := Ipv6ToBytes(ip); v6 != nil {
		return &Addr{Bytes: v6, Family: 6}
	}
	return nil
}

var rePrefix = regexp.MustCompile(`^\d{1,3}$`)

// ParseCidr reproduit parseCidr().
func ParseCidr(pattern string) *Block {
	pattern = strings.TrimSpace(pattern)
	i := strings.Index(pattern, "/")
	addr := pattern
	if i != -1 {
		addr = pattern[:i]
	}
	parsed := ToBytes(strings.TrimSpace(addr))
	if parsed == nil {
		return nil
	}
	maxPrefix := 32
	if parsed.Family == 6 {
		maxPrefix = 128
	}
	prefix := maxPrefix
	if i != -1 {
		prefixStr := strings.TrimSpace(pattern[i+1:])
		if !rePrefix.MatchString(prefixStr) {
			return nil
		}
		p, err := strconv.Atoi(prefixStr)
		if err != nil {
			return nil
		}
		prefix = p
		if prefix < 0 || prefix > maxPrefix {
			return nil
		}
	}
	return &Block{Bytes: parsed.Bytes, Family: parsed.Family, Prefix: prefix}
}

// MappedV4Bytes reproduit mappedV4Bytes().
func MappedV4Bytes(bytes16 []byte) []byte {
	if len(bytes16) != 16 {
		return nil
	}
	for i := 0; i < 10; i++ {
		if bytes16[i] != 0 {
			return nil
		}
	}
	if bytes16[10] != 0xff || bytes16[11] != 0xff {
		return nil
	}
	out := make([]byte, 4)
	copy(out, bytes16[12:16])
	return out
}

// ContainsParsed reproduit containsParsed().
func ContainsParsed(addr *Addr, block *Block) bool {
	if addr == nil || block == nil {
		return false
	}
	addrBytes, addrFamily := addr.Bytes, addr.Family
	blockBytes, blockFamily, blockPrefix := block.Bytes, block.Family, block.Prefix

	if addrFamily != blockFamily {
		if addrFamily == 6 && blockFamily == 4 {
			v4 := MappedV4Bytes(addrBytes)
			if v4 == nil {
				return false
			}
			addrBytes, addrFamily = v4, 4
		} else if addrFamily == 4 && blockFamily == 6 && blockPrefix >= 96 {
			v4 := MappedV4Bytes(blockBytes)
			if v4 == nil {
				return false
			}
			blockBytes, blockFamily = v4, 4
			blockPrefix -= 96
			if blockPrefix > 32 {
				blockPrefix = 32
			}
		} else {
			return false
		}
	}

	fullBytes := blockPrefix >> 3
	for i := 0; i < fullBytes; i++ {
		if addrBytes[i] != blockBytes[i] {
			return false
		}
	}
	remBits := blockPrefix % 8
	if remBits == 0 {
		return true
	}
	mask := byte((0xff << (8 - remBits)) & 0xff)
	return (addrBytes[fullBytes] & mask) == (blockBytes[fullBytes] & mask)
}

// IpInCidr reproduit ipInCidr().
func IpInCidr(ip, pattern string) bool {
	addr := ToBytes(ip)
	block := ParseCidr(pattern)
	return ContainsParsed(addr, block)
}

// IsValidPattern reproduit isValidPattern().
func IsValidPattern(pattern string) bool {
	return ParseCidr(pattern) != nil
}

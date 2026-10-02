// Package geoip fait des recherches GeoIP sur des bases MaxMind (.mmdb).
//
// Partage l'esprit du lecteur du dashboard Node : lit le format binaire
// .mmdb directement plutot que d'importer une bibliotheque, puisque seules
// des recherches ponctuelles IPv4/IPv6 sont necessaires. Le lecteur est
// deliberement minimal et renvoie nil sur tout ce qu'il ne comprend pas,
// pour qu'une base corrompue ou partiellement telechargee degrade en
// "pas de donnee geo" plutot que de faire tomber une requete.
//
// Les resultats sont mis en cache : un access log actif relirait sinon la
// base a chaque ligne.
package geoip

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"

	"nginx-analyzer-go/internal/cidr"
)

func envStr(name, def string) string {
	v, ok := os.LookupEnv(name)
	if !ok {
		return def
	}
	return strings.TrimSpace(v)
}

var (
	CityDB    = envStr("GEOIP_CITY_DB", "/geoip/GeoLite2-City.mmdb")
	CountryDB = envStr("GEOIP_COUNTRY_DB", "/geoip/GeoLite2-Country.mmdb")
	ASNDB     = envStr("GEOIP_ASN_DB", "/geoip/GeoLite2-ASN.mmdb")
)

// Result reproduit l'objet retourne par geoipLookup().
type Result struct {
	IP      string
	Country string
	City    string
	ASN     string
	Org     string
}

// cache borne — vide par moities plutot que de suivre un ordre LRU exact,
// suffisant pour une recherche bon marche a recalculer.
var (
	cacheMu sync.Mutex
	cache   = map[string]*Result{}
)

const maxCacheSize = 20000
const evictCount = 1000

func geoipCached(ip string) *Result {
	cacheMu.Lock()
	if r, ok := cache[ip]; ok {
		cacheMu.Unlock()
		return r
	}
	cacheMu.Unlock()

	result := geoipLookup(ip)

	cacheMu.Lock()
	if len(cache) > maxCacheSize {
		n := 0
		for k := range cache {
			if n >= evictCount {
				break
			}
			delete(cache, k)
			n++
		}
	}
	cache[ip] = result
	cacheMu.Unlock()
	return result
}

func geoipLookup(ip string) *Result {
	result := &Result{IP: ip}
	if city := mmdbLookup(CityDB, ip); city != nil {
		if iso, ok := stringAt(city, "country", "iso_code"); ok {
			result.Country = iso
		} else if iso, ok := stringAt(city, "registered_country", "iso_code"); ok {
			result.Country = iso
		}
		if name, ok := stringAt(city, "city", "names", "en"); ok {
			result.City = name
		}
	} else if country := mmdbLookup(CountryDB, ip); country != nil {
		if iso, ok := stringAt(country, "country", "iso_code"); ok {
			result.Country = iso
		}
	}
	if asn := mmdbLookup(ASNDB, ip); asn != nil {
		if n, ok := numberAt(asn, "autonomous_system_number"); ok && n != 0 {
			result.ASN = "AS" + strconv.FormatInt(n, 10)
		}
		if org, ok := stringAt(asn, "autonomous_system_organization"); ok {
			result.Org = org
		}
	}
	if result.Country == "" && result.ASN == "" {
		return nil
	}
	return result
}

// stringAt navigue une map[string]any imbriquee (decodee du MMDB) et lit une
// chaine au chemin donne.
func stringAt(m any, path ...string) (string, bool) {
	cur := m
	for _, key := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		cur, ok = mm[key]
		if !ok {
			return "", false
		}
	}
	s, ok := cur.(string)
	return s, ok
}

func numberAt(m any, path ...string) (int64, bool) {
	cur := m
	for _, key := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return 0, false
		}
		cur, ok = mm[key]
		if !ok {
			return 0, false
		}
	}
	switch v := cur.(type) {
	case int64:
		return v, true
	case uint64:
		return int64(v), true
	case int:
		return int64(v), true
	}
	return 0, false
}

// bufIndexOf cherche needle dans buf en partant de la fin.
func bufIndexOf(buf, needle []byte) int {
	for i := len(buf) - len(needle); i >= 0; i-- {
		if bytes.Equal(buf[i:i+len(needle)], needle) {
			return i
		}
	}
	return -1
}

// readNode lit un enregistrement d'un noeud de l'arbre de recherche. bit
// selectionne la branche gauche (0) ou droite (1). Les tailles
// d'enregistrement autres que 24, 28 et 32 bits ne se rencontrent pas en
// pratique. -1 signale une erreur (hors limites).
func readNode(buf []byte, node, nodeSize, recordSize, bit int) int {
	offset := node * nodeSize
	if offset+nodeSize > len(buf) {
		return -1
	}
	switch recordSize {
	case 24:
		if bit == 0 {
			return int(buf[offset])<<16 | int(buf[offset+1])<<8 | int(buf[offset+2])
		}
		return int(buf[offset+3])<<16 | int(buf[offset+4])<<8 | int(buf[offset+5])
	case 28:
		if bit == 0 {
			return int(buf[offset+3]&0xf0)<<20 | int(buf[offset])<<16 | int(buf[offset+1])<<8 | int(buf[offset+2])
		}
		return int(buf[offset+3]&0x0f)<<24 | int(buf[offset+4])<<16 | int(buf[offset+5])<<8 | int(buf[offset+6])
	case 32:
		if bit == 0 {
			return int(binary.BigEndian.Uint32(buf[offset : offset+4]))
		}
		return int(binary.BigEndian.Uint32(buf[offset+4 : offset+8]))
	}
	return -1
}

var mmdbMarker = []byte{0xab, 0xcd, 0xef, 0x4d, 0x61, 0x78, 0x4d, 0x69, 0x6e, 0x64, 0x2e, 0x63, 0x6f, 0x6d}

type dbEntry struct {
	mtime      int64
	size       int64
	buf        []byte
	meta       map[string]any
	nodeCount  int
	recordSize int
	nodeSize   int
	dataStart  int
}

var (
	dbCacheMu sync.Mutex
	dbCache   = map[string]*dbEntry{}
)

func loadDb(dbPath string) *dbEntry {
	st, err := os.Stat(dbPath)
	if err != nil {
		dbCacheMu.Lock()
		delete(dbCache, dbPath)
		dbCacheMu.Unlock()
		return nil
	}
	mtime := st.ModTime().UnixNano()
	size := st.Size()

	dbCacheMu.Lock()
	cached, ok := dbCache[dbPath]
	dbCacheMu.Unlock()
	if ok && cached.mtime == mtime && cached.size == size {
		return cached
	}

	buf, err := os.ReadFile(dbPath)
	if err != nil {
		return nil
	}
	markerPos := bufIndexOf(buf, mmdbMarker)
	if markerPos < 0 {
		return nil
	}
	metaAny, _ := decodeMmdbValue(buf, markerPos+len(mmdbMarker), markerPos+len(mmdbMarker))
	meta, _ := metaAny.(map[string]any)
	if meta == nil {
		meta = map[string]any{}
	}
	nodeCount := int(asInt(meta["node_count"]))
	recordSize := int(asInt(meta["record_size"]))
	if recordSize == 0 {
		recordSize = 28
	}
	nodeSize := (recordSize*2 + 7) / 8
	dataStart := nodeCount*nodeSize + 16 // separateur de 16 octets

	entry := &dbEntry{
		mtime: mtime, size: size, buf: buf, meta: meta,
		nodeCount: nodeCount, recordSize: recordSize, nodeSize: nodeSize, dataStart: dataStart,
	}
	dbCacheMu.Lock()
	dbCache[dbPath] = entry
	dbCacheMu.Unlock()
	return entry
}

func asInt(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case uint64:
		return int64(n)
	case int:
		return int64(n)
	}
	return 0
}

// addrBits donne les octets d'adresse pour parcourir l'arbre, et combien de
// bits parcourir.
//
// Une adresse IPv6-mappee (::ffff:a.b.c.d) est depaquetee vers ses 4 octets
// embarques, puisque c'est la meme adresse que a.b.c.d et doit renvoyer le
// meme resultat dans les deux cas.
func addrBits(ip string) ([]byte, int, bool) {
	if v4 := cidr.Ipv4ToBytes(ip); v4 != nil {
		return v4, 32, true
	}
	v6 := cidr.Ipv6ToBytes(ip)
	if v6 == nil {
		return nil, 0, false
	}
	if mapped := cidr.MappedV4Bytes(v6); mapped != nil {
		return mapped, 32, true
	}
	return v6, 128, true
}

// mmdbLookup est un lecteur binaire MMDB minimal — prend en charge les
// recherches IPv4 et IPv6 au format MaxMind DB.
func mmdbLookup(dbPath, ip string) map[string]any {
	db := loadDb(dbPath)
	if db == nil {
		return nil
	}
	bytesAddr, bitLength, ok := addrBits(ip)
	if !ok {
		return nil
	}

	ipVersion := int(asInt(db.meta["ip_version"]))

	node := 0
	if ipVersion == 6 && bitLength == 32 {
		// Dans une base IPv6, les adresses IPv4 vivent sous ::/96. Atteindre
		// ce sous-arbre signifie parcourir 96 bits a zero depuis la racine,
		// pas sauter au "noeud 96" - l'index du noeud et la profondeur en
		// bits sont sans rapport.
		for i := 0; i < 96 && node < db.nodeCount; i++ {
			node = readNode(db.buf, node, db.nodeSize, db.recordSize, 0)
			if node < 0 {
				return nil
			}
		}
		if node >= db.nodeCount {
			return nil // pas de sous-arbre IPv4
		}
	} else if ipVersion == 4 && bitLength == 128 {
		// Une vraie adresse IPv6 (non mappee) n'a pas de sens dans une base
		// IPv4 uniquement.
		return nil
	}

	for i := 0; i < bitLength; i++ {
		bit := (bytesAddr[i/8] >> (7 - uint(i%8))) & 1
		node = readNode(db.buf, node, db.nodeSize, db.recordSize, int(bit))
		if node < 0 {
			return nil
		}
		if node >= db.nodeCount {
			break
		}
	}
	if node <= db.nodeCount {
		return nil
	}
	dataOffset := db.dataStart + (node - db.nodeCount - 16)
	if dataOffset >= len(db.buf) {
		return nil
	}
	val, _ := decodeMmdbValue(db.buf, dataOffset, db.dataStart)
	m, _ := val.(map[string]any)
	return m
}

// decodeMmdbValue decode une valeur MMDB (type control byte + charge utile)
// a la position pos. dataStart est le debut de la section donnees, utilise
// pour resoudre les pointeurs.
func decodeMmdbValue(buf []byte, pos, dataStart int) (any, int) {
	if pos < 0 || pos >= len(buf) {
		return nil, pos
	}
	ctrl := buf[pos]
	pos++
	typ := int(ctrl>>5) & 0x7
	size := int(ctrl & 0x1f)
	if typ == 0 {
		if pos >= len(buf) {
			return nil, pos
		}
		typ = int(buf[pos]) + 7
		pos++
	}
	if size == 29 {
		if pos >= len(buf) {
			return nil, pos
		}
		size = int(buf[pos]) + 29
		pos++
	} else if size == 30 {
		if pos+1 >= len(buf) {
			return nil, pos
		}
		size = int(buf[pos])<<8 | int(buf[pos+1])
		size += 285
		pos += 2
	} else if size == 31 {
		if pos+2 >= len(buf) {
			return nil, pos
		}
		size = int(buf[pos])<<16 | int(buf[pos+1])<<8 | int(buf[pos+2])
		size += 65821
		pos += 3
	}

	switch typ {
	case 1: // pointeur
		psize := (size >> 3) & 0x3
		ptr := size & 0x7
		switch psize {
		case 0:
			if pos >= len(buf) {
				return nil, pos
			}
			ptr = ptr<<8 | int(buf[pos])
			pos++
		case 1:
			if pos+1 >= len(buf) {
				return nil, pos
			}
			ptr = ptr<<16 | int(buf[pos])<<8 | int(buf[pos+1])
			ptr += 2048
			pos += 2
		case 2:
			if pos+2 >= len(buf) {
				return nil, pos
			}
			ptr = ptr<<24 | int(buf[pos])<<16 | int(buf[pos+1])<<8 | int(buf[pos+2])
			ptr += 526336
			pos += 3
		}
		v, _ := decodeMmdbValue(buf, dataStart+ptr, dataStart)
		return v, pos
	case 2: // utf8
		if pos+size > len(buf) {
			return nil, pos + size
		}
		return string(buf[pos : pos+size]), pos + size
	case 5: // uint16
		var v uint64
		for i := 0; i < size && pos+i < len(buf); i++ {
			v = v<<8 | uint64(buf[pos+i])
		}
		return v, pos + size
	case 6: // uint32
		var v uint64
		for i := 0; i < size && pos+i < len(buf); i++ {
			v = v<<8 | uint64(buf[pos+i])
		}
		return v, pos + size
	case 7: // map
		obj := map[string]any{}
		p := pos
		for i := 0; i < size; i++ {
			var k, v any
			k, p = decodeMmdbValue(buf, p, dataStart)
			v, p = decodeMmdbValue(buf, p, dataStart)
			if ks, ok := k.(string); ok {
				obj[ks] = v
			}
		}
		return obj, p
	case 8: // int32
		var v int64
		for i := 0; i < size && pos+i < len(buf); i++ {
			v = v<<8 | int64(buf[pos+i])
		}
		if size == 4 && v&0x80000000 != 0 {
			v = -(^v&0xffffffff + 1)
		}
		return v, pos + size
	case 9: // uint64 (retourne en int64, perte de precision acceptable pour un ASN)
		var v int64
		for i := 0; i < size && pos+i < len(buf); i++ {
			v = v*256 + int64(buf[pos+i])
		}
		return v, pos + size
	case 11: // array
		arr := make([]any, 0, size)
		p := pos
		for i := 0; i < size; i++ {
			var v any
			v, p = decodeMmdbValue(buf, p, dataStart)
			arr = append(arr, v)
		}
		return arr, p
	case 14: // bool true
		return true, pos
	case 15: // bool false
		return false, pos
	default:
		return nil, pos + size
	}
}

// CountryOf renvoie le code pays d'une adresse, ou "". Chemin chaud : appele
// par requete.
func CountryOf(ip string) string {
	g := geoipCached(ip)
	if g == nil {
		return ""
	}
	return g.Country
}

var ready bool

// Init detecte si une base MaxMind est presente.
func Init() bool {
	_, errCountry := os.Stat(CountryDB)
	_, errCity := os.Stat(CityDB)
	ready = errCountry == nil || errCity == nil
	if !ready {
		log.Println("[geoip] Aucune base MaxMind trouvee — pas de ventilation par pays")
	}
	return ready
}

// Status reproduit status().
type StatusInfo struct {
	Available bool
	Database  string
	Cached    int
}

func Status() StatusInfo {
	db := ""
	if _, err := os.Stat(CityDB); err == nil {
		db = CityDB
	} else if _, err := os.Stat(CountryDB); err == nil {
		db = CountryDB
	}
	cacheMu.Lock()
	n := len(cache)
	cacheMu.Unlock()
	return StatusInfo{Available: ready, Database: db, Cached: n}
}

// GeoipLookup expose geoipLookup() pour les tests / usages avances.
func GeoipLookup(ip string) *Result { return geoipLookup(ip) }

// MmdbLookup expose mmdbLookup() pour les tests / usages avances. Renvoie la
// map[string]any decodee brute (equivalent de l'objet JS decode).
func MmdbLookup(dbPath, ip string) map[string]any { return mmdbLookup(dbPath, ip) }

// GeoipCached expose geoipCached() pour les tests.
func GeoipCached(ip string) *Result { return geoipCached(ip) }

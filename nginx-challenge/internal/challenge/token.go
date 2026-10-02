package challenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var b64 = base64.RawURLEncoding

// ClientKey normalise l'adresse liée au cookie : IPv4 telle quelle ; IPv6
// réduite à son préfixe /64 (les adresses « à vie privée » changent en
// permanence dans un même /64). bindIP=false renvoie une clé constante.
// Une adresse invalide donne "" (à refuser).
func ClientKey(ip string, bindIP bool) string {
	p := net.ParseIP(strings.TrimSpace(ip))
	if p == nil {
		return ""
	}
	if !bindIP {
		return "*"
	}
	if v4 := p.To4(); v4 != nil {
		return v4.String()
	}
	return p.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// HostOnly met le nom d'hôte en minuscules et retire le port.
func HostOnly(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	return h
}

// Signer produit et vérifie jetons de défi et cookies.
type Signer struct {
	secret []byte
	bits   int
	cookie time.Duration
	token  time.Duration
	now    func() time.Time
}

// NewSigner construit un Signer à partir de la configuration.
func NewSigner(c Config) *Signer {
	return &Signer{secret: c.Secret, bits: c.Bits, cookie: c.CookieTTL, token: c.TokenTTL, now: time.Now}
}

func (s *Signer) mac(parts ...string) string {
	m := hmac.New(sha256.New, s.secret)
	for _, p := range parts {
		m.Write([]byte(p))
		m.Write([]byte{0})
	}
	return b64.EncodeToString(m.Sum(nil))
}

func eq(a, b string) bool { return hmac.Equal([]byte(a), []byte(b)) }

// NewChallenge émet un jeton de défi lié au client et à l'hôte :
// v1.<émis>.<bits>.<sel>.<signature>.
func (s *Signer) NewChallenge(key, host string) (string, error) {
	salt := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	issued := strconv.FormatInt(s.now().Unix(), 10)
	bits := strconv.Itoa(s.bits)
	sl := hex.EncodeToString(salt)
	sig := s.mac("chal", key, host, issued, bits, sl)
	return strings.Join([]string{"v1", issued, bits, sl, sig}, "."), nil
}

// CheckChallenge valide la signature, la liaison (client + hôte) et l'âge du
// jeton ; renvoie le nombre de bits de difficulté.
func (s *Signer) CheckChallenge(token, key, host string) (int, bool) {
	p := strings.Split(token, ".")
	if len(p) != 5 || p[0] != "v1" || len(token) > 200 {
		return 0, false
	}
	issued, err := strconv.ParseInt(p[1], 10, 64)
	if err != nil {
		return 0, false
	}
	bits, err := strconv.Atoi(p[2])
	if err != nil || bits < 1 || bits > 64 {
		return 0, false
	}
	age := s.now().Unix() - issued
	if age < -30 || age > int64(s.token/time.Second) {
		return 0, false
	}
	if !eq(s.mac("chal", key, host, p[1], p[2], p[3]), p[4]) {
		return 0, false
	}
	return bits, true
}

// SolutionOK vérifie la preuve de travail : SHA-256(jeton ":" compteur) doit
// commencer par au moins `bits` bits à zéro.
func SolutionOK(token, counter string, bits int) bool {
	if counter == "" || len(counter) > 16 {
		return false
	}
	for _, r := range counter {
		if r < '0' || r > '9' {
			return false
		}
	}
	sum := sha256.Sum256([]byte(token + ":" + counter))
	return LeadingZeroBits(sum[:]) >= bits
}

// LeadingZeroBits compte les bits à zéro en tête.
func LeadingZeroBits(b []byte) int {
	n := 0
	for _, v := range b {
		if v == 0 {
			n += 8
			continue
		}
		for m := byte(0x80); m != 0 && v&m == 0; m >>= 1 {
			n++
		}
		break
	}
	return n
}

// NewCookie émet la valeur du cookie « humain vérifié » : v1.<expiration>.<signature>.
func (s *Signer) NewCookie(key, host string) (value string, expires time.Time) {
	expires = s.now().Add(s.cookie)
	exp := strconv.FormatInt(expires.Unix(), 10)
	return "v1." + exp + "." + s.mac("cookie", key, host, exp), expires
}

// CheckCookie valide un cookie pour ce client et cet hôte.
func (s *Signer) CheckCookie(value, key, host string) bool {
	p := strings.Split(value, ".")
	if len(p) != 3 || p[0] != "v1" || len(value) > 200 {
		return false
	}
	exp, err := strconv.ParseInt(p[1], 10, 64)
	if err != nil || exp < s.now().Unix() {
		return false
	}
	return eq(s.mac("cookie", key, host, p[1]), p[2])
}

// SafeTarget ne renvoie que des chemins relatifs sûrs (jamais d'URL absolue,
// ni "//hôte", ni antislash, ni caractère de contrôle) ; sinon "/". Évite la
// redirection ouverte et les boucles vers la page de défi elle-même.
func SafeTarget(t string) string {
	if t == "" || len(t) > 2048 || t[0] != '/' || strings.HasPrefix(t, "//") {
		return "/"
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if c < 0x20 || c == 0x7f || c == '\\' {
			return "/"
		}
	}
	u, err := url.ParseRequestURI(t)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return "/"
	}
	if strings.HasPrefix(strings.ToLower(u.Path), "/.nc-challenge") {
		return "/"
	}
	return t
}

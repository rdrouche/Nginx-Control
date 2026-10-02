// Package challenge implémente le service « nginx-challenge » : une page de
// vérification navigateur (preuve de travail) qui délivre un cookie signé, et
// un point de contrôle (/check) appelé par nginx via auth_request.
//
// Aucune dépendance externe, aucun état persistant : le secret de signature
// suffit. Si NC_SECRET est absent : avec NC_SECRET_FILE, le secret est tiré une
// fois et conservé dans ce fichier ; sans, il est aléatoire à chaque démarrage
// (les cookies ne survivent pas à un redémarrage).
package challenge

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config regroupe les réglages du service (variables d'environnement NC_*).
type Config struct {
	Bind            string        // NC_BIND, défaut ":8080"
	StatsFile       string        // stats.json à côté de NC_SECRET_FILE (vide = mémoire seule)
	Secret          []byte        // NC_SECRET / NC_SECRET_FILE (>= 32 octets)
	SecretGenerated bool          // vrai si tiré au hasard au démarrage
	Bits            int           // NC_DIFFICULTY_BITS (8..64), défaut 16
	CookieName      string        // NC_COOKIE_NAME, défaut "nc_chal"
	CookieTTL       time.Duration // NC_COOKIE_HOURS (1..720), défaut 24
	TokenTTL        time.Duration // NC_TOKEN_SECONDS (30..900), défaut 300
	BindIP          bool          // NC_BIND_IP, défaut true : cookie lié à l'IP (/64 en IPv6)
	Secure          bool          // NC_COOKIE_SECURE, défaut true
	RateLimit       int           // NC_RATE_PER_MIN (1..600), défaut 30 appels /api par IP et par minute
	Lang            string        // NC_LANG : auto (Accept-Language, repli en), fr ou en
	GoodBots        bool          // NC_GOODBOTS, défaut true : robots d'indexation vérifiés (si le vhost l'autorise)
	ExtraBots       []BotRule     // NC_GOODBOTS_EXTRA : règles supplémentaires nom|regex|.suffixe
}

const minSecretLen = 32

// LoadConfig lit la configuration depuis getenv (os.Getenv en production).
func LoadConfig(getenv func(string) string) (Config, error) {
	c := Config{
		Bind: ":8080", Bits: 16, CookieName: "nc_chal", CookieTTL: 24 * time.Hour,
		TokenTTL: 5 * time.Minute, BindIP: true, Secure: true, RateLimit: 30, GoodBots: true,
	}
	if v := strings.TrimSpace(getenv("NC_BIND")); v != "" {
		c.Bind = v
	}
	secret := strings.TrimSpace(getenv("NC_SECRET"))
	c.StatsFile = statsPathFor(strings.TrimSpace(getenv("NC_SECRET_FILE")))
	if f := strings.TrimSpace(getenv("NC_SECRET_FILE")); f != "" && secret == "" {
		b, err := os.ReadFile(f)
		switch {
		case err == nil:
			secret = strings.TrimSpace(string(b))
		case errors.Is(err, os.ErrNotExist):
			// Absent : on tire un secret et on le conserve (comme le secret de session
			// du dashboard), pour que les cookies survivent aux redémarrages.
			raw := make([]byte, 32)
			if _, rerr := rand.Read(raw); rerr != nil {
				return c, rerr
			}
			secret = hex.EncodeToString(raw)
			if werr := os.WriteFile(f, []byte(secret+"\n"), 0o600); werr != nil {
				return c, fmt.Errorf("NC_SECRET_FILE non inscriptible : %w", werr)
			}
		default:
			return c, fmt.Errorf("NC_SECRET_FILE illisible : %w", err)
		}
	}
	switch {
	case secret == "":
		c.Secret = make([]byte, 32)
		if _, err := rand.Read(c.Secret); err != nil {
			return c, err
		}
		c.SecretGenerated = true
	case len(secret) < minSecretLen:
		return c, fmt.Errorf("NC_SECRET trop court (%d caractères, minimum %d)", len(secret), minSecretLen)
	default:
		c.Secret = []byte(secret)
	}
	var err error
	if c.Bits, err = intEnv(getenv, "NC_DIFFICULTY_BITS", c.Bits, 8, 64); err != nil {
		return c, err
	}
	hours, err := intEnv(getenv, "NC_COOKIE_HOURS", int(c.CookieTTL/time.Hour), 1, 720)
	if err != nil {
		return c, err
	}
	c.CookieTTL = time.Duration(hours) * time.Hour
	secs, err := intEnv(getenv, "NC_TOKEN_SECONDS", int(c.TokenTTL/time.Second), 30, 900)
	if err != nil {
		return c, err
	}
	c.TokenTTL = time.Duration(secs) * time.Second
	if c.RateLimit, err = intEnv(getenv, "NC_RATE_PER_MIN", c.RateLimit, 1, 600); err != nil {
		return c, err
	}
	if v := strings.TrimSpace(getenv("NC_COOKIE_NAME")); v != "" {
		if !validCookieName(v) {
			return c, errors.New("NC_COOKIE_NAME invalide (lettres, chiffres, _ et - uniquement)")
		}
		c.CookieName = v
	}
	if c.BindIP, err = boolEnv(getenv, "NC_BIND_IP", c.BindIP); err != nil {
		return c, err
	}
	if c.Secure, err = boolEnv(getenv, "NC_COOKIE_SECURE", c.Secure); err != nil {
		return c, err
	}
	switch l := strings.ToLower(strings.TrimSpace(getenv("NC_LANG"))); l {
	case "", "auto":
		c.Lang = "auto"
	case "fr", "en":
		c.Lang = l
	default:
		return c, fmt.Errorf("NC_LANG : auto, fr ou en attendu")
	}
	if c.GoodBots, err = boolEnv(getenv, "NC_GOODBOTS", c.GoodBots); err != nil {
		return c, err
	}
	if c.ExtraBots, err = ParseExtraBotRules(getenv("NC_GOODBOTS_EXTRA")); err != nil {
		return c, err
	}
	return c, nil
}

func validCookieName(s string) bool {
	if s == "" || len(s) > 40 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func intEnv(getenv func(string) string, name string, def, lo, hi int) (int, error) {
	v := strings.TrimSpace(getenv(name))
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		return 0, fmt.Errorf("%s doit être un entier entre %d et %d", name, lo, hi)
	}
	return n, nil
}

func boolEnv(getenv func(string) string, name string, def bool) (bool, error) {
	v := strings.ToLower(strings.TrimSpace(getenv(name)))
	switch v {
	case "":
		return def, nil
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("%s doit valoir true ou false", name)
}

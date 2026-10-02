// Package store porte lib/store.js : agregation et stockage.
//
// Les lignes de log brutes ne sont jamais gardees : un serveur charge en
// produit des millions par jour et l'analyseur deviendrait le probleme disque
// qu'il est cense signaler. Le trafic est reduit en buckets par minute, cles
// par (vhost, pays, classe de statut, methode) — suffisant pour repondre a
// toutes les questions du dashboard.
//
// La retention est par paliers — minutes pendant un jour, heures pendant un
// mois, jours pendant un an. Promouvoir plutot que supprimer garde
// l'historique long terme disponible a cout constant, et la baseline
// volumetrique a besoin de semaines d'historique pour avoir un sens.
//
// Cote Node, ce module s'appuie sur node:sqlite (integre a Node 22) pour
// rester sans dependance comme le dashboard. Cote Go, modernc.org/sqlite
// (choix initial du projet, pur Go/CGO-free) est inaccessible depuis ce
// bac a sable de developpement (hote bloque par la politique reseau) ; le
// pilote retenu ici, github.com/ncruces/go-sqlite3, est egalement pur Go
// (SQLite compile en WASM, execute via wazero), sans CGO, et garde donc le
// meme objectif de binaire statique multi-arch facile sur Alpine. Si
// l'ouverture echoue, l'agent degrade en memoire seule plutot que de refuser
// de demarrer : la detection de signatures continue de fonctionner, seul
// l'historique est perdu.
package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	_ "github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/embed"
)

// Retention definit les paliers de conservation, cf. RETENTION en JS.
type Retention struct {
	MinuteHours int
	HourDays    int
	DayDays     int
}

// DefaultRetention reproduit RETENTION.
var DefaultRetention = Retention{MinuteHours: 24, HourDays: 30, DayDays: 365}

// Entry est le sous-ensemble d'un acces log necessaire a record()/recordBot().
// Decouple de internal/parse pour que store reste reutilisable independamment
// du format d'origine (l'orchestrateur d'ingestion fera la conversion).
type Entry struct {
	Ts     int64 // epoch ms
	Vhost  string
	Status int
	Method string
	Bytes  int64
}

type bucketKey struct {
	bucket  int64 // epoch secondes, tronque
	grain   string
	vhost   string
	country string
	status  int // classe de statut : 2,3,4,5
	method  string
}

type bucketVal struct {
	requests int64
	bytes    int64
}

type botBucketKey struct {
	bucket   int64
	grain    string
	vhost    string
	category string
	country  string
}

// Alert reproduit la forme d'une ligne de la table alerts / this.memory.alerts.
type Alert struct {
	ID       int64
	Ts       int64
	Type     string
	Severity string
	IP       string
	Vhost    string
	Summary  string
	Evidence any // decode JSON en mode SQLite ; valeur d'origine en mode memoire
	Acked    bool
}

// AlertInput reproduit l'argument attendu par addAlert().
type AlertInput struct {
	Type     string
	Severity string
	IP       string // optionnel, sinon derive de Evidence["ip"]
	Vhost    string // optionnel, sinon derive de Evidence["vhost"]
	Summary  string
	Evidence map[string]any
}

// Exception reproduit une ligne de la table exceptions.
type Exception struct {
	ID      int64
	Vhost   string
	IP      string
	Reason  string
	Created int64
	Author  string
}

// WafMessage reproduit un element du tableau JSON "messages" d'un evenement WAF.
type WafMessage struct {
	RuleID   string   `json:"ruleId"`
	Message  string   `json:"message"`
	Severity string   `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

// WafEvent reproduit une ligne (ou son equivalent memoire) de waf_events.
type WafEvent struct {
	ID       int64
	Ts       int64
	Vhost    string
	IP       string
	Method   string
	URI      string
	Status   int
	Blocked  bool
	Severity string
	RuleIDs  []string
	Messages []WafMessage
	UniqueID string
	Engine   string
	Raw      string
}

// BlocklistHit reproduit une ligne de blocklist_hits.
type BlocklistHit struct {
	ID     int64
	Ts     int64
	IP     string
	Vhost  string
	Method string
	URI    string
	Status int
}

// Store est le pendant de la classe Store en JS.
type Store struct {
	mu        sync.Mutex
	dbPath    string
	retention Retention
	db        *sql.DB // nil si non persistant (degrade en memoire)

	memBuckets    map[bucketKey]*bucketVal
	memBotBuckets map[botBucketKey]int64
	memAlerts     []Alert
	memAlertSeq   int64
	memExceptions []Exception
	memWaf        []WafEvent
	memWafSeq     int64
	memBlocklist  []BlocklistHit
	memBlockSeq   int64
}

// Options reproduit le deuxieme argument optionnel du constructeur JS.
type Options struct {
	Retention Retention // champs a zero ignores (fusion avec DefaultRetention)
}

// New ouvre (ou degrade en memoire) un Store a dbPath.
func New(dbPath string, opts ...Options) *Store {
	ret := DefaultRetention
	if len(opts) > 0 {
		if opts[0].Retention.MinuteHours > 0 {
			ret.MinuteHours = opts[0].Retention.MinuteHours
		}
		if opts[0].Retention.HourDays > 0 {
			ret.HourDays = opts[0].Retention.HourDays
		}
		if opts[0].Retention.DayDays > 0 {
			ret.DayDays = opts[0].Retention.DayDays
		}
	}
	s := &Store{
		dbPath:        dbPath,
		retention:     ret,
		memBuckets:    make(map[bucketKey]*bucketVal),
		memBotBuckets: make(map[botBucketKey]int64),
	}
	s.open()
	return s
}

const schema = `
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS traffic (
  bucket    INTEGER NOT NULL,
  grain     TEXT    NOT NULL,
  vhost     TEXT    NOT NULL,
  country   TEXT,
  status    INTEGER NOT NULL,
  method    TEXT    NOT NULL,
  requests  INTEGER NOT NULL DEFAULT 0,
  bytes     INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (bucket, grain, vhost, country, status, method)
);
CREATE INDEX IF NOT EXISTS idx_traffic_bucket ON traffic(grain, bucket);

CREATE TABLE IF NOT EXISTS bot_traffic (
  bucket    INTEGER NOT NULL,
  grain     TEXT    NOT NULL,
  vhost     TEXT    NOT NULL,
  category  TEXT    NOT NULL,
  country   TEXT,
  requests  INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (bucket, grain, vhost, category, country)
);
CREATE INDEX IF NOT EXISTS idx_bot_traffic_bucket ON bot_traffic(grain, bucket);

CREATE TABLE IF NOT EXISTS alerts (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  ts        INTEGER NOT NULL,
  type      TEXT    NOT NULL,
  severity  TEXT    NOT NULL,
  ip        TEXT,
  vhost     TEXT,
  summary   TEXT    NOT NULL,
  evidence  TEXT,
  acked     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);

CREATE TABLE IF NOT EXISTS state (
  key   TEXT PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS exceptions (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  vhost   TEXT    NOT NULL,
  ip      TEXT    NOT NULL,
  reason  TEXT,
  created INTEGER NOT NULL,
  author  TEXT,
  UNIQUE (vhost, ip)
);
CREATE INDEX IF NOT EXISTS idx_exceptions_vhost ON exceptions(vhost);

CREATE TABLE IF NOT EXISTS waf_events (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  ts       INTEGER NOT NULL,
  vhost    TEXT    NOT NULL,
  ip       TEXT,
  method   TEXT,
  uri      TEXT,
  status   INTEGER,
  blocked  INTEGER NOT NULL DEFAULT 0,
  severity TEXT,
  ruleIds  TEXT,
  messages TEXT,
  uniqueId TEXT,
  engine   TEXT,
  raw      TEXT
);
CREATE INDEX IF NOT EXISTS idx_waf_ts    ON waf_events(ts);
CREATE INDEX IF NOT EXISTS idx_waf_vhost ON waf_events(vhost, ts);

CREATE TABLE IF NOT EXISTS blocklist_hits (
  id     INTEGER PRIMARY KEY AUTOINCREMENT,
  ts     INTEGER NOT NULL,
  ip     TEXT,
  vhost  TEXT,
  method TEXT,
  uri    TEXT,
  status INTEGER
);
CREATE INDEX IF NOT EXISTS idx_blocklist_hits_ts ON blocklist_hits(ts);
CREATE INDEX IF NOT EXISTS idx_blocklist_hits_ip ON blocklist_hits(ip);

CREATE TABLE IF NOT EXISTS offsets (
  file   TEXT PRIMARY KEY,
  inode  INTEGER,
  offset INTEGER,
  format TEXT
);
`

// open reproduit _open() : tente SQLite, degrade en memoire sur toute erreur.
func (s *Store) open() {
	db, err := s.tryOpen()
	if err != nil {
		fmt.Printf("[store] SQLite indisponible, fonctionnement en memoire seule: %v\n", err)
		s.db = nil
		return
	}
	s.db = db
	fmt.Printf("[store] SQLite pret: %s\n", s.dbPath)
}

func (s *Store) tryOpen() (db *sql.DB, err error) {
	// Le pilote SQLite execute SQLite en WebAssembly (wazero) : sur un hote qui
	// refuse la memoire executable ou une allocation, l'initialisation peut
	// paniquer. Comme toute autre erreur d'ouverture, cela doit mener au repli
	// memoire (l'API reste joignable) et non faire tomber l'agent.
	defer func() {
		if r := recover(); r != nil {
			db, err = nil, fmt.Errorf("panique a l'ouverture de SQLite: %v", r)
		}
	}()
	if dir := filepath.Dir(s.dbPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	dsn := "file:" + s.dbPath + "?_pragma=busy_timeout(5000)"
	db, err = sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	// Une seule connexion : reproduit le comportement synchrone et
	// mono-thread de node:sqlite, et evite tout "database is locked" entre
	// plusieurs connexions du pool database/sql vers le meme fichier.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	if err := migrateWafColumns(db); err != nil {
		// Une ALTER TABLE qui echoue (colonne deja presente) n'est pas fatale.
		_ = err
	}
	if err := migrateBotTrafficKey(db); err != nil {
		fmt.Printf("[store] Migration de bot_traffic echouee: %v\n", err)
	}
	return db, nil
}

// migrateWafColumns ajoute engine/raw sur une base creee avant leur existence.
// CREATE TABLE IF NOT EXISTS ne s'execute que si la table n'existe pas du
// tout ; une mise a jour de schema a besoin de sa propre migration, et
// chaque ALTER est protege car le rejouer sur une base deja migree ne doit
// pas etre une erreur.
func migrateWafColumns(db *sql.DB) error {
	for _, col := range []string{"engine TEXT", "raw TEXT"} {
		_, _ = db.Exec("ALTER TABLE waf_events ADD COLUMN " + col)
	}
	return nil
}

// migrateBotTrafficKey reconstruit bot_traffic pour inclure country dans la
// cle primaire, cf. le commentaire detaille de _open() en JS : ALTER TABLE
// ADD COLUMN ajoute bien la colonne mais ne peut pas elargir la cle, et
// l'UPSERT de flush() exige un index unique sur les cinq colonnes. Protege
// pour ne s'executer qu'une fois et jamais sur une base deja correcte.
func migrateBotTrafficKey(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(bot_traffic)`)
	if err != nil {
		return err
	}
	type colInfo struct {
		name string
		pk   int
	}
	var cols []colInfo
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		cols = append(cols, colInfo{name: name, pk: pk})
	}
	rows.Close()
	if len(cols) == 0 {
		return nil
	}
	hasCountryInKey := false
	hasCountryCol := false
	for _, c := range cols {
		if c.name == "country" {
			hasCountryCol = true
			if c.pk > 0 {
				hasCountryInKey = true
			}
		}
	}
	if hasCountryInKey {
		return nil
	}
	fmt.Println("[store] Migration de bot_traffic : reconstruction pour inclure country dans la cle")
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	rollback := func(cause error) error {
		_ = tx.Rollback()
		return cause
	}
	if _, err := tx.Exec(`CREATE TABLE bot_traffic_migrated (
		bucket    INTEGER NOT NULL,
		grain     TEXT    NOT NULL,
		vhost     TEXT    NOT NULL,
		category  TEXT    NOT NULL,
		country   TEXT,
		requests  INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (bucket, grain, vhost, category, country)
	)`); err != nil {
		return rollback(err)
	}
	src := "'??'"
	if hasCountryCol {
		src = "COALESCE(country, '??')"
	}
	insertSQL := fmt.Sprintf(`
		INSERT INTO bot_traffic_migrated (bucket, grain, vhost, category, country, requests)
		SELECT bucket, grain, vhost, category, %s, SUM(requests)
		FROM bot_traffic
		GROUP BY bucket, grain, vhost, category, %s
	`, src, src)
	if _, err := tx.Exec(insertSQL); err != nil {
		return rollback(err)
	}
	if _, err := tx.Exec(`DROP TABLE bot_traffic`); err != nil {
		return rollback(err)
	}
	if _, err := tx.Exec(`ALTER TABLE bot_traffic_migrated RENAME TO bot_traffic`); err != nil {
		return rollback(err)
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_bot_traffic_bucket ON bot_traffic(grain, bucket)`); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	fmt.Println("[store] Migration de bot_traffic terminee")
	return nil
}

// Persistent reproduit le getter persistent.
func (s *Store) Persistent() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db != nil
}

// Retention() expose la retention effective (fusionnee avec les defauts).
func (s *Store) Retention() Retention {
	return s.retention
}

// Close reproduit close() : flush puis fermeture.
func (s *Store) Close() {
	s.mu.Lock()
	db := s.db
	s.mu.Unlock()
	s.Flush()
	if db != nil {
		_ = db.Close()
	}
}

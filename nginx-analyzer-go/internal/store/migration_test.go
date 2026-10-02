package store

import (
	"path/filepath"
	"testing"
	"time"
)

// Reproduit le test Node "une base de la version precedente est reconstruite,
// historique preserve, ecritures debloquees" : bug reel signale en
// production ou country manquait de la cle primaire de bot_traffic apres une
// ALTER TABLE ADD COLUMN, ce qui faisait echouer silencieusement chaque
// ecriture (ON CONFLICT exigeant un index unique sur les 5 colonnes).
func TestMigrationBotTrafficAncienneVersion(t *testing.T) {
	tmp := t.TempDir()
	oldPath := filepath.Join(tmp, "ancienne-version.db")
	raw, err := openRawForTest(oldPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE bot_traffic (
		bucket INTEGER NOT NULL, grain TEXT NOT NULL, vhost TEXT NOT NULL,
		category TEXT NOT NULL, requests INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (bucket, grain, vhost, category))`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO bot_traffic VALUES (?,?,?,?,?)`, 1789500000, "minute", "site.fr", "human", 10738); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO bot_traffic VALUES (?,?,?,?,?)`, 1789500000, "minute", "site.fr", "good", 252); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	migrated := New(oldPath)
	defer migrated.Close()

	rows, err := migrated.db.Query(`PRAGMA table_info(bot_traffic)`)
	if err != nil {
		t.Fatal(err)
	}
	var pk []string
	for rows.Next() {
		var cid, notnull, pkIdx int
		var name, ctype string
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pkIdx); err != nil {
			t.Fatal(err)
		}
		if pkIdx > 0 {
			pk = append(pk, name)
		}
	}
	rows.Close()
	want := []string{"bucket", "grain", "vhost", "category", "country"}
	if len(pk) != len(want) {
		t.Fatalf("cle primaire attendue %v, obtenu %v", want, pk)
	}

	var human, good int
	migrated.db.QueryRow(`SELECT SUM(requests) FROM bot_traffic WHERE category='human'`).Scan(&human)
	migrated.db.QueryRow(`SELECT SUM(requests) FROM bot_traffic WHERE category='good'`).Scan(&good)
	if human != 10738 {
		t.Fatalf("historique human attendu 10738, obtenu %d", human)
	}
	if good != 252 {
		t.Fatalf("historique good attendu 252, obtenu %d", good)
	}

	now := time.Now().UnixMilli()
	migrated.RecordBot(e(Entry{Ts: now, Vhost: "site.fr"}), "human", "FR")
	migrated.RecordBot(e(Entry{Ts: now, Vhost: "site.fr"}), "human", "FR")
	written := migrated.Flush()
	if written <= 0 {
		t.Fatal("flush() doit ecrire, pas echouer en silence")
	}
	var apres int
	migrated.db.QueryRow(`SELECT SUM(requests) FROM bot_traffic WHERE category='human'`).Scan(&apres)
	if apres != 10740 {
		t.Fatalf("total attendu 10740 apres migration, obtenu %d", apres)
	}
}

func TestMigrationBotTrafficIdempotente(t *testing.T) {
	tmp := t.TempDir()
	p2 := filepath.Join(tmp, "idempotence.db")
	raw, err := openRawForTest(p2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE bot_traffic (
		bucket INTEGER NOT NULL, grain TEXT NOT NULL, vhost TEXT NOT NULL,
		category TEXT NOT NULL, requests INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (bucket, grain, vhost, category))`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO bot_traffic VALUES (?,?,?,?,?)`, 1789500000, "minute", "s.fr", "human", 5); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	a := New(p2)
	a.Close()
	b := New(p2)
	defer b.Close()
	var total int
	b.db.QueryRow(`SELECT SUM(requests) FROM bot_traffic`).Scan(&total)
	if total != 5 {
		t.Fatalf("une seconde ouverture ne doit ni dupliquer ni perdre de lignes, obtenu %d", total)
	}
	b.RecordBot(e(Entry{Ts: time.Now().UnixMilli(), Vhost: "s.fr"}), "human", "FR")
	if b.Flush() <= 0 {
		t.Fatal("les ecritures doivent toujours fonctionner apres une 2e ouverture")
	}
}

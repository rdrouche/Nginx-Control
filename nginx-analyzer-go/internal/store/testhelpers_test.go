package store

import "database/sql"

// openRawForTest ouvre une connexion SQLite brute, sans le schema/migrations
// de Store, pour simuler une base d'une version anterieure du projet dans
// les tests de migration.
func openRawForTest(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "file:"+path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

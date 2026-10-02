package store

import (
	"os"

	"github.com/ncruces/go-sqlite3"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// Choix du runtime WebAssembly qui execute SQLite (pilote pur Go, sans CGO).
//
//   - "compiler"    : wazero compile SQLite en code natif. Rapide, mais ce code
//     natif reside en RAM (~50 Mo d'empreinte residente au repos).
//   - "interpreter" : pas de compilation native ; SQLite est plus lent, mais
//     l'analyseur ne l'utilise que pour des flushes periodiques et des
//     requetes du dashboard, pas dans le chemin chaud d'ingestion.
//
// Variable SQLITE_RUNTIME ; defaut defini par defaultSQLiteRuntime.
const defaultSQLiteRuntime = "compiler"

func init() {
	mode := os.Getenv("SQLITE_RUNTIME")
	if mode == "" {
		mode = defaultSQLiteRuntime
	}
	if mode != "interpreter" {
		return // laisse le pilote choisir (compilateur si supporte)
	}
	sqlite3.RuntimeConfig = wazero.NewRuntimeConfigInterpreter().
		WithCoreFeatures(api.CoreFeaturesV2).
		WithMemoryLimitPages(4096) // 256 Mo max, comme le defaut du pilote
}

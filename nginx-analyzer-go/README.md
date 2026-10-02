# nginx-analyzer (portage Go)

Réécriture en Go de `../nginx-analyzer` (Node.js) pour **réduire l'empreinte mémoire**
(objectif initial : les 300-400 Mo du Node en production). **Remplacement direct, sans
changement côté dashboard** : même API HTTP, mêmes variables d'environnement, même format
de base SQLite.

## Résultats mesurés (mêmes logs, Node 22 vs Go 1.24)

| Charge | Node | Go | Écart |
|---|---|---|---|
| Repos (aucun trafic) | 56 Mo | 70 Mo | +14 Mo (runtime SQLite/WASM embarqué) |
| 20 000 lignes, 20 000 IP | 131 Mo · 0,9 s | 82 Mo · 0,5 s | **−37 % RAM** |
| 300 000 lignes, 50 000 IP (plafond de suivi) | 297 Mo · 10,8 s | 176 Mo · 6,0 s | **−41 % RAM**, ingestion ×1,8 |

Reproductible : `python3 test/parity/parity.py mem` (voir « Tests »). Le gain grandit avec le
trafic ; le surcoût au repos (~14 Mo) est le prix de SQLite pur Go (pas de CGO, binaire
statique de ~11 Mo).

## Bascule depuis l'image Node

L'API et la base sont identiques, la bascule est donc **un changement d'image** :

1. Construire et publier l'image (`docker build -t <registre>/nginx-analyzer-go:12.52.0 nginx-analyzer-go/`).
2. Dans `nginx-dashboard/config/analyzer.yml`, changer `container_image:` vers cette image.
   Le dashboard recrée le conteneur (`ngx-analyzer`) ; le volume `host_data_path` est
   réutilisé tel quel : **historique, baseline apprise, exceptions, règles et offsets de
   lecture sont repris** (testé dans les deux sens, voir `parity.py db`).
3. **Retour arrière** : remettre l'ancienne image. Le Node rouvre la base écrite par le Go
   sans perte. Le dossier `nginx-analyzer/` reste livré à cet effet.

Variables d'environnement : identiques au Node (`LOGS_DIR`, `DB_PATH`, `PORT`, `LOG_PATTERN`,
`LEARNING_DAYS`, `ANALYZER_TOKEN`, …), plus des réglages propres à Go :

| Variable | Défaut | Rôle |
|---|---|---|
| `GOGC` | `40` (fixé par le binaire) | Compromis RAM/CPU du GC. `100` (défaut Go) = +50 % de RAM pour ~2× moins de CPU d'ingestion ; `30` = −10 % de RAM, ingestion plus lente. |
| `GOMEMLIMIT` | aucun | Plafond mémoire souple (ex. `256MiB`). Ne pas le fixer sous le volume vivant : le GC s'emballerait. |
| `SQLITE_RUNTIME` | `compiler` | `interpreter` : −12 Mo au repos mais plus de mémoire et de CPU sous charge ; déconseillé. |
| `TZ` | vide (UTC) | Heure **locale** : baseline hebdomadaire et horodatage WAF sans fuseau. La base des fuseaux est embarquée dans le binaire. |

## Architecture

Un seul binaire, découpé en packages indépendants (un futur ingest central + workers par
hash d'IP s'insérerait entre `tail` et `detect` sans toucher au reste) :

```
cmd/analyzer/      point d'entrée : câblage, boucles de fond, HTTP, arrêt propre
internal/config    variables d'environnement (parité avec server.js)
internal/parse     parseurs access / WAF / blocklist (purs, sans état)
internal/tail      suivi de fichiers par polling (rotation, troncature)
internal/cidr      IP/CIDR v4+v6, IPv4-mappées
internal/detect    moteur par IP : bruteforce, scan, flood, scraping, règles perso
internal/baseline  anomalie volumétrique (médiane+MAD) + accumulateur horaire
internal/rules     YAML des règles perso + gestionnaire de règles
internal/store     SQLite (+ repli mémoire), schéma identique au Node
internal/geoip     lecteur MMDB minimal
internal/botclass  classification bot/humain (cache borné par User-Agent)
internal/blocklistsources  sources de blocklist poussées par le dashboard
internal/app       assemblage : ingestion, boucles de fond, état partagé
internal/httpapi   les routes /api/* (mêmes clés JSON que le Node)
```

### Concurrence (différence majeure avec le Node)

Le Node est mono-thread ; le Go exécute le tailer, les boucles de fond et chaque requête HTTP
en goroutines concurrentes. `Detector`, `Baseline`, `rules.Manager` et `Store` portent donc
chacun leur mutex (méthodes exportées verrouillées, versions internes `…NL`/minuscules pour
les appels croisés). **Toute nouvelle méthode exportée d'un de ces types doit prendre le
verrou.** `TestConcurrentLoad` + `go test -race ./...` détectent un oubli.

### Particularités de parité avec JavaScript

- Ordre d'itération : les `Map` JS itèrent en ordre d'insertion, pas les `map` Go. Le détecteur
  garde une liste d'ordre (`Detector.order`) pour que l'ordre de création des alertes soit
  déterministe et identique au Node.
- `null` vs `[]` : `encoding/json` écrit `null` pour une slice nil. `httpapi.send` convertit
  toute slice nil en `[]` ; les colonnes nullables (`engine`, `ip`…) passent par
  `nullStr`/`nullInt`.
- Valeurs par défaut JSON : `enabled` absent dans `/api/vhost-rules` vaut `true`
  (`cfg.enabled !== false`) ; `ignore` accepte des chaînes numériques (`Number(x)`).
- Horodatages WAF : mêmes formats que `Date.parse` (dont `toUTCString()`).

## Tests

```
go vet ./... && go test -count=1 ./...           # 315 tests et sous-tests
go test -race -count=1 ./...                     # + détecteur de courses (~1 min)
TZ=Pacific/Auckland go test -count=1 ./...       # la baseline dépend de l'heure locale

go build -o /tmp/analyzer-go ./cmd/analyzer
python3 test/parity/parity.py api    # Node vs Go : mêmes logs, réponses JSON comparées
python3 test/parity/parity.py db     # base SQLite créée par l'un, rouverte par l'autre
python3 test/parity/parity.py mem    # débit et RAM sous charge (N=60000 K=go …)
```

Chaque package porte le port 1:1 de la suite Node correspondante ; `internal/httpapi` ajoute
un test de bout en bout (vrais fichiers de log, agent assemblé), l'authentification par
jeton, les routes de blocklist par règle (v12.50.0) et un test de charge concurrent.
`parity.py` exige Node 22 et les deux implémentations ; code de sortie ≠ 0 si divergence.

## Diagnostic

- Profils : `go build -tags pprof -o /tmp/analyzer-pprof ./cmd/analyzer` expose
  `/debug/pprof` sur `127.0.0.1:6060` (`PPROF_ADDR`). Absent du binaire de production.
- `/api/status` : `memoryMb` est le RSS réel (`/proc/self/status`).

## Build et dépendances

`go.mod` contient deux directives `replace` (`golang.org/x/sys`, `golang.org/x/text` →
miroirs GitHub) nécessaires dans un environnement dont le réseau est restreint à GitHub ;
elles sont inoffensives ailleurs. Le build Docker nécessite un accès à `proxy.golang.org`
(ou à GitHub) ; `go mod vendor` permet un build hors-ligne si besoin.

**Non vérifié dans l'environnement de développement** : `docker build` (pas de démon Docker
disponible). Le binaire statique (`CGO_ENABLED=0 go build -trimpath -ldflags="-s -w"`) et les
étapes du Dockerfile ont été vérifiés un par un.

## Dépannage

| Symptôme | Vérification |
|---|---|
| Conteneur « Running » mais API injoignable | `docker logs ngx-analyzer` : la 1re ligne donne `demarrage (OS/ARCH, version Go)`, puis `SQLite pret` (ou le repli mémoire) et `[nginx-analyzer] :9100`. |
| Redémarrages en boucle, `exec format error` | Image construite pour une autre architecture que l'hôte : `docker build --platform linux/arm64` (ou amd64). |
| `impossible d'ecouter sur :9100` | Un autre processus utilise le port ; `PORT` permet de le changer (et `port:` dans `analyzer.yml`). |
| `Base : … (memoire seule)` | SQLite n'a pas pu s'ouvrir (permissions du volume, hôte refusant la mémoire exécutable) : l'historique n'est pas persisté. |

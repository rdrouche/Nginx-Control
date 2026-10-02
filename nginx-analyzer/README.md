# nginx-analyzer

Agent d analyse des journaux nginx. Conteneur separe du dashboard : il lit les
fichiers de log, detecte les comportements malveillants et expose ses resultats
sur une API que le dashboard consomme.

## Etat

Ce paquet contient le **coeur analytique**, teste (52 assertions,
`./test/run.sh`). Le suivi de fichiers, le stockage et l API HTTP restent a
ecrire.

| Module | Role | Etat |
| --- | --- | --- |
| `lib/parse.js` | Lecture des deux formats de log nginx | teste |
| `lib/detect.js` | Detection par signature | teste |
| `lib/baseline.js` | Apprentissage et ecart volumetrique | teste |
| `lib/tail.js` | Suivi des fichiers et rotations | a ecrire |
| `lib/store.js` | Agregation SQLite et retention | a ecrire |
| `lib/api.js` | API HTTP consommee par le dashboard | a ecrire |

## Detection par signature

Active des la premiere minute, sans apprentissage.

| Type | Declencheur | Severite |
| --- | --- | --- |
| `bruteforce` | echecs d authentification repetes sur un chemin de connexion | haute |
| `scan` | beaucoup de chemins distincts, majoritairement en 404 | moyenne |
| `flood` | debit de requetes soutenu depuis une adresse | haute |
| `scraping` | volume eleve sur peu de chemins, agent automatise | basse |

Chaque alerte porte ses preuves : exemples de requetes, agents utilisateurs,
repartition des codes de statut. De quoi decider, pas seulement un verdict.

Une attaque en cours produit **une** alerte, pas une par requete : la
deduplication porte sur le triplet (type, adresse, vhost) pendant la duree de la
fenetre.

## Detection volumetrique

Necessite un apprentissage. Trois choix structurent ce module, chacun tire d un
mode d echec connu de ce type de detecteur.

**La saisonnalite n est pas optionnelle.** Un mardi 14 h n a rien de commun avec
un dimanche 4 h. La reference est donc calculee par creneau horaire de la
semaine — 168 buckets — et non sur une moyenne globale, qui produirait une
alerte permanente.

**Mediane et ecart absolu median, pas moyenne et ecart-type.** Une seule attaque
passee deplace une moyenne pendant des semaines et gonfle l ecart-type, apres
quoi le detecteur se tait precisement quand il ne devrait pas. La mediane ignore
les valeurs extremes.

**Le volume seul ne distingue pas un succes d une attaque.** Un article qui
marche ressemble exactement a une attaque volumetrique. Ce qui les separe est la
structure : une audience reelle apporte beaucoup d adresses, des agents varies,
des chemins varies et peu d erreurs. L agent rapporte ce qu il observe et ajuste
la severite, sans decider a la place de l operateur.

Comptez **trois semaines** d observation avant la premiere alerte fiable.
L agent annonce explicitement son etat d apprentissage plutot que d alerter sur
des donnees insuffisantes.

## Trafic inhabituel par pays

Meme moteur que la detection volumetrique ci-dessus (`lib/baseline.js`, une
seconde instance), applique cette fois au volume horaire agrege par pays
plutot que par vhost — un pays qui envoie brutalement beaucoup plus de trafic
qu a l accoutumee, tous vhosts confondus, est le signe d une attaque
distribuee (credential stuffing, DDoS applicatif) menee depuis une plage
d adresses concentree geographiquement, ou d un scan de masse.

Les signaux structurels different legerement de la detection par vhost :
nombre d adresses distinctes et **nombre de vhosts distincts touches** (une
audience reelle depuis un pays atteint generalement plus d un vhost, une
attaque concentree generalement pas) plutot que le nombre de chemins.

Un pays agrege naturellement plus de trafic qu un vhost pris isolement, d ou
un seuil minimal de volume distinct (`COUNTRY_MIN_REQUESTS`, 300 requetes par
defaut contre 100 pour la detection par vhost).

Alertes de type `country_traffic`, memes regles que le reste : apprentissage
de trois semaines, mediane + MAD par creneau horaire de la semaine, severite
ajustee selon la structure. `GET /api/baseline/country` expose les memes
statistiques que `/api/baseline` pour la detection par vhost ; un creneau
legitime se marque comme normal via
`POST /api/baseline/country/exclude?country=<ISO2>&hour=<ISO8601>`.

Variables d environnement : `COUNTRY_SIGMA_THRESHOLD` (defaut 6, comme
`SIGMA_THRESHOLD`) et `COUNTRY_MIN_REQUESTS` (defaut 300). Reutilise
`LEARNING_DAYS` — un seul delai d apprentissage a l esprit plutot que deux.

## Hits blocklist (nginx-dashboard)

nginx-dashboard choisit, par source (`hit_logging_method` dans
`config/blocklists.yml`), comment cet agent detecte les hits :

- **`dedicated`** (Methode 1) : nginx-dashboard genere un fichier de log
  global dedie (`blocklist-hits.log` par defaut) contenant une ligne par
  requete bloquee, tous vhosts confondus (le vhost vient d un champ de la
  ligne, pas du nom de fichier — voir `lib/parse-blocklist.js`). Cet agent le
  suit exactement comme les journaux d acces et le journal WAF : un `Tailer`
  dedie, reprise sur redemarrage, tolerance aux lignes partielles.
- **`approx`** (Methode 2, depuis la v12.29.0) : aucun fichier dedie —
  l agent derive les hits directement du log d acces principal qu il suit
  deja, en comparant chaque requete a la liste d IP/CIDR de chaque source
  activee que nginx-dashboard lui pousse periodiquement (voir
  `POST /api/blocklist-sources` ci-dessous et `lib/blocklist-sources.js`).
  Aucune configuration nginx supplementaire requise.

Variables d environnement : `BLOCKLIST_LOG_PATTERN` (regex du nom de
fichier utilise en mode `dedicated`, defaut `^blocklist-hits\.log$`),
`BLOCKLIST_RETENTION_DAYS` (purge automatique, defaut 60 jours).

Endpoints exposes :
- `POST /api/blocklist-sources` — pousse par nginx-dashboard : `{ mode:
  'dedicated'|'approx', sources: { [nom]: { ips: [...] } } }`. En memoire
  uniquement, comme `/api/vhost-rules` — un redemarrage de l agent attend
  simplement le prochain push (typiquement sous la minute).
- `GET /api/blocklist-hits/summary?hours=24&limit=500` — total de hits, IP
  distinctes, les IP les plus actives sur la fenetre, et `bySource`
  (repartition par source de blocklist, calculee ici a partir des sources
  synchronisees ci-dessus — depuis la v12.29.0, plus besoin que
  nginx-dashboard croise ces IP avec son propre cache).
- `GET /api/blocklist-hits/check?ip=...&hours=24` — nombre de hits, premiere
  et derniere occurrence pour une IP precise.
- `POST /api/blocklist-hits/clear` — purge manuelle.

## Formats de log

Les deux formats courants sont acceptes, y compris melanges sur un meme serveur :

```
combined        127.0.0.1 - - [09/Sep/2026:10:00:00 +0200] "GET / HTTP/1.1" 200 1234 "-" "curl/8"
combined_vhost  example.com 127.0.0.1 - - [09/Sep/2026:...] "GET / HTTP/1.1" 200 1234 "-" "curl/8"
```

Le format est detecte **une fois par fichier** a partir d un echantillon, puis
applique tel quel. Le deviner ligne par ligne casse des qu un nom d hote
ressemble a une adresse IP.

Pour un fichier au format `combined`, le vhost est deduit du nom de fichier
(`forge.rdr-it.com.access.log` donne `forge.rdr-it.com`).

Une ligne illisible est ignoree sans erreur : une ecriture partielle en fin de
fichier pendant une rotation est normale.

## Tests

```
./test/run.sh
```

Les tests verifient autant que l agent **detecte** que le fait qu il **se
taise** : un site legitime avec beaucoup de pages, un navigateur sur une seule
page, une variation de trafic ordinaire. Un detecteur qui crie au loup est
ignore en trois jours, et devient alors pire qu inutile.

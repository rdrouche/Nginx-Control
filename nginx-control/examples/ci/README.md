# Déclencher un déploiement Git depuis un pipeline CI/CD

Le dashboard expose les mêmes actions que le bouton **Déploiement Git** de
l'interface (Pull / Test / Sauvegarde / Déploiement complet) via son API,
avec une authentification dédiée aux pipelines : un **jeton de déploiement**
(`config/deploy-tokens.yml`), distinct du jeton API admin global
(`API_TOKEN`). Voir la section « Jetons de déploiement (CI/CD) » du README
principal pour le détail du mécanisme et des garanties de sécurité.

## 1. Créer un jeton

Depuis **Configurations → Éditeur → Jetons de déploiement (CI/CD)** (ou en
éditant directement `config/deploy-tokens.yml` sur l'hôte) :

```yaml
tokens:
  - name: forgejo-ci
    token: "REMPLACER_PAR_UN_SECRET_ALEATOIRE_D_AU_MOINS_16_CARACTERES"
    enable: true
    actions: [pull, test, deploy, backup]   # ou un sous-ensemble, ex: [test]
```

Générer un secret aléatoire, par exemple :

```sh
openssl rand -hex 32
```

Ce jeton ne donne accès **qu'à** `POST /api/git/pull`, `POST /api/git/test`,
`POST /api/git/deploy`, `GET /api/git/status` et `POST /api/backups` — jamais
au reste du dashboard, quoi qu'il arrive par ailleurs. Restreindre `actions`
permet par exemple de donner à un pipeline de vérification (sur chaque push)
un jeton limité à `test`, et de réserver un jeton `deploy` à un pipeline
déclenché uniquement depuis la branche protégée.

## 2. Configurer le secret côté CI

Ajouter dans les secrets du dépôt (jamais en clair dans le fichier de
pipeline) :

- `DASHBOARD_URL` — ex. `https://dashboard.example.com` (sans slash final)
- `DEPLOY_TOKEN` — le jeton créé à l'étape 1

## 3. Appeler l'API

Chaque action répond par un code HTTP qui reflète directement le résultat —
un échec (config invalide, `nginx -t` en échec, jeton non autorisé pour
cette action) est un code **non-2xx**, ce qui suffit à faire échouer
l'étape du pipeline sans logique supplémentaire :

| Action | Requête | Code de succès | Code d'échec |
|---|---|---|---|
| Pull | `POST /api/git/pull` | 200 | 500 |
| Test | `POST /api/git/test` | 200 | 422 (config invalide) |
| Déploiement complet (pull+test+backup+sync+reload) | `POST /api/git/deploy` | 200 | 422 (test `nginx -t` échoué) ou 500 |
| Sauvegarde seule | `POST /api/backups` (body `{"mode":"git"}` ou `{"mode":"both"}`) | 201 | 500 |
| Statut courant | `GET /api/git/status` | 200 | — |

Trois exemples complets et prêts à adapter sont fournis dans ce dossier :

- [`github-actions-deploy.yml`](github-actions-deploy.yml) — GitHub Actions
- [`gitlab-ci-deploy.yml`](gitlab-ci-deploy.yml) — GitLab CI
- [`forgejo-deploy.yml`](forgejo-deploy.yml) — Forgejo Actions (syntaxe
  compatible GitHub Actions)

Les trois suivent la même logique : un job **test** (jeton limité à `test`,
peut tourner sur chaque push/MR sans risque) et un job **deploy** (jeton
complet, déclenché manuellement ou uniquement sur la branche principale).

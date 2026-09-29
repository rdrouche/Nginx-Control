# Déployer Ninx et Nginx Control

## Prérequis

Un serveur Linux avec Docker et Docker compose d'installé

> La documentation a été faite depuis un serveur Debian 13

## Préparation des dossiers

Sur votre serveur, créer un dossier pour les différents fichiers et dossier du stack.

> Dans cette documentation utilise le dossier `/containers/nginx`

Créer le dossier : 

```bash
mkdir -p /containers/nginx
cd /containers/nginx
```

## Cloner les fichiers

Les fichiers et dossiers du stacks sont disponibles à ces emplacements : 
- https://forge.rdr-it.com/romain/Docker-Compose/src/branch/main/ReverseProxy
- https://github.com/rdrouche/Docker-Compose/tree/main/ReverseProxy

Utiliser la commande ci-dessous pour cloner le répertoire depuis le dépôt : 

```bash
bash <(wget -qO- https://forge.rdr-it.com/romain/Docker-Compose/raw/branch/main/get.sh) ReverseProxy
```

## Configuration de base

Commencer par copier le `[sample.env](https://forge.rdr-it.com/romain/Docker-Compose/src/branch/main/ReverseProxy/sample.env)` en le nommant .env et éditer le.

```bash
cp sample.env .env
nano .env
```

Générer le token et les sécrets pour les variables :

- NGX_DHB_API_TOKEN
- NGX_DHB_WEBHOOK_SECRET
- NGX_DHB_SESSION_SECRET

> Vous pouvez utiliser le générateur alétoire disponible sur [tools.rdr-it.com](https://tools.rdr-it.com/#randgen)

```
NGX_DHB_API_TOKEN=6e3d05027a9d3dd686cec2d1f4ec3d1ff9c84bac6a4d7addfbc860e554a5b86f
NGX_DHB_WEBHOOK_SECRET=958bc8ed17d3a495a419b4e5daab67a2dd1dd693515060641b978df889c35b66
NGX_DHB_SESSION_SECRET=ba1a8ddd2f524c873ec8b76e4c6dd76199fec00db27d5447a8e0da38fabb838f
```

Ensuite modifier le fichier : `./config/nginx-dashboard/config/users.yml` pour configurer le mot de passe du compte **admin**.

```bash
nano config/nginx-dashboard/config/users.yml
```

Modifier la valeur du parametre `password:`.

> Le mot de passe sera chiffré au premier démarrage du tableau de bord.

Par défaut, le dashboard n'est pas publié, créer un fichier `compose.override.yml` avec le contenu suivant : 

```yaml
services:
  nginx-dashboard:
    ports:
      - "3000:3000"
```

## Démarrer les conteneurs

Télécharger les conteneurs et démarrer les : 

```bash
docker compose up
```

> Les images vont être téléchargé puis les conteneurs seront démarrés

> L'absense du paramètre `-d` vous permet d'avoir les logs et vérifier les conteneurs démarrent.
> 
> Depuis Debian, cliquer sur la touche **d** pour détacher et faire fonctionner les conteneurs en arrières plan.

## Accéder au Dashboard

Depuis un navigateur aller à l'URL : http://ip:3000 qui vous emene sur la page d'authentification.

- Identifiant : admin
- Mot de passe : celui défini dans le fichier `users.yml`

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-001-login.png" width="800" />

Une fois connecté, vous arrivez sur page qui vous affiche des métriques sur les requetes qui sont issue de Nginx VTS

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-002-overview.png" width="800" />

# Génération des certificats Let's Encrypt - DNS Challenge

Les certificats générés par Certbot sont stockés sur l'hôte dans le dossier :

```text
./certificats/certbot
```

Ce dossier est monté dans le conteneur Nginx à l'emplacement :

```text
/etc/letsencrypt
```

Ce choix permet de conserver la même arborescence que celle utilisée par une installation standard de Nginx avec Certbot. Cela facilite une éventuelle migration vers **Nginx Control** et permet également de conserver les liens symboliques créés par Certbot.

Historiquement, la génération des certificats avec un **DNS Challenge** était réalisée en dehors de **Nginx Control**. Il était alors nécessaire de configurer manuellement un conteneur Certbot dans le fichier `compose.yml` du stack.

Depuis la version **12.4**, la génération des certificats DNS Challenge est directement intégrée à **Nginx Control**.

> ⚠️ **Attention :** seul le DNS Challenge a été testé en conditions de production.

## Principe de fonctionnement

Un conteneur Certbot est démarré en permanence en parallèle de **Nginx Control**. Son rôle est uniquement de gérer le renouvellement des certificats existants.

Lorsqu'un nouveau certificat doit être généré, **Nginx Control** démarre un conteneur Certbot éphémère dédié à cette demande.

Le certificat généré est ensuite conservé dans le répertoire partagé :

```text
./certificats/certbot
```

Il est ainsi immédiatement disponible pour Nginx via le montage `/etc/letsencrypt`.

## Prérequis

Pour utiliser cette fonctionnalité, vous devez disposer :

* d'un fournisseur DNS pris en charge par les plugins DNS de Certbot ;
* d'une clé ou d'un token d'API permettant à Certbot de modifier automatiquement les enregistrements DNS ;
* d'un domaine dont la gestion DNS est assurée par ce fournisseur.

L'utilisation d'une API DNS permet à Certbot de créer automatiquement les enregistrements nécessaires à la validation du challenge, sans avoir à intervenir manuellement lors de la génération ou du renouvellement du certificat.

## Confiugration & utilisation

### Cloudflare

#### Configuration

1 - Ouvrir le fichier `./config/certbot/cloudflare/credentials.ini`

```bash
nano ./config/certbot/cloudflare/credentials.ini
```

2 - Dans le fichier rempalcer `YOUR-API-TOKEN` par votre clé d'API et enregistrer les modifications.

3 - Sur ***Nginx Control*** aller ADMINISTRATION / Configuration puis sur l'onglet Certbot - défi DNS et adapter la configuration si dessous et cliquer sur Sauvagrder.

```yaml
enable: true
provider: cloudflare
email: user@domain.tld
credentials_host_path: /containers/nginx/config/certbot/cloudflare//credentials.ini
certs_host_path: /containers/nginx/certificats/certbot
```

>Les varialbes contenant des chemins (path) est l'emplacement depuis hôte Docker.

4 - Aller ensuite sur le page SSL / Certbot et démarrer le conteneur DEFI DNS en charge du renouvellement.

#### Demander un certificat

Pour demander un certificat, rendez-vous dans la zone **Émettre un ou plusieurs certificats**.

Saisissez les noms DNS à inclure dans le certificat, par exemple :

```text
*.example.com example.com
```

Vous pouvez saisir plusieurs noms DNS en les séparant par un espace.

Cliquez ensuite sur **Générer**.

Patientez quelques secondes pendant que Certbot effectue le challenge DNS et procède à l'émission du certificat.

Une fois l'opération terminée, le certificat est disponible dans **Nginx Control** et peut être utilisé dans vos hôtes virtuels.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-016-ssl-cerbot-dns.png" width="800" />
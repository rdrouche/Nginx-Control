# Gestion de la configuration avec Git (GitOps)

**Nginx Control** permet d'utiliser un dépôt Git comme **source de vérité** pour les fichiers de configuration Nginx.

Les éléments suivants peuvent ainsi être versionnés dans le dépôt :

* `sites`
* `conf.d`
* `snippets`
* `streams`
* `ssl`

L'objectif est de ne plus considérer la configuration présente sur le serveur Nginx comme la seule référence, mais de conserver une version de référence dans Git.

Cette fonctionnalité permet notamment de :

* conserver l'historique des modifications ;
* identifier qui a effectué une modification ;
* revenir à une version précédente de la configuration ;
* travailler avec les outils habituels de Git ;
* préparer et valider les modifications avant leur déploiement.

> **Pourquoi cette fonctionnalité ?**
>
> Le fonctionnement GitOps est l'une des raisons qui ont motivé le développement de **Nginx Control**. L'objectif était de pouvoir gérer la configuration Nginx avec un dépôt Git et de disposer d'un historique des modifications, tout en conservant un contrôle sur le déploiement de la configuration.

## Prérequis

Il est nécessaire de disposer d'un dépôt Git accessible par **Nginx Control**.

Il est recommandé d'utiliser un dépôt **privé**, notamment parce que la configuration peut contenir les certificats SSL ainsi que leurs clés privées (`.pem` et `.key`).

Un token d'accès au dépôt Git est également nécessaire.

## Initialiser votre dépôt

La première étape consiste à initialiser le dépôt Git avec la configuration Nginx actuellement utilisée.

Pour cela, vous pouvez utiliser la fonctionnalité **Sauvegarde** de **Nginx Control** afin de récupérer les fichiers de configuration et de les envoyer (`push`) dans votre dépôt Git.

L'objectif est de partir de la configuration actuellement fonctionnelle avant de mettre en place le déploiement GitOps.

## Configuration de Nginx Control

Rendez-vous dans **ADMINISTRATION → Configuration**, puis sélectionnez l'onglet **Git (dépôt config)**.

Saisissez la configuration de votre dépôt puis cliquez sur **Enregistrer**.

Par exemple :

```yaml id="x8n4k2"
repo_url: https://forge.domain.tld/organisation/nginx-reverse-proxy-config.git

token: **********

user_name: NginxControl
user_email: nginxcontrol@domain.tld
```

Rendez-vous ensuite dans **CONFIGURATION → Déploiement Git** afin de vérifier que la configuration du dépôt a bien été prise en compte.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-050-git.png" width="800" />

## Initialiser la branche Backup

Lors des opérations Git, notamment lors d'un **Pull** ou d'un **Déploiement**, **Nginx Control** sauvegarde la configuration actuellement utilisée par Nginx.

Cette sauvegarde est envoyée dans une branche **Backup** du dépôt Git.

Une étiquette (*tag*) est également créée afin de pouvoir identifier et retrouver une ancienne version de la configuration.

Avant d'utiliser le mécanisme de sauvegarde, la branche doit être initialisée.

Cliquez une seule fois sur **Initialiser la branche Backup**.

Cette opération crée la branche nécessaire aux sauvegardes automatiques des configurations précédentes.

## Utilisation

L'utilisation du GitOps est volontairement simple.

Après avoir effectué une modification de la configuration dans votre dépôt Git et envoyé celle-ci (`push`), rendez-vous dans **CONFIGURATION → Déploiement Git**.

Cliquez d'abord sur **Pull** afin de récupérer les modifications présentes dans le dépôt.

Une fois la nouvelle configuration récupérée, cliquez sur **Déployer** pour lancer son déploiement sur Nginx.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-051-git.png" width="800" />

### Vérification avant déploiement

Avant toute mise à jour de la configuration Nginx en production, **Nginx Control** effectue un test de la configuration dans un **conteneur éphémère**.

La configuration n'est appliquée à Nginx que si ce test est réussi.

Si le test échoue, la configuration actuellement utilisée par Nginx **n'est pas modifiée**.

Ce mécanisme permet ainsi de conserver une configuration fonctionnelle en production même lorsqu'une modification présente une erreur de configuration.

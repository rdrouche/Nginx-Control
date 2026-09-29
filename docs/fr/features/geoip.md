# Geoip - localisation géographique des visiteurs

Les version de Nginx sont compilés avec le module [geopip2](https://nginx-extras.getpagespeed.com/modules/geoip2/) qui permet d'utiliser les bases de données [MaxMind](https://www.maxmind.com/en/home) pour determiner la provenance géographique des requetes reçu sur votre reverse proxy.

Les bases de données de MaxMind sont nécéssaire pour plusieurs fonctionnalités de **Nginx Control** :

- Carte en temps réél
- Analyse géographique des requetes
- Résumé périodique
- Logs en directe

En plus d'être utiliser dans **Nginx Control**, vous allez pouvoir utiliser ces bases de données dans vos configurations d'hôtes virtuels pour filtrer le trafic sur votre site.

**Nginx Control** s'appuie sur 3 bases de données : 

- GeoLite2-City : qui permet de determiné la ville d'origine
- GeoLite2-Country : qui permet de determiné le pays d'orgine
- GeoLite2-ASN : qui permet de filtrer sur [ASN](https://fr.wikipedia.org/wiki/Autonomous_System) (Autonomous System) de l'adresse IP

## Prérequis

Afin de récupérer les bases de données depuis le site de MaxMind, vous devez créer un compte si vous n'en n'avez pas encore.

- https://www.maxmind.com/en/create-account
- https://www.maxmind.com/en/account/sign-in

Une fois connecté à votre compte cliquer sur View license key :

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-008-geoip.png" width="800" />

Puis créer une nouvelle clé que l'on va utiliser pour le conteneur geoipupdate.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-009-geoip.png" width="800" />

> Au passage noter votre identifiant **Account ID**

## Configuration dans Nginx Control

Depuis le menu aller Integration / GeoIP, sélectionner le modèle de configuration et copier le.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-010-geoip.png" width="800" />

Ensuite aller sur Configuration puis sur la page ouvrir l'onglet : GeoIP et coller le code de configuration en l'adaptant à votre environnement et cliquer sur Sauvegarder.

```yaml
enable: true
account_id: 123456
license_key: VOTRE_CLE
edition_ids: GeoLite2-City GeoLite2-Country GeoLite2-ASN
frequency_hours: 168
geoip_host_path: /containers/nginx/geoip_data
```

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-011-geoip.png" width="800" />

> Le parametre `geoip_host_path` doit correspondre au chemin absolu sur hôte docker où les fichiers de bases de données seront enregistrés.

Retrouner ensuite sur Integration / GeoIP et cliquer sur le bouton Démarrer.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-012-geoip.png" width="800" />

Patienter quelques secondes pendant le démarrage du conteneur et de la récupération des bases de données puis cliquer sur le bouton le bouton Refresh pour vérifier le bon fonctionnement.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-013-geoip.png" width="800" />

Les bases de données MaxMind peuvent maintenant être utilisé avec Nginx et Nginx Control.

## Utiliser le Géolocalisation dans vos hôtes virtuels

### Charger les bases de données avec `geoip2`

La première étape pour utiliser les bases de données va être d'indiquer à Nginx de les chargés.

Dans le dossier : `./nginx/config/conf.d/` renommer le fichier `geoip2-load-database.conf.DISABLE` en `geoip2-load-database.conf` afin qu'il soit chargé.

```bash
mv ./nginx/config/conf.d/geoip2-load-database.conf.DISABLE ./nginx/config/conf.d/geoip2-load-database.conf
```

[Tester la configuration de Nginx et recharge le](../start-with-dashboard.md#appliquer-la-configuration).

### Utilisation dans virtualhost

Les restrictions GeoIP doivent être appliquées avec prudence, en fonction du site ou de l'application que vous souhaitez publier.

Pour une application métier que vous souhaitez restreindre à un pays, comme la France, l'impact est généralement limité. En revanche, pour un site Internet public, la situation est plus délicate, notamment si vous souhaitez que celui-ci soit correctement indexé par les moteurs de recherche.

Une autre précaution concerne l'utilisation du même reverse proxy pour les accès externes (exposés sur Internet) et les accès internes. Dans ce cas, les utilisateurs internes peuvent accéder au reverse proxy avec une adresse IP privée. Si une restriction GeoIP est configurée, ces adresses ne pourront pas être associées à un pays et les utilisateurs risquent donc d'être bloqués.

Pour résoudre ce problème, plusieurs approches sont possibles. Vous pouvez notamment mettre en place une boucle via votre pare-feu (*NAT loopback / hairpin NAT*), afin que les utilisateurs internes accèdent au reverse proxy via son adresse IP publique. Cela implique que la résolution DNS interne utilise également le nom public et l'adresse IP publique du service.

Une autre solution consiste à adapter la directive `map` utilisée pour la restriction GeoIP afin d'autoriser explicitement les plages d'adresses IP privées. Cette approche permet de conserver un accès direct au reverse proxy depuis le réseau interne, sans faire transiter les connexions par l'adresse IP publique.

> ***Séparer les reverse proxy***
>
>Pour des raisons de séparation logique et de sécurité, il peut être préférable de mettre en place deux reverse proxy distincts : un reverse proxy exposé sur Internet et dédié aux applications publiées, et un second reverse proxy réservé aux usages internes.
>
>Cette architecture permet notamment de séparer clairement les flux Internet et les flux internes, mais également d'appliquer des politiques de sécurité différentes sur chacun des reverse proxy. Les restrictions GeoIP, les règles de filtrage, les protections contre les attaques ou encore les applications accessibles peuvent ainsi être configurées indépendamment.
>
>Cette séparation apporte également un avantage intéressant pour l'exploitation. Une application peut être retirée de la publication Internet tout en restant accessible depuis le réseau interne. Cela peut être particulièrement utile pour les environnements de maintenance, de test ou de préproduction.
>
>Par exemple, une application peut être publiée sur le reverse proxy Internet pendant sa phase de production, puis retirée de celui-ci lors d'une opération de maintenance tout en restant accessible aux administrateurs via le reverse proxy interne. De la même manière, une application de test peut être accessible uniquement depuis le réseau interne sans jamais être exposée sur Internet.
>
>Cette architecture à double reverse proxy constitue donc une solution particulièrement intéressante lorsque les besoins d'accès internes et externes sont différents.

Dans cette documentation, nous allons présenter plusieurs cas d'usage afin d'illustrer ces différentes configurations et vous aider à choisir l'approche la plus adaptée à votre environnement.

#### Cas 1 : Autoriser seulement les adresses IP provenant de France

Pour commencer, nous allons voir comment autoriser le trafic vers un hôte virtuel uniquement lorsque celui-ci provient d'une adresse IP française.

1 - Créer la configuration `map`

Créez un fichier de configuration dans `./nginx/config/conf.d/`. Ce fichier doit avoir l'extension `.conf` afin d'être automatiquement chargé par Nginx.

```nginx
# file : allow-from-france.conf

map $geoip2_data_country_iso_code $allow_from_france {
    default 0;       # Par défaut, on interdit le trafic
    FR 1;            # Si le code pays ISO est FR (France), on autorise le trafic
}
```

> La directive `map` permet de créer la variable `$allow_from_france` et de lui attribuer la valeur `0` ou `1` en fonction du code pays retourné par GeoIP2.
>
> Dans notre exemple, toutes les adresses IP sont refusées par défaut. Seules les adresses IP identifiées comme provenant de France (`FR`) sont autorisées.
>
> Cette variable pourra ensuite être utilisée dans la configuration de l'hôte virtuel afin de filtrer le trafic.

2 - Configurer l'hôte virtuel

Dans l'hôte virtuel, on ajoute ensuite : `if ($allow_from_france = 0) { return 403; }` pour filtrer le trafic.

```nginx
server{
    listen 80;
    server_name example.com;

    # Pages d'erreurs personnalisees
    include snippets/global-error.conf;

    # Filtrage du trafic : France seulement
    if ($allow_from_france = 0) { return 403; }

    location / {
        http://192.168.1.1;
    }
}
```

> 💡 **Tip:** La variable `$allow_from_france` peut être utilisée dans plusieurs hôtes virtuels. C'est pourquoi je vous conseille de déclarer vos directives `map` dans des fichiers de configuration dédiés plutôt que directement dans les fichiers de vos hôtes virtuels, avant le bloc `server { ... }`.
>
> Cette organisation permet notamment de réutiliser facilement les mêmes variables dans plusieurs hôtes virtuels et de centraliser les règles de filtrage.


#### Cas 2 : Bloquer seulement les adresses IP provenant de France

Dans ce second exemple, nous allons prendre le problème à l'inverse et bloquer tout le trafic provenant d'adresse IP française.

1 - Créer la configuration `map`

Créez un fichier de configuration dans `./nginx/config/conf.d/`. Ce fichier doit avoir l'extension `.conf` afin d'être automatiquement chargé par Nginx.

```nginx
# file : block-from-france.conf

map $geoip2_data_country_iso_code $block_from_france {
    default 1;       # Par défaut, on autorise tout le trafic
    FR 0;            # Si le code pays ISO est FR (France), on bloque le trafic
}
```

2 - Configurer l'hôte virtuel

Dans l'hôte virtuel, on ajoute ensuite : `if ($block_from_france = 1) { return 403; }` pour filtrer le trafic.

```nginx
server{
    listen 80;
    server_name example.com;

    # Pages d'erreurs personnalisees
    include snippets/global-error.conf;

    # Filtrage du trafic : on bloque la France
    if ($block_from_france = 1) { return 403; }

    location / {
        http://192.168.1.1;
    }
}
```

#### Cas 3 : Autoriser les adresses IP provenant de France et les adresses ip privées

Nous allons repartir du premier cas et voir maintenant comment autoriser également les connexions provenant d'adresses IP privées.

Dans les fichiers de configuration de base du reverse proxy, vous trouverez le fichier [`private-ips.conf`](https://forge.rdr-it.com/romain/Docker-Compose/src/branch/main/ReverseProxy/nginx/config/conf.d/private-ips.conf). Celui-ci contient un mappage des différentes plages d'adresses IP privées et renseigne la variable `$is_private_ip`.

Cette variable vaut `1` lorsque l'adresse IP du client appartient à une plage d'adresses privées, et `0` dans le cas contraire.

Nous allons pouvoir utiliser cette variable dans notre configuration GeoIP afin d'autoriser les connexions provenant du réseau interne, même si GeoIP2 ne peut pas associer une adresse IP privée à un pays.

1 - Créer la configuration `map`

Créez un fichier de configuration dans `./nginx/config/conf.d/`. Ce fichier doit avoir l'extension `.conf` afin d'être automatiquement chargé par Nginx.

```nginx
# file : allow-from-france-and-private-ips.conf

map "$geoip2_data_country_iso_code:$is_private_ip" $allow_from_france_and_private_ips {
    default 0;           # Par défaut, on interdit le trafic
    "~^FR:" 1;           # Si le code pays ISO est FR (France), on autorise le trafic
    "~:1$"  1;           # Si l'adresse IP est privée, on autorise le trafic
}
```

>La valeur évaluée par le map est composée des deux variables, séparées par `:`. Par exemple :
>
>- `FR:0` : adresse IP publique située en France ;
>- `US:0` : adresse IP publique située aux États-Unis ;
>- `:1` : adresse IP privée, pour laquelle aucun pays n'est retourné par GeoIP2.
>
>Les deux expressions régulières permettent donc d'autoriser le trafic dans les deux situations qui nous intéressent :
>
>- `~^FR:` : le code pays commence par FR ;
>- `~:1$` : la valeur se termine par `:1`, indiquant que l'adresse IP est privée.
>
>Toutes les autres combinaisons correspondent à la valeur default `0` et sont donc refusées.

2 - Configurer l'hôte virtuel

Dans l'hôte virtuel, on ajoute ensuite : `if ($allow_from_france_and_private_ips = 0) { return 403; }` pour filtrer le trafic.

```nginx
server{
    listen 80;
    server_name example.com;

    # Pages d'erreurs personnalisees
    include snippets/global-error.conf;

    # Filtrage du trafic
    if ($allow_from_france_and_private_ips = 0) { return 403; }

    location / {
        http://192.168.1.1;
    }
}
```

#### Cas 4 :  Autoriser les adresses IP provenant de France, les bots de references et les adresses ip privées

Nous allons repartir du **Cas 3** et ajouter cette fois-ci les bots d'indexation des moteurs de recherche.

L'objectif est de rendre notre site accessible uniquement aux visiteurs provenant d'une adresse IP française ou privée, tout en autorisant les robots des moteurs de recherche à accéder au site, quelle que soit leur adresse IP.

Cette configuration permet donc de conserver une restriction géographique pour les visiteurs tout en permettant aux moteurs de recherche d'explorer et d'indexer le contenu du site.

Pour déterminer les « bons » robots, nous allons utiliser le fichier [`good-bots.conf`](https://forge.rdr-it.com/Nginx/reference-files/src/branch/main/conf/good-bots.conf).

Ce fichier utilise la directive `map` de Nginx afin d'identifier les robots d'indexation à partir de leur **User-Agent** et de définir la valeur de la variable `$is_good_bot`.

La variable `$is_good_bot` permet ainsi de déterminer si la requête provient d'un robot identifié comme légitime et autorisé à accéder au site.

1 - Créer la configuration `map`

Créez un fichier de configuration dans `./nginx/config/conf.d/`. Ce fichier doit avoir l'extension `.conf` afin d'être automatiquement chargé par Nginx.

```nginx
# file : allow-from-france-and-private-ips-and-bots.conf

map "$geoip2_data_country_iso_code:is_good_bot:$is_private_ip" $allow_from_france_and_private_ips_and_bots {
    default 0;           # Par défaut, on interdit le trafic
    "~^FR:" 1;           # Si le code pays ISO est FR (France), on autorise le trafic
    "~:1:"  1;           # Si la requête provient d'un bot autorisé, on autorise le trafics
    "~:1$"  1;           # Si l'adresse IP est privée, on autorise le trafic
}
```

>La valeur évaluée par le map est cette fois composée de trois variables, séparées par : :
>
>`$geoip2_data_country_iso_code` : le code pays déterminé par GeoIP2 ;
>`$is_good_bot` : indique si le User-Agent correspond à un bot identifié comme autorisé ;
>`$is_private_ip` : indique si l'adresse IP est une adresse privée.
>
>Par exemple, les valeurs évaluées pourront être :
>
>`FR:0:0` → visiteur avec une IP publique française → autorisé ;
>`US:1:0` → bot autorisé provenant des États-Unis → autorisé ;
>`US:0:0` → visiteur avec une IP publique américaine → refusé ;
>`:0:1` → visiteur provenant d'une adresse IP privée → autorisé.
>
>Les trois règles du map permettent ensuite de définir les conditions d'autorisation :
>
>`~^FR:` : la valeur commence par `FR:`. L'adresse IP est donc identifiée comme française, quel que soit le statut du bot ou de l'adresse privée ;
>`~:1:` : la valeur contient `:1:`. Cela signifie que `$is_good_bot` vaut `1`, quel que soit le pays d'origine ou le caractère privé de l'adresse IP ;
>`~:1$` : la valeur se termine par :1. Cela signifie que `$is_private_ip` vaut `1`, et l'accès est donc autorisé.
>
>Toutes les autres combinaisons correspondent à la règle default `0` et sont refusées.

2 - Configurer l'hôte virtuel

Dans l'hôte virtuel, on ajoute ensuite : `if ($allow_from_france_and_private_ips_and_bots = 0) { return 403; }` pour filtrer le trafic.

```nginx
server{
    listen 80;
    server_name example.com;

    # Pages d'erreurs personnalisees
    include snippets/global-error.conf;

    # Filtrage du trafic
    if ($allow_from_france_and_private_ips_and_bots = 0) { return 403; }

    location / {
        http://192.168.1.1;
    }
}
```
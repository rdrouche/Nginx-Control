# Contrôle du cache Nginx avec Nginx Control

**Nginx Control** permet de gérer le cache Nginx des hôtes virtuels lorsque celui-ci est configuré.

Nginx est capable de mettre en cache les réponses provenant du serveur backend afin d'éviter de solliciter ce dernier à chaque requête. Cette fonctionnalité est particulièrement intéressante pour les fichiers statiques tels que les fichiers **JavaScript, CSS, images, polices**, etc.

Le cache permet ainsi de :

* réduire le nombre de requêtes envoyées au serveur backend ;
* diminuer la charge de l'application ;
* améliorer les temps de réponse ;
* accélérer la distribution des ressources fréquemment demandées.

## Consulter le cache

Depuis le menu :

**CONTROLE → Nginx Cache**

Nginx Control permet d'obtenir une vue d'ensemble des caches configurés sur Nginx.

Pour chaque répertoire de cache, l'interface affiche notamment :

* le nombre de fichiers présents ;
* la taille occupée par le cache.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-002-overview.png" width="800" />

Depuis cette page, il est possible de :

* **vider l'ensemble des caches** ;
* gérer individuellement les différents répertoires de cache ;
* consulter l'espace occupé par chaque cache.

> **À noter :** après une opération sur le cache, il est recommandé de recharger la configuration de Nginx afin de s'assurer que les modifications sont correctement prises en compte.

## Configurer un cache dans un hôte virtuel

La gestion du cache par Nginx Control nécessite au préalable d'avoir configuré un cache dans le VHost.

### Cache des fichiers statiques

L'exemple suivant configure un cache destiné aux ressources statiques d'un site :

```nginx id="u8h3fw"
proxy_cache_path /var/cache/nginx/myvhost_static_file
    levels=1:2
    keys_zone=cache_myvhost_static_file:10m
    max_size=1g
    inactive=60m
    use_temp_path=off;

server {
    listen 80;
    server_name example.com;

    location ~* \.(?:jpg|jpeg|gif|png|ico|woff2|ttf|woff|css|js)$ {
        proxy_cache cache_myvhost_static_file;
        proxy_pass http://192.168.1.1;

        include snippets/proxy-common.conf;

        # Permet de connaître l'état du cache
        add_header X-Cache-Status $upstream_cache_status;

        access_log off;
        log_not_found off;
    }

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

Dans cet exemple, les requêtes correspondant aux extensions définies dans le bloc `location` utilisent le cache `cache_myvhost_static_file`.

Le paramètre :

```nginx
add_header X-Cache-Status $upstream_cache_status;
```

permet d'ajouter l'état du cache dans la réponse HTTP. Il est particulièrement utile pour vérifier le fonctionnement du cache lors de la mise en place ou du diagnostic.

Selon la requête, cette valeur peut notamment indiquer si la réponse provient du cache ou si elle a dû être récupérée depuis le serveur backend.

## Mettre en cache du contenu dynamique

Il est également possible de mettre en cache du contenu généré dynamiquement par l'application.

Prenons l'exemple d'une application qui génère des images avec une URL de ce type :

```text
/image.php?id=123
```

Même si la réponse est générée dynamiquement par PHP, le résultat peut être mis en cache par Nginx afin d'éviter de solliciter l'application à chaque requête.

On peut également utiliser un cache distinct pour les ressources statiques.

```nginx id="z5m9jp"
proxy_cache_path /var/cache/nginx/myvhost_static_file
    levels=1:2
    keys_zone=cache_myvhost_static_file:10m
    max_size=1g
    inactive=60m
    use_temp_path=off;

proxy_cache_path /var/cache/nginx/myvhost_dyna_img
    levels=1:2
    keys_zone=cache_myvhost_dyna_img:10m
    max_size=4g
    inactive=24h
    use_temp_path=off;

server {
    listen 80;
    server_name example.com;

    # Cache des images générées dynamiquement
    location ~ /(?:.*/)?image\.php$ {
        proxy_pass http://192.168.1.1;

        proxy_ssl_verify off;

        access_log off;
        log_not_found off;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Activation du cache
        proxy_cache cache_myvhost_dyna_img;

        # Durée de conservation des réponses
        proxy_cache_valid 200 302 24h;
        proxy_cache_valid 404 1m;

        # Ignorer les instructions de cache retournées par l'application
        proxy_ignore_headers Cache-Control Expires Set-Cookie;

        # Utiliser la query string dans la clé du cache
        proxy_cache_key "$scheme$request_method$host$request_uri";

        # Header de diagnostic
        add_header X-Cache-Status $upstream_cache_status;
    }

    # Cache des fichiers statiques
    location ~* \.(?:jpg|jpeg|gif|png|ico|woff2|ttf|woff|css|js)$ {
        proxy_cache cache_myvhost_static_file;
        proxy_pass http://192.168.1.1;

        include snippets/proxy-common.conf;

        add_header X-Cache-Status $upstream_cache_status;

        access_log off;
        log_not_found off;
    }

    # Autres requêtes
    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

Dans cet exemple, deux zones de cache sont utilisées :

* `cache_myvhost_static_file` pour les ressources statiques ;
* `cache_myvhost_dyna_img` pour les images générées dynamiquement par `image.php`.

La clé de cache :

```nginx
proxy_cache_key "$scheme$request_method$host$request_uri";
```

permet notamment de prendre en compte la **query string**. Ainsi, `/image.php?id=123` et `/image.php?id=456` correspondent à deux entrées différentes dans le cache.

> **Attention :** la mise en cache de contenu dynamique doit être réalisée avec précaution. Avant d'utiliser `proxy_ignore_headers Cache-Control Expires Set-Cookie`, vérifiez que les réponses concernées peuvent réellement être mises en cache et qu'elles ne contiennent pas de données personnalisées ou sensibles.

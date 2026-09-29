# Supervision des backends — cibles des proxy_pass

Avec **Nginx Control**, vous pouvez superviser les backends utilisés par les directives `proxy_pass` de vos VHosts.

Par défaut, la supervision est désactivée. Son activation et sa configuration se font directement dans les fichiers de configuration des VHosts à l'aide de commentaires spécifiques.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-049-monitoring.png" width="800" />

## Activer le monitoring

Pour activer la supervision d'un VHost, ajoutez les commentaires suivants dans le bloc `server { ... }` :

```nginx
# nginx-control-monitoring: on
# nginx-control-monitoring-interval: 60s
```

Par exemple :

```nginx
server {
    listen 80;
    server_name example.com;

    # nginx-control-monitoring: on
    # nginx-control-monitoring-interval: 60s

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

Une fois la configuration rechargée, les cibles des `proxy_pass` sont supervisées par **Nginx Control**.

Le suivi de l'état des backends est disponible depuis **CONFIGURATION → Monitoring**.

## Désactiver le monitoring sur une location

Par défaut, chaque `proxy_pass` présent dans un VHost supervisé est pris en compte.

Dans certains cas, il peut cependant être inutile de superviser une location spécifique. C'est notamment le cas lorsqu'une location est utilisée pour servir du contenu mis en cache.

Pour exclure une location du monitoring, ajoutez le commentaire :

```nginx
# nginx-control-monitoring-ignore-location: on
```

Par exemple :

```nginx
server {
    ...

    # nginx-control-monitoring: on
    # nginx-control-monitoring-interval: 60s

    location /cache {
        # nginx-control-monitoring-ignore-location: on
    }
}
```

La location `/cache` ne sera alors pas prise en compte par la supervision.

## Configurer les codes HTTP valides

Selon l'architecture utilisée, il peut être nécessaire d'adapter les codes HTTP considérés comme valides.

Par défaut, une cible est considérée comme indisponible en cas de timeout ou d'erreur HTTP **5XX**.

Prenons l'exemple d'une application exécutée dans un conteneur Docker et publiée par **Traefik** sur un hôte distant.

Si le conteneur de l'application est arrêté, Traefik peut retourner une réponse **404**. Du point de vue HTTP, le backend répond donc correctement, même si l'application n'est plus disponible.

Il est alors possible de définir les codes HTTP considérés comme valides avec :

```nginx
# nginx-control-monitoring-valid-http-code: 2xx, 3xx
```

Par exemple :

```nginx
server {
    listen 80;
    server_name example.com;

    # nginx-control-monitoring: on
    # nginx-control-monitoring-interval: 60s
    # nginx-control-monitoring-valid-http-code: 2xx, 3xx

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

Dans cet exemple, les réponses **2XX** et **3XX** sont considérées comme valides par le monitoring.

Cette configuration permet d'adapter la supervision au fonctionnement réel de votre architecture, notamment lorsque le backend est lui-même placé derrière un autre reverse proxy.

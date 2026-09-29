# Configuration des logs

La première étape pour pouvoir exploiter les journaux dans **Nginx Control** consiste à configurer les `access.log` de vos hôtes virtuels.

Comme **Nginx Control** utilise Nginx de manière classique, il suffit d'ajouter la directive `access_log` dans vos hôtes virtuels :

```nginx
access_log /var/log/nginx/<server-name>.access.log;
```

Cette configuration permet d'enregistrer les requêtes HTTP reçues par chaque hôte virtuel dans un fichier de journal dédié.

## Optimiser les journaux

Les journaux peuvent rapidement devenir volumineux, notamment pour les sites Internet qui génèrent de nombreuses requêtes vers des fichiers statiques tels que les fichiers JavaScript, CSS, images ou polices.

Pour limiter le volume de données à analyser, **Nginx Control** fournit le fichier [`logging-config.conf`](https://forge.rdr-it.com/Nginx/reference-files/src/branch/main/conf/logging-config.conf).

Ce fichier contient notamment un `map` permettant d'identifier les requêtes vers les ressources statiques afin de pouvoir les exclure des journaux.

Voici son contenu :

```nginx
# name: logging-config
# description: configuration format log et filtrage
# require:
# usage:
# version: 1.0.0

# Permet de ne pas logger les fichiers statiques.
# Pour utiliser ce filtre, ajouter if=$is_not_static
# à la fin de la directive access_log.

map $request_uri $is_not_static {

    # Extensions ou chemins à ignorer
    ~*\.(js|css|png|jpg|jpeg|gif|ico|svg|woff2?|ttf|otf|map)(\?|$) 0;
    ~*\/robots\.txt 0;

    # Par défaut, on journalise la requête
    default 1;
}

# Support des versions de Nginx à partir de 1.29.X :
# la variable $server_name ne peut plus être utilisée directement
# dans certains chemins de fichiers.
log_format combined_vhost '$server_name $remote_addr - $remote_user [$time_local] '
                          '"$request" $status $body_bytes_sent '
                          '"$http_referer" "$http_user_agent"';
```

> 💡 Le fichier **`logging-config.conf`** se trouve dans le dossier `conf.d` de Nginx. Il est donc automatiquement chargé par Nginx et les variables `is_not_static` et `combined_vhost` sont disponibles dans vos hôtes virtuels.

Pour utiliser le filtrage des fichiers statiques, utilisez la directive suivante :

```nginx 
access_log /var/log/nginx/<server-name>.access.log combined if=$is_not_static;
```

Dans cette configuration, seules les requêtes dont la variable `$is_not_static` vaut `1` sont enregistrées. Les requêtes vers les fichiers statiques définis dans le `map` sont donc exclues.

## Utiliser un fichier de logs commun

Si vous ne souhaitez pas créer un fichier de logs différent pour chaque hôte virtuel, vous pouvez utiliser le snippet [`logging.conf`](https://forge.rdr-it.com/Nginx/reference-files/src/branch/main/snippets/logging.conf).

Celui-ci permet de centraliser les requêtes de vos différents hôtes virtuels dans le fichier :

```text
/var/log/nginx/vhosts_access.log
```

Pour l'utiliser, il suffit d'inclure le snippet dans votre hôte virtuel :

```nginx
include snippets/logging.conf;
```

Cette approche permet de conserver une configuration simple lorsque vous gérez de nombreux hôtes virtuels, tout en fournissant à **Nginx Control** un fichier de logs unique à analyser.

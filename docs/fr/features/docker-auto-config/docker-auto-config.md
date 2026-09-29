# Auto-configuration Docker avec les labels

Par défaut, cette fonctionnalité est désactivée.

Pour l'activer, rendez-vous dans **ADMINISTRATION → Configuration**, puis sélectionnez l'onglet **Auto-config Docker (labels)**.

Dans le champ de configuration, saisissez la configuration suivante, puis cliquez sur **Enregistrer** :

```yaml
enable: true
require_approval: true
poll_interval_sec: 15
events_enable: true
events_debounce_ms: 3000
certbot_retry_minutes: 15
allowed_server_name_patterns:
```

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-039-autodocker.png" width="800" />

Rechargez ensuite l'interface **Nginx Control** avec la touche **F5** afin que le nouveau menu soit disponible dans la navigation.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-040-autodocker.png" width="800" />

## Créer un conteneur Docker

Pour tester l'auto-configuration, créez un conteneur Docker qui doit être connecté au **même réseau Docker que Nginx**. Cela permet à Nginx d'accéder directement au conteneur afin de lui transmettre les requêtes.

Par exemple, le fichier `compose.yml` suivant crée un conteneur Nginx simple :

```yaml
services:
  web:
    image: nginx:alpine
    container_name: simple_nginx

    # ports:
    #   - "80:80"

    # volumes:
    #   - ./html:/usr/share/nginx/html:ro

    restart: always

    networks:
      - nginx-net

    labels:
      - "nginx-control.enable=true"
      - "nginx-control.vhost.server_name=test-01.domain.tld"
      - "nginx-control.vhost.location01=/"
      - "nginx-control.vhost.location01.proxy_pass=http://web:80"
      - "nginx-control.network=nginx-net"
      - "nginx-control.vhost.server.snippet01=logging.conf"

networks:
  nginx-net:
    external: true
```

Les labels permettent à **Nginx Control** de déterminer comment publier le conteneur :

* `nginx-control.enable=true` : active la publication du conteneur ;
* `nginx-control.vhost.server_name` : définit le nom DNS du VHost ;
* `nginx-control.vhost.location01` : définit la première `location` ;
* `nginx-control.vhost.location01.proxy_pass` : définit la destination du trafic ;
* `nginx-control.network` : indique le réseau Docker utilisé pour communiquer avec le conteneur ;
* `nginx-control.vhost.server.snippet01` : ajoute un snippet au niveau du `server`.

### Approbation de la publication

Démarrez le conteneur.

Après quelques secondes, celui-ci doit apparaître dans Nginx Control **en attente d'approbation**.

Cliquez sur **Approuver** pour autoriser sa publication.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-041-autodocker.png" width="800" />

Une fois le conteneur approuvé, le VHost est automatiquement généré et devient actif.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-042-autodocker.png" width="800" />

La configuration générée peut être consultée depuis **CONFIGURATION → Fichiers de conf**.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-043-autodocker.png" width="800" />

Cette configuration est générée automatiquement à partir des labels Docker du conteneur. Il est donc possible de modifier la publication directement depuis le fichier `compose.yml`, puis de laisser **Nginx Control** détecter les changements et mettre à jour la configuration Nginx.

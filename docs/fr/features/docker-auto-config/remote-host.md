# Auto-configuration Docker avec les labels sur des hôtes distants

L'auto-configuration Docker peut également être utilisée avec des conteneurs présents sur des **hôtes distants**.

Dans ce cas, **Nginx Control** ne peut pas accéder directement au socket Docker de l'hôte distant. Un agent léger, développé en Go, est donc installé sur chaque hôte Docker afin de communiquer avec **Nginx Control** et de lui transmettre les informations sur les conteneurs à publier.

Cette configuration permet également de choisir la manière dont Nginx doit communiquer avec les applications distantes.

Trois modes de communication sont disponibles :

* **direct** : mode utilisé par défaut. Nginx se connecte directement à la cible définie dans le label `target`. L'hôte Nginx doit donc pouvoir joindre directement l'hôte distant sur le port utilisé ;
* **tunnel** : l'agent ouvre une connexion WebSocket sortante vers **Nginx Control**. Aucune connexion entrante n'est nécessaire sur l'hôte distant, ce qui permet notamment de publier des conteneurs situés derrière un NAT ;
* **relay** : l'agent expose un ou deux ports fixes permettant à Nginx de joindre les différents VHosts publiés. Le routage est ensuite effectué par `server_name`. Ce mode constitue un compromis entre le mode **direct** et le mode **tunnel**.

Pour le mode **relay**, le label `relay_scheme` permet d'indiquer si le VHost doit utiliser le relais HTTP ou HTTPS.

## Activer la fonctionnalité dans Nginx Control

Rendez-vous dans **ADMINISTRATION → Configuration**, puis sélectionnez l'onglet **Hôtes Docker distants (agent)**.

Ajoutez la configuration suivante puis cliquez sur **Enregistrer** :

```yaml
enable: true
offline_after_sec: 90
max_vhosts_per_agent: 50
tunnel_enable: false
certbot_retry_minutes: 15
```

Actualisez ensuite l'interface **Nginx Control** avec la touche **F5**.

Le menu **INTEGRATIONS → Hôtes distants** est alors disponible.

## Déployer l'agent

Sur l'hôte Docker distant, créez un dossier destiné à stocker les fichiers de l'agent.

Créez ensuite le fichier `compose.yml` :

```yaml
services:
  nginx-control-agent:
    image: forge.rdr-it.com/dockerfiles/nginx-reverse-proxy-dashboard-agent:nightly
    container_name: nginx-control-agent
    restart: ${AGENT_RESTART_POLICY:-always}

    networks:
      - proxy-relay

    environment:
      - DASHBOARD_URL=${DASHBOARD_URL:-}
      - AGENT_HOSTNAME=${AGENT_HOSTNAME:-}
      - AGENT_FINGERPRINT=${AGENT_FINGERPRINT:-}
      - TOKEN_FILE=/data/token
      - STATE_FILE=/data/nginx-control-agent-state.json
      - DOCKER_SOCKET=/var/run/docker.sock
      - POLL_INTERVAL=${POLL_INTERVAL:-30s}
      - INSECURE_SKIP_VERIFY=${INSECURE_SKIP_VERIFY:-false}
      - TUNNEL_ENABLE=${TUNNEL_ENABLE:-true}
      - RELAY_HTTP_LISTEN=${RELAY_HTTP_LISTEN:-}
      - RELAY_HTTP_ADVERTISE=${RELAY_HTTP_ADVERTISE:-}
      - RELAY_HTTPS_LISTEN=${RELAY_HTTPS_LISTEN:-}
      - RELAY_HTTPS_ADVERTISE=${RELAY_HTTPS_ADVERTISE:-}
      - RELAY_HTTPS_CERT=${RELAY_HTTPS_CERT:-}
      - RELAY_HTTPS_KEY=${RELAY_HTTPS_KEY:-}
      - RELAY_BACKEND_INSECURE_SKIP_VERIFY=${RELAY_BACKEND_INSECURE_SKIP_VERIFY:-false}
      - TARGETS_FILE=${TARGETS_FILE:-}

    ports:
      - "${RELAY_HTTP_HOST_PORT:-8080}:8080"
      - "${RELAY_HTTPS_HOST_PORT:-8443}:8443"

    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./data:/data

networks:
  proxy-relay:
    name: proxy-relay
    driver: bridge
```

Créez ensuite le fichier `.env` :

```text
DASHBOARD_URL=http://ip-nginx-control:3000
AGENT_HOSTNAME=remote-host
AGENT_FINGERPRINT=remote-host

POLL_INTERVAL=30s
INSECURE_SKIP_VERIFY=false
TUNNEL_ENABLE=true
AGENT_RESTART_POLICY=always

RELAY_HTTP_LISTEN=8080
RELAY_HTTPS_LISTEN=8443

RELAY_HTTP_HOST_PORT=8080
RELAY_HTTPS_HOST_PORT=8443

RELAY_HTTP_ADVERTISE=http://ip-host-agent:8080
RELAY_HTTPS_ADVERTISE=http://ip-host-agent:8443

RELAY_HTTPS_CERT=
RELAY_HTTPS_KEY=

RELAY_BACKEND_INSECURE_SKIP_VERIFY=false

# TARGETS_FILE=
```

### Première connexion de l'agent

Démarrez une première fois l'agent :

```bash
docker compose up -d
```

L'agent apparaît alors dans **Nginx Control** et doit être approuvé.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-044-remote.png" width="800" />

Une fois l'agent approuvé, **Nginx Control** affiche un token permettant d'authentifier l'agent.

> Le token n'est affiché qu'une seule fois. Conservez-le avant de poursuivre la configuration.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-045-remote.png" width="800" />

Sur l'hôte distant, arrêtez ensuite l'agent :

```bash
docker compose down
```

Dans le dossier `./data/`, créez le fichier `token` et ajoutez-y le token fourni par **Nginx Control**.

Redémarrez ensuite l'agent :

```bash
docker compose up -d
```

L'agent est maintenant enregistré et apparaît **En ligne** dans **Nginx Control**.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-046-remote.png" width="800" />

## Exemples d'auto-configuration

### Mode direct

Dans ce mode, Nginx se connecte directement à la cible définie dans `target`.

L'hôte sur lequel fonctionne Nginx doit donc pouvoir joindre directement l'application distante.

```yaml
services:
  web3:
    image: nginx:alpine
    container_name: simple_nginx3
    ports:
      - "8889:80"
    restart: always
    networks:
      - proxy-relay
    labels:
      - "nginx-control.enable=true"
      - "nginx-control.vhost.mode=direct"
      - "nginx-control.vhost.server_name=test-03.domain.tld"
      - "nginx-control.vhost.location01=/"
      - "nginx-control.vhost.location01.target=http://ip-remote-host:8889"
      - "nginx-control.vhost.server.snippet01=logging.conf"

networks:
  proxy-relay:
    external: true
```

### Mode relay

Dans ce mode, Nginx passe par l'agent.

```yaml
services:
  web2:
    image: nginx:alpine
    container_name: simple_nginx2
    restart: always
    networks:
      - proxy-relay
    labels:
      - "nginx-control.enable=true"
      - "nginx-control.vhost.mode=relay"
      - "nginx-control.vhost.server_name=test-02.domain.tld"
      - "nginx-control.vhost.location01=/"
      - "nginx-control.vhost.location01.target=http://web2:80"
      - "nginx-control.vhost.server.snippet01=logging.conf"

networks:
  proxy-relay:
    external: true
```

Une fois le conteneur détecté par l'agent, le VHost apparaît dans **INTEGRATIONS → Hôtes distants**.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-047-remote.png" width="800" />

La configuration Nginx générée peut également être consultée depuis cette interface.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-048-remote.png" width="800" />

Les VHosts sont ainsi générés automatiquement à partir des labels Docker présents sur les conteneurs de l'hôte distant.

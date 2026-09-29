# Déployer CrowdSec avec Docker

[**CrowdSec**](https://www.crowdsec.net/) est une solution open source de détection comportementale qui analyse les journaux et différents événements afin d'identifier des comportements malveillants.

Contrairement à un simple système de blocage basé sur des listes d'adresses IP, CrowdSec s'appuie sur des **scénarios de détection** pour identifier différents types d'attaques, puis produit des décisions qui peuvent être exploitées par des **bouncers** afin d'appliquer une remédiation, par exemple en bloquant une adresse IP.

Dans cette partie, nous allons uniquement voir comment **déployer CrowdSec afin de l'intégrer à Nginx Control**.

Pour une installation complète de CrowdSec avec la configuration des bouncers et la mise en place de la remédiation, vous trouverez plusieurs ressources complémentaires à la fin de cette page.

## Déployer CrowdSec

Dans un dossier dédié à CrowdSec, par exemple `/containers/crowdsec`, créer le fichier `compose.yml` suivant :

```yaml
services:
  crowdsec:
    image: crowdsecurity/crowdsec:latest
    restart: always
    user: root
    environment:
      COLLECTIONS: "crowdsecurity/nginx crowdsecurity/sshd crowdsecurity/wordpress crowdsecurity/base-http-scenarios crowdsecurity/http-cve crowdsecurity/http-dos"
      GID: "${GID-1000}"
    volumes:
      - /var/log:/var/log
      - /containers/nginx/nginx/logs:/var/log/nginx
      - ./crowdsec/db:/var/lib/crowdsec/data/
      - ./crowdsec/config:/etc/crowdsec/
    networks:
      crowdsec_network:
        ipv4_address: 10.199.0.5

networks:
  crowdsec_network:
    ipam:
      driver: default
      config:
        - subnet: 10.199.0.0/24
```

> **À noter :** cet exemple monte directement le répertoire de logs de Nginx Control dans le conteneur CrowdSec. Adaptez le chemin `/containers/nginx/nginx/logs` à votre installation.

Démarrer ensuite CrowdSec :

```bash
docker compose up -d
```

Vérifier que le conteneur est correctement démarré :

```bash
docker compose ps
```

## Configurer l'analyse des logs Nginx

Nous allons maintenant indiquer à CrowdSec qu'il doit analyser les journaux Nginx.

Dans le répertoire :

```text
./crowdsec/config/acquis.d/
```

créer le fichier :

```text
nginx.yaml
```

Par exemple :

```bash
nano ./crowdsec/config/acquis.d/nginx.yaml
```

Ajouter le contenu suivant :

```yaml
filenames:
  - /var/log/nginx/*.log

labels:
  type: nginx
```

Le chemin `/var/log/nginx/*.log` correspond au chemin **vu depuis le conteneur CrowdSec**.

Le montage Docker défini précédemment permet de faire correspondre ce chemin aux journaux générés par Nginx Control sur l'hôte.

Redémarrer ensuite CrowdSec afin de prendre en compte la nouvelle configuration :

```bash
docker compose restart crowdsec
```

## Vérifier le fonctionnement

Pour vérifier que CrowdSec analyse bien les journaux, utiliser la commande :

```bash
docker compose exec crowdsec cscli metrics
```

Cette commande permet notamment de vérifier que les fichiers de logs sont bien pris en compte et que les événements sont analysés par CrowdSec.

Si les journaux Nginx sont correctement détectés, ils apparaissent dans les métriques de CrowdSec.

## Intégration avec Nginx Control

À ce stade, CrowdSec est capable d'analyser les journaux générés par Nginx Control.

Cette configuration constitue la partie **détection**.

Elle permet notamment à Nginx Control de s'appuyer sur CrowdSec pour obtenir des informations sur les adresses IP ayant fait l'objet de décisions ou de détections.

Pour mettre en place le **blocage automatique** des adresses IP, il faut ensuite configurer un bouncer adapté à votre architecture.

> **CrowdSec et Nginx Control sont complémentaires :** Nginx Control fournit l'administration et la visibilité autour de Nginx, tandis que CrowdSec apporte son moteur de détection comportementale et, avec un bouncer, la capacité de mettre en œuvre une remédiation automatique.

## Ressources complémentaires

Si vous souhaitez aller plus loin dans la mise en place de CrowdSec, voici plusieurs articles disponibles sur RDR-IT :

* [**CrowdSec : installation et configuration en conteneur avec Docker**](https://rdr-it.com/crowdsec-installation-et-configuration-en-conteneur-avec-docker/)
* [**CrowdSec : intégration avec les pare-feu Fortigate – Fortinet**](https://rdr-it.com/crowdsec-integration-avec-les-pares-feu-fortigate-fortinet/)
* [**Mettre en place une instance centrale CrowdSec pour sécuriser son infrastructure**](https://rdr-it.com/mettre-en-place-une-instance-centrale-crowdsec-pour-securiser-son-infrastructure/)

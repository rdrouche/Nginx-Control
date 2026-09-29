# CrowdSec

**Nginx Control** permet de s'interfacer avec [**CrowdSec**](../../appendices/deploy-crowdsec-docker.md) afin de disposer directement dans l'interface des informations et des fonctionnalités liées à CrowdSec.

L'intégration peut être réalisée à **trois niveaux**, selon les besoins :

* **Prometheus** : permet de récupérer les statistiques et métriques de CrowdSec, avec notamment un affichage équivalent à la commande `cscli metrics`.
* **Bouncer** : permet à Nginx Control d'interroger l'API locale de CrowdSec afin de consulter les décisions, notamment les adresses IP actuellement bloquées.
* **Machine** : permet à Nginx Control d'interagir avec l'API CrowdSec et notamment de créer ou supprimer des décisions depuis l'interface.

Ces trois intégrations peuvent être utilisées indépendamment les unes des autres.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-032-crowdsec.png" width="800" />

> **À noter :** l'intégration CrowdSec apparaît dans le menu de Nginx Control uniquement lorsqu'une configuration CrowdSec est définie.

## Prérequis

Nginx Control doit pouvoir communiquer avec CrowdSec.

Lorsque CrowdSec et Nginx Control sont exécutés dans des conteneurs Docker sur le même hôte, le conteneur Nginx Control doit notamment être connecté au réseau Docker utilisé par CrowdSec.

Par exemple, si le réseau CrowdSec est un réseau Docker externe nommé `crowdsec-net`, créer un fichier `compose.override.yml` :

```yaml
services:
  nginx-control:
    networks:
      - crowdsec-net

networks:
  crowdsec-net:
    external: true
```

Cette configuration permet au conteneur Nginx Control de joindre directement le conteneur CrowdSec sur son réseau Docker.

---

## Intégration avec Prometheus

La première intégration permet à Nginx Control de récupérer les **métriques exposées par CrowdSec**.

Elle permet notamment d'obtenir depuis Nginx Control des informations similaires à celles retournées par :

```bash
cscli metrics
```

### Configuration

Aller dans : **ADMINISTRATION → Configuration → CrowdSec**

Dans la configuration, renseigner l'URL de l'endpoint Prometheus de CrowdSec :

```yaml
prometheus_url: http://10.199.0.5:6060/
```

Adapter l'adresse IP à votre environnement.

Cliquer ensuite sur **Sauvegarder**.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-033-crowdsec.png" width="800" />

Actualiser ensuite **Nginx Control** avec la touche **F5** afin de recharger la configuration.

L'intégration CrowdSec est alors disponible dans le menu : **INTEGRATION → CrowdSec**

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-034-crowdsec.png" width="800" />

Cette première intégration est suffisante si vous souhaitez uniquement disposer des **statistiques CrowdSec** dans Nginx Control.

---

## Intégration en tant que Bouncer pour accéder à l'API

La deuxième intégration permet à Nginx Control d'interroger l'API locale de CrowdSec afin notamment de récupérer les **décisions** prises par CrowdSec.

Pour cela, nous allons créer un Bouncer dédié à Nginx Control afin d'obtenir une clé d'API.

Depuis le conteneur CrowdSec, exécuter :

```bash
docker compose exec crowdsec cscli bouncers add nginx-control
```

CrowdSec retourne alors une clé d'API.

Retourner ensuite dans : **ADMINISTRATION → Configuration → CrowdSec**

et ajouter les informations suivantes :

```yaml
url: http://10.199.0.5:8080/
api_key: "****************"
local_only: true
```

Adapter l'URL à votre environnement et remplacer la valeur de `api_key` par la clé retournée par CrowdSec.

Cliquer sur **Sauvegarder**, puis recharger **Nginx Control** avec la touche **F5**.

Les décisions CrowdSec sont maintenant accessibles depuis la page **CrowdSec** de Nginx Control.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-035-crowdsec.png" width="800" />

> **À noter :** l'API utilisée ici retourne uniquement les **100 premières décisions**.

Cette intégration donne à Nginx Control une visibilité sur les décisions prises par CrowdSec, mais ne permet pas encore à Nginx Control de modifier ces décisions.

---

## Intégration en tant que Machine pour agir sur l'API

La troisième intégration permet d'aller plus loin.

Nginx Control peut être déclaré comme une **Machine CrowdSec** afin de pouvoir interagir avec l'API et notamment **ajouter ou supprimer des décisions**.

Cette intégration est particulièrement intéressante lorsqu'une adresse IP détectée par les règles d'analyse de Nginx Control doit être bloquée directement dans CrowdSec.

### Créer la Machine CrowdSec

Depuis le conteneur CrowdSec, exécuter :

```bash
docker compose exec crowdsec cscli machines add nginx-control --auto --file /etc/crowdsec/lapi_api_cred_nginx_control.yaml
```

Cette commande crée les identifiants permettant à Nginx Control de s'authentifier auprès de l'API CrowdSec en tant que Machine.

Le fichier contenant les identifiants est :

```text
/etc/crowdsec/lapi_api_cred_nginx_control.yaml
```

Dans notre exemple, ce fichier correspond sur l'hôte au chemin :

```text
./crowdsec/config/lapi_api_cred_nginx_control.yaml
```

Ouvrir ce fichier et récupérer le mot de passe généré pour la Machine `nginx-control`.

### Configurer Nginx Control

Retourner dans : **ADMINISTRATION → Configuration → CrowdSec**

et ajouter les informations suivantes :

```yaml
machine_id: nginx-control
machine_password: "*******"
```

Cliquer sur **Sauvegarder**, puis recharger **Nginx Control** avec la touche **F5**.

Nginx Control dispose maintenant des droits nécessaires pour interagir avec les décisions CrowdSec.

Il devient notamment possible de **bloquer une adresse IP directement depuis Nginx Control**, en créant une décision CrowdSec.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-036-crowdsec.png" width="800" />

## Les trois niveaux d'intégration

Pour résumer :

| Intégration    | Fonction                   | Droits             |
| -------------- | -------------------------- | ------------------ |
| **Prometheus** | Statistiques et métriques  | Lecture            |
| **Bouncer**    | Consultation des décisions | Lecture            |
| **Machine**    | Gestion des décisions      | Lecture / écriture |

La configuration dépend donc de ce que vous souhaitez faire avec CrowdSec dans Nginx Control.

Si vous souhaitez uniquement consulter les métriques, **Prometheus suffit**.

Pour afficher les IP bannies et les décisions CrowdSec, ajoutez l'intégration **Bouncer**.

Enfin, si vous souhaitez permettre à Nginx Control de **créer ou supprimer des décisions CrowdSec**, l'intégration **Machine** est nécessaire.
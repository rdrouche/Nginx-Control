# Blocklists IP

**Blocklists IP** est une intégration de **Nginx Control** permettant de mettre en place un blocage basé sur des adresses IP en utilisant la directive `geo` de Nginx.

Les adresses IP provenant des différentes listes sont agrégées et dédupliquées avant d'être intégrées à la configuration Nginx.

## Les listes

Les listes d'adresses IP doivent être accessibles depuis une URL et respecter le format suivant, avec une adresse IP par ligne :

```text
1.1.1.1
8.8.8.8
9.9.9.9
```

Il existe différentes listes communautaires disponibles sur Internet, notamment :

* [duggytuxy/Data-Shield_IPv4_Blocklist](https://github.com/duggytuxy/Data-Shield_IPv4_Blocklist) — **recommandée**
* [Blocklist.de](https://www.blocklist.de/fr/export.html)
* [GreenSnow Blocklist](https://blocklist.greensnow.co/greensnow.txt)
* **CrowdSec** via une bouncer — [voir la documentation RDR-IT](https://rdr-it.com/crowdsec-integration-avec-les-pares-feu-fortigate-fortinet/)

Afin d'optimiser la configuration, les différentes listes sont automatiquement **agrégées et dédupliquées**.

## Configuration des listes

Pour configurer les listes, rendez-vous dans : **ADMINISTRATION → Configuration → Blocklists IP**

Dans la zone de saisie, renseignez la configuration souhaitée, puis cliquez sur **Enregistrer**.

### Exemple 1 : une seule liste

L'exemple suivant utilise uniquement la liste **Data-Shield** et effectue une mise à jour toutes les six heures :

```yaml
enable: true

interval_cron: "0 */6 * * *"

block_action: deny_403

hit_logging_enable: true
hit_logging_method: dedicated

sources:
  - name: datashield
    url: "https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_data-shield_ipv4_blocklist.txt"
    enable: true
```

### Exemple 2 : plusieurs listes

Il est également possible d'utiliser plusieurs sources simultanément. Dans cet exemple, les listes **Data-Shield** et **GreenSnow** sont utilisées :

```yaml
enable: true

interval_cron: "0 */6 * * *"

block_action: deny_403

hit_logging_enable: true
hit_logging_method: dedicated

sources:
  - name: datashield
    url: "https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_data-shield_ipv4_blocklist.txt"
    enable: true

  - name: greensnow
    url: "https://blocklist.greensnow.co/greensnow.txt"
    enable: true
```

Chaque source possède son propre nom, son URL et un paramètre `enable` permettant de l'activer ou de la désactiver.

### Actions de blocage

Le paramètre `block_action` permet de définir le comportement de Nginx lorsqu'une adresse IP présente dans une blocklist est détectée.

Dans nos exemples :

```yaml
block_action: deny_403
```

Les requêtes provenant d'une adresse IP présente dans les listes sont alors refusées avec une réponse HTTP **403 Forbidden**.

Le paramètre `hit_logging_enable` permet d'activer la journalisation des blocages.

Avec :

```yaml
hit_logging_method: dedicated
```

les blocages sont enregistrés dans un journal dédié, ce qui facilite leur consultation et leur analyse.

## Consulter l'état des Blocklists

Une fois la configuration enregistrée, rendez-vous dans : **INTEGRATIONS → Blocklists IP**

Cette page permet de consulter l'état de l'intégration ainsi qu'un récapitulatif des listes configurées et des adresses IP chargées.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-017-blocklists.png" width="800" />

## Consulter la configuration générée

Vous pouvez également consulter le fichier de configuration généré par **Nginx Control** depuis : **CONFIGURATION → Fichiers de conf → conf.d**

Le fichier généré est :

```text
blocklist-ips.conf
```

Ce fichier contient la configuration nécessaire à la gestion des adresses IP provenant des différentes blocklists.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-018-blocklists.png" width="800" />

## Configuration des hôtes virtuels pour utiliser Blocklists IP

La configuration des Blocklists IP étant générée au niveau global, il est nécessaire d'indiquer dans chaque hôte virtuel pour lequel vous souhaitez appliquer le filtrage que celui-ci doit utiliser la blocklist.

Pour cela, ajoutez les directives suivantes dans l'hôte virtuel :

```nginx
# Enregistre les blocages dans un fichier dédié
access_log /var/log/nginx/blocklist-hits.log blocklist_hits if=$blocklist_ip;

# Active le blocage des adresses IP présentes dans les blocklists
include snippets/blocklist-enforce.conf;
```

La première directive permet d'enregistrer dans un fichier dédié les requêtes provenant d'adresses IP présentes dans les blocklists.

La seconde directive inclut le *snippet* `blocklist-enforce.conf`, qui applique effectivement le blocage lorsque la variable `$blocklist_ip` indique que l'adresse IP du client est présente dans une liste.

Votre hôte virtuel peut donc être configuré de la manière suivante :

```nginx
server {
    listen 80;
    server_name example.com;

    # Journalise les requêtes bloquées par les blocklists
    access_log /var/log/nginx/blocklist-hits.log blocklist_hits if=$blocklist_ip;

    # Active le blocage des adresses IP présentes dans les blocklists
    include snippets/blocklist-enforce.conf;

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

> 💡 **Tip:** Le filtrage n'est appliqué qu'aux hôtes virtuels dans lesquels le *snippet* `blocklist-enforce.conf` est inclus. Vous pouvez donc choisir précisément les sites et applications auxquels vous souhaitez appliquer les Blocklists IP.

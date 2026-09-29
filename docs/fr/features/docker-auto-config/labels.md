# Labels `nginx-control.*` — référence complète

Ce document liste **tous** les labels Docker reconnus par les deux mécanismes d'auto-configuration, qui partagent la même famille de préfixe `nginx-control.*` mais **ne sont pas le même code** et **ne comprennent pas exactement le même jeu de labels** :

| | Auto-config **locale** | Auto-config **hôte distant** |
|---|---|---|
| Composant | `nginx-dashboard/lib/docker-autoconfig.js` | `nginx-agent/labels.go` (binaire Go séparé, tourne sur l'hôte distant) |
| Voit | les conteneurs du **même hôte** que nginx, via le socket Docker | les conteneurs de **son propre hôte** (différent de celui de nginx) |
| Doc associée | section « Auto-config Docker » du README | section « Hôtes Docker distants (agents) » du README |

---

## 1. Auto-config locale (`nginx-control.*`)

### Socle (vhost HTTP simple)

| Label | Obligatoire | Défaut | Description |
|---|---|---|---|
| `nginx-control.enable` | oui | — | `true` pour publier ce conteneur. Sans lui, tous les autres labels sont ignorés. |
| `nginx-control.network` | oui | — | Nom du réseau Docker **réellement attaché au conteneur nginx**. Sans ce label, rien ne remonte, sans message d'erreur ailleurs que dans les logs. |
| `nginx-control.vhost.server_name` | oui | — | Un ou plusieurs noms, séparés par un espace ou une virgule. |
| `nginx-control.vhost.listen` | non | `80` (HTTP) ou `443` (dès que du SSL est demandé) | Port d'écoute. Un label explicite l'emporte toujours sur le défaut. |
| `nginx-control.vhost.location<NN>` | oui (au moins une) | — | Chemin de la location. `NN` = `01`, `02`, ... |
| `nginx-control.vhost.location<NN>.proxy_pass` | oui (par location) | — | Cible `http://host:port`. |
| `nginx-control.vhost.location<NN>.target` | non | — | **Alias** de `.proxy_pass` (identique à l'agent distant, voir plus bas). Si les deux sont posés sur la même location, **`.target` gagne**. |

### SSL

| Label | Défaut | Description |
|---|---|---|
| `nginx-control.vhost.ssl_certificate` | `none` | `none` \| `snippet` \| `auto` \| `certbot_http` \| `certbot_dns`. |
| `nginx-control.vhost.ssl_certificate.snippet` | — | Requis si `ssl_certificate=snippet` : nom d'un fichier existant dans `snippets/`. |
| `nginx-control.vhost.http_to_https_auto` | `false` | `true` ajoute la redirection 301 HTTP→HTTPS, seulement une fois le certificat effectivement résolu. |

`ssl_certificate=auto` : cherche un certificat Let's Encrypt déjà émis (correspondance exacte ou wildcard) ; reste en HTTP simple si aucun ne correspond, bascule automatiquement au cycle suivant.

`ssl_certificate=certbot_http` / `certbot_dns` : comme `auto`, mais déclenche activement une émission Certbot/Certbot-DNS s'il n'existe pas encore de certificat, **à condition que** Certbot/Certbot-DNS soit configuré et actif (`config/certbot.yml` / `config/certbot-dns.yml`) — sinon erreur explicite (`ssl.error.code`/`ssl.error.message`, statut `ssl_error`). Un délai minimum entre deux tentatives est appliqué (`certbot_retry_minutes`, défaut 15 min).

### snippets

| Label | Description |
|---|---|
| `nginx-control.vhost.server.snippet<NN>` | `include snippets/<fichier>;` au niveau du bloc serveur. |
| `nginx-control.vhost.location<NN>.snippet<MM>` | `include snippets/<fichier>;` au niveau d'une location spécifique. |

### monitoring / diagnostic / analyse

Ces labels écrivent exactement les mêmes commentaires magiques qu'un vhost écrit à la main (`# nginx-control-monitoring: on`, etc.) — un vhost généré automatiquement se pilote ensuite comme n'importe quel autre.

| Label | Défaut | Comportement |
|---|---|---|
| `nginx-control.vhost.monitor.enable` | `false` (**opt-in**) | Active le monitoring HTTP du vhost. |
| `nginx-control.vhost.monitor.interval` | — | Ex. `60s`. |
| `nginx-control.vhost.monitor.valid_http_code` | — | Ex. `2xx, 3xx` ou `200,301,302`. |
| `nginx-control.vhost.location<NN>.monitor.ignore` | `false` (surveillée par défaut) | `true` exclut **cette location précise** du monitoring alors que le vhost l'a activé. |
| `nginx-control.vhost.diagnostic.enable` | `true` (**opt-out**) | `false` désactive le diagnostic pour ce vhost. |
| `nginx-control.vhost.analyze.enable` | `true` (**opt-out**) | `false` désactive l'analyse des logs pour ce vhost. |
| `nginx-control.vhost.analyze.ignore_rules` | — | Ex. `1, 2, 4` — identifiants de règles à ignorer. |

### Agrégation multi-conteneurs (`upstream_group`)

| Label | Description |
|---|---|
| `nginx-control.vhost.location<NN>.upstream_group` | Plusieurs conteneurs (répliques) posant le **même** `server_name` sont normalement en conflit (aucun des deux appliqué). En posant le **même** nom de groupe sur la **même** location, ils sont agrégés en un seul vhost avec un bloc `upstream {}`. Nécessite en plus : même réseau, même port, même config SSL, mêmes chemins de location — le moindre écart retombe sur le conflit normal. |

---

## 2. Auto-config hôte distant (`nginx-control.*`, `nginx-agent`)

Même préfixe et même esprit, mais **ce n'est pas la même implémentation** : pas de `nginx-control.network` (pas de réseau Docker partagé possible entre deux hôtes distincts), et plusieurs labels n'existent **que** côté agent distant.

| Label | Défaut | Description |
|---|---|---|
| `nginx-control.enable` | — | `true` pour publier ce conteneur. |
| `nginx-control.vhost.server_name` | — | Nom(s) du vhost. |
| `nginx-control.vhost.mode` | `direct` | `direct` \| `tunnel` \| `relay` — voir « Modes de routage » ci-dessous. |
| `nginx-control.vhost.relay_scheme` | `http` | `http` \| `https` — **utilisé seulement si `mode=relay`** : indique par quel port du relais (HTTP ou HTTPS) ce vhost est joignable. |
| `nginx-control.vhost.listen` | selon SSL, comme en local | Port d'écoute côté nginx. |
| `nginx-control.vhost.ssl_certificate` | `none` | `none` \| `snippet` \| `auto` \| `certbot_http` \| `certbot_dns` — mêmes sémantiques qu'en local. |
| `nginx-control.vhost.ssl_certificate.snippet` | — | Comme en local. |
| `nginx-control.vhost.http_to_https_auto` | — | Comme en local. |
| `nginx-control.vhost.server.snippet<NN>` | — | Comme en local. |
| `nginx-control.vhost.location<NN>` | — | Chemin de la location. |
| `nginx-control.vhost.location<NN>.target` | — | Cible `scheme://host:port` **directement joignable depuis l'hôte de l'agent** (jamais un nom de conteneur Docker seul — pas de réseau partagé avec nginx dans ce mode). Forme **principale** ici (contrairement au local où `.proxy_pass` est historique). |
| `nginx-control.vhost.location<NN>.snippet<MM>` | — | Comme en local. |
| `nginx-control.vhost.location<NN>.monitor.enable` | `true` (**opt-out** par location) | ⚠️ **Nom inversé par rapport au local** : ici on désactive une location précise avec `monitor.enable=false` (équivalent de `location<NN>.monitor.ignore=true` en local) — même effet final, label et polarité différents. |
| `nginx-control.monitor.enable` | `false` (**opt-in**, au niveau du vhost) | ⚠️ **Pas sous `.vhost.`** contrairement au local (`nginx-control.vhost.monitor.enable`). |
| `nginx-control.monitor.interval` | — | ⚠️ Pas sous `.vhost.` non plus. |
| `nginx-control.monitor.valid_http_code` | — | ⚠️ Idem. |
| `nginx-control.diagnostic.enable` | `true` (**opt-out**) | ⚠️ Pas sous `.vhost.` non plus. |
| `nginx-control.vhost.analyze.enable` | `true` (**opt-out**) | Ici sous `.vhost.`, comme en local. |
| `nginx-control.vhost.analyze.ignore_rules` | — | Comme en local. |
| `nginx-control.publish` | toutes les cibles (`all`) | Routage multi-master : `dmz,lan` limite ce vhost aux cibles nommées. Sans effet si une seule cible/master est utilisée. |

### ⚠️ Divergences à ne jamais confondre entre les deux tableaux

1. **`.proxy_pass` vs `.target`** : les deux acceptent les deux formes (alias, `.target` prioritaire) — **seul point identique** entre les deux    schémas de monitoring/diagnostic.
2. **Préfixe `.vhost.` pour monitor/diagnostic** : présent en local (`nginx-control.vhost.monitor.enable`), **absent** côté agent distant (`nginx-control.monitor.enable`, sans `.vhost.`). `analyze.*` reste sous  `.vhost.` des deux côtés.
3. **Label d'exclusion par location** : local = `location<NN>.monitor.ignore` (`true` = exclue, défaut `false`) ; agent distant =  `location<NN>.monitor.enable` (`false` = exclue, défaut `true`) — **noms différents, polarité inversée, mais même résultat final** (une location non surveillée alors que le reste du vhost l'est).
4. **`nginx-control.network`** : requis en local, **n'existe pas** côté agent distant (pas de réseau Docker partagé entre deux hôtes différents).
5. **`mode` / `relay_scheme` / `publish`** : **n'existent que** côté agent distant — pas d'équivalent local (l'auto-config locale ne connaît qu'un    seul mode de routage, puisque nginx et les conteneurs partagent déjà le même hôte/réseau).
6. **`upstream_group`** : **n'existe que** côté local — pas d'équivalent documenté côté agent distant à ce jour.

### Modes de routage (agent distant uniquement)

- **`direct`** (défaut) : nginx se connecte directement au `.target` — nécessite que l'hôte nginx puisse joindre l'hôte distant sur ce port (VPN, réseau privé, IP publique...).
- **`tunnel`** : l'agent ouvre une connexion WebSocket sortante vers le dashboard (`GET /api/agent/tunnel`) et y reste connecté ; aucune ouverture de port entrante n'est nécessaire côté hôte distant (utile derrière un NAT sans IP publique). Une seule connexion tunnel active par agent.
- **`relay`** : un seul port fixe (ou deux, HTTP/HTTPS) exposé par l'agent ; le routage entre vhosts se fait par `server_name` (préfixe le plus long), avec streaming HTTP complet — sert de compromis entre `direct` (un port par cible) et `tunnel` (un saut JSON par requête). `relay_scheme` indique alors quel port du relais (HTTP ou HTTPS) sert ce vhost.
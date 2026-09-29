# Reverse proxy Nginx avec interface Web

## Présentation

**Nginx, sans compromis.**

Cette stack Docker propose un environnement Nginx prêt à l'emploi pour déployer et administrer un reverse proxy tout en conservant la philosophie et la configuration native de Nginx.

L'objectif du projet est simple : **faciliter l'exploitation de Nginx sans ajouter une nouvelle couche d'abstraction**.

Contrairement à certaines solutions de reverse proxy qui imposent leur propre syntaxe, leurs conventions ou leur manière de déclarer les services, cette stack utilise directement les fichiers de configuration Nginx.

Si vous savez configurer Nginx, vous savez déjà utiliser cette stack.

```text
nginx/config/
├── conf.d/
├── sites/
├── snippets/
└── streams/
```

Vos configurations Nginx existantes peuvent ainsi être réutilisées directement, avec seulement quelques adaptations si nécessaire.

Mais la stack ne se limite pas à fournir un conteneur Nginx. Elle ajoute autour du moteur un ensemble d'outils permettant de simplifier son administration au quotidien :

* tableau de bord et monitoring ;
* visualisation et gestion des configurations ;
* consultation des logs en temps réel ;
* gestion des certificats ;
* sauvegarde des configurations ;
* validation et rechargement de Nginx ;
* gestion du cache ;
* déploiement Git / GitOps ;
* intégration avec CrowdSec ;
* analyse avancée des logs ;
* intégration ModSecurity et Coraza ;
* statistiques GoAccess ;
* gestion DNS avec GoDNS ;
* génération de certificats Let's Encrypt.

L'approche est volontairement **modulaire** : le cœur de la stack reste un Nginx classique et les fonctionnalités supplémentaires peuvent être ajoutées en fonction des besoins.

### Le principe

**Nginx reste le moteur. La stack s'occupe du reste.**

Vous conservez la puissance et la flexibilité de Nginx, notamment l'utilisation de directives comme `map`, `limit_req`, `proxy_cache`, GeoIP ou encore les nombreuses possibilités offertes par les configurations natives.

L'objectif n'est donc pas de remplacer Nginx par une nouvelle solution, mais de fournir **un environnement complet autour de Nginx pour faciliter son déploiement, son administration, sa supervision et son intégration avec d'autres outils.**


## Concept d'utilisation de Nginx

L’objectif de cette stack, et plus particulièrement de la partie Nginx, a été de conserver une configuration aussi proche que possible d’une utilisation classique de Nginx.

L’idée est de ne pas imposer une nouvelle convention de configuration, comme peuvent le faire certaines solutions de reverse proxy « packagées », qui nécessitent d’apprendre une syntaxe ou une organisation spécifique.

Cette approche permet une adoption beaucoup plus simple : si vous disposez déjà de configurations Nginx, celles-ci devraient pouvoir fonctionner directement, ou ne nécessiter que quelques adaptations mineures pour être intégrées à la stack.

Elle permet également de continuer à exploiter facilement l’ensemble des fonctionnalités natives de Nginx, qui peuvent parfois être limitées ou moins accessibles avec certaines solutions de reverse proxy.

On peut notamment continuer à utiliser :

- le cache de fichiers ;
- le rate limiting avec les directives `limit_req` et `limit_conn` ;
- GeoIP ;
- les directives `map` pour créer des règles de configuration dynamiques ;
- et plus généralement les nombreuses directives disponibles nativement dans Nginx.

Le choix a donc été de ne pas chercher à masquer Nginx derrière une couche d’abstraction, mais au contraire de conserver toute sa souplesse tout en simplifiant son déploiement et son exploitation.

L’ensemble des fichiers de configuration Nginx se trouve dans le répertoire nginx/config.

La configuration est organisée en plusieurs répertoires afin de conserver une structure claire :

- conf.d : configurations générales de Nginx chargé dans le contexte `http { }`
- sites : configurations des différents sites et virtual hosts
- snippets : fragments de configuration réutilisables 
- streams : configurations pour les connexions TCP/UDP

Pour qu’un fichier soit automatiquement chargé dans la configuration Nginx, il doit impérativement avoir l’extension .conf.

Cette convention permet également de désactiver facilement une configuration sans avoir à supprimer le fichier. Il suffit de modifier son extension, par exemple :

```
site.conf
```

devient :

```
site.conf.DISABLE
```

Le fichier n’étant alors plus chargé par Nginx, la configuration peut être conservée pour être réactivée ultérieurement en lui redonnant simplement l’extension .conf.

## Les différentes images de Nginx

Pour configurer votre reverse proxy, trois images Docker sont disponibles, selon les fonctionnalités dont vous avez besoin :

- Nginx standard : basée sur la version stable de Nginx (1.30.4) ;
- Nginx avec ModSecurity : permet d’ajouter des fonctionnalités WAF à Nginx (1.30.4-waf) ;
- Nginx avec Coraza : intègre le WAF nouvelle génération Coraza (1.30.4-coraza). Cette version est actuellement considérée comme expérimentale.

Le fonctionnement et la configuration de Nginx restent identiques quelle que soit l’image utilisée. Le choix de l’image permet simplement d'activer ou non les fonctionnalités WAF dont vous avez besoin.

Pour une utilisation classique en reverse proxy, l’image Nginx standard est donc suffisante. Si vous souhaitez ajouter une couche de protection WAF, vous pouvez utiliser la version ModSecurity ou expérimenter Coraza.
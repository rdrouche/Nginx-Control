# Diagnostic

La fonctionnalité **Diagnostic** permet d'obtenir une vue globale ou détaillée d'un VHost.

Elle regroupe plusieurs informations permettant d'avoir rapidement une vue d'ensemble de la configuration et du fonctionnement du VHost :

* une vue d'ensemble du VHost ;
* les différents backends utilisés par les `proxy_pass` ;
* des tests des backends avec `curl` et `curl -v` ;
* des informations liées à la sécurité ;
* les informations de monitoring lorsque celui-ci est activé ;
* un schéma graphique du VHost et de ses backends ;
* le fichier de configuration du VHost.

## Vue d'ensemble

Cette section présente les informations générales de configuration du VHost dans **Nginx Control**.

Elle permet notamment d'avoir une vue rapide de la configuration du VHost et des éléments qui le composent.

## Backends

Cette section permet de tester individuellement les backends utilisés par les directives `proxy_pass`.

Pour chaque backend, **Nginx Control** effectue un test à l'aide de `curl`.

Le test avec `curl -v` permet d'aller plus loin en affichant notamment les en-têtes HTTP retournés par le backend.

Cela permet rapidement de vérifier :

* si le backend répond ;
* le code de réponse HTTP ;
* les en-têtes retournés ;
* les éventuels problèmes de communication avec le backend.

## Sécurité

Cette section présente un état des lieux des bonnes pratiques de sécurité appliquées au VHost.

Elle permet notamment de vérifier les en-têtes de sécurité ainsi que les liaisons HTTP/HTTPS utilisées par le VHost.

## Monitoring

Lorsque le monitoring est activé sur le VHost, cette section affiche les informations de supervision associées aux backends.

Elle permet ainsi de retrouver les informations de monitoring directement depuis le diagnostic du VHost.

## Schéma

Cette section affiche une représentation graphique du VHost et de ses backends.

Elle permet de visualiser rapidement les différentes `location` et les cibles utilisées par les `proxy_pass`.

Un peu de visualisation dans une configuration Nginx ne fait jamais de mal... **juste fun !**

## Conf

Cette section affiche directement le fichier de configuration du VHost.

Elle permet de consulter la configuration utilisée par Nginx depuis le diagnostic, sans avoir à rechercher manuellement le fichier correspondant.

## Flags de personnalisation

Comme pour les autres fonctionnalités d'analyse de **Nginx Control**, il est possible de désactiver le diagnostic pour un VHost ou pour un fichier de configuration.

### Exclure un fichier d'hôtes virtuels

Pour désactiver complètement le diagnostic d'un fichier de configuration, ajoutez le commentaire :

```nginx
# nginx-control-diagnostic: off

server {
    ...
}
```

### Exclure un bloc `server`

Il est également possible de désactiver le diagnostic pour un seul bloc `server` :

```nginx
server {
    # nginx-control-diagnostic-vhost: off

    ...
}
```

Cette possibilité est notamment utile lorsque plusieurs VHosts sont présents dans un même fichier et que certains ne doivent pas être analysés.

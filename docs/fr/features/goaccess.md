# GoAccess

[GoAccess](https://goaccess.io/) est un analyseur de journaux Web open source permettant de générer des statistiques détaillées à partir des fichiers `access_log` de Nginx.

Nginx Control permet d'intégrer **GoAccess directement dans son interface** afin de disposer, pour un ou plusieurs hôtes virtuels, d'une interface de statistiques sur les visites sans avoir à déployer et configurer manuellement un conteneur GoAccess.

L'objectif de cette intégration est de permettre aux personnes qui le souhaitent d'obtenir directement dans Nginx Control des statistiques telles que :

* le nombre de visiteurs et de requêtes ;
* les pages les plus consultées ;
* les fichiers les plus demandés ;
* les codes HTTP retournés ;
* les navigateurs et systèmes utilisés ;
* les User-Agent ;
* les pays d'origine des visiteurs ;
* les référents ;
* la consommation de bande passante ;
* l'évolution du trafic.

GoAccess fonctionne directement à partir des fichiers **`access_log`** de Nginx. Il n'intervient donc pas dans le traitement des requêtes et ne modifie pas le fonctionnement du reverse proxy.

> **GoAccess et Nginx Analyzer sont complémentaires :** GoAccess est principalement destiné à l'analyse statistique et à la visualisation du trafic, tandis que Nginx Analyzer est orienté vers la détection de comportements inhabituels et le déclenchement d'alertes.

## Démarrer un conteneur GoAccess

Pour démarrer GoAccess depuis Nginx Control, aller dans :

**INTEGRATION → GoAccess**

Sélectionner ensuite un VHost dans le panneau de gauche, puis cliquer sur **Démarrer**.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-028-goaccess.png" width="800" />

Une fenêtre de configuration permet ensuite de définir les paramètres du conteneur GoAccess pour le VHost sélectionné.

Deux options sont notamment proposées :

* **Données persistantes** : permet de conserver les données générées par GoAccess entre les redémarrages du conteneur ;
* **Intégration GeoIP** : permet d'enrichir les statistiques avec les informations géographiques associées aux adresses IP.

Pour l'intégration GeoIP, voir la documentation [**GeoIP**](geoip.md).

Une fois la configuration terminée, cliquer sur **Démarrer**.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-029-goaccess.png" width="800" />

## Analyse des journaux

Une fois le conteneur démarré, GoAccess commence à analyser les fichiers de logs associés au VHost sélectionné.

Il utilise les `access_log` de Nginx pour construire les différentes statistiques et générer son interface Web.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-030-goaccess.png" width="800" />

L'interface permet ensuite de consulter les différentes statistiques du VHost et d'analyser l'activité des visiteurs.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-031-goaccess.png" width="800" />

> **À noter :** GoAccess analyse les informations présentes dans les journaux Nginx. La qualité et la précision des statistiques dépendent donc directement de la configuration des `access_log` et du format de journalisation utilisé.

<hr />

> **À noter :** sur les VHost à fort trafic, après plusieurs semaines d'utilisation, le conteneur GoAccess peut devenir assez gourmand en ressources et consommer plusieurs centaines de mégaoctets de RAM.
>
> Pour disposer de statistiques sur une période plus longue tout en limitant la consommation de ressources, je réfléchis actuellement à l'intégration d'**AWStats** dans Nginx Control.
>
> L'objectif serait notamment de proposer une solution mieux adaptée aux sites générant un volume important de journaux et nécessitant un historique statistique sur le long terme.

# Carte

Cette fonctionnalité est clairement un **gadget**... donc totalement utile ! 😄

Elle permet d'afficher sur une carte, **en temps réel**, la provenance géographique des requêtes reçues par Nginx et d'identifier le type de visiteur à l'origine de celles-ci :

* **Humain**
* **Robot**

Les informations sont récupérées à partir des journaux analysés par **Nginx Analyzer Agent** et de la géolocalisation des adresses IP.

## Prérequis

Pour utiliser cette fonctionnalité, les composants suivants doivent être configurés :

* [**Nginx Analyzer Agent - NAA**](../nginx-analyzer.md)
* [**GeoIP**](../geoip.md)

NAA analyse les requêtes et transmet les informations nécessaires à Nginx Control, tandis que GeoIP permet de déterminer leur localisation géographique.

## Utilisation

La carte est accessible depuis : **INTEGRATION → Carte**

Les requêtes apparaissent alors directement sur la carte avec leur provenance géographique et leur classification **Humain / Robot**.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-027-map.png" width="800" />

> **À noter :** la géolocalisation d'une adresse IP reste approximative. La position affichée ne correspond pas à la localisation exacte de l'utilisateur ou du serveur à l'origine de la requête.

# Les actions sur Nginx

Depuis **Nginx Control**, vous pouvez effectuer différentes actions sur Nginx depuis la page **CONTROLE → Contrôle Nginx** :

* **Tester la configuration** : vérifie la configuration Nginx avant son application.
* **Recharger la configuration** : recharge la configuration sans redémarrer le conteneur Nginx.
* **Récupérer les métriques VTS** : récupère les métriques fournies par le module VTS.
* **Redémarrer Nginx** : redémarre le conteneur Nginx.

Pour pouvoir effectuer ces opérations, Nginx doit impérativement fonctionner dans un conteneur Docker et **Nginx Control doit avoir accès au socket Docker**.

Cette page permet également de consulter les principales métriques du conteneur Nginx :

* **CPU**
* **Mémoire RAM**
* **Réseau**

Cela permet notamment de suivre rapidement la consommation de ressources du reverse proxy et de vérifier son état lors d'une opération de maintenance ou après une modification de configuration.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-038-control.png" width="800" />

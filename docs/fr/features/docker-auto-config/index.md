# Auto-configuration Docker (expérimentale)

Afin de **faciliter le déploiement des conteneurs Docker**, **Nginx Control** intègre deux modes d'auto-configuration, adaptés à différents environnements :

* **Auto-publication depuis le même hôte que Nginx**
* **Auto-publication depuis des hôtes distants**

Si vous êtes déjà utilisateur de **Traefik**, le principe de fonctionnement vous sera familier.

Dans les deux modes, **Nginx Control s'appuie sur les labels Docker** pour récupérer les informations nécessaires à la publication d'un conteneur.

À partir de ces [labels](labels.md), Nginx Control génère dynamiquement la configuration du **VHost Nginx** permettant ensuite à Nginx de recevoir les requêtes et de les transmettre au conteneur concerné.

L'objectif est de pouvoir publier une application Docker sans avoir à créer manuellement toute la configuration du VHost.

Le fonctionnement diffère ensuite selon l'emplacement du conteneur :

* lorsque le conteneur est exécuté **sur le même hôte que Nginx**, Nginx Control peut communiquer directement avec le socket Docker local ;
* lorsque le conteneur est exécuté sur un **hôte distant**, Nginx Control utilise un **agent** pour récupérer les informations Docker et permettre la publication de l'application.

> **À noter :** cette fonctionnalité est actuellement **expérimentale**. Elle est destinée à simplifier la publication d'applications Docker tout en conservant le fonctionnement et la configuration native de Nginx.

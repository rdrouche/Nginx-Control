# Agent **Analyseur de journaux**

Pour profiter pleinement des fonctionnalités de **Nginx Control** et l'exploitation des journaux (logs), il est nécessaire de déployer l'**Agent Analyseur de journaux**.

Cet agent fonctionne dans un conteneur séparé de **Nginx Control**. Il surveille les fichiers de journaux Nginx en temps réel, analyse les requêtes et transmet les informations et alertes au tableau de bord.

L'agent permet notamment d'utiliser les fonctionnalités suivantes :

* **Analyse des journaux** : détection de comportements inhabituels ou potentiellement malveillants à partir de différentes règles, comme les tentatives répétées d'authentification, les scans, les floods ou encore certaines activités de scraping.
* **Analyse volumétrique** : détection des variations inhabituelles du volume de trafic par hôte virtuel. L'analyse tient notamment compte de la saisonnalité du trafic afin de limiter les faux positifs.
* **Analyse du trafic par pays** : détection d'une augmentation inhabituelle du trafic provenant d'un pays donné.
* **Analyse des journaux WAF** : lorsque vous utilisez une version de Nginx intégrant le WAF, comme les variantes WAF ou Coraza, l'agent peut également exploiter les journaux générés par celui-ci.
* **Affichage du trafic en temps réel** : les requêtes peuvent être visualisées en temps réel sur la carte du tableau de bord.
* **Résumés périodiques** : les données collectées et analysées permettent de générer des synthèses périodiques de l'activité du reverse proxy.

L'analyse volumétrique nécessite une période d'apprentissage afin de déterminer le comportement habituel du trafic. L'agent utilise notamment une référence par créneau horaire de la semaine et recommande environ trois semaines d'observation avant de considérer les premières alertes volumétriques comme fiables.

L'**Agent Analyseur de journaux** doit pouvoir accéder en lecture aux fichiers de logs générés par Nginx. Il fonctionne indépendamment du conteneur **Nginx Control** et communique avec celui-ci via son API.

## Déployer et configurer l'Agent Analyseur de journaux

### Déploiement de l'agent

Le déploiement et la configuration de l'**Agent Analyseur de journaux** se font directement depuis **Nginx Control**.

### Configuration de l'agent

Rendez-vous dans : **ADMINISTRATION → Configuration → Analyseur de journaux**

Dans la zone de saisie, renseignez la configuration de l'agent. Voici un exemple :

```yaml
enable: true

host_logs_path: /containers/nginx/nginx/logs
host_data_path: /containers/nginx/config/analyzer
host_geoip_path: /containers/nginx/geoip_data
```

> 💡 **Tip:** Les paramètres correspondant à des chemins (*paths*) doivent contenir les **chemins absolus sur l'hôte**. Ils sont utilisés pour configurer les *bind mounts* Docker nécessaires au fonctionnement de l'agent.

Cliquez ensuite sur **Enregistrer**.

## Démarrer l'agent

Une fois la configuration enregistrée, rendez-vous dans : **INTEGRATIONS → Analyse**

Cliquez ensuite sur le bouton **Démarrer**.

Nginx Control va alors créer et démarrer le conteneur de l'**Agent Analyseur de journaux** avec la configuration fournie.

Une fois l'agent démarré, il commence à surveiller les journaux Nginx et les données collectées peuvent être exploitées par les différentes fonctionnalités d'analyse de **Nginx Control**.
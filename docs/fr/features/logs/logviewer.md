# Log en direct

Le **log en direct** est l'une des seules fonctionnalités liées aux journaux qui ne nécessite pas **Nginx Analyzer**.

Cette fonctionnalité reste volontairement simple : elle permet d'afficher en temps réel le contenu des fichiers de logs présents dans `/var/log/nginx`. Elle revient à utiliser la commande `tail -f` directement sur un fichier de journal.

Pour accéder à cette fonctionnalité, aller dans **CONFIGURATION → Logs en direct**.

Dans le panneau de navigation, sélectionner le fichier de log à consulter, pour afficher son contenu en temps réel.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-019-logviewer.png" width="800" />

Les nouvelles lignes ajoutées au fichier sont automatiquement affichées, ce qui permet notamment de suivre les requêtes reçues par Nginx pendant un test ou lors d'une recherche de problème.
# Page d'erreur personnalisée

Cette fonctionnalité permet de personnaliser les pages d'erreur 4XX et 5XX retournées par Nginx en s'appuyant sur le projet : [tarampampam/error-pages](https://github.com/tarampampam/error-pages).

> Cette fonctionnalité est la première que j'ai intégrée à mon stack Nginx. Elle permet de remplacer les pages d'erreur par défaut de Nginx par des pages plus modernes et visuellement plus agréables.

Comment toutes les fonctionnalités auxiliaire, elle doit être configurer au niveau du tableau de bord.

## Activer les pages d'erreur personnalisée

Commencer par aller : Intergration / Pages d'erreur et copier la code configuration.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-004-error-page.png" width="800" />

Ensuite aller sur Administration / Configuration et aller sur l'onglet Pages d'erreur et copier le texte dans la zone de configuration et cliquer sur Sauvegarder.

```yaml
enable: true
container_image: tarampampam/error-pages:latest
template_name: connection
```

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-005-error-page.png" width="800" />

Retourner sur Pages d'erreur et cliquer sur le bouton Démarrer.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-006-error-page.png" width="800" />

Le conteneur est démarré pour servir les pages d'erreur personnalisées.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-007-error-page.png" width="800" />

## Configurer les pages d'erreurs personnalisées dans les hôtes virtuels

Pour servir les pages d'erreurs personnalisées, il faut utiliser le snippet [`global-error.conf`](https://forge.rdr-it.com/Nginx/reference-files/src/branch/main/snippets/global-error.conf)

Dans le bloc server{...} ajouter l'appel du snippet : 

```nginx
server{
    listen 80;
    server_name example.com;

    # Pages d'erreurs personnalisees
    include snippets/global-error.conf;
    
    location / {
        http://192.168.1.1;
    }
}
```
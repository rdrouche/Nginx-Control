# Commencer à utiliser le reverse proxy

Dans cette partie, nous allons avoir comment prendre en main votre nouveau reverse proxy en créant votre premier virtual host depuis le terminal.

Les fichiers de déclaration des virtualhosts se trouve dans le dossier suivant : `./nginx/config/sites/`.

Pour être "actif", les fichiers doivent l'extension `.conf` afin qu'ils soient chargés.

> Pour désactiver un virtualhost, il suffit de changer l'extension, par convention ajouter `.DISABLE`

## Créer le fichier du virtualhost

1- Créer votre fichier : 

```bash
nano ./nginx/config/sites/example.com.conf
```

2- Saisir la configuration du virtualhost

```nginx
server{
    listen 80;
    server_name example.com;
    
    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

## Appliquer la configuration <a id="#appliquer-la-configuration"></a>

Vous avez deux solutions pour appliquer test et appliquer la configuration du serveur 

- Depuis le terminal
- Depuis l'interface web

### Par le terminal

Tester la configuration de nginx : 

```bash
docker compose exec nginx nginx -t
```

Recharger la configuration : 

```bash
docker compose exec nginx nginx -s reload
```

### Par l'interface web

Dans le menu de navigation cliquer sur Contrôle Nginx et depuis cette page vous pourrez : 

- Tester la config
- Recharger Nginx

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-003-reload.png" width="800" />

<hr />

Vous savez maintenant créer un fichier pour configurer un hôte virtuel, tester la configuration et recharger Nginx.
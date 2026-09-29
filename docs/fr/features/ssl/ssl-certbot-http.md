# Génération des certificats Let's Encrypt - HTTP Challenge

Les certificats générés par Certbot sont stockés sur l'hôte dans le dossier :

```text
./certificats/certbot
```

Ce dossier est monté dans le conteneur Nginx à l'emplacement :

```text
/etc/letsencrypt
```

## Principe de fonctionnement

Un conteneur Certbot est démarré en permanence en parallèle de **Nginx Control**. Son rôle est uniquement de gérer le renouvellement des certificats existants.

Lorsqu'un nouveau certificat doit être généré, **Nginx Control** démarre un conteneur Certbot éphémère dédié à cette demande.

Le certificat généré est ensuite conservé dans le répertoire partagé :

```text
./certificats/certbot
```

## Configuration du certbot

1 - Aller à la page ADMINISTRATION / Configuration sur l'onglet : Certbot - défi HTTP.

2 - Dans la zone de saisie entrer la configuration et cliquer sur Sauvegarder.

```yaml
enable: true
email: user@domain.tld
stagging: false
container_image: certbot/certbot:latest
webroot_host_path: /containers/nginx/nginx/webroot
certs_host_path: /containers/nginx/certificats/certbot
```

si vous utilisez un service ACME privé

```yaml
enable: true
email: user@domain.tld
stagging: false
server: https://acme.domain.tld:9000/acme/acme/directory
ca_bundle_host_path: /path/file/ca-local-root.crt
container_image: certbot/certbot:latest
webroot_host_path: /containers/nginx/nginx/webroot
certs_host_path: /containers/nginx/certificats/certbot
```

>💡 Tip: Les chemins (paths) indiqués correspondent aux chemins absolus sur l'hôte.

3 - Aller sur la page SSL / Cerbot et démarrer le conteneur de renouvellement.

## Demander un certificat par challenge HTTP et configurer l'hôte virtuel

Contrairement à ce que vous pouvez connaître avec **Nginx Control**, il ne suffit pas de créer un hôte virtuel sur le port 80, de demander un certificat, puis de laisser **Nginx Control** configurer automatiquement l'hôte virtuel.

Ce fonctionnement est volontaire. **Nginx Control** est conçu pour être utilisé selon une approche **GitOps** et ne doit pas disposer de droits d'écriture sur le dépôt contenant la configuration.

La génération d'un certificat et la création de l'hôte virtuel sont donc deux opérations distinctes. Il est nécessaire de passer par plusieurs étapes afin de générer le certificat, récupérer les informations nécessaires, puis intégrer sa configuration dans le dépôt Git.

Cette approche permet de conserver **Git comme source de vérité** et d'éviter qu'une modification effectuée depuis l'interface de **Nginx Control** puisse directement modifier la configuration versionnée.


Nous allons partir de l'exemple utilisé au début de cette documentation :

```nginx
server {
    listen 80;
    server_name example.com;

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

>Attention : à chaque modification du fichier de configuration d'un hôte virtuel, vous devez recharger Nginx afin d'appliquer les changements.

1. Préparer le challenge HTTP

Avant de pouvoir demander le certificat, nous devons permettre à Let's Encrypt d'accéder à notre serveur afin de réaliser le challenge HTTP.

Pour cela, nous allons inclure le snippet snippets/letsencrypt-webroot.conf :

```nginx
location /.well-known/acme-challenge/ {
    root /var/www;
}
```

Ce snippet permet à Certbot de déposer les fichiers nécessaires à la validation du domaine dans /var/www. Nginx pourra ensuite les servir directement lors de la requête effectuée par Let's Encrypt.

Notre hôte virtuel devient donc :

```nginx
server {
    listen 80;
    server_name example.com;

    include snippets/letsencrypt-webroot.conf;

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

Rechargez ensuite Nginx afin d'appliquer cette configuration.

2. Générer le certificat

Dans SSL / Certbot, dans la section HTTP, saisissez le nom de domaine dans le champ prévu à cet effet.

Cliquez ensuite sur Ajouter, puis sur Générer.

Patientez quelques secondes pendant que Certbot effectue le challenge HTTP et génère le certificat.

Une fois le certificat généré, il sera disponible dans l'arborescence /etc/letsencrypt.

3. Passer l'hôte virtuel en HTTPS

Une fois le certificat généré, nous pouvons modifier l'hôte virtuel afin qu'il écoute en HTTPS :

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name example.com;

    include snippets/letsencrypt-webroot.conf;

    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    location / {
        proxy_pass http://192.168.1.1;
    }
}
```

Il est également nécessaire de conserver un hôte virtuel sur le port 80 afin de rediriger les visiteurs vers HTTPS :

```nginx
server {
    listen 80;
    server_name example.com;

    include snippets/letsencrypt-webroot.conf;

    return 301 https://$host$request_uri;
}
```

Le snippet letsencrypt-webroot.conf est volontairement conservé dans le bloc HTTP. Il permet notamment de continuer à répondre aux requêtes du challenge HTTP de Let's Encrypt lors des renouvellements du certificat.

Après avoir enregistré les modifications, rechargez Nginx pour appliquer la nouvelle configuration.

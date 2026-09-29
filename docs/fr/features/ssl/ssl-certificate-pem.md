# Certificat au format PEM/KEY

Les fichiers `.pem` et `.key`, contenant respectivement le certificat et la clé privée au format texte/Base64, doivent être placés sur l'hôte dans le dossier :

```text
./certificats/ssl/
```

Ce dossier est monté dans le conteneur Nginx à l'emplacement suivant :

```text
/ssl
```

Par exemple, si vous disposez des fichiers suivants :

* `exemplecom.cer`
* `exemplecom.key`

Vous pouvez les utiliser dans votre hôte virtuel avec les directives suivantes :

```nginx
ssl_certificate /ssl/exemplecom.cer;
ssl_certificate_key /ssl/exemplecom.key;
```

> 💡 **Tip:** Si vous utilisez le même certificat dans plusieurs hôtes virtuels, je vous conseille de créer un *snippet* afin d'éviter de dupliquer la configuration.
>
> ```nginx
> # file: snippets/ssl-exemplecom.conf
>
> ssl_certificate /ssl/exemplecom.cer;
> ssl_certificate_key /ssl/exemplecom.key;
> ```
>
> Vous pourrez ensuite inclure ce *snippet* dans les hôtes virtuels concernés :
>
> ```nginx
> include snippets/ssl-exemplecom.conf;
> ```
>
> Cette méthode permet de centraliser la configuration du certificat et de simplifier son remplacement ou sa modification.

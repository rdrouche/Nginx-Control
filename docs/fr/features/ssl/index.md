# Gestion des certificats SSL dans Nginx Control

**Nginx Control** prend en charge plusieurs méthodes de gestion des certificats SSL/TLS :

* **Certificat au format PEM/KEY** : certificat acquis auprès d'une autorité de certification publique ou émis par votre propre autorité de certification (CA).
* **Certificat Certbot avec challenge HTTP** : génération et renouvellement automatique du certificat à l'aide d'un challenge HTTP.
* **Certificat Certbot avec challenge DNS** : génération et renouvellement automatique du certificat à l'aide d'un challenge DNS. Pour le moment, seul **Cloudflare** a été testé.

Quelle que soit la source du certificat, celui-ci peut être consulté depuis le tableau de bord de **Nginx Control**, dans : **CONFIGURATION → SSL Certificates**

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-014-ssl.png" width="800" />

En cliquant sur un certificat, vous pouvez accéder à différentes informations le concernant, notamment sa date d'expiration, son émetteur et les noms de domaine associés.

<img src="https://static.rdr-it.com/docs/nginx-dashboard/nginxdash-015-ssl.png" width="800" />

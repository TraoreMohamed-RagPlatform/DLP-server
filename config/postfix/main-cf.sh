#!/bin/bash
# Réglages de /etc/postfix/main.cf utilisés dans le labo (AlmaLinux 9, Postfix 3.5)
# postconf -e modifie la ligne si elle existe, ou l'ajoute sinon.
# Astuce : lancer "sudo -v" avant pour ne taper le mot de passe qu'une fois.

# Identité du serveur
sudo postconf -e "myhostname = mail.mic.lab"
sudo postconf -e "mydomain = mic.lab"
sudo postconf -e 'myorigin = $mydomain'          # guillemets simples : garder le $

# Écoute et domaines acceptés
sudo postconf -e "inet_interfaces = all"
sudo postconf -e "inet_protocols = ipv4"
sudo postconf -e 'mydestination = $myhostname, localhost.$mydomain, localhost, $mydomain'
sudo postconf -e "mynetworks = 127.0.0.0/8"      # seul le serveur peut envoyer sans mot de passe

# Boîtes aux lettres au format Maildir (lues par Dovecot)
sudo postconf -e "home_mailbox = Maildir/"

# Chiffrement TLS (certificat signé par la CA du labo, voir config/pki)
sudo postconf -e "smtpd_tls_cert_file = /etc/pki/tls/certs/mail.mic.lab.crt"
sudo postconf -e "smtpd_tls_key_file = /etc/pki/tls/private/mail.mic.lab.key"
sudo postconf -e "smtpd_tls_security_level = may"

# Authentification des utilisateurs : Postfix demande à Dovecot (SASL)
sudo postconf -e "smtpd_sasl_type = dovecot"
sudo postconf -e "smtpd_sasl_path = private/auth"

# Vérification
postconf -n | grep -E "myhostname|mydomain|myorigin|mydestination|home_mailbox|smtpd_tls|smtpd_sasl"

#!/bin/bash
# Mini-PKI du labo : une autorité de certification (CA) "MIC LAB Root CA"
# qui signe le certificat du serveur mail.mic.lab.
#
# Pourquoi ? Thunderbird (comme tous les logiciels Mozilla) refuse un certificat
# auto-signé "CA:TRUE" utilisé comme certificat de serveur, et exige le champ
# SAN (subjectAltName). Avec une CA importée dans Thunderbird, plus aucun
# avertissement : c'est le fonctionnement d'une PKI d'entreprise.
#
# À lancer en tant qu'admin (pas root) : bash creer-pki.sh
set -e

mkdir -p ~/pki && cd ~/pki

# 1. L'autorité de certification (10 ans)
openssl req -x509 -new -nodes -days 3650 -newkey rsa:2048 \
  -keyout ca.key -out ca.crt -subj "/CN=MIC LAB Root CA"

# 2. Clé + demande de certificat (CSR) du serveur
openssl req -new -nodes -newkey rsa:2048 \
  -keyout mail.key -out mail.csr -subj "/CN=mail.mic.lab"

# 3. Extensions du certificat serveur
cat > mail.ext <<'EOF'
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:mail.mic.lab
EOF

# 4. La CA signe le certificat du serveur (825 jours)
openssl x509 -req -in mail.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out mail.crt -days 825 -extfile mail.ext

# 5. Vérification : doit afficher "mail.crt: OK"
openssl verify -CAfile ca.crt mail.crt

# 6. Installation pour Postfix et Dovecot
sudo cp mail.crt /etc/pki/tls/certs/mail.mic.lab.crt
sudo cp mail.key /etc/pki/tls/private/mail.mic.lab.key
sudo chmod 600 /etc/pki/tls/private/mail.mic.lab.key
chmod 600 ~/pki/*.key          # ca.key = la clé la plus sensible du labo
sudo systemctl restart postfix dovecot

echo "Copier ~/pki/ca.crt (jamais ca.key) sur le poste client et l'importer"
echo "dans Thunderbird : Paramètres > Vie privée et sécurité > Gérer les certificats > Autorités."

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dlp_filter.py - Filtre DLP (Data Loss Prevention) pour Postfix
Auteur : Mohamed Traore - Master 1 Ingenierie de la cybersecurite

Role : analyser chaque mail envoye par un utilisateur AVANT qu'il parte,
detecter les donnees sensibles (carte bancaire, IBAN, CIN, cle privee,
mot de passe, document confidentiel) et decider :
    LIVRER   -> le mail part normalement
    AVERTIR  -> le mail part, mais avec un en-tete X-DLP qui signale le risque
    BLOQUER  -> le mail est refuse et renvoye a l'expediteur avec une explication

Deux facons de l'utiliser :
    1) Par Postfix (le message arrive sur l'entree standard) :
         dlp_filter.py -f expediteur -- destinataire1 [destinataire2 ...]
    2) En mode test, sans Postfix (marche aussi sous Windows) :
         python dlp_filter.py --test exemples/02_carte_bancaire.eml

Compatible Python 3.9 (version installee sur AlmaLinux 9) :
pas de match/case, qui demande Python 3.10.
"""

import argparse
import re
import subprocess
import sys
from email import message_from_bytes, policy
from email.utils import getaddresses

# Le module syslog n'existe que sous Linux. Sous Windows (mode test), on s'en passe.
try:
    import syslog
    SYSLOG_DISPONIBLE = True
except ImportError:
    SYSLOG_DISPONIBLE = False


# ---------------------------------------------------------------------------
# 1. CONFIGURATION
# ---------------------------------------------------------------------------

DOMAINE_INTERNE = "mic.lab"        # les adresses @mic.lab sont "internes"
SENDMAIL = "/usr/sbin/sendmail"    # sert a remettre le mail a Postfix

# Codes de sortie que Postfix comprend
EX_OK = 0             # tout va bien
EX_UNAVAILABLE = 69   # refus definitif : Postfix renvoie le mail a l'expediteur
EX_TEMPFAIL = 75      # probleme temporaire : le mail reste dans la file d'attente

# Niveaux de risque, du plus faible au plus grave (l'ordre compte !)
NIVEAUX = ["FAIBLE", "MOYEN", "ELEVE", "CRITIQUE"]

# Pieces jointes interdites : cles privees, certificats, coffres de mots de passe
EXTENSIONS_INTERDITES = [".pem", ".key", ".pfx", ".p12", ".kdbx"]


# ---------------------------------------------------------------------------
# 2. VERIFICATIONS (pour eviter les faux positifs)
# ---------------------------------------------------------------------------

def luhn_valide(numero):
    """Algorithme de Luhn : verifie qu'un numero de carte bancaire est plausible.
    On part de la droite, on double un chiffre sur deux, on retire 9 si le
    resultat depasse 9, puis on additionne tout. Le total doit finir par 0."""
    total = 0
    chiffres = numero[::-1]          # on lit le numero a l'envers
    for position in range(len(chiffres)):
        chiffre = int(chiffres[position])
        if position % 2 == 1:        # un chiffre sur deux
            chiffre = chiffre * 2
            if chiffre > 9:
                chiffre = chiffre - 9
        total = total + chiffre
    return total % 10 == 0


def iban_valide(iban):
    """Verification officielle d'un IBAN (norme ISO 13616, modulo 97).
    1) on deplace les 4 premiers caracteres a la fin ;
    2) on remplace chaque lettre par un nombre (A=10, B=11 ... Z=35) ;
    3) le grand nombre obtenu, divise par 97, doit donner un reste de 1."""
    iban = iban.replace(" ", "").upper()
    reorganise = iban[4:] + iban[:4]
    en_chiffres = ""
    for caractere in reorganise:
        if caractere.isdigit():
            en_chiffres = en_chiffres + caractere
        else:
            en_chiffres = en_chiffres + str(ord(caractere) - ord("A") + 10)
    return int(en_chiffres) % 97 == 1


def masquer(valeur):
    """Masquage (vu en cours) : on ne garde que les 4 derniers caracteres.
    Le journal ne doit JAMAIS contenir la donnee sensible en clair."""
    valeur = valeur.replace(" ", "").replace("-", "")
    if len(valeur) <= 4:
        return "****"
    return "*" * (len(valeur) - 4) + valeur[-4:]


# ---------------------------------------------------------------------------
# 3. REGLES DE DETECTION (pattern matching avec des expressions regulieres)
# ---------------------------------------------------------------------------

# Suite de chiffres, eventuellement separes par un espace ou un tiret
MOTIF_SUITE_CHIFFRES = re.compile(r"\d(?:[ -]?\d)*")

MOTIF_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?\d){10,30}\b")

MOTIF_CIN = re.compile(r"\bCIN\b\s*(?:n°|no|num[eé]ro)?\s*:?\s*([A-Z]{1,2}\d{4,6})\b",
                       re.IGNORECASE)

MOTIF_CLE_PRIVEE = re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")

MOTIF_MOT_DE_PASSE = re.compile(r"\b(?:mot de passe|mdp|password|passwd|pwd)\s*[:=]\s*(\S+)",
                                re.IGNORECASE)

MOTIF_CONFIDENTIEL = re.compile(r"\b(?:strictement confidentiel|confidentiel|diffusion restreinte)\b",
                                re.IGNORECASE)


def chercher_donnees_sensibles(texte):
    """Parcourt le texte et renvoie la liste des detections.
    Chaque detection est un dictionnaire : regle, niveau, extrait (masque)."""
    detections = []

    # Carte bancaire : 13 a 19 chiffres ET Luhn valide -> CRITIQUE
    for trouve in MOTIF_SUITE_CHIFFRES.finditer(texte):
        chiffres = trouve.group().replace(" ", "").replace("-", "")
        if 13 <= len(chiffres) <= 19 and luhn_valide(chiffres):
            detections.append({"regle": "CARTE_BANCAIRE", "niveau": "CRITIQUE",
                               "extrait": masquer(chiffres)})

    # Cle privee -> CRITIQUE
    if MOTIF_CLE_PRIVEE.search(texte):
        detections.append({"regle": "CLE_PRIVEE", "niveau": "CRITIQUE",
                           "extrait": "-----BEGIN ... PRIVATE KEY-----"})

    # IBAN : forme reconnue ET modulo 97 valide -> ELEVE
    for trouve in MOTIF_IBAN.finditer(texte):
        if iban_valide(trouve.group()):
            detections.append({"regle": "IBAN", "niveau": "ELEVE",
                               "extrait": masquer(trouve.group())})

    # Mot de passe ecrit en clair -> ELEVE
    for trouve in MOTIF_MOT_DE_PASSE.finditer(texte):
        detections.append({"regle": "MOT_DE_PASSE", "niveau": "ELEVE",
                           "extrait": masquer(trouve.group(1))})

    # Document classifie -> ELEVE
    trouve = MOTIF_CONFIDENTIEL.search(texte)
    if trouve:
        detections.append({"regle": "CLASSIFICATION", "niveau": "ELEVE",
                           "extrait": trouve.group().upper()})

    # Numero de CIN marocaine -> MOYEN
    for trouve in MOTIF_CIN.finditer(texte):
        detections.append({"regle": "CIN", "niveau": "MOYEN",
                           "extrait": masquer(trouve.group(1))})

    return detections


# ---------------------------------------------------------------------------
# 4. LECTURE DU MAIL : sujet, corps, pieces jointes
# ---------------------------------------------------------------------------

def extraire_contenu(message):
    """Renvoie (texte, noms_de_fichiers).
    Le texte regroupe le sujet, le corps et les pieces jointes de type texte."""
    morceaux = [str(message.get("Subject", ""))]
    noms_fichiers = []

    for partie in message.walk():
        if partie.is_multipart():
            continue                 # un conteneur, pas du contenu

        nom = partie.get_filename()
        if nom:
            noms_fichiers.append(nom)

        type_contenu = partie.get_content_type()
        if type_contenu.startswith("text/") or type_contenu == "application/csv" \
                or (nom and nom.lower().endswith((".txt", ".csv", ".pem", ".key"))):
            donnees = partie.get_payload(decode=True)
            if not donnees:
                continue
            encodage = partie.get_content_charset() or "utf-8"
            try:
                texte = donnees.decode(encodage, errors="replace")
            except LookupError:      # encodage inconnu
                texte = donnees.decode("utf-8", errors="replace")
            if type_contenu == "text/html":
                texte = re.sub(r"<[^>]+>", " ", texte)   # on enleve les balises
            morceaux.append(texte)

    return "\n".join(morceaux), noms_fichiers


def analyser_message(message):
    """Analyse complete : contenu + pieces jointes. Renvoie la liste des detections."""
    texte, noms_fichiers = extraire_contenu(message)
    detections = chercher_donnees_sensibles(texte)

    for nom in noms_fichiers:
        if nom.lower().endswith(tuple(EXTENSIONS_INTERDITES)):
            detections.append({"regle": "PIECE_JOINTE_INTERDITE", "niveau": "CRITIQUE",
                               "extrait": nom})
    return detections


# ---------------------------------------------------------------------------
# 5. POLITIQUE : qui decide quoi
# ---------------------------------------------------------------------------

def niveau_global(detections):
    """Le niveau du mail = le niveau le plus grave trouve."""
    niveau = "FAIBLE"
    for detection in detections:
        if NIVEAUX.index(detection["niveau"]) > NIVEAUX.index(niveau):
            niveau = detection["niveau"]
    return niveau


def est_externe(adresse):
    return not adresse.lower().endswith("@" + DOMAINE_INTERNE)


def decider(niveau, destinataires):
    """Politique DLP :
       CRITIQUE -> BLOQUER toujours
       ELEVE    -> BLOQUER si un destinataire est externe, sinon AVERTIR
       MOYEN    -> AVERTIR
       FAIBLE   -> LIVRER"""
    if niveau == "CRITIQUE":
        return "BLOQUER"
    elif niveau == "ELEVE":
        externe = False
        for adresse in destinataires:
            if est_externe(adresse):
                externe = True
        if externe:
            return "BLOQUER"
        return "AVERTIR"
    elif niveau == "MOYEN":
        return "AVERTIR"
    else:
        return "LIVRER"


# ---------------------------------------------------------------------------
# 6. ACTIONS : journal, en-tetes, renvoi a Postfix
# ---------------------------------------------------------------------------

def journaliser(texte, grave=False):
    """Ecrit dans le journal systeme (lisible avec : journalctl -t dlp-filter)."""
    if SYSLOG_DISPONIBLE:
        syslog.openlog("dlp-filter", syslog.LOG_PID, syslog.LOG_MAIL)
        if grave:
            syslog.syslog(syslog.LOG_WARNING, texte)
        else:
            syslog.syslog(syslog.LOG_INFO, texte)


def ajouter_entetes(brut, niveau, regles):
    """Ajoute deux en-tetes X-DLP tout en haut du mail (sans toucher au reste)."""
    fin_de_ligne = b"\r\n" if b"\r\n" in brut[:2000] else b"\n"
    entetes = ("X-DLP-Niveau: " + niveau).encode("ascii") + fin_de_ligne
    entetes += ("X-DLP-Regles: " + (", ".join(regles) or "aucune")).encode("ascii") + fin_de_ligne
    return entetes + brut


def reinjecter(brut, expediteur, destinataires):
    """Rend le mail a Postfix avec sendmail. Renvoie True si tout s'est bien passe.
    -G : le mail vient d'un filtre, pas d'un utilisateur ; -i : un '.' seul ne coupe pas le mail."""
    commande = [SENDMAIL, "-G", "-i", "-f", expediteur, "--"] + destinataires
    resultat = subprocess.run(commande, input=brut)
    return resultat.returncode == 0


def resume(detections):
    """Texte court : CARTE_BANCAIRE(************1111), IBAN(...)"""
    morceaux = []
    for detection in detections:
        morceaux.append(detection["regle"] + "(" + detection["extrait"] + ")")
    return ", ".join(morceaux)


# ---------------------------------------------------------------------------
# 7. PROGRAMME PRINCIPAL
# ---------------------------------------------------------------------------

def traiter(brut, expediteur, destinataires):
    """Mode Postfix. Renvoie le code de sortie a donner a Postfix."""
    message = message_from_bytes(brut, policy=policy.default)
    detections = analyser_message(message)
    niveau = niveau_global(detections)
    decision = decider(niveau, destinataires)
    regles = sorted(set(d["regle"] for d in detections))

    ligne = ("decision=" + decision + " niveau=" + niveau + " de=" + (expediteur or "<>")
             + " a=" + ",".join(destinataires) + " sujet=\"" + str(message.get("Subject", ""))
             + "\" detections=[" + resume(detections) + "]")
    journaliser(ligne, grave=(decision != "LIVRER"))

    if decision == "BLOQUER":
        # Ce texte apparait dans le mail de refus que recoit l'expediteur.
        print("Message bloque par la politique DLP de " + DOMAINE_INTERNE
              + " (niveau " + niveau + " : " + ", ".join(regles) + ")."
              + " Retirez les donnees sensibles ou contactez le RSSI.")
        return EX_UNAVAILABLE

    brut_final = ajouter_entetes(brut, niveau, regles)
    if reinjecter(brut_final, expediteur, destinataires):
        return EX_OK
    journaliser("echec de la reinjection via sendmail", grave=True)
    return EX_TEMPFAIL


def tester(fichier, destinataires):
    """Mode test : analyse un fichier .eml et affiche le resultat, sans rien envoyer."""
    with open(fichier, "rb") as f:
        brut = f.read()
    message = message_from_bytes(brut, policy=policy.default)
    if not destinataires:            # on prend les destinataires ecrits dans le mail
        champs = message.get_all("To", []) + message.get_all("Cc", [])
        destinataires = [adresse for nom, adresse in getaddresses([str(c) for c in champs])]

    detections = analyser_message(message)
    niveau = niveau_global(detections)
    decision = decider(niveau, destinataires)

    print("Fichier       :", fichier)
    print("Sujet         :", message.get("Subject", ""))
    print("Destinataires :", ", ".join(destinataires))
    print("Detections    :", resume(detections) or "aucune")
    print("Niveau        :", niveau)
    print("Decision      :", decision)
    return decision


def main():
    analyseur = argparse.ArgumentParser(description="Filtre DLP pour Postfix")
    analyseur.add_argument("-f", dest="expediteur", default="", help="adresse de l'expediteur")
    analyseur.add_argument("--test", metavar="FICHIER", help="analyser un fichier .eml sans rien envoyer")
    analyseur.add_argument("destinataires", nargs="*", help="adresses des destinataires")
    arguments = analyseur.parse_args()

    if arguments.test:
        tester(arguments.test, arguments.destinataires)
        return EX_OK

    if not arguments.destinataires:
        print("Aucun destinataire fourni.")
        return EX_TEMPFAIL

    try:
        brut = sys.stdin.buffer.read()
        return traiter(brut, arguments.expediteur, arguments.destinataires)
    except Exception as erreur:
        # Principe "fail-closed" : si la DLP plante, on ne laisse RIEN passer.
        # Le mail reste en file d'attente (code 75) le temps de corriger le bug.
        journaliser("erreur interne du filtre : " + repr(erreur), grave=True)
        print("Erreur temporaire du filtre DLP, nouvel essai plus tard.")
        return EX_TEMPFAIL


if __name__ == "__main__":
    sys.exit(main())

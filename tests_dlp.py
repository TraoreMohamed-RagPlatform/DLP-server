#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests_dlp.py - Verifie automatiquement que le filtre DLP prend la bonne decision
pour chaque mail d'exemple. A lancer apres chaque modification du filtre :

    python tests_dlp.py
"""

import contextlib
import io

import dlp_filter

# fichier d'exemple -> decision attendue
CAS_DE_TEST = [
    ("exemples/01_normal.eml", "LIVRER"),
    ("exemples/02_carte_bancaire.eml", "BLOQUER"),
    ("exemples/03_iban_externe.eml", "BLOQUER"),
    ("exemples/04_confidentiel_interne.eml", "AVERTIR"),
    ("exemples/05_confidentiel_externe.eml", "BLOQUER"),
    ("exemples/06_cin.eml", "AVERTIR"),
    ("exemples/07_mot_de_passe.eml", "AVERTIR"),
    ("exemples/08_cle_privee_piece_jointe.eml", "BLOQUER"),
    ("exemples/09_faux_positif_commande.eml", "LIVRER"),
]

reussis = 0
for fichier, attendu in CAS_DE_TEST:
    with contextlib.redirect_stdout(io.StringIO()):     # on cache l'affichage detaille
        obtenu = dlp_filter.tester(fichier, [])
    if obtenu == attendu:
        reussis = reussis + 1
        print("OK     ", fichier, "->", obtenu)
    else:
        print("ECHEC  ", fichier, "-> obtenu", obtenu, "au lieu de", attendu)

# Tests des fonctions de verification
assert dlp_filter.luhn_valide("4111111111111111") is True
assert dlp_filter.luhn_valide("1234567890123456") is False
assert dlp_filter.iban_valide("MA89 0117 8000 0012 3456 7890 1234") is True
assert dlp_filter.iban_valide("MA00 0117 8000 0012 3456 7890 1234") is False
assert dlp_filter.masquer("4111 1111 1111 1111") == "************1111"
print("OK      fonctions luhn_valide, iban_valide, masquer")

print()
print("Resultat :", reussis, "/", len(CAS_DE_TEST), "cas reussis")

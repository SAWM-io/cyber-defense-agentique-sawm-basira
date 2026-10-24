"""Lecteur continu de la seule base synthétique du démonstrateur défensif.

Aucune modification métier, aucun réseau. La connexion gardée ouverte permet
d'observer l'incarnation Linux du service et de tester sa disponibilité.
"""
import sqlite3
import time

PATH='/opt/sawm-labo/fixtures/database-defense/run-defense-permanente/ledger.sqlite'


def main():
    with sqlite3.connect('file:'+PATH+'?mode=ro',uri=True,timeout=.1) as connection:
        while True:
            try:connection.execute('SELECT count(*) FROM ledger').fetchone()
            except sqlite3.Error:pass  # Les sondes de défense constatent l'indisponibilité.
            time.sleep(2)


if __name__=='__main__':main()

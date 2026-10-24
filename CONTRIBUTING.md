# Contribuer

Une modification doit conserver la séparation observation, interprétation,
autorisation et effet vérifié. Une réponse du modèle ne crée jamais un droit.

1. Créez un environnement Python 3.11 ou supérieur, puis installez
   `requirements-dev.txt`. Installez Node.js 22 pour les contrôles du dashboard.
2. Exécutez `python tests/run_safe.py`, puis
   `python -m pytest -q tests/test_instance_parallele.py`.
3. Ajoutez un test sur un nouveau comportement ou une frontière de confiance.
4. Documentez les sources absentes, les effets non vérifiés et la couverture réelle.
5. Exécutez `python scripts/check_public_release.py` avant publication.

Ne joignez ni coffre, ni trace client, ni disque de VM, ni rapport contenant des
identifiants réels. Des exemples synthétiques et des compteurs suffisent aux tests.
Les scénarios système nécessitent un périmètre autorisé et une VM dédiée.

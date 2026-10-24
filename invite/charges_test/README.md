# Charges bénignes et bornées

Exécuter dans la VM depuis `/opt/sawm-labo/charges_test/`. Chaque script n'a
qu'une fonction, une durée maximale de 300 secondes et un état écrit sous
`/opt/sawm-labo/charges-etat/<source-id>.json`. Les identifiants sont opaques,
sans étiquette de scénario à communiquer au détecteur. Une source ne peut pas
servir deux charges simultanées (verrou local).

```sh
python3 transfert.py --source-id flux-a --run-id essai-1 --bytes 1073741824 --duration 300 --rate-bps 4194304
python3 cpu.py --source-id calcul-a --run-id essai-1 --duration 30 --duty-pct 20
python3 fichiers.py --source-id fichiers-a --run-id essai-1 --duration 10 --hidden
python3 tache.py --source-id battement-a --run-id essai-1 --duration 300 --deadline-epoch EPOQUE_FUTURE --interval 0.25
```

La copie lit une fixture `.txt` existante (ou `--fixture nom.txt`) et la répète
en mémoire jusqu'au volume demandé, au plus 20 Gio, avec des blocs d'au plus
64 Kio et un débit plafonné à 100 Mio/s. Elle ne fabrique aucun fichier énorme.
Elle ne connecte que `127.0.0.1:9009`. Le protocole est une ligne ASCII
`ANNONCE <octets> <source_id> <run_id>\n`, suivie des octets de fixture.
Les volumes envoyés ne sont pas les volumes reçus : la preuve du transfert
reste le compteur du récepteur. `octets_uniques_fixture` distingue le contenu
unique de ses répétitions réelles sur le réseau.

Pour la tâche à redémarrage, l'opérateur fixe `EPOQUE_FUTURE` à l'heure UNIX
du lancement plus au maximum 300 s. L'unité est une unité explicite de test,
avec `Restart=always`, `RestartSec=1`, `RestartPreventExitStatus=78` et
`KillMode=control-group`. L'échéance absolue doit rester inchangée lors des
redémarrages. Aucune installation ou persistance n'est faite par le script.
Le statut 78 empêche une relance indéfinie à l'expiration ; le contrôleur doit
également faire respecter le budget global du scénario.

`cause_fin` distingue fin naturelle par volume, expiration, signal reçu et
erreur. **Aucun de ces résultats n'attribue l'arrêt à SAWM.** Cette attribution
exige la décision, le reçu de l'exécuteur et la mesure indépendante. SIGKILL
ne permet pas au processus d'écrire un dernier reçu : un état périmé reste
incomplet. Une durée bornée est obligatoire, même pour les essais de défense.

Les tests locaux utilisent une socket substituée et des répertoires
temporaires, sans root, sans toucher la VM et sans connexion extérieure.

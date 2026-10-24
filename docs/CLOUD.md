# Utiliser les API publiques Basira / SAWM Cloud

[Retour au README](../README.md)

Le connecteur est un client de l'API : il n'importe aucun backend SAWM et n'accède directement à aucune base de données du fournisseur.

Le kit est réutilisable selon sa licence Apache 2.0. Les moteurs du Cloud restent privés ; leur accès exige un compte autorisé et reste soumis aux conditions, aux droits et aux crédits du service.

## Créer les accès

Depuis [votre espace client](https://basira.sawm.io/espace), avec un compte autorisé :

1. Créer un projet ou espace mémoire pour l'environnement de défense.
2. Créer une entité représentant le serveur ou périmètre suivi.
3. Créer un principal de service pour le connecteur.
4. Lui accorder `read` et `write` sur cette entité précise.
5. Émettre une clé avec le profil **Runtime agent + SAWM**.

Le profil attendu comprend :

```text
events:write jobs:read memory:recall tsst:recall odvl:rank sawm:run
```

La clé initiale d'un projet ne possède pas nécessairement `sawm:run`. Le scope de l'API et le grant sur l'entité sont deux contrôles différents : il faut les deux. Un accès administrateur sur la racine n'est pas nécessaire pour le connecteur.

## Préparer le coffre

```bash
mkdir -p "$HOME/.sawm-labo"
chmod 700 "$HOME/.sawm-labo"
cp .env.example "$HOME/.sawm-labo/env"
chmod 600 "$HOME/.sawm-labo/env"
```

Modifier ensuite ce fichier privé dans votre éditeur. Ne jamais le commiter ou le joindre à un ticket.

```dotenv
BASIRA_BASE=https://basira-api.sawm.io/api/v1/basira
BASIRA_SPACE=mem_REPLACE_WITH_YOUR_SPACE
BASIRA_ENTITY=ent_REPLACE_WITH_YOUR_ENTITY
BASIRA_PRINCIPAL=prn_REPLACE_WITH_YOUR_PRINCIPAL
BASIRA_KEY=REPLACE_WITH_YOUR_PRIVATE_SERVICE_KEY
```

Les champs `BASIRA_ENTITY_TEMOIN` et `BASIRA_PRINCIPAL_TEMOIN` du gabarit servent aux essais de cloisonnement. Utiliser des ressources de test distinctes ; ne pas copier celles d'un autre client.

Le code lit directement le fichier `~/.sawm-labo/env` : il n'est pas nécessaire de le `source` dans votre shell. Les clés doivent être propres à l'environnement, révocables et absentes des captures du dashboard.

## Parcours réellement utilisé

| Étape | Interface | Sens du résultat |
| --- | --- | --- |
| Enregistrer l'observation | `events:batch` | Un job est créé ; ce n'est pas encore une preuve rappelable. |
| Suivre l'ingestion | API jobs | `completed` confirme l'ingestion ; la projection peut encore être en cours. |
| Retrouver le contexte | `recall:tsst` | Preuves dans le périmètre autorisé, avec les métadonnées renvoyées. |
| Classer | `odvl:rank` | Ordre consultatif des candidats ; aucun nouveau droit. |
| Lire le vortex | `odvl:observe` | État disponible ou explicitement indisponible. |
| Demander une décision | Tour SAWM, flux SSE | Proposition retenue uniquement après événement terminal. |
| Conserver l'effet | Dépôt de résultat | Mémoire d'un effet rapporté, avec sa provenance. |

Le SDK est figé dans `connecteur/vendor/basira_client.py`. Son origine est documentée dans `PROVENANCE.txt`. Mettre à jour ce SDK exige de revoir les tests de contrat et les comportements de reprise.

## Exemple d'appel depuis votre intégration

```python
from uuid import uuid4
from connecteur.pont_memoire import PontMemoire

bridge = PontMemoire(coffre="~/.sawm-labo/env", campagne=uuid4().hex)
try:
    # Appel réel au Cloud, sur les événements déjà présents dans votre entité.
    recall = bridge.rappeler("Quels incidents de disponibilité ont été observés ?", limite=5)
    print({"preuves": recall.nombre, "moteur": recall.moteur,
           "latence_ms": recall.latence_ms})
finally:
    bridge.close()
```

Cet exemple ne dépose aucun événement et n'agit pas sur la VM. Il peut consommer du crédit selon votre offre. Une mémoire vide et un moteur indisponible restent deux situations différentes.

Pour construire un tour complet, voir [`connecteur/tour_sawm.py`](../connecteur/tour_sawm.py) et les tests associés. Une campagne réelle doit recevoir un identifiant unique ; les clés d'idempotence ne doivent pas être réutilisées pour des contenus différents.

## Données transmises et confidentialité

SAWM reçoit les observations sélectionnées, les preuves rappelées et les éléments de politique nécessaires à la décision. Selon le capteur, cela peut inclure noms d'unités, chemins, identités techniques, adresses réseau et métadonnées d'incident. Certaines sondes pseudonymisent les comptes ; cela ne rend pas toutes les données anonymes.

Avant une installation client, définir le périmètre envoyé, la rétention, les accès, l'usage des fournisseurs de modèle et les exigences de résidence des données. Héberger les capteurs localement ne signifie pas que tout le traitement est local : **ce dépôt utilise le Cloud**.

## Budget et indisponibilité

La veille propose `--cloud-per-hour` de 1 à 4. Les réservations sont persistées ; les inspections supplémentaires consomment aussi le budget prévu par le contrôleur. Un budget épuisé apparaît dans les incidents.

Les reprises sont bornées. Un refus d'autorisation ou un moteur indisponible ne devient pas un rappel vide silencieux. Une réponse SSE incomplète ne doit pas déclencher une action.

Le dashboard montre les appels enregistrés, statuts, latences, tentatives et usage fourni par l'API. Si les jetons ne sont pas fournis, ils restent indisponibles ; une latence ou un nombre d'appels ne suffit pas à calculer une facture. Consulter la grille de votre espace Cloud.

## Diagnostic rapide

- **403** : vérifier scope `sawm:run`, grants et entité ; ne pas élargir à la racine par défaut.
- **503 moteur indisponible** : conserver le diagnostic et les reprises ; vérifier le statut du service Cloud.
- **409 idempotence** : vérifier que la même clé n'a pas été réutilisée avec un autre corps.
- **Pas de `turn.done`** : traiter le tour comme incomplet et laisser l'exécuteur inactif.
- **Aucun appel dans le dashboard** : vérifier que `--cloud` est actif, que les incidents sont admissibles et que le budget reste disponible.

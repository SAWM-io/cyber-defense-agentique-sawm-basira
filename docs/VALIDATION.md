# Validation du kit client

[Retour au README](../README.md)

Ce document décrit les vérifications de **Cyber Defense Agentique SAWM&Basira** avant publication. Une réussite des tests logiciels ne constitue pas une certification de détection ni une preuve de disponibilité en production.

## Mise à jour du 26 octobre 2026

**676 tests locaux et 10 tests de portabilité réussis** sur macOS / Python 3.14.4, sans échec ni erreur, avec les sources inchangées pendant l’exécution.

Le premier passage Linux a révélé un test qui supposait un hôte Mac : il attendait un processus QEMU/UTM alors que le collecteur ignore volontairement cette mesure sur Linux. Les tests spécifient désormais leur plateforme. Un contrôle supplémentaire vérifie qu’en mode Linux ou VM locale, seul le processus du contrôleur est mesuré et aucun outil UTM n’est appelé. Les assertions d’UUID, de PID, de RAM et de CPU du cas Mac sont conservées.

La [CI publique](https://github.com/SAWM-io/cyber-defense-agentique-sawm-basira/actions/workflows/test.yml) exécute les suites et les contrôles de publication sous Linux / Python 3.11, 3.12 et 3.13. Consulter le résultat du commit utilisé : les essais locaux ne remplacent pas ces résultats Linux.

## Suite locale du 24 octobre 2026

Commande exécutée depuis la racine du dépôt :

```bash
python tests/run_safe.py
```

| Mesure | Résultat |
| --- | ---: |
| Tests exécutés | **675** |
| Échecs | **0** |
| Erreurs | **0** |
| Tests sautés | **0** |
| Sources inchangées pendant l'exécution | **Oui** |
| Environnement | macOS, Python **3.14.4** |

La suite utilise des gardes interdisant les commandes de VM et les connexions hors loopback. Les processus permis sont les contrôles d'interface Node et les acteurs SQLite temporaires prévus par les tests. Aucun appel Cloud n'est nécessaire à cette campagne.

Le résumé est produit dans `releves/rapports/tests-defense-20260923.json`. Le nom historique du fichier n'est pas la date d'exécution : le champ `started_at` du résultat vaut `2026-10-24T21:01:40.314101+00:00` pour cette vérification. Les futurs lancements remplacent ce résumé local ; conserver une copie privée si vous devez comparer vos campagnes.

## Contrôles complémentaires

Les tests pytest de portabilité sont une suite distincte : **10 tests réussis**, non inclus dans le total ci-dessus (`python -m pytest -q tests/test_instance_parallele.py`).

Le dashboard a également été démarré sur un port local distinct : la page et `/api/etat` répondent **HTTP 200**, sans demande Cloud. Le plan d’installation a été exécuté sans mutation, et le contrôle de publication n’a trouvé aucune anomalie.

Les résultats de l’intégration continue sont consultables dans l’onglet Actions du dépôt ; le nombre de tests ne mesure pas une couverture de sécurité universelle.

Les exemples du Cloud ont été rapprochés des signatures de `PontMemoire`, `rappeler()` et des champs de `Rappel` présents dans cette version. Ce contrôle documentaire ne lance pas d'appel facturable et ne prouve pas la disponibilité actuelle d'un compte Cloud.

## Ce qu'il faut encore vérifier chez le client

1. Installation sur une VM Linux dédiée : versions des outils, options noyau et droits effectifs.
2. Fraîcheur et provenance des événements remontés ; comportement lorsqu'un capteur manque.
3. Création de l'espace Cloud, scopes et refus d'accès à une entité non autorisée.
4. Analyse sans action, puis actions limitées à des cibles de test déclarées.
5. Maintenance signée, révocation, changement du manifeste et demandes périmées.
6. Mesure de l'effet et préservation du service légitime après intervention.
7. Panne Cloud, interruption de la réponse, redémarrage du contrôleur et reprise sans double action.

Le script de préparation de la VM et les configurations système sont fournis pour faciliter ces étapes. Ils ne démontrent pas, par leur seule présence, une installation complète réussie sur une machine neuve. Les relevés privés de l'environnement d'origine ne sont pas publiés ici.

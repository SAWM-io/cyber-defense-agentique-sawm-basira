# Construire votre propre agent de défense

[Retour au README](../README.md)

Commencer par un service précis : une base, une unité de traitement, un répertoire ou une application. Définir ce qui est normal, les opérations autorisées, les observations disponibles et l'effet acceptable d'une intervention.

## 1. Ajouter une observation

Implémenter un capteur dans `invite/agent_labo/` ou un adaptateur de télémétrie. Produire un événement structuré avec :

- date et origine de l'observation ;
- ressource et identité technique, lorsqu'elles sont vérifiables ;
- mesure observée, unité et version du schéma ;
- fraîcheur, erreurs, troncature et limites de couverture ;
- éléments de provenance utiles au rapprochement.

Une valeur inconnue doit rester inconnue. Ne pas convertir une lecture en échec en valeur zéro. Ne pas envoyer de secret ou de contenu métier lorsque des métadonnées suffisent.

## 2. Ajouter une inspection

Une inspection est une lecture bornée, différente d'une action. Déclarer son nom dans le contrat, sa cible dans le manifeste et son budget de temps/ressources. Le résultat doit distinguer une inspection réussie d'un accès absent ou refusé.

Voir `controleur/enquete_autonome.py`, `controleur/environnement_serveur.py` et `controleur/inspection_fichiers.py`. Éviter les requêtes libres permettant au LLM de parcourir tout le système ou de construire une commande shell.

## 3. Ajouter une action

Pour qu'une nouvelle action puisse être déléguée :

1. Définir un schéma et une cible explicites dans `connecteur/contrat.py`.
2. Ajouter l'implémentation locale avec une liste d'arguments déterministe.
3. Vérifier la politique, la génération et l'identité de la cible juste avant l'effet.
4. Définir les refus, la déduplication, les conditions de maintenance et le retour arrière éventuel.
5. Mesurer l'effet attendu et la santé du service légitime après action.
6. Montrer séparément proposition, autorisation, exécution et vérification dans le dashboard.

Un retour de commande égal à zéro ne suffit pas à prouver que l'incident est contenu. Par exemple, après arrêt d'une unité, vérifier son absence de reprise et le fonctionnement des services qui devaient rester accessibles.

## 4. Évaluer avec des témoins

Construire au minimum les cas suivants :

| Cas | Résultat attendu |
| --- | --- |
| Activité normale | Pas d'intervention injustifiée. |
| Activité inhabituelle mais maintenance autorisée | Conservation de l'opération couverte et trace de l'autorisation. |
| Incident attribué, action déléguée | Intervention sur la bonne cible, puis effet vérifié. |
| Attribution ou autorisation absente | Refus ou alerte explicite ; pas d'invention de preuve. |
| Observation ancienne, PID réutilisé ou manifeste changé | Revalidation ou refus de la demande périmée. |
| Cloud indisponible ou réponse interrompue | État dégradé visible ; pas d'exécution de texte incomplet. |
| Texte hostile dans un fichier ou un journal | Donnée conservée comme donnée, sans nouveau privilège. |

Les charges de `invite/charges_test/` sont des utilitaires de laboratoire bornés. Ne pas transférer leurs paramètres sur des données clients. Les campagnes qui changent le manifeste doivent être exécutées isolément, sans veille concurrente sur les mêmes ressources.

## 5. Mesurer l'apport de la mémoire

Comparer les mêmes observations et la même politique, avec et sans les composants étudiés, en conservant les scénarios défavorables et les erreurs. Le rappel natif de SAWM peut persister même lorsque le connecteur ne fournit pas de rappel : documenter exactement ce que l'ablation retire.

Mesurer les délais de détection, décision, action et vérification séparément. Compter les faux positifs, les refus corrects, les interventions manquées et les services légitimes préservés. Un résultat sur une VM de test ne devient pas un taux général de détection.

## 6. Passer à plusieurs serveurs ou clients

Séparer entités, principals, clés, politiques et fichiers d'état. Définir l'autorité de chaque opérateur et les ressources qu'il peut déléguer. Ne pas prendre le partage d'un espace Cloud pour une autorisation implicite entre tenants.

Ajouter une orchestration des contrôleurs, une supervision, des notifications, la rétention et une gestion de capacité avant de multiplier les hôtes. Les chemins locaux et labels de service du laboratoire sont à adapter ; le dépôt n'est pas une console multi-tenant prête à être exposée sur Internet.

## Repères de contribution

Conserver des changements ciblés, des schémas versionnés et des tests reproductibles. Éviter les secrets, historiques clients, images de VM et relevés privés dans une contribution. Fournir des exemples synthétiques et expliquer les limites de la validation.

L'API Cloud est la frontière d'intégration : le code de ce dépôt n'exige ni copie des moteurs propriétaires, ni accès aux bases internes du service.

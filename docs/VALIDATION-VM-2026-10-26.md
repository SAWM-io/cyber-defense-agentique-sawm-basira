# Déploiement et essais réels — 26 octobre 2026

Le profil de défense en profondeur et la garde locale signée ont été déployés
sur la VM Linux de démonstration. Les essais ci-dessous utilisent de vrais
processus, fichiers SQLite, sockets et contrôles du noyau, sur des données
fictives. Les appels Basira / SAWM utilisent le Cloud réel.

## Résultats observés

| Essai | Résultat | Qui décide ou applique ? |
|---|---|---|
| Verrou SQLite exclusif non autorisé | Processus responsable arrêté, lecture et écriture rétablies, service témoin disponible | **SAWM Cloud** choisit ; exécuteur local vérifie puis agit ; retour déposé dans Basira |
| Même verrou, sans Cloud | Arrêt et disponibilité vérifiés | Garde locale signée |
| Altération d’une base fictive | Processus attribué confiné ; l’altération reste une preuve, sans prétendre que l’arrêt restaure les données | Garde locale signée |
| Maintenance avec mandat signé | Processus conservé ; tentative d’arrêt refusée | Garde et exécuteur locaux |
| Maintenance, décision SAWM | Aucun arrêt ; **clarification supplémentaire demandée** | SAWM Cloud ; critère d’autonomie complète non satisfait |
| Ticket absent, falsifié ou expiré | Intervention refusée, processus conservé | Exécuteur local |
| Cinq mots de passe incorrects depuis l’hôte | Quatre refus HTTP 401, puis 429 et exclusion réseau ; expiration et accès rétabli vérifiés | Garde d’authentification locale, service fictif sur port 8082 |
| Trois connexions SSH avec une clé non autorisée | Trois refus et une alerte ; accès SSH légitime conservé | OpenSSH refuse ; capteur observe. Aucun bannissement du port 22 |
| Lecture de fichier protégée par LSM | Lecture refusée au processus testé, y compris root ; lecture autorisée témoin conservée | Politique Linux LSM bornée à la fixture |
| HTTP du service témoin | Jeton absent ou incorrect : 401 ; jeton valide : 200 | Authentification locale |

Les trois scénarios de garde locale ont été exécutés deux fois, dont une fois
après le dernier correctif de maintenance. Le manifeste initial a été restauré
à l’identique après chaque scénario. Les nettoyages opérateur sont enregistrés
séparément et ne comptent jamais comme une défense réussie.

Le parcours SAWM validé relie dépôt → rappel TSST → classement ODVL → décision
SAWM → ticket signé → exécution → vérification OS → retour mémoire. L’altération
de base n’a pas été revalidée par une décision SAWM après la remise en état du
Cloud ; sa validation de ce jour porte sur la garde locale. Le plafond existant
de quatre tours SAWM par heure a été conservé, y compris les tentatives échouées.

## Défauts rencontrés et corrections

- Un contrôle utilisait un relevé devenu ancien pendant la vérification du
  journal. L’audit précède désormais la collecte fraîche. Une nouvelle sonde
  SQLite est recueillie après la journalisation ; aucun TTL n’a été allongé.
- La garde locale doit présenter un ticket signé depuis l’activation du nouveau
  profil. Elle possède maintenant une autorité distincte, limitée à ses cibles,
  avec journal Ed25519 et réinspection locale.
- Une maintenance pouvait devenir active pendant l’écriture durable précédant
  l’action. L’exécuteur revérifie désormais identité, maintenance, manifeste et
  ticket après cette écriture, avant la première mutation.
- Les premiers appels Cloud ont échoué : Redis dépassait son plafond mémoire,
  le worker était arrêté après OOM, et des compteurs de limitation avaient perdu
  leur expiration. Les services ont été repris avec des ressources bornées ;
  les fenêtres normales ont été restaurées sans remise à zéro des compteurs.
  Un correctif atomique de l’incrément et de l’expiration a été préparé et testé ;
  sa livraison Cloud est distincte de ce déploiement du laboratoire.

Les tentatives initiales bloquées ou échouées sont conservées dans les preuves.
Elles ne sont pas remplacées par les essais réussis.

## Dashboard et preuves

Le panneau **« Essais d’autonomie — campagne récente »** distingue la garde
locale du pipeline SAWM, affiche les essais datés, les choix, les effets
vérifiés, les refus, le service témoin et les nettoyages. Chaque essai renvoie à
son rapport JSON. Les archives ne sont pas présentées comme l’état courant.

Les rapports privés sont sous `releves/rapports/`, notamment la famille
`validation-autonomie-profondeur-depth-*.json`. Les journaux signés, les clés,
les adresses et les données du laboratoire ne sont pas publiés dans Git.

Validation logicielle de cette révision : **775 tests du runner isolé**, sources
inchangées pendant l’exécution, puis **10 tests d’instances parallèles**. Ces
tests ne remplacent pas les essais VM ci-dessus.

## État et portée

La télémétrie, les capteurs, le témoin, la garde des fichiers et la garde
d’authentification sont supervisés. La veille Cloud conserve son budget durable
et n’intervient que sur les actions et cibles déléguées dans le manifeste.

Le profil expose 22 contrôles, dont 12 sondes OS. Sur cette VM, les paramètres
SSH et la synchronisation NTP demandent encore une revue ; ils ne sont pas
silencieusement déclarés conformes. Un contrôle inconnu reste inconnu.

Cette campagne démontre des capacités précises sur un laboratoire. Elle ne
constitue ni une certification ISO 27001, ni une validation de tous les
malwares, attaques Internet ou compromissions du noyau. La maintenance est
protégée, mais la demande de clarification SAWM reste un point d’amélioration
de l’autonomie.

Voir aussi [Défense en profondeur](DEFENSE-PROFONDEUR.md) et
[installation de la garde locale signée](GARDE-LOCALE-SIGNEE.md).

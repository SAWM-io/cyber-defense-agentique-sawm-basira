# Exploiter la défense et lire le dashboard

[Retour au README](../README.md)

## Trois modes explicites

| Mode | Commande | Effet |
| --- | --- | --- |
| Observation | `python controleur/veille.py --duration 60` | Observe le périmètre, sans analyse Cloud ni action automatique. |
| Analyse | `python controleur/veille.py --duration 300 --cloud` | Analyse avec SAWM ; propositions sans application. |
| Protection déléguée | `python controleur/veille.py --permanent --cloud --apply` | Peut agir dans les droits du manifeste ; journal durable signé. |

Le budget Cloud est borné et configurable par `--cloud-per-hour` entre 1 et 4. Les périodes de collecte et d'analyse ne sont pas équivalentes : le système n'appelle pas le modèle chaque seconde.

## Supervision

Le collecteur et la veille doivent être supervisés séparément. Les capteurs Linux utilisent systemd. Le contrôleur dispose également d'un helper macOS `controleur/supervision.py` ; examiner ses options avec `--help` et sélectionner explicitement les modes souhaités. Un LaunchAgent macOS dépend de la session utilisateur et d'un ordinateur éveillé.

Pour un service Linux, créer des unités sous un compte adapté, avec répertoire de travail et environnement explicites, redémarrage contrôlé et journaux privés. Les fonctions locales privilégiées doivent rester séparées des clés Cloud et du navigateur autant que l'architecture choisie le permet. Le mode local historique exige root ; ce n'est pas une preuve de séparation des privilèges complète.

Avant une activation permanente, vérifier :

- arrêt puis reprise du contrôleur sans double action ;
- expiration d'une observation et changement du manifeste pendant une enquête ;
- indisponibilité Cloud ou budget épuisé ;
- refus des demandes anciennes et préservation de la maintenance autorisée ;
- état du service légitime après intervention.

## Les informations du dashboard

Le collecteur lance l'interface sur **http://127.0.0.1:8899/**. Les séries JSONL sont conservées sous `releves/series/`. Un navigateur fermé n'arrête ni la collecte ni une veille supervisée.

Les panneaux présentent, selon les capteurs disponibles :

- CPU, mémoire, stockage, E/S et réseau du serveur ;
- activité des processus et unités suivis ;
- fraîcheur de la télémétrie et couverture des capteurs ;
- incidents à examiner, clarifications et refus d'action ;
- décision SAWM, politique locale, nettoyage opérateur et effet constaté ;
- appels Basira / SAWM Cloud, statuts, latences, tentatives et usage déclaré ;
- activité de l'agent et dispositions fonctionnelles heuristiques.

Une valeur `null` signifie **non mesuré**. Un état dégradé indique une limite de visibilité, pas une absence d'incident. Un incident ancien rappelé depuis Basira doit être distingué de l'état présent du serveur.

Les dispositions affichées, telles que vigilance ou confiance, évoluent selon des règles locales sur les événements. Elles ne sont pas une mesure de sentiments vécus et ne modifient jamais les permissions.

## Alertes et intervention humaine

« À examiner » rassemble notamment les demandes de clarification, les preuves insuffisantes, les refus et les erreurs d'analyse. Dans cette référence, l'affichage ne constitue pas un envoi automatique par courriel ou messagerie.

Une clarification reste ouverte pour examen. Une réponse humaine dans un texte ne vaut pas, à elle seule, un mandat signé ni une reprise automatique de l'incident. Pour une intégration SIEM, ticketing ou notification, ajouter un consommateur des événements avec identité, déduplication et accusé de réception.

## Audit et reçus

Le journal signé est distinct du flux de télémétrie. Chaque événement important doit conserver la source, la date, les identifiants d'incident et de décision, la politique utilisée et l'effet effectivement vérifié.

Vérifier une copie du journal avec la clé publique appropriée :

```bash
python controleur/audit_signe.py /chemin/audit.jsonl \
  --public-key /chemin/defense-audit-ed25519.pub
```

Conserver clés privées et données de fonctionnement hors Git. Protéger aussi les sauvegardes et les clés publiques de référence. Une signature aide à détecter une modification ; elle ne prouve pas que tous les événements ont été vus. Un dépôt Cloud accepté n'est pas une certification WORM.

## Panne et reprise

Les protections Linux déjà installées ne dépendent pas d'une réponse Cloud à chaque opération. Le contrôleur suspend les actions dont les preuves ou l'autorité ne sont plus vérifiables et expose l'état dégradé.

Après redémarrage, relire les incidents, vérifier la génération du manifeste et l'identité actuelle des processus avant de reprendre. Ne pas rejouer aveuglément les anciennes commandes. Tester les sauvegardes sur une instance distincte avant d'en dépendre.

Une panne du serveur surveillé peut aussi arrêter son contrôleur lorsqu'ils partagent la même VM. Pour un besoin de récupération indépendante, placer le contrôle et une copie des preuves hors de l'hôte. Aucun agent local ne peut garantir de survivre à la perte de son propre noyau ou de son alimentation.

## Évolution des coûts et de la couverture

Mesurer le taux d'événements, les files, la durée d'inspection, les appels Cloud, la RAM, le disque et la durée de vérification. La taille des fichiers, la profondeur des répertoires et les limites des scanners doivent apparaître dans les rapports.

Les historiques complets de notre VM interne ne sont pas distribués dans ce dépôt. Produire vos propres relevés dans votre environnement : tests logiciels, essais VM et charge réelle sont trois niveaux de preuve différents.

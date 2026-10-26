# Défense en profondeur — profil technique ISO 27001 / CIS

[README](../README.md) · [Référentiels et versions](REFERENTIELS.md) · [Modèle de sécurité](SECURITY-MODEL.md) · [Garde locale signée](GARDE-LOCALE-SIGNEE.md)

Ce profil apporte des contrôles techniques continus et des preuves pour un audit. Il ne déclare pas l’entreprise ni le produit « certifié ISO 27001 ». ISO 27001 porte sur un système de management avec un périmètre, des responsabilités, une analyse de risques et des vérifications organisationnelles. Les contrôles ci-dessous sont notre sélection technique ; ce n’est ni l’ensemble des CIS Controls ni un CIS Benchmark certifié.

## Les couches qui se complètent

1. **Mandat institutionnel** : le manifeste local détermine les ressources, les actions, les services protégés et les clés du contrôleur. Le modèle ne le modifie pas.
2. **Observation** : 12 mesures OS supplémentaires vérifient des réglages mémoire/noyau, la configuration SSH globale, l’état d’auditd et la synchronisation déclarée de l’horloge. Elles sont lues sans modifier le serveur.
3. **Mémoire et enquête** : SAWM reçoit les états techniques avec leurs limites, en plus des observations et du rappel Basira / TSST / ODVL de l’incident. Il peut choisir les inspections déjà autorisées et signaler les inconnues. Aucun contrôle de posture ne déclenche à lui seul un arrêt de service ou un appel Cloud supplémentaire.
4. **Veto du contrôleur** : avant une intervention de la veille, la politique, la délégation, la fraîcheur des observations, l’intégrité du journal signé et l’enrôlement de la clé sont vérifiés. Les contrôles supplémentaires choisis par l’administrateur peuvent aussi bloquer l’intervention.
5. **Autorisation signée de courte durée** : l’exécuteur Linux exige une autorisation Ed25519 liée à la décision, l’action, la cible, l’identité attendue du processus et l’empreinte du manifeste. Seules les clés publiques préalablement enrôlées sont acceptées. Une ancienne campagne appelant directement l’exécuteur sans autorisation est refusée lorsque ce profil est activé.
6. **Exécution limitée** : les vérifications existantes de cible, d’identité, de maintenance signée et de non-rejeu restent applicables. L’autorisation de posture ne les remplace pas.
7. **Vérification et preuve** : les effets sont contrôlés ; les changements de posture sont journalisés. Le dashboard affiche les sources et dates, avec export JSON. Une mesure manquante, future ou périmée ne devient jamais une réussite.

Le ticket signé expire au bout de cinq secondes. Une latence excessive ou un désaccord d’horloge doit produire un refus visible, pas une prolongation automatique. Le contrôleur et sa clé sont une frontière de confiance : leur compromission n’est pas résolue par une signature produite sur ce même contrôleur.

## Ce qui est mesuré

| Famille | Mesures et portée |
| --- | --- |
| Mémoire et noyau | ASLR, restriction des pointeurs noyau, accès à dmesg, ptrace, protection des liens physiques et symboliques. |
| SSH | Root direct, mot de passe, mots de passe vides et nombre d’essais, selon `sshd -T`. Les règles `Match`, PAM et tous les chemins MFA ne sont pas entièrement évalués. |
| Journaux et temps | État systemd d’auditd, `NTPSynchronized` et vérification Ed25519 du journal SAWM. Un service actif ne prouve pas que toutes ses règles sont adéquates. |
| Délégation et observations | Manifeste identifié, cibles bornées, clé du contrôleur enrôlée, fraîcheur de la télémétrie et budget des analyses. |
| Disponibilité et capteurs | Service témoin et sonde d’exécution. La présence d’un objet BPF épinglé ne suffit pas : l’attachement LSM demeure inconnu dans cette évaluation. |
| Conservation extérieure | L’ancre n’est satisfaite que si elle est effectivement vérifiée. Une simple copie ou un envoi annoncé ne suffit pas. |

Les seuils SSH proposés sont prudents et doivent être confrontés au rôle du serveur. Un bastion, un équipement industriel ou un service particulier peut nécessiter une politique différente. Le logiciel **ne change pas automatiquement ces configurations** pour obtenir un indicateur vert.

Les mesures OS sont rafraîchies en arrière-plan, avec une validité maximale de 60 secondes et une relecture anticipée avant expiration, en conservant leur date d’origine. Les actions exigent une télémétrie beaucoup plus récente. La vue distingue `satisfait`, `ecart`, `inconnu` et `non_applicable` ; elle ne publie pas de pourcentage de conformité ISO.

## Activer sur une installation autorisée

Le [manifeste de nouvelle installation](../config/manifeste.observation.json) contient le profil, sans cible modifiable ni clé enrôlée. Les installations existantes conservent leur comportement jusqu’à activation explicite. Sauvegarder leur manifeste et intégrer le bloc suivant, sans remplacer les droits ni les données existants :

```json
"defense_profondeur": {
  "profil": "industriel-prudent-v1",
  "controles_bloquants": ["service_temoin", "os_aslr", "os_ssh_empty_passwords"],
  "cles_controleur": []
}
```

Les cinq contrôles obligatoires restent requis même si `controles_bloquants` est vide : `politique_chargee`, `delegation_limitee`, `telemetrie_fraiche`, `journal_signe`, `autorite_controleur`. Un nom de contrôle inconnu ou un profil malformé est refusé. Les contrôles OS non bloquants sont visibles pour l’opérateur, sans interrompre arbitrairement la défense.

1. Installer cette version du kit sur le contrôleur et les fichiers invités correspondants dans la VM, en suivant le [démarrage](QUICKSTART.md). Le Python employé par l’exécuteur doit disposer de `cryptography` ; sur une distribution Debian compatible, cela peut être fourni par le paquet système `python3-cryptography`. Une erreur de dépendance doit être corrigée avant les essais d’action.
2. Démarrer le collecteur et la veille **sans `--apply`**, avec `--permanent`. Le journal Ed25519 est créé dans le coffre de l’utilisateur qui exécute le contrôleur. En mode local Linux, suivre les commandes `sudo env SAWM_LABO_LOCAL_VM=1` du guide : le coffre est alors celui de root.
3. Lire uniquement la clé publique du contrôleur, depuis ce même compte :

```bash
python -c 'from pathlib import Path; print((Path.home()/".sawm-labo/audit-ed25519.key.pub").read_bytes().hex())'
```

4. L’administrateur vérifie cette empreinte par son canal institutionnel, ajoute la chaîne hexadécimale publique à `cles_controleur` dans le manifeste protégé de la VM, puis incrémente sa génération. **La clé privée reste dans le coffre**. Aucun texte envoyé à SAWM ne réalise cet enrôlement.
5. Redémarrer la veille afin qu’elle charge le nouveau mandat. Consulter le panneau **Défense en profondeur** : les inconnues et écarts doivent être examinés. Enregistrer l’export JSON avec le contexte de l’essai.
6. Tester les refus puis, seulement dans les ressources déléguées, activer `--cloud --apply` avec la veille permanente. Une maintenance autorisée doit toujours être préservée. Les scripts de scénarios manuels ne reçoivent pas de ticket automatiquement.

Un administrateur peut révoquer une clé dans le manifeste et changer sa génération. L’ancien ticket est lié à l’ancienne empreinte, donc ne permet plus une nouvelle exécution. Cette procédure ne remplace pas un annuaire, une MFA, un HSM ou une gestion institutionnelle des identités.

## Continuité de la protection locale

Une garde de fichiers déjà active doit recevoir son propre raccordement signé avant l'activation du profil : aucune exemption implicite ne contourne la vérification de l'exécuteur. Le [guide de la garde locale](GARDE-LOCALE-SIGNEE.md) décrit l'enrôlement d'une clé distincte, sa portée limitée à certaines unités et à l'arrêt de service, la réinspection des preuves et le journal local signé.

Cette voie fonctionne sans appel Cloud lorsque ses observations et son mandat sont valides. Les décisions locales restent distinguées de celles de SAWM. Après l'écriture durable d'une demande, l'exécuteur revérifie aussi l'identité et la maintenance : une fenêtre autorisée qui vient de commencer ne doit pas être ignorée à cause d'un contrôle antérieur.

## Autonomie déléguée : décider sans confirmation répétée

Le mandat est approuvé une fois par le propriétaire. Ensuite, SAWM choisit ses inspections et sa proposition à partir des observations courantes et des précédents rappelés. Le contrôleur peut exécuter une action préautorisée sans demander une nouvelle confirmation à chaque incident. Les contrôles de sécurité vérifient cette délégation ; ils ne constituent pas un vote humain supplémentaire.

| Situation | Comportement attendu |
| --- | --- |
| Une preuve technique manque et une inspection autorisée peut l’obtenir | SAWM choisit une inspection, reçoit son résultat et réévalue la situation. |
| Violation attribuée, cible et intervention déléguées, maintenance respectée, preuves fraîches | Le contrôleur vérifie la proposition et l’exécuteur applique l’action autorisée, puis son effet est mesuré. |
| Maintenance authentifiée couvrant l’opération en cours | L’exception doit être respectée ; la surveillance et la traçabilité continuent. |
| Information métier absente, attribution impossible, droit insuffisant ou budget épuisé | Le motif est enregistré et rendu visible au dashboard. Aucune permission n’est inventée ; une clarification peut être proposée. |

Le [manifeste autonome d’exemple](../config/manifeste.autonomie.example.json) active `veille.enquete_autonome` et délègue les trois actions disponibles à **une seule unité illustrative**, `labo-demo.service`. Il n’est jamais installé automatiquement. Adapter l’unité au service de laboratoire effectivement créé dans la tranche prévue, les seuils et la délégation au mandat de votre organisation. Conserver les protections existantes et enrôler la clé publique selon la procédure ci-dessus : sans cette clé, aucune intervention de ce profil n’est autorisée. Le quota CPU de l’exemple vaut 20 % d’un cœur.

Après ces vérifications, lancer la veille selon le mode local ou distant du [guide](QUICKSTART.md) :

```bash
python controleur/veille.py --permanent --cloud --apply --cloud-per-hour 4
```

Le périmètre actuel reste explicite : trois actions automatiques (`geler-transfert`, `arreter-service`, `limiter-cpu`), quatre types d’inspection, au plus trois inspections par enquête sous 120 secondes et quatre tours Cloud par heure au maximum. Chaque tour d’une enquête consomme ce budget ; quatre tours ne signifient pas quatre enquêtes complètes. La perception périodique des ressources inspecte au plus huit unités déclarées, avec au moins dix secondes entre deux inspections d’une même unité. Les capteurs continuent de collecter pendant l’analyse.

Une demande de clarification place l’incident en attente de preuves. Cette version ne reprend pas automatiquement le même incident après une réponse humaine : il faut relancer une analyse avec les éléments actualisés, sans réutiliser une ancienne autorisation d’exécution.

Ces bornes font de cette version un kit de démonstration maîtrisé. Une exploitation à fort débit exige une qualification de capacité et une politique de budget adaptée ; cette version ne promet pas une décision LLM en quelques millisecondes ni une couverture de tous les processus du serveur. Les mécanismes locaux déjà installés continuent de fonctionner lorsque le Cloud manque ; ils ne créent pas de nouvelles décisions SAWM hors ligne.

## Pièces pour l’auditeur

Conserver la version déployée, le manifeste approuvé, les clés publiques, les événements signés de changement de posture, les reçus d’action et leurs vérifications, les exports datés, les exceptions motivées et les résultats des tests de restauration. Les fichiers privés et clés ne doivent pas être ajoutés au dépôt Git public.

Il reste à vérifier chez chaque client : périmètre réel et inventaire, authentification du transport de télémétrie, segmentation réseau, gestion des correctifs et des vulnérabilités, sauvegardes/restauration, surveillance des comptes, conservation extérieure résistante à l’altération et procédures de réponse. L’annexe ISO applicable et les contrôles CIS doivent être sélectionnés à partir de l’analyse de risques, pas uniquement de ce qui est déjà facile à mesurer.

En environnement industriel, les interventions doivent respecter les contraintes de sûreté et de disponibilité du procédé. Le kit ne donne aucun droit implicite de couper un automate, un réseau de sécurité ou un équipement physique.

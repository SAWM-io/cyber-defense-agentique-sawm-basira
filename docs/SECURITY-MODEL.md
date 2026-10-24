# Modèle de sécurité et périmètre des protections

[Retour au README](../README.md)

## Autorité et décision

Le propriétaire fixe un manifeste local protégé : ressources, unités, actions, générations et politiques. Le modèle reçoit les éléments utiles pour comprendre cette délégation ; il ne peut pas la modifier par sa réponse.

L'exécuteur reçoit une demande structurée et vérifie notamment :

- génération et empreinte du manifeste ;
- action et cible autorisées ;
- identité actuelle de l'unité et du processus, lorsque l'action l'exige ;
- absence de demande rejouée ;
- fichiers et chemins attendus, liens symboliques et changements de cible ;
- mandats de maintenance applicables ;
- état toujours pertinent juste avant l'effet.

Une demande invalide est refusée et journalisée. Le contrôleur ne remplace pas en silence une proposition refusée par une action plus agressive.

## Données non fiables

Noms de fichiers, extraits de paquets, journaux, observations rappelées et messages réseau sont des **données à examiner**. Une phrase « ignore la politique » dans l'un d'eux n'accorde aucun privilège.

Le contrat de sortie, la liste d'actions et les contrôles locaux restent nécessaires même si le modèle semble convaincant. La justification affichée explique la proposition ; elle ne la rend pas vraie.

## Maintenance signée

Le code de maintenance utilise des clés Ed25519 enregistrées par l'administrateur. Un mandat lie un principal, une opération, un fichier, une identité de processus, une génération et une période de validité.

La CLI propose `keygen`, `sign`, `install`, `revoke` et `verify` :

```bash
python -m controleur.maintenance_cli --help
```

L'enrôlement de la clé publique dans le manifeste est une opération administrative distincte. Une clé nouvelle ne devient pas administrateur en se signant elle-même. La signature atteste la possession d'une clé, pas l'identité civile ; annuaire, MFA et coffre matériel relèvent de l'intégration institutionnelle.

Le contrôle d'une maintenance est spécifique : autoriser une écriture ne permet pas forcément un verrou exclusif, un transfert ou une autre cible. Pour les incidents de fichier/base couverts, une opération actuellement autorisée doit être préservée ; un mandat inconnu, expiré ou invérifiable ne doit pas être inventé.

## Couverture réelle

| Fonction | Périmètre de cette référence |
| --- | --- |
| Ressources et sockets | Inspections bornées des unités suivies, notamment leur processus principal ; pas tous les descendants ou protocoles. |
| Fichiers et bases | Cibles déclarées, intégrité, disponibilité et attribution selon les capteurs disponibles. Un hash différent seul ne prouve pas l'auteur. |
| BPF LSM | Protections ciblées du laboratoire ; la politique par inode ne révoque pas les descripteurs déjà ouverts. |
| SSH | Lecture des événements d'authentification, rapprochement et alerte ; pas de bannissement automatique du port 22 par cette sonde. |
| Authentification applicative | Gardes distinctes sur le service témoin ; ne pas les présenter comme une protection universelle de tous les accès. |
| Paquets logiciels | `.deb` explicitement soumis au sas, inspection et ClamAV ; pas interception de tous les installateurs ou téléchargements. |
| Géographie et IP multiples | Contexte ou hypothèse de rapprochement ; une IP ne prouve ni identité humaine ni localisation physique. |
| Continuité réseau | Politiques et liens témoins explicitement configurés ; pas contrôle de toutes les routes d'un serveur. |

CPU élevé, fichier caché ou connexion inhabituelle sont des indices d'enquête. L'intervention repose sur une combinaison de preuves et d'autorisation, pas sur un mot « malware » dans une réponse.

## Inspection de paquets

Le sas prépare un instantané du `.deb`, inventorie ses archives sans installer le logiciel et exécute l'analyse dans une unité systemd restreinte. Les signatures et la version de ClamAV doivent être vérifiables et à jour.

Les résultats distinguent signature détectée, analyse incomplète, revue nécessaire et absence d'alerte dans le périmètre examiné. **Aucun de ces résultats ne déclenche une installation automatique.** Un binaire fermé ne fournit pas son code source ; aucune promesse d'absence générale de backdoor n'est faite.

## Contrôleur, réseau et secrets

Le contrôleur et sa clé administrative sont des composants de confiance. Dans le transport de référence, ils disposent d'une capacité d'administration de la VM. Les isoler, protéger leurs fichiers et auditer leurs accès est indispensable.

Le dashboard reste sur loopback. La télémétrie TCP n'authentifie pas seule l'émetteur ; utiliser un tunnel authentifié ou un réseau isolé et contrôlé. Une interface privée n'est pas automatiquement un canal de confiance.

Séparer les clés Cloud, SSH, maintenance et audit. Les clés d'un client ne doivent pas être réutilisées pour un autre. Les preuves et leur conservation peuvent contenir des données personnelles ou opérationnelles : appliquer le périmètre et la rétention convenus.

## Root hostile et continuité

Une protection ciblée peut refuser une opération à UID 0 dans le laboratoire ; cela ne démontre pas une résistance générale à un administrateur root hostile. Root peut modifier le système d'exploitation, les capteurs ou les données si aucune frontière indépendante ne l'en empêche.

Une défense contre ce scénario demande un contrôleur indépendant, des preuves extérieures, une chaîne de démarrage et un mécanisme de récupération adaptés. Ce dépôt ne certifie ni un noyau inviolable, ni un antivirus universel, ni une disponibilité totale.

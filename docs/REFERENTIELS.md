# Défense en profondeur et référentiels industriels

[Retour au README](../README.md) · [Modèle de sécurité](SECURITY-MODEL.md) · [Validation](VALIDATION.md)

Références vérifiées le **26 octobre 2026**. Ce guide explique comment préparer les preuves d’un déploiement client. Les correspondances ci-dessous sont une analyse du projet, **pas une attestation de conformité ni un audit exhaustif des normes**.

## La base adaptée au projet

La défense en profondeur consiste ici à disposer de contrôles distincts : observer, limiter les droits, examiner une proposition, vérifier l’autorisation au moment de l’action, constater son effet et conserver les preuves. Une réponse convaincante de SAWM ne remplace aucun de ces contrôles.

La base retenue pour ce kit est ISO 27001, avec les contrôles CIS comme référence technique et NIST pour structurer les objectifs. Les versions consultées sont les suivantes :

| Référence | Version publiée consultée | Utilité pour le client |
| --- | --- | --- |
| [ISO/IEC 27001](https://www.iso.org/standard/27001) | **2022**, avec [amendement 1:2024](https://www.iso.org/standard/88435.html) | Organiser le système de management de la sécurité de l’information et son périmètre. L’amendement traite de la prise en compte du changement climatique ; il ne constitue pas un nouveau protocole de défense. |
| [ISO/IEC 27002](https://www.iso.org/standard/75652.html) | **2022**, version corrigée 2022-03 | Guider le choix et la mise en œuvre de mesures de sécurité. Ce document n’est pas, en lui-même, une norme de certification. |
| [CIS Controls](https://www.cisecurity.org/controls/v8-1) | **v8.1** | Prioriser les mesures techniques et organisationnelles. Les [groupes de mise en œuvre](https://www.cisecurity.org/controls/implementation-groups) permettent d’adapter les priorités au risque et aux ressources. La présence de ce kit ne vaut pas réalisation de tout IG1. |
| [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) | **2.0** | Structurer les objectifs et les preuves autour de Gouverner, Identifier, Protéger, Détecter, Répondre et Rétablir. |

Le référentiel retenu, son édition, le périmètre et les exclusions doivent figurer dans le dossier du client. Une exigence contractuelle ou réglementaire dépend aussi du pays, de l’activité et du rôle de l’organisation ; elle ne se déduit pas d’un badge dans le dashboard.

## Pour les usines et les systèmes opérationnels : IEC 62443

IEC 62443 est une **série** destinée aux systèmes d’automatisation et de commande, avec des responsabilités différentes selon l’exploitant, l’intégrateur et le fournisseur. Il n’existe pas un unique numéro de version à appliquer à tout le produit.

| Partie pertinente | Référence officielle consultée | Question à traiter |
| --- | --- | --- |
| Programme de sécurité de l’exploitant | [IEC 62443-2-1:2024](https://webstore.iec.ch/en/publication/62883) | Qui organise et maintient la sécurité du système en exploitation ? |
| Analyse de risque et architecture | [IEC 62443-3-2:2020](https://webstore.iec.ch/en/publication/30727) | Quel système protège-t-on, comment définir ses zones et conduits et ses niveaux cibles ? |
| Exigences du système | [IEC 62443-3-3:2013](https://webstore.iec.ch/en/publication/7033), corrigendum 2014 intégré | Quelles propriétés techniques sont exigées du système délimité ? |
| Développement sécurisé | [IEC 62443-4-1:2018](https://webstore.iec.ch/en/publication/33615) | Comment développer, maintenir et retirer le produit en maîtrisant sa sécurité ? |
| Exigences des composants | [IEC 62443-4-2:2019](https://webstore.iec.ch/en/publication/34421), corrigendum 2022 intégré | Quelles capacités de sécurité le composant doit-il démontrer ? |

Ces éditions étaient indiquées valides dans le catalogue IEC lors de la vérification. Les dates de stabilité et les travaux de révision annoncés ne sont pas de nouvelles éditions publiées. Les parties applicables doivent être choisies pour le rôle et le périmètre effectivement évalués.

**Le kit serveur Linux ne devient pas un contrôleur industriel certifié en ajoutant cette table.** Pour une installation OT, l’intégrateur doit déterminer les fonctions essentielles et les conséquences physiques possibles avant toute délégation d’action. Une unité de sûreté, un automate ou une liaison critique ne doit pas être arrêté par simple analogie avec un service de démonstration. Les interverrouillages et l’autorité de sûreté du site restent distincts de l’agent.

## Correspondances techniques indicatives

Les numéros CIS ci-dessous renvoient aux familles de la [liste officielle des 18 contrôles](https://www.cisecurity.org/controls/cis-controls-list). Ils indiquent un domaine auquel le mécanisme peut contribuer, **pas la satisfaction de tous ses Safeguards**. Les fonctions NIST sont également des repères, pas des résultats de certification. Aucun score ISO ou niveau IEC SL n’est calculé à partir de cette table.

| Objectif | Mécanismes présents et tests à examiner | Repères indicatifs | Preuve attendue dans le déploiement |
| --- | --- | --- | --- |
| Connaître les ressources observées | [Veille](../controleur/veille.py), [perception du serveur](../controleur/perception_serveur.py), [tests](../tests/test_veille.py) | NIST Identifier ; CIS 1, 2 | Inventaire daté, propriétaire, périmètre, éléments inconnus et capteurs manquants. Un inventaire partiel ne devient pas complet par son enregistrement. |
| Réserver l’action à l’autorité locale | [Contrat de proposition](../connecteur/contrat.py), [exécuteur](../invite/executeur/executeur.py), [tests d’identité](../tests/test_executeur_identity.py) | NIST Gouverner / Protéger ; CIS 6 | Manifeste approuvé et protégé, actions/cibles permises, génération, identité actuelle, refus des demandes hors périmètre ou rejouées. |
| Préserver une maintenance autorisée | [Mandats](../controleur/maintenance.py), [tests](../tests/test_executeur_maintenance.py) | NIST Protéger ; CIS 5, 6 | Principal enrôlé, signature, opération exacte, durée, révocation et refus hors mandat. L’identité civile et le MFA demandent une intégration séparée. |
| Détecter sans prendre un indice pour une preuve | [Corrélation](../controleur/correlation.py), [enquête](../controleur/enquete_autonome.py), [tests d’enquête](../tests/test_enquete_autonome.py) | NIST Détecter / Répondre ; CIS 13 | Observations fraîches, attribution, hypothèses, inspections demandées, inconnues et alertes à l’opérateur. |
| Réduire le risque lié aux logiciels soumis | [Sas de paquets](../controleur/package_preflight.py), [tests](../tests/test_package_preflight.py) | NIST Protéger ; CIS 2, 10 | Paquet examiné, empreinte, état des signatures antivirus, résultat et limites. Ce sas n’intercepte pas tous les téléchargements et ne démontre pas l’absence de toute porte dérobée. |
| Vérifier l’effet d’une intervention | [Vérification](../controleur/verification_action.py), [tests](../tests/test_verification_action.py) | NIST Répondre | État avant, reçu de l’exécuteur, état après, effet attendu et contrôle du service légitime. Un ordre accepté ne suffit pas. |
| Conserver une piste d’audit | [Journal signé](../controleur/audit_signe.py), [ancrage](../controleur/ancrage_basira.py), [tests](../tests/test_audit_signe.py) | NIST Gouverner / Détecter ; CIS 8 | Chronologie, signatures vérifiées, chaîne, références des preuves et politique de conservation. La copie extérieure doit être configurée et vérifiée ; la seule signature locale ne protège pas d’un effacement de toute la machine. |
| Préparer et éprouver la reprise | [Contrat de récupération](../controleur/recovery_contract.py), [tests](../tests/test_recovery_contract.py) | NIST Rétablir ; CIS 11 | Référence saine, autorité indépendante, sauvegarde récupérable et exercice mesuré. Une restauration de fixtures ne valide pas la reprise complète du client. |

Les suites logicielles vérifient des propriétés du code. Le [dossier de validation](VALIDATION.md) distingue ces résultats des contrôles qui doivent être exécutés dans l’installation du client.

## Ce que l’agent doit suivre et ce que l’organisation doit décider

Le fonctionnement autonome se fait dans la politique locale approuvée. L’agent peut rassembler des observations, demander une inspection permise, proposer une réponse et conserver les éléments permettant de la revoir. Il ne peut ni se certifier, ni augmenter ses droits, ni transformer un contrôle inconnu en contrôle réussi.

Pour chaque mesure, conserver au minimum :

- un identifiant interne stable et un objectif compréhensible ;
- le périmètre et le responsable ;
- l’origine de la preuve, sa date, sa validité et sa référence vérifiable ;
- un résultat distinguant **vérifié**, **écart**, **inconnu** et **non applicable avec justification** ;
- la réaction prévue, la priorité et la personne à prévenir ;
- les changements, dérogations et corrections, sans effacer le résultat initial.

La même règle s’applique aux mesures humaines : une formation, une revue fournisseur, une procédure de sauvegarde ou une analyse de risque ne devient pas réalisée parce qu’un modèle l’a rédigée. Il faut son responsable et la preuve de son exécution.

Le programme client doit notamment couvrir les accès et leur revue, l’authentification renforcée, les vulnérabilités et correctifs, la segmentation, les sauvegardes, la gestion d’incident, les fournisseurs, la protection physique, les compétences et l’évaluation périodique. Le choix précis, la pertinence et les éventuelles mesures compensatoires relèvent de l’analyse du périmètre. Ces sujets ne sont pas tous réalisés par ce dépôt.

## Dossier de preuve pour un client industriel

1. **Délimiter** les serveurs, données, réseaux et fonctions concernés ; documenter les dépendances et les exclusions.
2. **Approuver** les autorités, mandats, ressources protégées et actions admissibles, en associant l’exploitation et la sûreté du site.
3. **Mesurer** la couverture réelle, les délais, les erreurs, les faux positifs, les effets et le comportement en panne. Garder les résultats complets, y compris un échec corrigé.
4. **Rejouer** les scénarios sur une installation représentative : maintenance valide, action non autorisée, preuve périmée, perte de capteur, indisponibilité Cloud, reprise et intégrité du journal.
5. **Relier** chaque conclusion à un commit, une configuration, des résultats datés et un propriétaire de contrôle.
6. **Faire évaluer** le périmètre et les exigences retenues par les responsables et, lorsque requis, par l’organisme compétent.

Une certification ISO/IEC 27001 vise un système de management dans un périmètre défini ; publier un agent ou réussir ses tests ne certifie pas ce système. ISO explique que les certifications sont délivrées par des [organismes externes](https://www.iso.org/certification.html), pas par ISO elle-même. Un projet IEC 62443 doit de même préciser la partie, le système ou composant, le niveau visé et la méthode d’évaluation retenue.

**Formulation client défendable :** « Cyber Defense Agentique SAWM&Basira apporte des contrôles techniques traçables et des preuves d’exécution pour soutenir le programme de sécurité et les audits du client. Le périmètre, les écarts et les validations restent explicites. »

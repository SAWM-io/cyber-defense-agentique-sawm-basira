<p align="center">
  <img src="docs/assets/sawm-basira-flower.png" width="104" alt="Fleur SAWM et Basira">
</p>

# Cyber Defense Agentique SAWM&Basira

[![Tests](https://github.com/SAWM-io/cyber-defense-agentique-sawm-basira/actions/workflows/test.yml/badge.svg)](https://github.com/SAWM-io/cyber-defense-agentique-sawm-basira/actions/workflows/test.yml)

**SAWM × Basira — Observer, comprendre, intervenir et vérifier.**

> **English:** A Linux defence reference implementation powered by the public Basira / SAWM Cloud APIs. It combines operating-system observations, scoped memory, bounded agent investigations, locally authorised actions and an auditable dashboard. The LLM proposes; a separate local executor enforces the owner's policy.

La **Salle des Machines** est une base d'intégration pour les équipes qui veulent construire leur propre agent de défense : un système qui suit ce qui se passe sur un serveur, rapproche les événements, enquête et peut intervenir dans le périmètre que son propriétaire lui a confié.

Le dépôt contient les capteurs Linux, le connecteur Cloud, le contrôleur, l'exécuteur, le tableau de bord et des tests. Les moteurs propriétaires SAWM, Basira, TSST et ODVL sont consommés **par leurs API publiques** ; leur code serveur n'est pas embarqué ici.

![Fonctionnement de la défense agentique SAWM et Basira](docs/assets/architecture.png)

## Rapport client et résultats vérifiés

**[Lire le rapport PDF — Cyberdéfense agentique SAWM & Basira](docs/rapports/SAWM-Basira-Cyberdefense-Agentique-2026-10-26.pdf)** · Édition du 26 octobre 2026, 10 pages.

Fonctionnement et schéma d’architecture, capacités, résultats sur VM Linux avec le Cloud réel, auditabilité, défense en profondeur, repères **ISO/IEC 27001, 27002 et 27035-1**, base **CIS Controls v8.1** et correspondances **MITRE D3FEND**. Le rapport distingue les décisions SAWM des protections locales et les essais validés des points à compléter. Ces correspondances ne constituent pas une certification.

**[Article prêt pour Medium — utiliser Basira et SAWM pour défendre un serveur](docs/articles/BASIRA-CYBERDEFENSE-MEDIUM.md)** : cas concret, architecture et intégration aux API Cloud.

Les [preuves de campagne](docs/VALIDATION-VM-2026-10-26.md) précisent le périmètre. Le PDF est reproductible avec sa [source](scripts/build_defense_report.py) :

```bash
python -m pip install -r requirements-report.txt
python scripts/build_defense_report.py
# Résultat : output/pdf/SAWM-Basira-Cyberdefense-Agentique-2026-10-26.pdf
```

## À quoi cela sert ?

| Situation | Ce que l'intégration permet |
| --- | --- |
| Un transfert inhabituel apparaît | Relier l'activité à une unité, rappeler les observations pertinentes et, si la politique le permet, arrêter l'unité de transfert ciblée. |
| Une base SQLite devient indisponible ou change d'empreinte | Séparer disponibilité, intégrité et attribution ; vérifier les autorisations de maintenance ; enquêter ou contenir la cible autorisée. |
| Un service consomme anormalement des ressources | Examiner processus, compte et connexions, puis proposer une limite CPU, un arrêt délégué ou une simple surveillance. |
| Des échecs d'authentification se répètent | Regrouper les observations et afficher une alerte. La sonde SSH ne bannit pas automatiquement le port 22. |
| Un paquet logiciel doit être examiné | Inventorier un `.deb` explicitement soumis, analyser ses contenus avec ClamAV et produire un rapport avant toute installation. |
| Un responsable demande « pourquoi cette action ? » | Retrouver les observations, la justification publique, la politique appliquée, le reçu d'exécution et le résultat vérifié. |

Les scénarios du dépôt emploient des données fictives et des charges bornées. Le périmètre de chaque contrôle est décrit dans le [modèle de sécurité](docs/SECURITY-MODEL.md).

## Comment l'agent prend une décision

1. **Observer** : les capteurs remontent des faits datés, avec leur source et leurs limites.
2. **Se souvenir** : Basira conserve les événements ; TSST retrouve les éléments pertinents ; ODVL contribue à leur classement.
3. **Enquêter** : SAWM peut demander des inspections supplémentaires du processus, du compte, des connexions ou de la base déclarée.
4. **Choisir** : SAWM produit une proposition structurée, avec ses preuves, sa justification publique et les informations manquantes.
5. **Contrôler et agir** : l'exécuteur local vérifie l'autorité, la cible actuelle et les mandats, puis applique uniquement une action autorisée.
6. **Vérifier et conserver** : le système contrôle l'effet, préserve le service témoin et journalise le résultat pour les décisions suivantes.

**L'autonomie est une délégation explicite.** Une intervention peut être exécutée sans confirmation à chaque incident lorsque le propriétaire l'a autorisée à l'avance. Une phrase du modèle, un nom de fichier ou un journal ne peut jamais lui accorder de nouveaux droits. Le modèle ne dispose pas d'un shell root libre.

Le [profil d’autonomie](docs/DEFENSE-PROFONDEUR.md#autonomie-déléguée--décider-sans-confirmation-répétée) précise les inspections, les actions déléguées et les situations qui doivent remonter à l’opérateur. Son manifeste d’exemple est fourni sans clé enrôlée et n’est jamais appliqué automatiquement.

## Commencer sans Cloud ni action système

```bash
git clone https://github.com/SAWM-io/cyber-defense-agentique-sawm-basira.git
cd cyber-defense-agentique-sawm-basira
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
mkdir -p releves/rapports releves/series
python tests/run_safe.py
```

Node.js est nécessaire aux contrôles de l'interface. Le runner interdit les connexions extérieures et les commandes de VM ; les tests SQLite travaillent dans des répertoires temporaires. Il produit un résumé local, sans effectuer de test contre votre serveur.

Pour ouvrir le tableau de bord vide :

```bash
python controleur/collecteur.py
# Dans le navigateur : http://127.0.0.1:8899/
```

Un tableau de bord démarré ne signifie pas qu'un serveur est protégé : il faut installer les capteurs, déclarer les ressources et raccorder le Cloud. Suivez le [guide de démarrage](docs/QUICKSTART.md).

## Documentation

| Guide | Contenu |
| --- | --- |
| [Démarrage](docs/QUICKSTART.md) | Tests locaux, Linux, télémétrie, progression observation → analyse → action. |
| [Architecture](docs/ARCHITECTURE.md) | Rôle de chaque moteur, boucle de décision et circulation des preuves. |
| [Connexion au Cloud](docs/CLOUD.md) | Espace, entité, principal, scopes, clé, reprises et coûts. |
| [Exploitation](docs/OPERATIONS.md) | Veille continue, dashboard, budget, panne, audit et reprise. |
| [Défense en profondeur](docs/DEFENSE-PROFONDEUR.md) | Contrôles continus, profil ISO/CIS, autorisation signée et export des preuves. |
| [Garde locale signée](docs/GARDE-LOCALE-SIGNEE.md) | Confinement borné hors Cloud, clé locale distincte, maintenance et journal signé. |
| [Essais VM du 26 octobre](docs/VALIDATION-VM-2026-10-26.md) | Décision SAWM exécutée, protections locales mesurées, incidents corrigés et limites observées. |
| [Référentiels](docs/REFERENTIELS.md) | ISO 27001, CIS, NIST : versions, contributions techniques et démarche d’audit. |
| [Modèle de sécurité](docs/SECURITY-MODEL.md) | Droits locaux, maintenance signée, isolation et couverture réelle. |
| [Validation](docs/VALIDATION.md) | Résultats locaux, tests reproductibles et vérifications avant mise en service. |
| [Construire votre agent](docs/EXTENDING.md) | Ajouter un capteur, une inspection, une action ou un nouveau cas métier. |

## Ce qui se trouve dans ce dépôt

```text
connecteur/       API publiques Basira / SAWM, SDK figé, contrat de décision
controleur/      enquête, veille, corrélation, vérification, audit, dashboard
invite/          capteurs Linux, exécuteur et charges bénignes de démonstration
provisionnement/ exemples systemd et configuration noyau du laboratoire
tests/           tests locaux des contrats et protections
docs/            guides d'intégration et architecture
```

Le noyau Linux exécute les sondes eBPF et les protections BPF LSM prévues ; **SAWM et Basira ne sont pas des modules noyau**. Les exemples constituent une référence technique à adapter, tester et exploiter dans votre environnement. La publication du code ne vaut pas certification de couverture complète, de disponibilité ou de détection universelle.

## Licence et service Cloud

Le kit d'intégration est proposé sous [licence Apache 2.0](LICENSE), avec les informations de provenance dans [NOTICE](NOTICE). Le programme noyau `invite/capteurs/lsm_refus.bpf.c` porte séparément la licence [GPL-2.0-only](LICENSES/GPL-2.0-only.txt). Vous pouvez l'utiliser et l'adapter selon cette licence sans demander un accord commercial individuel pour ce code. Les marques et logos ne sont pas concédés comme une autorisation de présenter votre produit comme officiel.

**Les moteurs SAWM, Basira, TSST et ODVL restent propriétaires.** Leur utilisation passe par le Cloud et ses conditions de service : compte autorisé, clés, droits et crédits applicables. La licence de ce dépôt ne donne ni accès gratuit au Cloud, ni droit sur le code privé des moteurs.

**Cloud et documentation produit :** [basira.sawm.io](https://basira.sawm.io/) · [Espace client](https://basira.sawm.io/espace) · [Documentation](https://basira.sawm.io/documentation)

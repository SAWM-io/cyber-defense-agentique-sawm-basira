# Démarrage : tester, observer, puis déléguer

[Retour au README](../README.md)

Ce parcours commence sans Cloud ni privilèges sur un serveur. Les étapes Linux sont destinées à une **VM de test dédiée**, dont vous êtes propriétaire. Les scripts de démonstration ne sont pas un installateur universel pour un serveur métier.

## 1. Préparer l'environnement local

Prérequis : Python 3.11 ou ultérieur, `venv`, Git et Node.js pour les tests d'interface. Les dépendances principales du connecteur et de la signature sont `httpx` et `cryptography`.

```bash
git clone https://github.com/SAWM-io/cyber-defense-agentique-sawm-basira.git
cd cyber-defense-agentique-sawm-basira
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
mkdir -p releves/rapports releves/series
python tests/run_safe.py
```

Le résumé est écrit dans `releves/rapports/`. Ce runner bloque les commandes de VM et les connexions hors loopback. Les petits acteurs SQLite autorisés utilisent des répertoires temporaires. Ces gardes encadrent des tests de confiance ; elles ne constituent pas un bac à sable système pour du code tiers.

`requirements-dev.txt` ajoute les dépendances de test au runtime. Pour une installation d'exécution seule, utiliser `requirements.txt` ; ne pas supposer que cela suffit à exécuter toutes les suites.

## 2. Ouvrir le dashboard sans capteur

```bash
python controleur/collecteur.py
```

Ouvrir **http://127.0.0.1:8899/**. Sans télémétrie, l'interface doit signaler l'absence de mesures. Des valeurs absentes ne doivent pas être interprétées comme un serveur sain.

Le collecteur écoute aussi la télémétrie sur `127.0.0.1:47900` par défaut. Le fermer arrête cette collecte ; fermer le navigateur ne l'arrête pas. Aucun modèle n'est appelé par la seule ouverture de cette page.

## 3. Préparer Linux

Le code invité utilise systemd, cgroup v2, `/proc`, journald et les outils de réseau Linux. Les fonctionnalités eBPF/BPF LSM nécessitent un noyau compatible, les options de noyau correspondantes et des outils `clang`, `bpftool` et `bpftrace` compatibles avec son BTF.

La référence historique a été développée sur Ubuntu ARM64 avec un noyau 6.8. Ce n'est pas une preuve de compatibilité avec toutes les distributions ou versions. Vérifier les fonctionnalités sur votre VM :

```bash
uname -r
cat /sys/kernel/security/lsm
sudo bpftool feature probe
stat -fc %T /sys/fs/cgroup
```

Le script fourni prépare une **nouvelle** VM. Commencer par lire le plan, sans mutation :

```bash
python scripts/prepare_linux_lab.py
```

Après revue du code de cette version et confirmation qu'il s'agit d'une VM dédiée, lancer dans Linux :

```bash
sudo python3 scripts/prepare_linux_lab.py --apply --acknowledge-dedicated-vm
sudo python3 /opt/sawm-labo/agent/jetons.py init
sudo systemctl daemon-reload
sudo systemctl enable --now labo-temoin.service labo-telemetrie.service
```

La préparation copie les modules, un manifeste initial sans droit d'intervention, deux fichiers fictifs et les unités du témoin et de la télémétrie. Elle refuse une installation existante. Elle n'installe aucune dépendance, ne démarre aucun service par elle-même et ne change ni GRUB, ni pare-feu, ni SSH.

Le manifeste initial est [`config/manifeste.observation.json`](../config/manifeste.observation.json) : aucune unité n'est autorisée à être arrêtée ou limitée. Le script ne compile ni n'attache les sondes eBPF et ne configure pas les scénarios avancés. Sa présence ne vaut pas validation d'une VM neuve dans votre environnement.

Pour le reste de l'installation, l'administrateur doit :

1. Conserver les modules invités dans `/opt/sawm-labo/`, sous propriété root, sans écriture groupe/autres.
2. Construire les sondes depuis `invite/capteurs/` pour le noyau cible.
3. Adapter les unités systemd et les chemins de `provisionnement/` à cette VM.
4. Compléter le manifeste local : unités, fichiers, actions et politiques autorisés ; conserver les actions automatiques désactivées au départ.
5. Configurer le transport de télémétrie, les permissions et la clé administrative dédiée.
6. Démarrer les services choisis, puis vérifier leur présence et la fraîcheur des mesures.

Les exemples GRUB sont des modèles à examiner. Ne pas écraser la ligne de démarrage d'un serveur existant sans vérifier les LSM déjà actifs et le mécanisme de récupération. Les exemples système se trouvent dans [provisionnement/](../provisionnement/).

## 4. Relier le contrôleur à la VM

**Tout dans la VM de démonstration :** le mode local nécessite root. Depuis la copie du dépôt dans Linux, utiliser le Python de son environnement virtuel et déclarer le mode explicitement :

```bash
sudo env SAWM_LABO_LOCAL_VM=1 "$PWD/.venv/bin/python" controleur/collecteur.py
```

La clé Cloud devra alors appartenir au compte qui lance la veille, donc dans `/root/.sawm-labo/env` si elle tourne sous root. Le dashboard reste sur le loopback de la VM : pour y accéder depuis votre poste, utiliser un tunnel SSH authentifié. Cette disposition réunit le contrôle et le serveur surveillé ; elle ne fournit pas de contrôleur indépendant en cas de compromission de la VM.

**Contrôleur distinct :** le transport SSH doit être déclaré explicitement :

```bash
export SAWM_LABO_SSH_CIBLE='operateur@vm-defense.example'
```

Remplacer cet exemple par votre hôte. Le code attend la clé privée dédiée dans `~/.sawm-labo/cle_labo` et les clés hôtes dans `~/.sawm-labo/known_hosts`. Vérifier l'empreinte de la VM par un canal de confiance avant de l'enregistrer. La vérification stricte SSH refuse une clé hôte inconnue ou modifiée.

Le compte administratif appelle `sudo -n python3 -` pour les opérations prévues par le contrôleur. C'est une capacité puissante du **contrôleur de confiance**, pas un accès donné au LLM. Pour une intégration métier, réduire le transport à des opérations explicites et auditer sa politique sudo.

Pour la télémétrie distante, utiliser un tunnel ou une interface privée isolée. `LABO_BIND` accepte une adresse privée ou loopback explicite ; les adresses publiques et génériques sont refusées. Adapter aussi la destination du service de télémétrie invité.

## 5. Observer avant d'agir

Avec le dashboard et la VM configurés :

```bash
python controleur/veille.py --duration 60
```

En mode local Linux, préfixer chaque commande de veille par `sudo env SAWM_LABO_LOCAL_VM=1` et utiliser le chemin absolu du Python de votre `.venv`, comme pour le collecteur.

Cette étape lit le manifeste et les observations. Elle n'autorise ni analyse Cloud ni intervention automatique. Vérifier qu'un capteur manquant ou arrêté produit un état dégradé visible.

## 6. Activer le Cloud

Créer vos ressources et votre coffre suivant [CLOUD.md](CLOUD.md), puis lancer :

```bash
python controleur/veille.py --duration 300 --cloud --cloud-per-hour 4
```

Ce mode peut effectuer de vrais appels facturables. Il n'applique pas les propositions de SAWM. Contrôler les preuves rappelées, les inconnues et les propositions dans le dashboard.

## 7. Déléguer des actions sur des cibles de test

Après vérification du manifeste et des ressources autorisées :

```bash
python controleur/veille.py --duration 300 --cloud --apply --cloud-per-hour 4
```

`--apply` ne suffit pas : la liste `veille.actions_automatiques` du manifeste doit inclure les actions déléguées, et la cible/action doit être permise. L'exécuteur revalide le contexte avant chaque effet. Tester aussi le **refus** d'une cible hors manifeste et la préservation d'une maintenance signée.

Pour le profil ISO/CIS, suivre aussi l’[enrôlement du contrôleur et l’exemple d’autonomie](DEFENSE-PROFONDEUR.md) : la signature de courte durée est exigée par l’exécuteur. Le manifeste d’observation n’accorde aucune action ; le manifeste autonome d’exemple doit être adapté aux cibles réelles avant installation.

Ne pas faire tourner en parallèle une campagne de validation qui modifie le manifeste et une veille qui pourrait agir sur les mêmes ressources.

## 8. Passer en veille continue

```bash
python controleur/veille.py --permanent --cloud --apply --cloud-per-hour 4
```

Cette commande utilise un journal signé et persistant. Installer ensuite une supervision adaptée au système selon [OPERATIONS.md](OPERATIONS.md). Il faut tester le redémarrage des processus, la panne Cloud, le budget épuisé et la reprise d'un incident avant de proposer ce service à un client.

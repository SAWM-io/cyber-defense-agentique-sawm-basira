# Garde locale signée et défense en profondeur

Le profil `industriel-prudent-v1` demande une autorisation Ed25519 courte pour toute intervention de l’exécuteur. La garde locale des fichiers utilise la même vérification : elle ne bénéficie d’aucune exemption. Elle continue à fonctionner sans requête Cloud sur les cibles déclarées, si ses propres preuves et ses autorisations restent valides.

La garde est une protection déterministe locale. Ses décisions sont identifiées comme `garde_locale`, distinctes des analyses SAWM. Elle ne prétend pas reconnaître tous les malwares ni disposer d’une autorité supérieure à root.

## Enrôlement explicite

L’administrateur prépare une clé Ed25519 privée **RAW de 32 octets**, root:root, mode 0600, dans `/etc/sawm-labo/garde-locale-ed25519.key`, puis sa clé publique RAW dans le fichier de même nom suffixé `.pub`. Les parents doivent appartenir à root, sans écriture groupe/autres et sans lien symbolique. Le programme ne crée ni ne remplace une clé manquante.

Il crée également `/var/lib/sawm-labo/garde-locale/`, root:root, mode 0700. Le journal et son checkpoint signé y sont écrits :

- `audit.jsonl` : décision figée avant intervention, puis reçu de résultat ;
- `audit.jsonl.checkpoint.json` : dernier état de la chaîne ;
- les fichiers `.lock` assurent l’exclusion pendant les écritures.

Ajouter au profil du manifeste root, en conservant les clés et contrôles existants :

```json
{
  "profil": "industriel-prudent-v1",
  "controles_bloquants": [],
  "cles_controleur": ["CLE_PUBLIQUE_DU_CONTROLEUR_EN_HEXADECIMAL"],
  "gardes_locales": [
    {
      "cle_publique": "CLE_PUBLIQUE_LOCALE_EN_HEXADECIMAL",
      "unites": ["labo-ledger-demo.service"]
    }
  ]
}
```

Les deux clés doivent être distinctes. La clé locale autorise exclusivement `arreter-service`, pour les unités explicitement inscrites dans sa portée, présentes dans `unites_autorisees`, absentes de `unites_protegees`, associées à une cible `defense_fichiers` avec `automatic_containment:true`, et permises par `veille.actions_automatiques`. La garde des fichiers doit elle-même être activée. Une même unité associée à plusieurs cibles automatiques est refusée par cette voie pour éviter une attribution ambiguë.

L’identité du processus et le préfixe de décision `local-file-` sont obligatoires. Une clé locale ne devient jamais une clé générale du contrôleur. Une clé copiée dans les deux rôles invalide le profil.

## Déroulement d’une intervention

1. La garde relit le manifeste root et constate une infraction locale attribuée : écriture non autorisée corrélée à une différence d’intégrité, ou verrou SQLite exclusif attribué et indisponibilité constatée.
2. L’autoriseur relit à nouveau le manifeste, réinspecte le fichier et l’identité OS, puis vérifie la maintenance signée. Une maintenance autorisée empêche le confinement.
3. Il vérifie l’intégrité complète du journal et applique le même évaluateur de posture que Veille, avec son rôle local. Des contrôles additionnels non mesurés restent inconnus et bloquent s’ils sont obligatoires.
4. Il conserve une décision signée, les preuves, l’identité et les statuts de posture. Après l’écriture, il revérifie la fraîcheur maximale de 1 500 ms et l’empreinte du manifeste.
5. Il délivre un ticket de cinq secondes lié à la décision, à l’action, à la cible, à l’identité et au manifeste. L’exécuteur applique ses propres contrôles de maintenance, identité, mandat et rejeu avant d’agir.
6. Le reçu est conservé dans le journal local. Si cette dernière écriture échoue après une action effectuée, le résultat reste marqué `ecriture_incomplete_a_examiner` ; l’action n’est pas déclarée inexistante.

Le contrôle « observations récentes » repose ici sur la réinspection OS locale ; il ne dépend pas d’une connexion au Cloud. La disponibilité du service témoin n’est mesurée que si elle est exigée. Les sondes OS sont en lecture seule, avec leur cache de 60 secondes. Les capacités non observées, notamment un attachement LSM ou une ancre extérieure, ne sont jamais inventées pour franchir un contrôle.

## Installation additive sur une VM existante

Conserver les unités systemd, destinations de télémétrie, ports et mandats existants. Ne pas relancer le préparateur de VM neuve sur une installation active.

Installer les modules suivants, avec Python et `cryptography` disponibles pour `/usr/bin/python3` :

- `/opt/sawm-labo/agent/defense_runtime.py` et `local_guard_authorizer.py` ;
- `/opt/sawm-labo/executeur/defense_autorisation.py`, avec l’exécuteur qui vérifie les tickets ;
- paquet de support `/opt/sawm-labo/controleur/` : `audit_signe.py`, `defense_profondeur.py`, `diagnostic_defense.py`, `maintenance.py` ;
- paquet de support `/opt/sawm-labo/invite/agent_labo/` : `defense_runtime.py`, `posture_securite.py`, `auth_campaigns.py` ;
- paquet de support `/opt/sawm-labo/invite/executeur/defense_autorisation.py`.

Les fichiers d’un même module dupliqués dans ces chemins doivent correspondre à la même révision. L’arbre doit être root, sans écriture groupe/autres. Les paquets peuvent être des espaces de noms Python ou comporter leurs `__init__.py` existants.

Préparer les clés et le journal avant d’activer le profil, puis redémarrer `labo-defense-fichiers.service`. Une autorité indisponible produit une alerte/refus, jamais un retour silencieux à une intervention non signée. La garde existante déduplique les tentatives par incarnation du processus ; après correction d’un refus d’installation, redémarrer le service pour permettre une nouvelle tentative.

Vérifier ensuite : maintenance autorisée conservée, confinement d’une cible de test non autorisée, service témoin disponible, refus d’une autre cible/action, refus d’un ticket expiré, journal local valide, continuité de la télémétrie et du contrôleur. Ne pas supprimer les anciennes preuves pour faire passer une validation.

## Preuves et limites

La suite `tests/test_local_guard_authorizer.py` utilise de vraies clés Ed25519, des fichiers réellement modifiés et un journal réellement signé, avec les observations de processus simulées. Elle couvre la réinspection, la maintenance, l’expiration pendant l’écriture, la rotation/révocation des clés, la séparation des rôles, l’altération du journal et les limites de portée. Elle ne remplace pas la campagne Linux réelle.

Le ticket atteste la décision de l’autoriseur enrôlé ; il ne fournit pas une attestation matérielle indépendante. Un administrateur root capable de remplacer les clés, les modules et le manifeste reste dans la frontière de confiance. Pour détecter le retour arrière simultané du journal et du checkpoint, conserver une ancre indépendante extérieure à cette VM.

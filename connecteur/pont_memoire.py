"""Pont vers la memoire Basira Cloud, par la surface PUBLIQUE uniquement.

Aucun import du backend, aucun acces direct a une base, aucun sidecar local :
ce module ne connait que `https://basira-api.sawm.io/api/v1/basira` et le SDK
telechargeable par n'importe quel client depuis
`https://basira.sawm.io/static/sdk/basira_client.py`.

Ce qu'il encode, ce sont les pieges mesures le 2026-09-22 contre la production,
et qui ne se deduisent d'aucune lecture de code :

* un rappel TSST peut rendre **503 engine_unavailable** a froid — mesure une
  fois sur six, 4,26 s — puis 200 en 104 a 280 ms. Un rejeu borne le rattrape ;
  l'absence de rejeu ferait conclure "memoire vide" a tort ;
* attendre un etat d'ingestion qui n'existe pas ne leve RIEN. Les etats sont
  `pending`, `processing`, `completed`, `dead_letter`. On attend `completed`,
  puis un rappel TSST exact : `completed` confirme l'ingestion, pas la fin de
  sa projection asynchrone. Mesure le 23 septembre : ACK 17,6 s plus tard.
  Le rappel dispose de 45 s au total et de dix rejeux SDK au maximum ;
* `odvl:rank` **ne conserve pas l'ordre des scores** : mesure, il a place
  `ne-rien-faire` (score 0,20) au rang 1 devant `geler-transfert` (0,81), avec
  `reordered: true`. Son rang 1 n'est donc PAS une recommandation. On s'en sert
  comme signal de hierarchisation, jamais comme decideur ;
* `odvl:observe` existe et repond (`basira-odvl-observation/v1`, `mode: on`,
  `clock: frozen`) : c'est la lecture qui ne fait pas avancer le vortex ;
  `available: false` signifie "pas de mesure", jamais "mesure a zero" ;
* la cle d'idempotence doit etre **unique par campagne** : une cle deterministe
  rejouee d'un lancement a l'autre rend `409 idempotency_conflict`.
"""

from __future__ import annotations

import os
import math
import pathlib
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Sequence

import httpx

from .telemetrie_cloud import ClientHTTPObserve, TelemetrieCloud

# Le SDK public est charge tel qu'un client le telechargerait. On enregistre
# son empreinte : un rapport qui ne dit pas quelle version du client il a
# utilisee n'est pas reproductible.
_ICI = pathlib.Path(__file__).resolve().parent
_SDK = _ICI / "vendor" / "basira_client.py"
if _SDK.exists():                                     # copie figee du labo
    sys.path.insert(0, str(_SDK.parent))
import basira_client as bc  # noqa: E402  (chemin resolu juste au-dessus)


ETATS_TERMINAUX = frozenset({"completed", "dead_letter"})
REJOUABLES = frozenset({"engine_unavailable", "flashback_projection_unavailable"})


class MemoireIndisponible(Exception):
    """Indisponibilite explicite : on ne remplace jamais par une copie locale.

    `flashback_projection_unavailable` et `engine_unavailable` restent des
    trous declares. Les combler en silence avec la memoire courante ou une
    copie locale produirait un banc qui ne peut pas echouer bruyamment.
    """


@dataclass
class Rappel:
    """Une preuve rappelee, avec sa PROVENANCE.

    La provenance separe ce que le connecteur a explicitement demande de ce que
    SAWM Cloud a rappele tout seul pendant son tour. Sans cette separation on
    compte deux fois la meme preuve et le gain de la memoire est surevalue.
    """

    provenance: str                     # "connecteur" | "sawm-cloud"
    preuves: tuple[Mapping[str, Any], ...]
    latence_ms: float
    moteur: str | None = None
    tentatives: int = 1

    @property
    def nombre(self) -> int:
        return len(self.preuves)


class PontMemoire:
    """Surface publique Basira, avec les gardes mesurees contre la production."""

    def __init__(
        self,
        *,
        coffre: str | os.PathLike[str] = "~/.sawm-labo/env",
        campagne: str | None = None,
        budget_rejeu: int = 3,
        budget_rappel_s: float = 45.0,
        budget_rejeu_rappel: int = 10,
        telemetrie: TelemetrieCloud | None = None,
        http_client: httpx.Client | None = None,
        post_evenement: Callable[[dict], None] | None = None,
    ) -> None:
        if (isinstance(budget_rappel_s, bool)
                or not isinstance(budget_rappel_s, (int, float))
                or not math.isfinite(budget_rappel_s)
                or not 0 < budget_rappel_s <= 120):
            raise ValueError("budget_rappel_s doit etre fini, entre 0 exclu et 120 secondes")
        conf = lire_coffre(coffre)
        self.espace = conf["BASIRA_SPACE"]
        self.entite = conf["BASIRA_ENTITY"]
        self.base = conf.get("BASIRA_BASE", bc.DEFAULT_BASE_URL)
        self.campagne = campagne or uuid.uuid4().hex[:12]
        self.budget_rejeu = budget_rejeu
        self.budget_rappel_s = float(budget_rappel_s)
        self._owns_telemetrie = telemetrie is None
        self.telemetrie = telemetrie or TelemetrieCloud(
            self.campagne, secrets=(conf["BASIRA_KEY"],),
            post_evenement=post_evenement)
        if telemetrie is not None and post_evenement is not None:
            self.telemetrie.post_evenement = post_evenement
        self.telemetrie.proteger(conf["BASIRA_KEY"])
        self._http_observe = ClientHTTPObserve(self.telemetrie, http_client)
        self._client = bc.BasiraClient(
            self.espace, conf["BASIRA_KEY"], base_url=self.base,
            http_client=self._http_observe,
            max_retries=budget_rejeu,
        )
        # Une seule autorite de rejeu, le SDK, et le meme transport observe.
        # La projection asynchrone peut terminer apres le job d'ingestion.
        # Son attente ne doit rallonger ni les ecritures ni les tours SAWM.
        self._recall_client = bc.BasiraClient(
            self.espace, conf["BASIRA_KEY"], base_url=self.base,
            http_client=self._http_observe,
            max_retries=budget_rejeu_rappel,
        )

    # -- traçabilite --------------------------------------------------------

    @property
    def journal_appels(self) -> tuple[dict[str, Any], ...]:
        """Chaque appel Cloud, avec son statut et sa latence murale."""
        return tuple(self.telemetrie.appels)

    def _mesure(self, nom: str, fn, *, rejouer: bool = False):
        # Le SDK fait lui-meme plusieurs requetes (retries, lots, polls).
        # L'adaptateur trace chacune ; cette couche mesure l'operation logique.
        with self.telemetrie.operation(nom) as operation:
            t0 = time.monotonic()
            # Une seule autorite de rejeu : le SDK conserve corps/idempotence,
            # respecte les refus de quota et borne deja toutes ses tentatives.
            valeur = fn()
            ms = (time.monotonic() - t0) * 1000
            return valeur, ms, operation["tentative"]

    # -- depot --------------------------------------------------------------

    def deposer(
        self,
        observations: Sequence[Mapping[str, Any]],
        *,
        attendre: bool = True,
        budget_s: float = 60.0,
    ) -> dict[str, Any]:
        """Verse des observations et attend leur ingestion durable.

        `attendre=False` ne doit servir qu'a mesurer la latence d'acceptation :
        `completed` ne garantit pas encore la projection TSST. Le rappel
        suivant attend son ACK exact dans un budget distinct et borne.
        """
        evenements = []
        for i, obs in enumerate(observations):
            evenements.append({
                # Cle unique par occurrence : une claim_key partagee mettrait
                # les occurrences en REVISION et supplanterait l'ancienne, ce
                # qui rend le flashback impossible par construction.
                "event_id": f"{self.campagne}-{obs['id']}",
                "kind": "document",
                "title": str(obs.get("titre") or "")[:160],
                "content": str(obs["contenu"]),
                "occurred_at": obs.get("survenu_a"),
            })
        recus, ms, _ = self._mesure(
            "events:batch",
            lambda: self._client.events_batch(evenements, entity_id=self.entite),
            rejouer=True,
        )
        resultat = {"recus": recus, "acceptation_ms": round(ms, 1), "jobs": []}
        if not attendre:
            return resultat
        for recu in recus:
            job, jms, _ = self._mesure(
                "jobs:read (attente completed)",
                lambda r=recu: self._client.wait_job(
                    r["job_id"], timeout=budget_s, poll=1.0),
            )
            resultat["jobs"].append({"job_id": job["job_id"],
                                     "statut": job.get("status"),
                                     "projection_ms": round(jms, 1)})
            if job.get("status") != "completed":
                raise MemoireIndisponible(
                    f"job {job['job_id']} en {job.get('status')!r} : "
                    "l'ingestion n'est pas terminee, rien n'est suppose"
                )
        return resultat

    # -- rappel -------------------------------------------------------------

    def rappeler(
        self,
        question: str,
        *,
        limite: int = 5,
        avant_ms: int | None = None,
    ) -> Rappel:
        """Rappel TSST explicite du connecteur.

        `avant_ms` pose la coupure temporelle : pour un flashback honnete, on
        n'interroge que ce qui etait CONNU au moment considere. Sans cette
        coupure on demontre une prescience, pas une memoire.
        """
        temporel = None
        if avant_ms is not None:
            temporel = {"as_of_transaction_time_ms": avant_ms}
        reponse, ms, tentatives = self._mesure(
            "recall:tsst",
            lambda: self._recall_client.recall_tsst(
                question, entity_id=self.entite, limit=limite,
                temporal=temporel,
                timeout=self.budget_rappel_s,
            ),
            rejouer=True,
        )
        return Rappel(
            provenance="connecteur",
            preuves=tuple(reponse.get("evidence") or ()),
            latence_ms=round(ms, 1),
            moteur=(reponse.get("memory_engine") or reponse.get("engine") or reponse.get("schema")),
            tentatives=tentatives,
        )

    # -- ODVL ---------------------------------------------------------------

    def hierarchiser(
        self, candidats: Sequence[tuple[str, float, float]],
    ) -> dict[str, Any]:
        """`odvl:rank` — signal de hierarchisation, PAS une recommandation.

        Mesure du 2026-09-22 : appele avec geler-transfert 0,81, ouvrir-dossier
        0,64 et ne-rien-faire 0,20, il rend ne-rien-faire au rang 1. Le rang
        d'ODVL n'exprime ni la gravite ni la securite d'une option. On le
        journalise, on ne s'en sert pas pour choisir.
        """
        rows = [bc.Candidate(candidate_id=cid, score=score, importance=imp)
                for cid, score, imp in candidats]
        reponse, ms, _ = self._mesure(
            "odvl:rank",
            lambda: self._client.odvl_rank(rows, entity_id=self.entite),
            rejouer=True,
        )
        reponse["_latence_ms"] = round(ms, 1)
        reponse["_avertissement"] = (
            "ordre consultatif : n'ajoute aucune preuve et ne valide la "
            "securite d'aucune option"
        )
        return reponse

    def observer_vortex(self, candidats: Sequence[str]) -> dict[str, Any]:
        """`odvl:observe` — lecture pure, n'avance pas l'horloge du vortex."""
        reponse, ms, _ = self._mesure(
            "odvl:observe",
            lambda: self._client.odvl_observe(list(candidats),
                                              entity_id=self.entite),
            rejouer=True,
        )
        reponse["_latence_ms"] = round(ms, 1)
        if not reponse.get("available"):
            # Distinction qui ne doit jamais etre lissee dans un tableau de bord.
            reponse["_lecture"] = "indisponible (pas une mesure a zero)"
        return reponse

    def close(self) -> None:
        self._client.close()
        self._recall_client.close()
        self._http_observe.close()
        if self._owns_telemetrie:
            self.telemetrie.close()


def lire_coffre(chemin: str | os.PathLike[str]) -> dict[str, str]:
    """Lit le coffre hors depot. Ne renvoie jamais la cle dans une exception."""
    p = pathlib.Path(os.path.expanduser(str(chemin)))
    if not p.exists():
        raise FileNotFoundError(
            f"coffre absent : {p}. Voir .env.example et le tutoriel client."
        )
    mode = p.stat().st_mode & 0o777
    if mode & 0o077:
        raise PermissionError(f"coffre {p} lisible par d'autres (mode {mode:o})")
    conf: dict[str, str] = {}
    for ligne in p.read_text().splitlines():
        ligne = ligne.strip()
        if not ligne or ligne.startswith("#") or "=" not in ligne:
            continue
        cle, valeur = ligne.split("=", 1)
        conf[cle.strip()] = valeur.strip()
    manquants = [c for c in ("BASIRA_SPACE", "BASIRA_ENTITY", "BASIRA_KEY")
                 if not conf.get(c)]
    if manquants:
        raise KeyError(f"coffre incomplet, manque : {', '.join(manquants)}")
    return conf


def empreinte_sdk() -> dict[str, str]:
    """Version et empreinte du SDK client effectivement charge."""
    import hashlib
    source = pathlib.Path(bc.__file__).read_bytes()
    return {
        "fichier": bc.__file__,
        "sha256": hashlib.sha256(source).hexdigest(),
        "octets": str(len(source)),
        "base_par_defaut": bc.DEFAULT_BASE_URL,
    }

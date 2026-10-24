"""Client Python officiel de l'API Memoire Basira.

Un seul module, sans dependance hors ``httpx`` (``websockets`` est optionnel
pour le canal WebSocket). Python >= 3.10.

Il couvre toute l'API publique :

* ``BasiraClient`` : le data plane d'un espace memoire (entites, depot
  d'evenements avec decoupage automatique par 100, jobs, rappel, flashback,
  TSST a quatre axes types, classement ODVL, usage, purge) et le canal SAWM
  Cloud (sessions, tours en SSE, WebSocket si la dependance est presente) ;
* ``BasiraConsole`` : le control plane du compte (environnements, principals,
  grants, cles, rotation, usage) avec le JWT de connexion au compte.

Installation::

    python -m pip install httpx
    curl -fsSLO https://basira.sawm.io/static/sdk/basira_client.py

Usage minimal::

    import os
    from basira_client import BasiraClient

    basira = BasiraClient(os.environ["BASIRA_SPACE"], os.environ["BASIRA_KEY"])
    nyra = basira.create_entity("personnage", "Nyra")
    receipt = basira.remember(
        nyra["entity_id"], "Le pont nord est tombe.", event_id="tour-0042",
    )
    basira.wait_job(receipt["job_id"])
    print(basira.recall("pont nord", entity_id=nyra["entity_id"]))

Principes :

* fail-closed : le client ne fabrique jamais une valeur absente et refuse un
  contrat de reponse invalide (``BasiraError(502, ...)``) ;
* chaque erreur publique est une ``BasiraError(status, code)`` dont ``code``
  est le ``detail.code`` renvoye par le service. Les deux enveloppes qui n'en
  portent pas sont normalisees : un ``422`` de validation de schema (tableau
  ``detail``) devient ``validation_error`` et ``details`` porte le tableau ;
  un ``429`` de limite IP (``detail`` textuel) devient ``ip_rate_limited`` ;
  une erreur HTTP de passerelle sans code API devient
  ``http_gateway_unavailable`` et ne rejoue qu'une requete idempotente ;
* une coupure ou un delai de lecture PENDANT un flux SSE ou WebSocket est
  ``BasiraError(0, "stream_interrupted")``, jamais rejouee en cours de flux :
  rejouer ``respond()`` avec le meme ``turn_id`` rend le recu idempotent
  (``turn.done`` avec ``replayed``). La lecture d'un flux attend jusqu'a
  ``stream_timeout`` (120 s par defaut, un tour peut durer 90 s) ;
* les operations facturees portent une cle ``Idempotency-Key``. Les rappels
  et classements generent une cle fraiche par appel pour voir la memoire
  actuelle ; leurs tentatives automatiques gardent cette meme cle. Passez
  une cle explicite pour rejouer un recu entre plusieurs appels applicatifs.
  Les creations et depots gardent leurs cles deterministes ;
* les refus transitoires (``429 concurrency_limit_reached``,
  ``503 engine_unavailable`` et assimiles) sont rejoues un nombre borne de
  fois avec la MEME cle d'idempotence. ``429 monthly_quota_exceeded`` n'est
  jamais rejoue automatiquement : une reprise apres retablissement des
  ressources reste explicite, avec l'identifiant d'origine pour reprendre
  la meme operation.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
import time
from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Iterable, Iterator, Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit

import httpx

try:  # Dependance optionnelle : `python -m pip install websockets`.
    from websockets.sync.client import connect as _ws_connect
except Exception:  # noqa: BLE001 - toute absence rend le WS indisponible
    _ws_connect = None

__version__ = "1.0.0"

#: Identite explicite du client. La bordure publique refuse les agents
#: generiques (``Python-urllib``) ; ce User-Agent est toujours envoye.
USER_AGENT = f"basira-client/{__version__} (+https://basira.sawm.io)"

DEFAULT_BASE_URL = "https://basira-api.sawm.io/api/v1/basira"
DEFAULT_CONSOLE_URL = "https://basira-api.sawm.io/api/v1/basira/cloud/console"
SAWM_WEBSOCKET_PATH = "/api/v1/basira/sawm/realtime"
SAWM_SUBPROTOCOL = "sawm.cloud.v1"

ENTITY_TYPES = frozenset({"personnage", "monde", "service", "actif"})
EVENT_KINDS = frozenset({"message", "document"})
SCOPES = (
    "events:write", "jobs:read", "memory:recall", "memory:purge",
    "usage:read", "tsst:recall", "odvl:rank", "entities:read",
    "entities:write", "entities:delete", "sawm:run",
)

_ENTITY_ID_RE = re.compile(r"^ent_[0-9a-f]{32}$")
_PRINCIPAL_ID_RE = re.compile(r"^prn_[0-9a-f]{32}$")
_SPACE_ID_RE = re.compile(r"^[A-Za-z0-9._~:+/=-]{1,160}$")
_JOB_ID_RE = re.compile(r"^job_[0-9a-f]{32}$")
_OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9._~:+/=-]{1,160}$")
_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9._~:+/=-]{8,160}$")
_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9._~:+/=-]{8,128}$")

#: Sondage des jobs : facteur de croissance et plafond de l'intervalle (s).
POLL_GROWTH = 1.5
POLL_CEILING = 5.0

#: Refus transitoires rejoues avec la meme cle d'idempotence. La limite
#: globale par IP (``detail`` textuel normalise en ``ip_rate_limited``) est
#: rejouee en respectant ``Retry-After``.
HTTP_GATEWAY_STATUSES = frozenset({502, 503, 504, 520, 521, 522, 523, 524})
RETRYABLE_ERRORS = frozenset({
    (429, "concurrency_limit_reached"),
    (429, "ip_rate_limited"),
    (503, "engine_unavailable"),
    (503, "metering_unavailable"),
    (503, "sawm_cloud_unavailable"),
    (503, "body_reader_capacity_exceeded"),
    (503, "basira_temporarily_unavailable"),
} | {(status, "http_gateway_unavailable") for status in HTTP_GATEWAY_STATUSES})


class BasiraError(Exception):
    """Echec public de l'API : ``status`` HTTP et ``code`` du ``detail``.

    ``status == 0`` signale une erreur de transport (connexion, delai,
    ``stream_interrupted`` pendant un flux) sans reponse HTTP. ``retryable``
    indique si le service considere le refus comme transitoire. ``details``
    porte le ``detail`` brut quand il n'est pas un objet ``{"code"}`` : le
    tableau d'un ``422`` de validation, le texte d'une limite IP.
    ``retry_after`` indique le delai avant une reprise lorsque disponible ;
    sans en-tete, une limite IP utilise un recul prudent de 60 secondes.
    """

    def __init__(
        self,
        status: int,
        code: str,
        *,
        retryable: bool = False,
        details: object = None,
        retry_after: float | None = None,
    ):
        self.status = int(status)
        self.code = str(code or "basira_api_error")[:160]
        self.retryable = bool(retryable)
        self.details = details
        self.retry_after = retry_after
        super().__init__(f"Basira API {self.status}: {self.code}")

    @property
    def status_code(self) -> int:
        """Alias de ``status`` compatible avec ``BasiraGameError``."""
        return self.status


# ---------------------------------------------------------------------------
# Axes TSST types (recall:tsst)
# ---------------------------------------------------------------------------


def _axis_payload(axis: object) -> dict[str, Any]:
    """Convertit une dataclass d'axe (ou un mapping) en corps JSON sans None."""
    if axis is None:
        return {}
    if is_dataclass(axis) and not isinstance(axis, type):
        result: dict[str, Any] = {}
        for item in fields(axis):
            value = getattr(axis, item.name)
            if value is None:
                continue
            if is_dataclass(value) and not isinstance(value, type):
                value = _axis_payload(value)
            result[item.name] = value
        return result
    if isinstance(axis, Mapping):
        return {str(k): v for k, v in axis.items() if v is not None}
    raise ValueError("un axe TSST doit etre une dataclass ou un mapping")


@dataclass
class Temporal:
    """Axe temporel : cibles (``target_*``) et coupures (``as_of_*``) en ms."""

    target_valid_time_ms: int | None = None
    target_transaction_time_ms: int | None = None
    target_decision_time_ms: int | None = None
    target_belief_time_ms: int | None = None
    as_of_valid_time_ms: int | None = None
    as_of_transaction_time_ms: int | None = None
    as_of_decision_time_ms: int | None = None
    as_of_belief_time_ms: int | None = None
    temporal_half_life_ms: int | None = None


@dataclass
class PhysicalPosition:
    """Position geographique (WGS84) ; ``kind`` est fixe par le contrat."""

    latitude_deg: float
    longitude_deg: float
    altitude_m: float = 0.0
    kind: str = "physical"


@dataclass
class CartesianPosition:
    """Position cartesienne dans un repere nomme (``frame``)."""

    frame: str
    x: float
    y: float
    z: float = 0.0
    kind: str = "cartesian"


@dataclass
class AbstractPosition:
    """Position abstraite : un ``frame`` et un ``scope`` (zone logique)."""

    frame: str
    scope: str
    kind: str = "abstract"


@dataclass
class CoordinatePosition:
    """Tenseur de coordonnees (``shape`` x ``values``) dans un ``frame``."""

    frame: str
    shape: list[int]
    values: list[float]
    kind: str = "coordinates"


@dataclass
class Spatial:
    """Axe spatial : une position et des rayons ``max_*`` / ``within_*``."""

    position: (
        PhysicalPosition | CartesianPosition | AbstractPosition
        | CoordinatePosition | Mapping[str, Any] | None
    ) = None
    max_spatial_distance_km: float | None = None
    max_cartesian_distance: float | None = None
    coordinate_distance_scale: float | None = None
    within_spatial_distance_km: float | None = None
    within_cartesian_distance: float | None = None
    within_coordinate_distance: float | None = None


@dataclass
class Semantic:
    """Axe semantique : source, entite (+ type), predicat, portee."""

    source_id: str | None = None
    entity: str | None = None
    entity_type: str | None = None
    predicate: str | None = None
    semantic_scope_id: str | None = None


@dataclass
class Epistemic:
    """Axe epistemique : statuts admis, confiance minimale, historique."""

    allowed_epistemic: list[str] | None = None
    min_confidence: float | None = None
    include_belief_history: bool = False


@dataclass
class Weights:
    """Ponderation des trois axes ; la somme doit valoir 1."""

    temporal: float
    spatial: float
    semantic: float


@dataclass
class Candidate:
    """Candidat ODVL : identifiant opaque, score [0,1], importance, ancre."""

    candidate_id: str
    score: float
    importance: float = 0.0
    anchor: bool = False
    cluster_id: str | None = None


# ---------------------------------------------------------------------------
# Transport commun
# ---------------------------------------------------------------------------


def _derived_idempotency(prefix: str, value: object) -> str:
    """Cle deterministe derivee du contenu canonique de la requete."""
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return f"{prefix}.{hashlib.sha256(canonical).hexdigest()[:40]}"


def _fresh_idempotency(prefix: str) -> str:
    """Cle unique pour une operation que l'on veut executer a nouveau."""
    return f"{prefix}.{secrets.token_hex(20)}"


def _snake_code(text: str) -> str:
    """Normalise un message humain en code ``snake_case`` borne."""
    code = re.sub(r"[^a-z0-9]+", "_", str(text).strip().lower()).strip("_")
    return code[:80] or "basira_api_error"


def _error_from_response(response: httpx.Response) -> BasiraError:
    """Traduit les trois enveloppes de refus en ``BasiraError``.

    ``{"detail":{"code"}}`` est le format nominal ; un ``422`` FastAPI rend un
    tableau ``detail`` (``validation_error``) ; la limite globale par IP rend
    un ``detail`` textuel (``ip_rate_limited`` sur ``429``, sinon le texte
    normalise en ``snake_case``). Le ``detail`` brut reste dans ``details``.
    """
    try:
        body = response.json()
    except ValueError:
        body = None
    detail = body.get("detail") if isinstance(body, dict) else None
    status = response.status_code
    details: object = None
    # A proxy may return HTML, plain text, or a textual JSON detail after the
    # origin has already accepted a mutation. Keep a stable transport code,
    # not a truncated human sentence; never override a structured API refusal.
    if status in HTTP_GATEWAY_STATUSES and not (isinstance(detail, dict) and detail.get("code")):
        code, retryable, details = "http_gateway_unavailable", True, detail
    elif isinstance(detail, dict):
        code = str(detail.get("code") or "basira_api_error")
        retryable = bool(detail.get("retryable", False))
        details = detail
    elif isinstance(detail, list):
        code, retryable, details = "validation_error", False, detail
    elif isinstance(detail, str):
        code = "ip_rate_limited" if status == 429 else _snake_code(detail)
        retryable, details = False, detail
    else:
        code, retryable = "invalid_json_response", False
    retry_after = _retry_after(response)
    if retry_after is None and (status, code) == (429, "ip_rate_limited"):
        retry_after = 60.0
    return BasiraError(
        status, code,
        retryable=retryable or (status, code) in RETRYABLE_ERRORS,
        details=details,
        retry_after=retry_after,
    )


def _retry_after(response: httpx.Response) -> float | None:
    """Honor delta-seconds or an HTTP-date without shortening the wait."""
    raw = (response.headers.get("Retry-After") or "").strip()
    if not raw:
        return None
    try:
        if raw.isdigit():
            delay = float(raw)
        else:
            date = parsedate_to_datetime(raw)
            if date.tzinfo is None:
                date = date.replace(tzinfo=timezone.utc)
            delay = max(0.0, date.timestamp() - time.time())
        return delay if math.isfinite(delay) else None
    except (TypeError, ValueError, OverflowError):
        return None


def _retry_delay(response: httpx.Response | None, attempt: int) -> float:
    if response is not None:
        delay = _retry_after(response)
        if delay is not None:
            return delay
        # The public IP limiter currently omits Retry-After. Fast retries
        # cannot free its 60-second bucket and only add rejected requests.
        error = _error_from_response(response)
        if (error.status, error.code) == (429, "ip_rate_limited"):
            return 60.0
    return min(8.0, 0.5 * (2 ** (attempt - 1)))


class _Http:
    """Socle HTTP partage : identite, erreurs publiques, rejeux bornes."""

    def __init__(
        self,
        *,
        base_url: str,
        bearer: str,
        timeout: float,
        max_retries: int,
        http_client: httpx.Client | None,
        sleep: Callable[[float], None],
    ) -> None:
        base = str(base_url or "").strip().rstrip("/")
        parsed = urlsplit(base)
        if parsed.scheme not in {"https", "http"} or not parsed.netloc:
            raise ValueError("base_url doit etre une URL HTTP(S) absolue")
        if parsed.query or parsed.fragment:
            raise ValueError("base_url ne doit porter ni query ni fragment")
        if parsed.scheme != "https" and parsed.hostname not in {
            "127.0.0.1", "localhost", "::1",
        }:
            raise ValueError("un secret ne voyage qu'en HTTPS hors loopback")
        credential = str(bearer or "").strip()
        if not credential:
            raise ValueError("le secret d'authentification est requis")
        if timeout <= 0:
            raise ValueError("timeout doit etre strictement positif")
        if isinstance(max_retries, bool) or not 0 <= int(max_retries) <= 10:
            raise ValueError("max_retries doit etre compris entre 0 et 10")
        self.base_url = base
        self.timeout = float(timeout)
        self.max_retries = int(max_retries)
        self._bearer = credential
        self._sleep = sleep
        self._owns_http_client = http_client is None
        self._http = http_client or httpx.Client(
            timeout=self.timeout, headers={"User-Agent": USER_AGENT},
        )

    def __enter__(self):
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        """Ferme le client HTTP si ce module l'a cree."""
        if self._owns_http_client:
            self._http.close()

    def _headers(
        self, *, accept: str, has_body: bool, idempotency_key: str | None,
    ) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self._bearer}",
            "Accept": accept,
            "User-Agent": USER_AGENT,
        }
        if has_body:
            headers["Content-Type"] = "application/json"
        if idempotency_key is not None:
            candidate = str(idempotency_key).strip()
            if not _IDEMPOTENCY_RE.fullmatch(candidate):
                raise ValueError("Idempotency-Key invalide (8 a 160 caracteres)")
            headers["Idempotency-Key"] = candidate
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Mapping[str, Any] | None = None,
        params: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
        _deadline: float | None = None,
    ) -> dict[str, Any]:
        """Un appel JSON ; rejoue les refus transitoires avec la meme cle."""
        headers = self._headers(
            accept="application/json",
            has_body=json_body is not None,
            idempotency_key=idempotency_key,
        )
        attempt = 0
        replay_safe = method.upper() == "GET" or idempotency_key is not None
        while True:
            remaining = None if _deadline is None else _deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                raise TimeoutError("delai HTTP Basira depasse")
            try:
                response = self._http.request(
                    method,
                    self.base_url + path,
                    headers=headers,
                    params=dict(params or {}),
                    json=dict(json_body) if json_body is not None else None,
                    timeout=self.timeout if remaining is None else min(self.timeout, remaining),
                )
            except httpx.TransportError as exc:
                if replay_safe and attempt < self.max_retries:
                    attempt += 1
                    delay = _retry_delay(None, attempt)
                    if _deadline is not None and time.monotonic() + delay >= _deadline:
                        raise BasiraError(0, "transport_error", retryable=True) from exc
                    self._sleep(delay)
                    continue
                raise BasiraError(
                    0, "transport_error", retryable=True,
                ) from exc
            if response.status_code < 400:
                try:
                    body = response.json()
                except ValueError:
                    raise BasiraError(502, "invalid_json_response") from None
                if not isinstance(body, dict):
                    raise BasiraError(502, "invalid_json_response")
                return body
            error = _error_from_response(response)
            if (
                (error.status, error.code) in RETRYABLE_ERRORS
                and (error.code != "http_gateway_unavailable" or replay_safe)
                and attempt < self.max_retries
            ):
                attempt += 1
                delay = _retry_delay(response, attempt)
                if _deadline is not None and time.monotonic() + delay >= _deadline:
                    # Preserve the refusal and its retry_after hint; never
                    # shorten the server's wait to fit a polling deadline.
                    raise error
                self._sleep(delay)
                continue
            raise error


# ---------------------------------------------------------------------------
# Data plane + SAWM Cloud
# ---------------------------------------------------------------------------


class BasiraClient(_Http):
    """Client du data plane d'un espace memoire et du canal SAWM Cloud.

    :param space_id: identifiant de l'espace memoire (``mem_...``).
    :param api_key: cle de service ``bsr_live_key-...`` ou ``bsr_test_key-...``,
        emise depuis la console pour un principal de cet espace. Elle ne voit
        que cet espace et seulement l'intersection de ses portees et des
        grants de son principal. Ne la placez jamais dans un navigateur.
    :param base_url: racine de l'API (par defaut la production publique).
    :param timeout: delai HTTP en secondes (connexion, ecriture, appels JSON).
    :param stream_timeout: delai de lecture d'un flux SSE ou WebSocket entre
        deux evenements, en secondes (120 par defaut : un tour SAWM Cloud
        peut durer 90 s sans battement de coeur avant son premier delta).
    :param max_retries: nombre maximal de rejeux des refus transitoires.
    :param http_client: ``httpx.Client`` a reutiliser (tests, pool partage).
    :param sleep: fonction d'attente entre deux rejeux (injectable).
    """

    def __init__(
        self,
        space_id: str,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 30.0,
        stream_timeout: float = 120.0,
        max_retries: int = 3,
        http_client: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        space = str(space_id or "").strip()
        if not _SPACE_ID_RE.fullmatch(space):
            raise ValueError("space_id invalide")
        if stream_timeout <= 0:
            raise ValueError("stream_timeout doit etre strictement positif")
        super().__init__(
            base_url=base_url,
            bearer=api_key,
            timeout=timeout,
            max_retries=max_retries,
            http_client=http_client,
            sleep=sleep,
        )
        self.space_id = space
        self.stream_timeout = float(stream_timeout)

    def __repr__(self) -> str:
        return (
            f"BasiraClient(space_id={self.space_id!r}, "
            f"base_url={self.base_url!r}, api_key=<masquee>)"
        )

    # -- validation ---------------------------------------------------------

    @staticmethod
    def _entity_id(value: str | None, *, required: bool = True) -> str | None:
        if value is None and not required:
            return None
        candidate = str(value or "").strip()
        if not _ENTITY_ID_RE.fullmatch(candidate):
            raise ValueError("entity_id public invalide (ent_ + 32 hex)")
        return candidate

    @staticmethod
    def _limit(value: int, *, maximum: int) -> int:
        if isinstance(value, bool) or not 1 <= int(value) <= maximum:
            raise ValueError(f"limit doit etre compris entre 1 et {maximum}")
        return int(value)

    @staticmethod
    def _time_ms(value: int | None, *, field: str) -> int | None:
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{field} doit etre un entier en millisecondes")
        if not 0 <= value <= 2 ** 62:
            raise ValueError(f"{field} hors bornes")
        return value

    @staticmethod
    def _occurred_at(value: datetime | str | None) -> str | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            return value.isoformat()
        candidate = str(value).strip()
        if not candidate:
            raise ValueError("occurred_at ne doit pas etre vide")
        return candidate

    def _path(self, suffix: str) -> str:
        return f"/spaces/{self.space_id}{suffix}"

    def _with_entity(
        self, payload: dict[str, Any], entity_id: str | None,
    ) -> dict[str, Any]:
        normalized = self._entity_id(entity_id, required=False)
        if normalized is not None:
            payload["entity_id"] = normalized
        return payload

    # -- entites ------------------------------------------------------------

    def create_entity(
        self,
        entity_type: str,
        name: str,
        *,
        description: str = "",
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """``POST /spaces/{space}/entities`` (portee ``entities:write``).

        Sans ``idempotency_key``, la cle est derivee du type, du nom et de la
        description : recreer la meme entite rejoue le meme recu. Donnez une
        cle explicite pour creer deux entites homonymes.
        """
        normalized_type = str(entity_type or "").strip().lower()
        if normalized_type not in ENTITY_TYPES:
            raise ValueError("entity_type non supporte")
        normalized_name = str(name or "").strip()
        if not normalized_name or len(normalized_name) > 160:
            raise ValueError("name doit contenir entre 1 et 160 caracteres")
        if len(str(description)) > 2_000:
            raise ValueError("description : 2000 caracteres au plus")
        payload = {
            "entity_type": normalized_type,
            "name": normalized_name,
            "description": str(description),
        }
        return self._request(
            "POST",
            self._path("/entities"),
            json_body=payload,
            idempotency_key=idempotency_key
            or _derived_idempotency("entity.create", payload),
        )

    def create_entities(
        self,
        items: Iterable[Mapping[str, Any]],
        *,
        batch_size: int = 100,
    ) -> Iterator[dict[str, Any]]:
        """``POST /spaces/{space}/entities:batch`` par lots de 100 au plus.

        Consomme n'importe quel iterable (generateur inclus) sans le charger
        en memoire ; chaque lot porte une cle derivee de son contenu et les
        recus sont rendus dans l'ordre d'entree (``external_id`` ->
        ``entity_id``).
        """
        size = self._limit(batch_size, maximum=100)
        batch: list[dict[str, str]] = []
        for raw in items:
            if not isinstance(raw, Mapping):
                raise ValueError("chaque entite doit etre un mapping")
            unknown = set(raw) - {
                "external_id", "entity_type", "name", "description",
            }
            if unknown or not {"external_id", "entity_type", "name"} <= set(raw):
                raise ValueError("champs d'entite invalides")
            external_id = str(raw.get("external_id") or "").strip()
            entity_type = str(raw.get("entity_type") or "").strip().lower()
            name = str(raw.get("name") or "").strip()
            description = str(raw.get("description") or "").strip()
            if not _OPAQUE_ID_RE.fullmatch(external_id):
                raise ValueError("external_id invalide")
            if entity_type not in ENTITY_TYPES:
                raise ValueError("entity_type non supporte")
            if not name or len(name) > 160:
                raise ValueError("name doit contenir entre 1 et 160 caracteres")
            if len(description) > 2_000:
                raise ValueError("description : 2000 caracteres au plus")
            batch.append({
                "external_id": external_id,
                "entity_type": entity_type,
                "name": name,
                "description": description,
            })
            if len(batch) == size:
                yield from self._create_entity_batch(batch)
                batch = []
        if batch:
            yield from self._create_entity_batch(batch)

    def _create_entity_batch(
        self, batch: Sequence[Mapping[str, str]],
    ) -> Iterator[dict[str, Any]]:
        payload = {"items": [dict(item) for item in batch]}
        response = self._request(
            "POST",
            self._path("/entities:batch"),
            json_body=payload,
            idempotency_key=_derived_idempotency("entities.batch", payload),
        )
        created = response.get("entities")
        expected = [item["external_id"] for item in batch]
        received = [
            str(item.get("external_id") or "") if isinstance(item, dict) else ""
            for item in (created if isinstance(created, list) else [])
        ]
        if received != expected or any(
            not _ENTITY_ID_RE.fullmatch(str(item.get("entity_id") or ""))
            for item in created
        ):
            raise BasiraError(502, "invalid_entity_batch_response")
        yield from created

    def list_entities(
        self,
        *,
        limit: int = 50,
        after: str = "",
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """``GET /spaces/{space}/entities`` (une page, ``next_cursor``).

        Une lecture de page est comptee : sans cle explicite, chaque appel est
        une nouvelle operation. Passez la meme cle pour rejouer une page.
        """
        params: dict[str, Any] = {"limit": self._limit(limit, maximum=200)}
        if after:
            params["after"] = self._entity_id(after)
        return self._request(
            "GET",
            self._path("/entities"),
            params=params,
            idempotency_key=idempotency_key,
        )

    def iter_entities(self, *, page_size: int = 100) -> Iterator[dict[str, Any]]:
        """Parcourt toutes les entites de l'espace en suivant ``next_cursor``."""
        after = ""
        while True:
            page = self.list_entities(limit=page_size, after=after)
            rows = page.get("entities")
            if not isinstance(rows, list):
                raise BasiraError(502, "invalid_entity_list_response")
            yield from rows
            cursor = page.get("next_cursor")
            if not cursor:
                return
            after = str(cursor)

    def delete_entity(
        self, entity_id: str, *, idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """``DELETE /spaces/{space}/entities/{entity_id}`` : purge physique.

        Exige la portee ``entities:delete`` et un grant ``admin`` exact sur la
        racine. Le recu (``purge_receipt`` ``edp_...``) est verifie.
        """
        normalized = self._entity_id(entity_id)
        receipt = self._request(
            "DELETE",
            self._path(f"/entities/{normalized}"),
            idempotency_key=idempotency_key or _derived_idempotency(
                "entity.delete", {"entity_id": normalized},
            ),
        )
        if (
            receipt.get("entity_id") != normalized
            or receipt.get("status") != "deleted"
            or not str(receipt.get("purge_receipt") or "").startswith("edp_")
        ):
            raise BasiraError(502, "invalid_entity_delete_receipt")
        return receipt

    def delete_entities(
        self, entity_ids: Iterable[str],
    ) -> Iterator[dict[str, Any]]:
        """Purge un flux d'entites une par une ; chaque recu est verifie."""
        for entity_id in entity_ids:
            yield self.delete_entity(entity_id)

    # -- evenements et jobs -------------------------------------------------

    def _event(self, raw: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(raw, Mapping):
            raise ValueError("chaque evenement doit etre un mapping")
        unknown = set(raw) - {
            "event_id", "kind", "role", "content", "title", "occurred_at",
        }
        if unknown:
            raise ValueError(f"champs d'evenement inconnus : {sorted(unknown)}")
        event_id = str(raw.get("event_id") or "").strip()
        if not _OPAQUE_ID_RE.fullmatch(event_id):
            raise ValueError("event_id invalide")
        kind = str(raw.get("kind") or "document").strip().lower()
        if kind not in EVENT_KINDS:
            raise ValueError("kind doit valoir message ou document")
        content = str(raw.get("content") or "")
        if not content or len(content) > 65_536:
            raise ValueError("content doit contenir entre 1 et 65536 caracteres")
        title = str(raw.get("title") or "")
        if len(title) > 512:
            raise ValueError("title : 512 caracteres au plus")
        event: dict[str, Any] = {
            "event_id": event_id, "kind": kind, "content": content,
        }
        if title:
            event["title"] = title
        role = raw.get("role")
        if role is not None:
            if kind != "message" or role not in {"user", "assistant"}:
                raise ValueError("role n'est valide que pour un message")
            event["role"] = role
        occurred_at = self._occurred_at(raw.get("occurred_at"))
        if occurred_at is not None:
            event["occurred_at"] = occurred_at
        return event

    def events_batch(
        self,
        events: Iterable[Mapping[str, Any]],
        *,
        entity_id: str | None = None,
        batch_size: int = 100,
        idempotency_key: str | None = None,
    ) -> list[dict[str, Any]]:
        """``POST /spaces/{space}/events:batch`` avec decoupage par 100.

        Rend un recu ``{"job_id", "status": "pending", ...}`` par lot envoye.
        Sans cle explicite, chaque lot porte une cle derivee de l'entite et
        des ``event_id`` du lot : rejouer le meme lot rend le meme job ;
        renvoyer les memes identifiants avec un contenu different est refuse
        (``409 idempotency_conflict``) au lieu de doubler les souvenirs. Une
        cle explicite n'est acceptee que si tout tient dans un seul lot.
        """
        size = self._limit(batch_size, maximum=100)
        normalized_entity = self._entity_id(entity_id, required=False)
        if idempotency_key is not None:
            # Une cle explicite ne peut couvrir qu'une seule requete : on
            # materialise le flux pour refuser AVANT tout envoi.
            events = list(events)
            if len(events) > size:
                raise ValueError(
                    "idempotency_key explicite : un seul lot de 100 au plus"
                )
        receipts: list[dict[str, Any]] = []
        batch: list[dict[str, Any]] = []

        def flush() -> None:
            if not batch:
                return
            if idempotency_key is not None and (receipts or len(batch) > size):
                raise ValueError(
                    "idempotency_key explicite : un seul lot de 100 au plus"
                )
            payload: dict[str, Any] = {"events": list(batch)}
            if normalized_entity is not None:
                payload["entity_id"] = normalized_entity
            key = idempotency_key or _derived_idempotency("events.batch", {
                "entity_id": normalized_entity,
                "event_ids": [item["event_id"] for item in batch],
            })
            receipt = self._request(
                "POST", self._path("/events:batch"),
                json_body=payload, idempotency_key=key,
            )
            if not _JOB_ID_RE.fullmatch(str(receipt.get("job_id") or "")):
                raise BasiraError(502, "invalid_job_receipt")
            receipts.append(receipt)
            batch.clear()

        seen: set[str] = set()
        for raw in events:
            event = self._event(raw)
            if event["event_id"] in seen:
                raise ValueError("event_id duplique dans le depot")
            seen.add(event["event_id"])
            batch.append(event)
            if len(batch) == size:
                flush()
        flush()
        if not receipts:
            raise ValueError("events ne doit pas etre vide")
        return receipts

    def remember(
        self,
        entity_id: str | None,
        content: str,
        *,
        event_id: str,
        kind: str = "document",
        title: str = "",
        role: str | None = None,
        occurred_at: datetime | str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Depose un seul souvenir (document ou message) et rend son recu."""
        return self.events_batch(
            [{
                "event_id": event_id, "kind": kind, "content": content,
                "title": title, "role": role, "occurred_at": occurred_at,
            }],
            entity_id=entity_id,
            idempotency_key=idempotency_key,
        )[0]

    def remember_turn(
        self,
        entity_id: str | None,
        *,
        turn_id: str,
        user_message: str,
        assistant_message: str,
        occurred_at: datetime | str | None = None,
    ) -> dict[str, Any]:
        """Depose un echange complet (user + assistant) en un seul lot."""
        normalized_turn = str(turn_id or "").strip()
        if not _OPAQUE_ID_RE.fullmatch(normalized_turn) or len(normalized_turn) > 140:
            raise ValueError("turn_id invalide")
        return self.events_batch(
            [
                {
                    "event_id": f"{normalized_turn}:user", "kind": "message",
                    "role": "user", "content": user_message,
                    "occurred_at": occurred_at,
                },
                {
                    "event_id": f"{normalized_turn}:assistant",
                    "kind": "message", "role": "assistant",
                    "content": assistant_message, "occurred_at": occurred_at,
                },
            ],
            entity_id=entity_id,
        )[0]

    def job(self, job_id: str, *, _deadline: float | None = None) -> dict[str, Any]:
        """``GET /spaces/{space}/jobs/{job_id}`` (portee ``jobs:read``)."""
        normalized = str(job_id or "").strip()
        if not _JOB_ID_RE.fullmatch(normalized):
            raise ValueError("job_id public invalide")
        return self._request("GET", self._path(f"/jobs/{normalized}"), _deadline=_deadline)

    def wait_job(
        self,
        job_id: str,
        *,
        timeout: float = 30.0,
        poll: float = 1.0,
    ) -> dict[str, Any]:
        """Attend ``completed`` ; ``dead_letter`` leve ``BasiraError(409)``.

        ``poll`` est l'intervalle initial entre deux lectures ; il croit
        ensuite geometriquement (x1,5, plafond ``POLL_CEILING`` = 5 s) pour
        qu'une attente longue reste sous la limite globale par IP du data
        plane (120 appels par minute), partagee entre tous les clients d'une
        meme adresse. ``TimeoutError`` est levee si le job n'est pas termine a
        l'echeance : le souvenir n'est alors pas encore rappelable, rien n'est
        suppose. Si un refus transitoire demande une attente qui depasse
        ce budget, son BasiraError est remonte (retry_after indique le delai),
        sans le rejouer trop tot. Le timeout HTTP est borne au budget restant.
        """
        if timeout <= 0 or poll <= 0:
            raise ValueError("timeout et poll doivent etre positifs")
        deadline = time.monotonic() + timeout
        delay = float(poll)
        ceiling = max(POLL_CEILING, delay)
        while True:
            result = self.job(job_id, _deadline=deadline)
            status = result.get("status")
            if status == "completed":
                return result
            if status == "dead_letter":
                raise BasiraError(409, "job_dead_letter")
            if status not in {"pending", "processing"}:
                raise BasiraError(503, "unknown_job_status")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"job Basira {job_id!r} non termine")
            self._sleep(min(delay, remaining))
            delay = min(delay * POLL_GROWTH, ceiling)

    def wait_jobs(
        self,
        receipts: Iterable[Mapping[str, Any] | str],
        *,
        timeout: float = 60.0,
        poll: float = 1.0,
    ) -> list[dict[str, Any]]:
        """Attend tous les jobs d'une liste de recus (ou d'identifiants).

        Le recul geometrique de ``wait_job`` s'applique a chaque job.
        """
        deadline = time.monotonic() + timeout
        results = []
        for receipt in receipts:
            job_id = receipt if isinstance(receipt, str) else str(
                receipt.get("job_id") or ""
            )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("tous les jobs ne sont pas termines")
            results.append(self.wait_job(job_id, timeout=remaining, poll=poll))
        return results

    # -- rappel -------------------------------------------------------------

    def recall(
        self,
        query: str,
        *,
        entity_id: str | None = None,
        limit: int = 5,
        as_of_event_time_ms: int | None = None,
        as_of_knowledge_time_ms: int | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """``POST /spaces/{space}/recall`` : preuves ``basira-evidence/v1``.

        La reponse porte ``memory_engine`` (``basira-v2-exact`` en nominal),
        ``evidence``, ``count`` et ``flashback``. Le rappel est compte : une
        reservation de quota superieure au cout reel est liberee au reglement.
        Sans cle explicite, chaque appel demande une vue fraiche ; seuls les
        retries internes reutilisent sa cle. Une cle explicite rejoue le recu.
        """
        normalized_query = str(query or "")
        if not normalized_query or len(normalized_query) > 8_192:
            raise ValueError("query doit contenir entre 1 et 8192 caracteres")
        payload: dict[str, Any] = {
            "query": normalized_query, "limit": self._limit(limit, maximum=10),
        }
        event_cut = self._time_ms(as_of_event_time_ms, field="as_of_event_time_ms")
        if event_cut is not None:
            payload["as_of_event_time_ms"] = event_cut
        knowledge_cut = self._time_ms(
            as_of_knowledge_time_ms, field="as_of_knowledge_time_ms",
        )
        if knowledge_cut is not None:
            payload["as_of_knowledge_time_ms"] = knowledge_cut
        self._with_entity(payload, entity_id)
        return self._request(
            "POST",
            self._path("/recall"),
            json_body=payload,
            idempotency_key=idempotency_key
            or _fresh_idempotency("recall"),
        )

    def flashback(
        self,
        query: str,
        *,
        as_of_event_time_ms: int | None = None,
        as_of_knowledge_time_ms: int | None = None,
        entity_id: str | None = None,
        limit: int = 5,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Rappel a une date passee : ce que l'on savait alors.

        ``as_of_event_time_ms`` coupe sur le temps de l'evenement,
        ``as_of_knowledge_time_ms`` sur le moment ou Basira l'a appris. Au
        moins une coupure est requise. ``503 flashback_projection_unavailable``
        signifie que la projection historique n'a pas servi la requete : ne
        remplacez jamais ce refus par un rappel courant presente comme
        historique.
        """
        if as_of_event_time_ms is None and as_of_knowledge_time_ms is None:
            raise ValueError("un flashback exige au moins une coupure as_of_*")
        return self.recall(
            query,
            entity_id=entity_id,
            limit=limit,
            as_of_event_time_ms=as_of_event_time_ms,
            as_of_knowledge_time_ms=as_of_knowledge_time_ms,
            idempotency_key=idempotency_key,
        )

    def recall_tsst(
        self,
        query: str,
        *,
        entity_id: str | None = None,
        limit: int = 5,
        temporal: Temporal | Mapping[str, Any] | None = None,
        spatial: Spatial | Mapping[str, Any] | None = None,
        semantic: Semantic | Mapping[str, Any] | None = None,
        epistemic: Epistemic | Mapping[str, Any] | None = None,
        weights: Weights | Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """``POST /spaces/{space}/recall:tsst`` avec quatre axes types.

        Passez des instances de ``Temporal``, ``Spatial``, ``Semantic``,
        ``Epistemic`` (ou des mappings equivalents) ; les champs ``None`` sont
        omis. ``Weights`` pondere temporel/spatial/semantique (somme = 1).
        Chaque appel utilise une cle fraiche, conservee pendant ses retries.
        Fournissez une cle explicite pour rejouer exactement un recu precedent.
        ``timeout`` borne l'appel et tous ses retries, comme pour ``usage``.
        """
        if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                                    or not math.isfinite(timeout) or timeout <= 0):
            raise ValueError("timeout doit etre un nombre fini strictement positif")
        deadline = None if timeout is None else time.monotonic() + timeout
        normalized_query = str(query or "")
        if not normalized_query or len(normalized_query) > 8_192:
            raise ValueError("query doit contenir entre 1 et 8192 caracteres")
        payload: dict[str, Any] = {
            "query": normalized_query, "limit": self._limit(limit, maximum=10),
        }
        for name, axis in (
            ("temporal", temporal), ("spatial", spatial),
            ("semantic", semantic), ("epistemic", epistemic),
        ):
            body = _axis_payload(axis)
            if body:
                payload[name] = body
        if weights is not None:
            payload["weights"] = _axis_payload(weights)
        self._with_entity(payload, entity_id)
        return self._request(
            "POST",
            self._path("/recall:tsst"),
            json_body=payload,
            idempotency_key=idempotency_key
            or _fresh_idempotency("recall.tsst"),
            _deadline=deadline,
        )

    def flashback_tsst(
        self,
        query: str,
        *,
        as_of_valid_time_ms: int,
        as_of_transaction_time_ms: int | None = None,
        entity_id: str | None = None,
        limit: int = 5,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Flashback bitemporel par TSST avec l'historique des croyances."""
        return self.recall_tsst(
            query,
            entity_id=entity_id,
            limit=limit,
            temporal=Temporal(
                as_of_valid_time_ms=self._time_ms(
                    as_of_valid_time_ms, field="as_of_valid_time_ms",
                ),
                as_of_transaction_time_ms=self._time_ms(
                    as_of_transaction_time_ms, field="as_of_transaction_time_ms",
                ),
            ),
            epistemic=Epistemic(include_belief_history=True),
            idempotency_key=idempotency_key,
        )

    # -- ODVL ---------------------------------------------------------------

    def odvl_rank(
        self,
        candidates: Sequence[Candidate | Mapping[str, Any]],
        *,
        entity_id: str | None = None,
        qualification_floor: float | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """``POST /spaces/{space}/odvl:rank`` : ordre consultatif, rien execute.

        La reponse ``basira-odvl-ranking/v1`` rend ``ranking`` (permutation
        des candidats fournis), ``reordered`` et ``ranking_applied``.
        Sans cle explicite, chaque appel demande un nouveau classement ; les
        retries internes gardent la meme cle pour ne pas doubler le debit.
        """
        rows = [
            _axis_payload(item) if is_dataclass(item) else dict(item)
            for item in candidates
        ]
        if not 1 <= len(rows) <= 128:
            raise ValueError("de 1 a 128 candidats")
        identifiers = [str(row.get("candidate_id") or "") for row in rows]
        if len(set(identifiers)) != len(identifiers) or not all(
            _OPAQUE_ID_RE.fullmatch(item) for item in identifiers
        ):
            raise ValueError("candidate_id invalides ou dupliques")
        payload: dict[str, Any] = {"candidates": rows}
        if qualification_floor is not None:
            if not 0.0 <= float(qualification_floor) < 1.0:
                raise ValueError("qualification_floor dans [0, 1[")
            payload["qualification_floor"] = float(qualification_floor)
        self._with_entity(payload, entity_id)
        return self._request(
            "POST",
            self._path("/odvl:rank"),
            json_body=payload,
            idempotency_key=idempotency_key
            or _fresh_idempotency("odvl.rank"),
        )

    def write_assertion(
        self, assertion: Mapping[str, Any], *, entity_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Write a typed claim/revision (ACL write and events:write).

        ``known_at_ms`` is assigned by the server and cannot be supplied.
        The server validates evidence and revision authority; keep an explicit key when
        retrying a write whose response was lost.
        """
        payload = dict(assertion)
        self._with_entity(payload, entity_id)
        return self._request(
            "POST", self._path("/assertions"), json_body=payload,
            idempotency_key=idempotency_key or _derived_idempotency("assertion", payload),
        )

    def odvl_observe(
        self, candidate_ids: Sequence[str], *, entity_id: str | None = None,
        cluster_ids: Sequence[str] = (), limit: int = 128,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Pure ODVL read, with per-domain resonance; never advances time.

        Requires ACLv2, odvl:rank and a read grant. ``available: false`` means
        no vortex measurement is available, never a measured zero.
        """
        ids = list(candidate_ids)
        if not 1 <= len(ids) <= 128 or len(set(ids)) != len(ids):
            raise ValueError("de 1 a 128 candidate_ids uniques")
        payload = {"candidate_ids": ids, "cluster_ids": list(cluster_ids),
                   "limit": self._limit(limit, maximum=128)}
        self._with_entity(payload, entity_id)
        return self._request(
            "POST", self._path("/odvl:observe"), json_body=payload,
            idempotency_key=idempotency_key or _fresh_idempotency("odvl.observe"),
        )

    def odvl_stimulate(
        self, stimuli: Sequence[Candidate | Mapping[str, Any]] = (), *,
        entity_id: str | None = None, qualification_floor: float | None = None,
        elapsed_units: float = 0.0, settle_steps: int = 0, dt_units: float = 1.0,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Touch, then advance game time; ACLv2, odvl:rank and write grant.

        One game hour is one ODVL unit in the tavern adapter. Read subsequent
        state with odvl_observe: odvl_rank also applies wall-clock aging.
        Retries reuse the same key and body to avoid applying a tick twice.
        """
        rows = [_axis_payload(item) if is_dataclass(item) else dict(item)
                for item in stimuli]
        if len(rows) > 128:
            raise ValueError("au plus 128 stimuli")
        payload = {"stimuli": rows, "elapsed_units": elapsed_units,
                   "settle_steps": settle_steps}
        if qualification_floor is not None:
            payload["qualification_floor"] = qualification_floor
        if dt_units != 1.0:
            payload["dt_units"] = dt_units
        self._with_entity(payload, entity_id)
        return self._request(
            "POST", self._path("/odvl:stimulate"), json_body=payload,
            idempotency_key=idempotency_key or _fresh_idempotency("odvl.stimulate"),
        )

    # -- usage et purge -----------------------------------------------------

    def usage(self, *, timeout: float | None = None) -> dict[str, Any]:
        """``GET /spaces/{space}/usage`` (portee ``usage:read``).

        Le compteur est retourne tel que publie par le service. Un compte
        sans plafond mensuel expose ``unlimited: true`` et
        ``monthly_limit: null`` (``None`` en Python), jamais un faux grand
        nombre. Sinon ``unlimited`` vaut ``false`` et ``monthly_limit`` est
        un entier. ``used`` et ``reserved`` restent des compteurs reels ;
        ``max_concurrency`` et les limites techniques restent applicables.
        Verifiez ``unlimited is True`` avant de calculer un solde ou un
        pourcentage. ``quota_scope: account`` indique un quota partage avec
        les autres espaces du compte. Cette lecture ne modifie aucun quota.

        ``timeout`` borne cette lecture et ses reprises. Un Retry-After qui
        depasse le budget remonte son refus, sans reprise prematuree. Sans
        timeout explicite, les limites HTTP ordinaires du client s'appliquent.
        """
        if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                                    or not math.isfinite(timeout) or timeout <= 0):
            raise ValueError("timeout doit etre un nombre fini strictement positif")
        deadline = None if timeout is None else time.monotonic() + timeout
        return self._request("GET", self._path("/usage"), _deadline=deadline)

    def purge_entity(
        self, entity_id: str, *, idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """``POST /spaces/{space}/purge`` limite a une entite (``memory:purge``).

        L'entite reste ; sa memoire est effacee et un recu ``pgr_...`` rendu.
        Chaque appel sans cle explicite est une nouvelle purge.
        """
        payload = {
            "confirmation": "PURGE", "entity_id": self._entity_id(entity_id),
        }
        return self._request(
            "POST",
            self._path("/purge"),
            json_body=payload,
            idempotency_key=idempotency_key or _fresh_idempotency("purge.entity"),
        )

    def purge_space(
        self, *, confirm: bool = False, idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Purge racine : TOUTE la memoire de l'espace. Exige ``confirm=True``."""
        if confirm is not True:
            raise ValueError("purge_space exige confirm=True")
        return self._request(
            "POST",
            self._path("/purge"),
            json_body={"confirmation": "PURGE"},
            idempotency_key=idempotency_key or _fresh_idempotency("purge.space"),
        )

    # -- SAWM Cloud ---------------------------------------------------------

    @staticmethod
    def _session_id(value: str, *, field: str) -> str:
        candidate = str(value or "").strip()
        if not _SESSION_ID_RE.fullmatch(candidate):
            raise ValueError(f"{field} invalide (8 a 128 caracteres opaques)")
        return candidate

    @property
    def websocket_url(self) -> str:
        """URL ``wss://`` du canal temps reel derivee de ``base_url``."""
        parsed = urlsplit(self.base_url)
        scheme = "wss" if parsed.scheme == "https" else "ws"
        return urlunsplit((scheme, parsed.netloc, SAWM_WEBSOCKET_PATH, "", ""))

    def open_session(
        self, session_id: str, *, entity_id: str | None = None,
    ) -> dict[str, Any]:
        """``POST /spaces/{space}/sawm/sessions`` : ticket a usage unique.

        Le ticket lie la cle, le principal, l'espace, l'entite et la version
        de politique ; il sert a ``respond_ws``. Le repli ``respond_sse`` n'en
        a pas besoin.
        """
        payload: dict[str, Any] = {
            "session_id": self._session_id(session_id, field="session_id"),
        }
        self._with_entity(payload, entity_id)
        receipt = self._request(
            "POST", self._path("/sawm/sessions"), json_body=payload,
        )
        if not str(receipt.get("ticket") or ""):
            raise BasiraError(502, "invalid_session_receipt")
        return receipt

    def respond_sse(
        self,
        session_id: str,
        turn_id: str,
        message: str,
        *,
        entity_id: str | None = None,
        max_output_tokens: int = 1024,
    ) -> Iterator[dict[str, Any]]:
        """``POST /spaces/{space}/sawm/responses`` en flux SSE.

        Generateur d'evenements dans l'ordre du contrat : ``turn.accepted``,
        zero ou plusieurs ``response.delta``, ``memory.committed``,
        ``usage.final``, ``turn.done``. Un ``turn.error`` est terminal et
        est leve en ``BasiraError``. Seul ``turn.done`` prouve que le depot,
        le quota et l'audit sont durables ; le ``job_id`` de
        ``memory.committed`` peut encore etre ``pending``.

        Les refus transitoires AVANT le flux sont rejoues. Une coupure ou un
        delai de lecture (``stream_timeout``) PENDANT le flux leve
        ``BasiraError(0, "stream_interrupted")`` sans rejeu : les deltas deja
        rendus restent provisoires ; rejouez l'appel avec le meme ``turn_id``,
        le service rend alors le recu idempotent du tour.
        """
        normalized_message = str(message or "")
        if not normalized_message or len(normalized_message) > 131_072:
            raise ValueError("message doit contenir entre 1 et 131072 caracteres")
        if isinstance(max_output_tokens, bool) or not 1 <= int(max_output_tokens) <= 32_768:
            raise ValueError("max_output_tokens dans [1, 32768]")
        payload: dict[str, Any] = {
            "session_id": self._session_id(session_id, field="session_id"),
            "turn_id": self._session_id(turn_id, field="turn_id"),
            "message": normalized_message,
            "max_output_tokens": int(max_output_tokens),
        }
        self._with_entity(payload, entity_id)
        headers = self._headers(
            accept="text/event-stream", has_body=True, idempotency_key=None,
        )
        stream_timeout = httpx.Timeout(
            connect=self.timeout, write=self.timeout, pool=self.timeout,
            read=self.stream_timeout,
        )
        attempt = 0
        while True:
            try:
                stream = self._http.stream(
                    "POST",
                    self.base_url + self._path("/sawm/responses"),
                    headers=headers,
                    json=payload,
                    timeout=stream_timeout,
                )
                response = stream.__enter__()
            except httpx.TransportError as exc:
                raise BasiraError(0, "transport_error", retryable=True) from exc
            try:
                content_type = (response.headers.get("Content-Type") or "").lower()
                if (
                    response.status_code >= 400
                    or not content_type.startswith("text/event-stream")
                ):
                    response.read()
                    error = _error_from_response(response)
                    if (
                        (error.status, error.code) in RETRYABLE_ERRORS
                        and attempt < self.max_retries
                    ):
                        attempt += 1
                        stream.__exit__(None, None, None)
                        self._sleep(_retry_delay(response, attempt))
                        continue
                    raise error
                try:
                    for event in _iter_sse(response.iter_lines()):
                        if event.get("type") == "turn.error":
                            raise BasiraError(
                                502, str(event.get("code") or "turn_error"),
                                retryable=bool(event.get("retryable")),
                            )
                        yield event
                except httpx.TransportError as exc:
                    # Coupure ou delai de lecture en cours de flux : le tour
                    # est peut-etre deja engage cote service, on ne rejoue
                    # pas a l'aveugle (meme turn_id -> recu idempotent).
                    raise BasiraError(
                        0, "stream_interrupted", retryable=False,
                    ) from exc
                return
            finally:
                stream.__exit__(None, None, None)

    def respond(
        self,
        session_id: str,
        turn_id: str,
        message: str,
        *,
        entity_id: str | None = None,
        max_output_tokens: int = 1024,
    ) -> dict[str, Any]:
        """Tour SAWM Cloud consomme jusqu'a ``turn.done`` ; texte assemble.

        Rend ``{"text", "done", "memory", "usage", "events"}``. Leve
        ``BasiraError(502, "turn_incomplete")`` si le flux se termine sans
        ``turn.done`` : les deltas recus restent provisoires.
        """
        events = list(self.respond_sse(
            session_id, turn_id, message,
            entity_id=entity_id, max_output_tokens=max_output_tokens,
        ))
        done = next((e for e in events if e.get("type") == "turn.done"), None)
        if done is None:
            raise BasiraError(502, "turn_incomplete")
        return {
            "text": "".join(
                str(e.get("delta") or "")
                for e in events if e.get("type") == "response.delta"
            ),
            "done": done,
            "memory": next(
                (e for e in events if e.get("type") == "memory.committed"), None,
            ),
            "usage": next(
                (e for e in events if e.get("type") == "usage.final"), None,
            ),
            "events": events,
        }

    def respond_ws(
        self,
        ticket: str,
        turn_id: str,
        message: str,
        *,
        max_output_tokens: int = 1024,
        websocket_url: str | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Tour SAWM Cloud par WebSocket (``websockets`` requis).

        Envoie ``{"type":"auth","ticket":...}`` puis, sur ``session.ready``,
        une frame ``turn.start``. Rend les memes evenements que
        ``respond_sse``. Sans la dependance ``websockets`` :
        ``BasiraError(0, "websocket_dependency_missing")``. Si la bordure ne
        monte pas en protocole (404 a l'ouverture), utilisez ``respond_sse``,
        qui offre les memes garanties.

        Chaque trame est attendue jusqu'a ``stream_timeout`` ; une fermeture
        ou un delai en cours de flux leve ``BasiraError(0,
        "stream_interrupted")`` sans rejeu (meme ``turn_id`` -> recu
        idempotent). Le ticket etant a usage unique, rouvrez une session
        avant de rejouer par WebSocket.
        """
        if _ws_connect is None:
            raise BasiraError(0, "websocket_dependency_missing")
        normalized_ticket = str(ticket or "").strip()
        if not re.fullmatch(r"^[A-Za-z0-9_-]{32,128}$", normalized_ticket):
            raise ValueError("ticket invalide")
        normalized_message = str(message or "")
        if not normalized_message or len(normalized_message) > 131_072:
            raise ValueError("message doit contenir entre 1 et 131072 caracteres")
        turn_frame = {
            "type": "turn.start",
            "turn_id": self._session_id(turn_id, field="turn_id"),
            "message": normalized_message,
            "max_output_tokens": int(max_output_tokens),
        }
        url = websocket_url or self.websocket_url
        if urlsplit(url).scheme != "wss" and urlsplit(url).hostname not in {
            "127.0.0.1", "localhost", "::1",
        }:
            raise ValueError("le ticket ne voyage qu'en wss hors loopback")
        try:
            connection = _ws_connect(
                url,
                subprotocols=[SAWM_SUBPROTOCOL],
                additional_headers={"User-Agent": USER_AGENT},
                open_timeout=self.timeout,
                max_size=256 * 1024,
            )
        except Exception as exc:  # noqa: BLE001 - handshake refuse ou reseau
            raise BasiraError(0, "websocket_open_failed", retryable=True) from exc
        with connection as ws:
            ws.send(json.dumps({"type": "auth", "ticket": normalized_ticket}))
            while True:
                try:
                    raw = ws.recv(timeout=self.stream_timeout)
                except Exception as exc:  # noqa: BLE001 - fermeture ou delai
                    raise BasiraError(
                        0, "stream_interrupted", retryable=False,
                    ) from exc
                try:
                    event = json.loads(raw)
                except ValueError:
                    raise BasiraError(502, "invalid_ws_payload") from None
                if not isinstance(event, dict):
                    raise BasiraError(502, "invalid_ws_payload")
                kind = event.get("type")
                if kind == "turn.error":
                    raise BasiraError(
                        502, str(event.get("code") or "turn_error"),
                        retryable=bool(event.get("retryable")),
                    )
                yield event
                if kind == "session.ready":
                    ws.send(json.dumps(turn_frame))
                elif kind == "turn.done":
                    return


def _iter_sse(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
    """Analyse un flux ``text/event-stream`` en dictionnaires JSON."""
    event_name: str | None = None
    data_lines: list[str] = []

    def flush() -> dict[str, Any] | None:
        if not data_lines:
            return None
        try:
            event = json.loads("\n".join(data_lines))
        except ValueError:
            raise BasiraError(502, "invalid_sse_payload") from None
        if not isinstance(event, dict):
            raise BasiraError(502, "invalid_sse_payload")
        event.setdefault("type", event_name or "message")
        return event

    for raw in lines:
        line = raw.rstrip("\r\n")
        if not line:
            event = flush()
            event_name, data_lines = None, []
            if event is not None:
                yield event
            continue
        if line.startswith(":"):
            continue
        name, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]
        if name == "event":
            event_name = value
        elif name == "data":
            data_lines.append(value)
    event = flush()
    if event is not None:
        yield event


# ---------------------------------------------------------------------------
# Console (control plane du compte)
# ---------------------------------------------------------------------------


class BasiraConsole(_Http):
    """Control plane du compte : environnements, principals, grants, cles.

    :param account_jwt: le JWT obtenu par la connexion au compte Basira
        (``https://basira.sawm.io/connexion``, ou le jeton de session que la
        console web porte apres connexion). Ce n'est PAS une cle de service
        ``bsr_*`` : une cle data plane est refusee ici (``401``), et
        inversement le JWT n'ouvre jamais le data plane. Le JWT expire ;
        reconnectez-vous pour en obtenir un nouveau.

    Chaque mutation exige une ``Idempotency-Key`` ; sans cle explicite, le
    client en derive une du contenu de la requete.
    """

    def __init__(
        self,
        account_jwt: str,
        *,
        base_url: str = DEFAULT_CONSOLE_URL,
        timeout: float = 30.0,
        max_retries: int = 2,
        http_client: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        super().__init__(
            base_url=base_url,
            bearer=account_jwt,
            timeout=timeout,
            max_retries=max_retries,
            http_client=http_client,
            sleep=sleep,
        )

    def __repr__(self) -> str:
        return f"BasiraConsole(base_url={self.base_url!r}, jwt=<masque>)"

    @staticmethod
    def _space(value: str) -> str:
        candidate = str(value or "").strip()
        if not _SPACE_ID_RE.fullmatch(candidate):
            raise ValueError("memory_space_id invalide")
        return candidate

    @staticmethod
    def _principal(value: str) -> str:
        candidate = str(value or "").strip()
        if not _PRINCIPAL_ID_RE.fullmatch(candidate):
            raise ValueError("principal_id invalide (prn_ + 32 hex)")
        return candidate

    @staticmethod
    def _scopes(value: Sequence[str] | None) -> list[str] | None:
        if value is None:
            return None
        scopes = [str(item) for item in value]
        unknown = set(scopes) - set(SCOPES)
        if unknown or len(set(scopes)) != len(scopes):
            raise ValueError(f"portees inconnues ou dupliquees : {sorted(unknown)}")
        return scopes

    @staticmethod
    def _page(limit: int, after: str) -> dict[str, Any]:
        if isinstance(limit, bool) or not 1 <= int(limit) <= 200:
            raise ValueError("limit doit etre compris entre 1 et 200")
        params: dict[str, Any] = {"limit": int(limit)}
        if after:
            params["after"] = str(after)[:36]
        return params

    # -- compte -------------------------------------------------------------

    def overview(self) -> dict[str, Any]:
        """``GET /console/overview`` : environnements, capacite, plans, limites."""
        return self._request("GET", "/overview")

    def plans(self) -> dict[str, Any]:
        """``GET /console/plans`` : catalogue des plans techniques."""
        return self._request("GET", "/plans")

    def capacity(self) -> dict[str, Any]:
        """``GET /console/capacity`` : capacite du compte et changements."""
        return self._request("GET", "/capacity")

    def usage_analytics(self, *, days: int = 30) -> dict[str, Any]:
        """``GET /console/usage/analytics?days=`` : usage agrege, sans contenu."""
        if isinstance(days, bool) or not 1 <= int(days) <= 90:
            raise ValueError("days doit etre compris entre 1 et 90")
        return self._request("GET", "/usage/analytics", params={"days": int(days)})

    def create_environment(
        self, name: str, *, idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """``POST /console/environments`` : un nouvel espace memoire facturable."""
        normalized = str(name or "").strip()
        if not normalized or len(normalized) > 160:
            raise ValueError("name doit contenir entre 1 et 160 caracteres")
        payload = {"name": normalized}
        return self._request(
            "POST", "/environments", json_body=payload,
            idempotency_key=idempotency_key
            or _derived_idempotency("environment.create", payload),
        )

    # -- principals et grants -----------------------------------------------

    def create_principal(
        self,
        memory_space_id: str,
        *,
        kind: str,
        name: str,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """``POST /console/spaces/{space}/principals`` (``agent`` ou ``service``)."""
        if kind not in {"agent", "service"}:
            raise ValueError("kind doit valoir agent ou service")
        normalized = str(name or "").strip()
        if not normalized or len(normalized) > 160:
            raise ValueError("name doit contenir entre 1 et 160 caracteres")
        space = self._space(memory_space_id)
        payload = {"kind": kind, "name": normalized}
        return self._request(
            "POST", f"/spaces/{space}/principals", json_body=payload,
            idempotency_key=idempotency_key
            or _derived_idempotency("principal.create", {"space": space, **payload}),
        )

    def list_principals(
        self, memory_space_id: str, *, limit: int = 50, after: str = "",
    ) -> dict[str, Any]:
        """``GET /console/spaces/{space}/principals`` (page + ``next_cursor``)."""
        return self._request(
            "GET", f"/spaces/{self._space(memory_space_id)}/principals",
            params=self._page(limit, after),
        )

    def create_grant(
        self,
        memory_space_id: str,
        *,
        principal_id: str,
        resource_kind: str,
        resource_id: str,
        permissions: Sequence[str],
        expires_at: datetime | str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """``POST /console/spaces/{space}/grants``.

        ``resource_kind`` vaut ``root`` (la racine et toutes ses entites) ou
        ``entity`` (une seule entite ``ent_...``). ``permissions`` parmi
        ``read``, ``write``, ``admin`` ; ``admin`` couvre aussi read/write.
        """
        if resource_kind not in {"root", "entity"}:
            raise ValueError("resource_kind doit valoir root ou entity")
        perms = [str(item) for item in permissions]
        if not perms or set(perms) - {"read", "write", "admin"} or len(set(perms)) != len(perms):
            raise ValueError("permissions parmi read, write, admin")
        space = self._space(memory_space_id)
        resource = str(resource_id or "").strip()
        if not resource or len(resource) > 160:
            raise ValueError("resource_id invalide")
        if resource_kind == "entity" and not _ENTITY_ID_RE.fullmatch(resource):
            raise ValueError("resource_id d'un grant entity doit etre un ent_")
        payload: dict[str, Any] = {
            "principal_id": self._principal(principal_id),
            "resource_kind": resource_kind,
            "resource_id": resource,
            "permissions": perms,
        }
        if expires_at is not None:
            payload["expires_at"] = (
                expires_at.isoformat() if isinstance(expires_at, datetime)
                else str(expires_at)
            )
        return self._request(
            "POST", f"/spaces/{space}/grants", json_body=payload,
            idempotency_key=idempotency_key
            or _derived_idempotency("grant.create", {"space": space, **payload}),
        )

    def list_grants(
        self, memory_space_id: str, *, limit: int = 50, after: str = "",
    ) -> dict[str, Any]:
        """``GET /console/spaces/{space}/grants`` (page + ``next_cursor``)."""
        return self._request(
            "GET", f"/spaces/{self._space(memory_space_id)}/grants",
            params=self._page(limit, after),
        )

    def revoke_grant(self, grant_id: str) -> dict[str, Any]:
        """``DELETE /console/grants/{grant_id}`` : la politique change aussitot."""
        candidate = str(grant_id or "").strip()
        if not re.fullmatch(r"^grt_[0-9a-f]{32}$", candidate):
            raise ValueError("grant_id invalide (grt_ + 32 hex)")
        return self._request("DELETE", f"/grants/{candidate}")

    # -- cles ---------------------------------------------------------------

    def create_key(
        self,
        memory_space_id: str,
        *,
        principal_id: str,
        scopes: Sequence[str] | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """``POST /console/spaces/{space}/keys`` : une cle de service.

        Le secret ``bsr_*`` n'est rendu qu'une fois, dans cette reponse.
        Sans ``scopes``, le service applique les portees par defaut.
        """
        space = self._space(memory_space_id)
        payload: dict[str, Any] = {"principal_id": self._principal(principal_id)}
        normalized_scopes = self._scopes(scopes)
        if normalized_scopes is not None:
            payload["scopes"] = normalized_scopes
        return self._request(
            "POST", f"/spaces/{space}/keys", json_body=payload,
            idempotency_key=idempotency_key
            or _derived_idempotency("key.create", {"space": space, **payload}),
        )

    def rotate_key(
        self,
        key_id: str,
        *,
        scopes: Sequence[str] | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """``POST /console/keys/{key_id}/rotate`` : nouveau secret, meme principal."""
        candidate = str(key_id or "").strip()
        if not _OPAQUE_ID_RE.fullmatch(candidate):
            raise ValueError("key_id invalide")
        payload: dict[str, Any] = {}
        normalized_scopes = self._scopes(scopes)
        if normalized_scopes is not None:
            payload["scopes"] = normalized_scopes
        return self._request(
            "POST", f"/keys/{candidate}/rotate", json_body=payload,
            idempotency_key=idempotency_key
            or _fresh_idempotency("key.rotate"),
        )

    def revoke_key(self, key_id: str) -> dict[str, Any]:
        """``DELETE /console/keys/{key_id}`` : revocation immediate."""
        candidate = str(key_id or "").strip()
        if not _OPAQUE_ID_RE.fullmatch(candidate):
            raise ValueError("key_id invalide")
        return self._request("DELETE", f"/keys/{candidate}")

    # -- entites et usage ---------------------------------------------------

    def create_entity(
        self,
        memory_space_id: str,
        *,
        entity_type: str,
        name: str,
        description: str = "",
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """``POST /console/spaces/{space}/entities`` depuis le compte."""
        if entity_type not in ENTITY_TYPES:
            raise ValueError("entity_type non supporte")
        normalized = str(name or "").strip()
        if not normalized or len(normalized) > 160:
            raise ValueError("name doit contenir entre 1 et 160 caracteres")
        space = self._space(memory_space_id)
        payload = {
            "entity_type": entity_type, "name": normalized,
            "description": str(description),
        }
        return self._request(
            "POST", f"/spaces/{space}/entities", json_body=payload,
            idempotency_key=idempotency_key
            or _derived_idempotency("entity.create", {"space": space, **payload}),
        )

    def entities(
        self, memory_space_id: str, *, limit: int = 50, after: str = "",
    ) -> dict[str, Any]:
        """``GET /console/spaces/{space}/entities`` (page + ``next_cursor``)."""
        return self._request(
            "GET", f"/spaces/{self._space(memory_space_id)}/entities",
            params=self._page(limit, after),
        )

    def usage(self, memory_space_id: str) -> dict[str, Any]:
        """``GET /console/spaces/{space}/usage`` : lecture du compteur public.

        ``unlimited: true`` accompagne ``monthly_limit: null`` pour un compte
        sans plafond mensuel. Les compteurs d'usage et limites de concurrence
        restent presents. Les champs sont preserves, sans modification du quota.
        """
        return self._request("GET", f"/spaces/{self._space(memory_space_id)}/usage")


__all__ = [
    "AbstractPosition",
    "BasiraClient",
    "BasiraConsole",
    "BasiraError",
    "Candidate",
    "CartesianPosition",
    "CoordinatePosition",
    "DEFAULT_BASE_URL",
    "DEFAULT_CONSOLE_URL",
    "Epistemic",
    "PhysicalPosition",
    "SCOPES",
    "Semantic",
    "Spatial",
    "Temporal",
    "USER_AGENT",
    "Weights",
    "__version__",
]

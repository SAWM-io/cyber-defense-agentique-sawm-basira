"""Trace chaque tentative HTTP du SDK, sans modifier sa copie publique.

Un evenement final par requete reelle, y compris les polls et reprises internes
du SDK. Le statut HTTP reste celui du serveur : une erreur SSE sur HTTP 200
porte ``resultat=stream_error``, jamais un faux statut HTTP 502.
Seules des metadonnees autorisees quittent cet adaptateur. Aucun corps, header,
URL complete, texte du modele ou message d'exception n'est journalise.
"""

from __future__ import annotations

import contextvars
import hashlib
import json
import math
import os
import pathlib
import re
import threading
import time
import uuid
from collections import OrderedDict
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Callable, Iterator, Mapping
from urllib.parse import urlsplit

import httpx

_MAX_FRAME = 262_144
_USAGE_FIELDS = frozenset({
    "input_tokens", "output_tokens", "total_tokens", "prompt_tokens",
    "completion_tokens", "units", "charged_units", "reserved_units",
    "used_units", "remaining_units", "monthly_units", "charged_tokens",
    "cached_tokens", "reasoning_tokens", "input", "output", "total",
})
_TOKEN_ALIASES = {
    "jetons_entree": ("input_tokens", "prompt_tokens"),
    "jetons_sortie": ("output_tokens", "completion_tokens"),
    "jetons_total": ("total_tokens",),
}


class TelemetrieCloud:
    """JSONL local d'abord, publication loopback ensuite (echec non bloquant).

    Par defaut : ``~/.sawm-labo/cloud-appels.jsonl`` et
    ``http://127.0.0.1:8899/api/cloud``. Variables facultatives :
    ``SAWM_CLOUD_JOURNAL`` et ``SAWM_CLOUD_DASHBOARD_URL`` (vide = desactive).
    ``etat_publication`` expose les echecs des puits sans masquer les appels.
    """

    def __init__(self, run_id: str, *, journal: str | os.PathLike | None = None,
                 dashboard_url: str | None = None,
                 dashboard_client: httpx.Client | None = None,
                 post_evenement: Callable[[dict], None] | None = None,
                 secrets: tuple[str, ...] = ()) -> None:
        self._secrets = tuple(s for s in secrets if s)
        self.run_id = self.identifiant(run_id)
        self.journal = pathlib.Path(journal or os.getenv(
            "SAWM_CLOUD_JOURNAL", "~/.sawm-labo/cloud-appels.jsonl")).expanduser()
        self.dashboard_url = (os.getenv("SAWM_CLOUD_DASHBOARD_URL",
            "http://127.0.0.1:8899/api/cloud") if dashboard_url is None else dashboard_url)
        if self.dashboard_url:
            url = urlsplit(self.dashboard_url)
            if (url.scheme not in {"http", "https"}
                    or url.hostname not in {"127.0.0.1", "localhost", "::1"}
                    or url.username or url.password or url.query or url.fragment):
                raise ValueError("le collecteur de telemetrie doit etre sur loopback")
        self._owns_dashboard = dashboard_client is None
        self.post_evenement = post_evenement
        self._dashboard = dashboard_client or httpx.Client(
            timeout=0.3, trust_env=False, follow_redirects=False)
        self._lock = threading.RLock()
        self._context = contextvars.ContextVar(f"cloud_{id(self)}", default=None)
        self._direct: OrderedDict[str, int] = OrderedDict()
        self._salt = uuid.uuid4().hex
        self.appels: list[dict[str, Any]] = []
        self.etat_publication = {"journal_echecs": 0, "dashboard_echecs": 0,
                                 "dashboard_publies": 0, "callback_echecs": 0}

    def proteger(self, secret: str) -> None:
        if secret:
            self._secrets = (*self._secrets, secret)

    def _sur(self, value: str) -> bool:
        return (not any(s in value for s in self._secrets)
                and not re.search(r"bsr_|bearer|sk-|swpk_|password|secret|token=",
                                  value, re.IGNORECASE))

    def identifiant(self, value: Any) -> str:
        text = str(value)
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", text) and self._sur(text):
            return text
        return "id_" + hashlib.sha256(text.encode()).hexdigest()[:24]

    def code(self, value: Any, default: str = "api_error") -> str:
        text = str(value or "")
        if re.fullmatch(r"[a-z][a-z0-9_]{0,95}", text) and self._sur(text):
            return text
        return default

    @contextmanager
    def operation(self, nom: str, **identifiants: str) -> Iterator[dict]:
        state = {"correlation_id": uuid.uuid4().hex, "tentative": 0,
                 **{k: self.identifiant(v) for k, v in identifiants.items()
                    if k in {"turn_id", "decision_id", "incident_id"}}}
        token = self._context.set(state)
        try:
            yield state
        finally:
            self._context.reset(token)

    def commencer(self, method: str, url: str, kwargs: Mapping[str, Any]) -> dict:
        path = urlsplit(url).path
        suffix = path.split("/spaces/", 1)[-1].split("/", 1)[-1]
        if suffix.startswith("jobs/"):
            appel = "jobs:read"
        elif suffix.startswith("entities/"):
            appel = "entities:delete" if method.upper() == "DELETE" else "entities"
        elif suffix in {"entities", "entities:batch", "events:batch", "assertions",
                        "recall", "recall:tsst", "odvl:rank", "odvl:observe",
                        "odvl:stimulate", "usage", "purge", "sawm/sessions",
                        "sawm/responses"}:
            appel = suffix.replace("sawm/", "sawm:")
        else:
            appel = "cloud:request"
        state = self._context.get()
        with self._lock:
            if state is None:
                # Le SDK peut etre appele directement : les reprises gardent
                # leur correlation sans publier corps ni cle d'idempotence.
                identity = json.dumps([self._salt, method, url,
                    dict(kwargs.get("headers") or {}).get("Idempotency-Key"),
                    kwargs.get("json"), kwargs.get("params")],
                    sort_keys=True, default=lambda _: "<opaque>")
                correlation = hashlib.sha256(identity.encode()).hexdigest()[:32]
                attempt = self._direct.get(correlation, 0) + 1
                self._direct[correlation] = attempt
                self._direct.move_to_end(correlation)
                if len(self._direct) > 2048:
                    self._direct.popitem(last=False)
                state = {"correlation_id": correlation, "tentative": attempt}
            else:
                state["tentative"] += 1
            now = time.time()
            return {"schema": "sawm-lab-cloud-call/v1", "event_id": uuid.uuid4().hex,
                    "heure": datetime.fromtimestamp(now, timezone.utc).isoformat(),
                    "mur_epoch_ms": int(now * 1000), "run_id": self.run_id,
                    **state, "appel": appel, "methode": method.upper(),
                    "statut": None, "phase": "http", "resultat": "transport_error"}

    def usage(self, body: Mapping, event: dict, *, usage_event: bool = False) -> None:
        sources = []
        if usage_event:
            sources.append(body)
        for key in ("usage", "billing", "tokens"):
            if isinstance(body.get(key), dict):
                sources.append(body[key])
                if isinstance(body[key].get("tokens"), dict):
                    sources.append(body[key]["tokens"])
        numeric = dict(event.get("usage") or {})
        for source in sources:
            for key in _USAGE_FIELDS:
                value = source.get(key)
                if (isinstance(value, (int, float)) and not isinstance(value, bool)
                        and 0 <= value <= 10**15 and math.isfinite(value)):
                    numeric[key] = value
        if numeric:
            event["usage"] = numeric
            for target, names in _TOKEN_ALIASES.items():
                for name in names:
                    value = numeric.get(name)
                    if isinstance(value, int):
                        event[target] = value
                        break

    def publier(self, event: dict, started: float) -> None:
        event["ms"] = round((time.monotonic() - started) * 1000, 3)
        line = (json.dumps(event, ensure_ascii=False, allow_nan=False) + "\n").encode()
        with self._lock:
            self.appels.append(dict(event))
            try:
                self.journal.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
                flags |= getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(self.journal, flags, 0o600)
                with os.fdopen(fd, "ab") as out:
                    os.fchmod(out.fileno(), 0o600)
                    out.write(line)
                    out.flush()
            except OSError:
                self.etat_publication["journal_echecs"] += 1
            if self.dashboard_url:
                try:
                    response = self._dashboard.post(self.dashboard_url, json=event)
                    response.raise_for_status()
                    self.etat_publication["dashboard_publies"] += 1
                except (httpx.HTTPError, OSError):
                    self.etat_publication["dashboard_echecs"] += 1
            if self.post_evenement is not None:
                try:
                    self.post_evenement(json.loads(line))
                except Exception:
                    self.etat_publication["callback_echecs"] += 1

    def close(self) -> None:
        if self._owns_dashboard:
            self._dashboard.close()

    def republier_journal(self, *, run_id: str | None = None, limite: int = 1000) -> dict:
        """Republie explicitement la fin du JSONL vers le collecteur revenu.

        Aucun appel Cloud, aucune nouvelle ligne JSONL, aucun nouvel event_id.
        Le collecteur deduplique les evenements deja recus. Par defaut, seul
        ce run est repris, au plus 1000 lignes parmi les 8 derniers Mio. Une
        erreur de publication arrete la reprise ; rappeler la methode est sur.
        Le bilan signale toute troncature, sans pretendre avoir tout rejoue.
        """
        if isinstance(limite, bool) or not isinstance(limite, int) or not 1 <= limite <= 10_000:
            raise ValueError("limite de republication attendue entre 1 et 10000")
        wanted = self.identifiant(run_id) if run_id is not None else self.run_id
        bilan = {"run_id": wanted, "lus": 0, "publies": 0, "echecs": 0,
                 "ignores": 0, "tronque": False, "dashboard_actif": bool(self.dashboard_url)}
        if not self.dashboard_url:
            return bilan
        fields = {"schema", "event_id", "heure", "mur_epoch_ms", "run_id",
                  "correlation_id", "tentative", "appel", "methode", "statut",
                  "phase", "resultat", "ms", "code", "usage", "jetons_entree",
                  "jetons_sortie", "jetons_total", "job_statut", "terminal",
                  "replayed", "turn_id", "decision_id", "incident_id"}
        with self._lock:
            try:
                fd = os.open(self.journal, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                with os.fdopen(fd, "rb") as source:
                    start = max(0, os.fstat(source.fileno()).st_size - 8 * 1024 * 1024)
                    source.seek(start)
                    if start:
                        source.readline()  # La premiere ligne peut etre tronquee.
                        bilan["tronque"] = True
                    lines = source.read(8 * 1024 * 1024).splitlines()
            except FileNotFoundError:
                return bilan
            except OSError:
                bilan["echecs"] = 1
                self.etat_publication["journal_echecs"] += 1
                return bilan
            events = []
            for line in lines:
                try:
                    event = json.loads(line)
                except (ValueError, UnicodeDecodeError):
                    bilan["ignores"] += 1
                    continue
                if not isinstance(event, dict) or event.get("run_id") != wanted:
                    continue
                bilan["lus"] += 1
                # Le secours ne devient pas une voie de publication de corps
                # libres : on n'accepte que notre enveloppe sans champ inconnu.
                if (set(event) - fields or event.get("schema") != "sawm-lab-cloud-call/v1"
                        or not re.fullmatch(r"[0-9a-f]{32}", str(event.get("event_id", "")))
                        or not self._sur(json.dumps(event, ensure_ascii=False))):
                    bilan["ignores"] += 1
                    continue
                events.append(event)
            if len(events) > limite:
                bilan["tronque"] = True
            for event in events[-limite:]:
                try:
                    response = self._dashboard.post(self.dashboard_url, json=event)
                    response.raise_for_status()
                except (httpx.HTTPError, OSError, ValueError):
                    bilan["echecs"] += 1
                    self.etat_publication["dashboard_echecs"] += 1
                    break
                bilan["publies"] += 1
                self.etat_publication["dashboard_publies"] += 1
        return bilan


def _json_metadata(response: httpx.Response, event: dict, telemetry: TelemetrieCloud) -> None:
    if len(response.content) > _MAX_FRAME:
        return
    try:
        body = response.json()
    except ValueError:
        if response.status_code < 400:
            event.update(resultat="http_error", code="invalid_json_response")
        return
    if not isinstance(body, dict):
        if response.status_code < 400:
            event.update(resultat="http_error", code="invalid_json_response")
        return
    telemetry.usage(body, event)
    if response.status_code >= 400:
        detail = body.get("detail")
        event["code"] = telemetry.code(detail.get("code") if isinstance(detail, dict)
                                        else None, "http_error")
    status = body.get("status")
    if isinstance(status, str) and status in {"pending", "processing", "completed", "dead_letter"}:
        event["job_statut"] = status


class _ObservedSSE:
    """Proxy de reponse : inspecte les lignes DECODEES, meme avec gzip/UTF-8."""

    def __init__(self, response: httpx.Response, event: dict, telemetry: TelemetrieCloud):
        self._response, self.event, self.telemetry = response, event, telemetry
        self._data: list[str] = []
        self._size = 0
        self._event_name: str | None = None

    def __getattr__(self, key: str):
        return getattr(self._response, key)

    def _frame(self) -> None:
        had_data = bool(self._data)
        try:
            body = json.loads("\n".join(self._data)) if self._data else None
        except ValueError:
            body = None
        self._data, self._size = [], 0
        event_name, self._event_name = self._event_name, None
        if not isinstance(body, dict):
            if had_data:
                self.event.update(resultat="stream_error", code="invalid_sse_payload")
            return
        typ = body.get("type", event_name)
        if typ == "usage.final":
            self.telemetry.usage(body, self.event, usage_event=True)
        elif typ == "turn.done":
            self.event.update(terminal=typ, resultat="ok")
            if isinstance(body.get("replayed"), bool):
                self.event["replayed"] = body["replayed"]
        elif typ == "turn.error":
            self.event.update(terminal=typ, resultat="stream_error",
                              code=self.telemetry.code(body.get("code")))

    def iter_lines(self):
        try:
            for line in self._response.iter_lines():
                if not line:
                    self._frame()
                elif line.startswith("event:"):
                    self._event_name = line[6:].lstrip(" ")
                elif line.startswith("data:"):
                    self._size += len(line)
                    if self._size <= _MAX_FRAME:
                        self._data.append(line[5:].lstrip(" "))
                    else:
                        self._data.clear()
                yield line
            self._frame()
        except httpx.TransportError:
            # Le SDK appelle __exit__(None, None, None) meme apres son propre
            # catch : capturer ici l'erreur de lecture avant cette conversion.
            self.event.update(resultat="stream_error", code="stream_interrupted")
            raise


class ClientHTTPObserve:
    """Interface ``http_client`` du SDK : chaque .request/.stream est trace.

    L'injection documentee du SDK permet de garder vendor strictement intact.
    Le proxy SSE ne modifie ni ne consomme les donnees avant le SDK.
    """

    def __init__(self, telemetry: TelemetrieCloud, client: httpx.Client | None = None):
        self.telemetry = telemetry
        self._owns_client = client is None
        self._client = client or httpx.Client()

    def request(self, method: str, url: str, **kwargs):
        event = self.telemetry.commencer(method, url, kwargs)
        started = time.monotonic()
        try:
            # En passant par stream, le statut reste connu meme si la lecture
            # JSON echoue apres reception des en-tetes.
            with self._client.stream(method, url, **kwargs) as response:
                event["statut"] = response.status_code
                event["resultat"] = "http_error" if response.status_code >= 400 else "ok"
                response.read()
                _json_metadata(response, event, self.telemetry)
                return response
        except httpx.TransportError as exc:
            event.update(resultat="transport_error", code=type(exc).__name__)
            raise
        finally:
            self.telemetry.publier(event, started)

    @contextmanager
    def stream(self, method: str, url: str, **kwargs):
        event = self.telemetry.commencer(method, url, kwargs)
        started = time.monotonic()
        response = None
        try:
            with self._client.stream(method, url, **kwargs) as response:
                event["statut"] = response.status_code
                is_sse = (response.status_code < 400 and response.headers.get(
                    "Content-Type", "").lower().startswith("text/event-stream"))
                event["phase"] = "sse" if is_sse else "http"
                event["resultat"] = "incomplete" if is_sse else "http_error"
                yield _ObservedSSE(response, event, self.telemetry) if is_sse else response
        except Exception as exc:
            if event["resultat"] != "http_error":
                event["resultat"] = "stream_error" if response is not None else "transport_error"
                # Les messages d'exception peuvent contenir URL/corps/secret.
                event["code"] = self.telemetry.code(getattr(exc, "code", None),
                    "stream_interrupted" if response is not None else "transport_error")
            raise
        finally:
            if response is not None and response.is_stream_consumed and event["phase"] != "sse":
                _json_metadata(response, event, self.telemetry)
            if event["resultat"] == "incomplete":
                event["code"] = "turn_incomplete"
            self.telemetry.publier(event, started)

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

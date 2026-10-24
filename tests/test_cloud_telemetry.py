"""Contrats de telemetrie : vrais SDK + HTTP simule, aucun acces Cloud."""

from __future__ import annotations

import gzip
import json
import pathlib
import sys
import tempfile
import unittest

import httpx

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from connecteur.pont_memoire import PontMemoire, bc
from connecteur.telemetrie_cloud import TelemetrieCloud
from connecteur.tour_sawm import TourSawm
from connecteur.contrat import CONSIGNE_FORMAT, PropositionInvalide, lire_proposition
from controleur.collecteur import valider_evenement

KEY = "bsr_test_key-synthetic-never-log"
ENTITY = "ent_" + "a" * 32
JOB = "job_" + "b" * 32


class BrokenStream(httpx.SyncByteStream):
    def __iter__(self):
        yield b'data: {"type":"response.delta","delta":"secret-text"}\n\n'
        raise httpx.ReadError("unsafe exception " + KEY)


def sse(*events, compressed=False):
    payload = "".join("data: " + json.dumps(ev, ensure_ascii=False) + "\n\n"
                      for ev in events).encode()
    headers = {"Content-Type": "text/event-stream"}
    if compressed:
        payload = gzip.compress(payload)
        headers["Content-Encoding"] = "gzip"
    return httpx.Response(200, headers=headers, content=payload)


class CloudTelemetryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = pathlib.Path(self.tmp.name)
        self.journal = self.directory / "appels.jsonl"
        self.coffre = self.directory / "env"
        self.coffre.write_text(f"BASIRA_SPACE=mem_test\nBASIRA_ENTITY={ENTITY}\n"
                              f"BASIRA_KEY={KEY}\nBASIRA_BASE=https://cloud.invalid/api/v1/basira\n")
        self.coffre.chmod(0o600)
        self.published = []

    def make_pont(self, handler, *, dashboard=None):
        def collect(request):
            self.assertEqual(str(request.url), "http://127.0.0.1:8899/api/cloud")
            self.assertNotIn("authorization", request.headers)
            event = json.loads(request.content)
            self.assertEqual(valider_evenement("cloud", event), event)
            # Le secours est ecrit AVANT le POST.
            self.assertIn(event["event_id"], self.journal.read_text())
            self.published.append(event)
            return httpx.Response(200, json={"ok": True})

        cloud = httpx.Client(transport=httpx.MockTransport(handler))
        local = httpx.Client(transport=httpx.MockTransport(dashboard or collect))
        self.addCleanup(cloud.close)
        self.addCleanup(local.close)
        telemetry = TelemetrieCloud("run-test", journal=self.journal,
            dashboard_url="http://127.0.0.1:8899/api/cloud", dashboard_client=local)
        pont = PontMemoire(coffre=self.coffre, campagne="run-test", budget_rejeu=3,
                           telemetrie=telemetry, http_client=cloud)
        pont._client._sleep = lambda seconds: None
        pont._recall_client._sleep = lambda seconds: None
        self.addCleanup(pont.close)
        return pont

    def records(self):
        return [json.loads(line) for line in self.journal.read_text().splitlines()]

    def test_202_and_each_job_poll_are_automatically_published(self):
        calls = []
        def cloud(request):
            self.assertEqual(request.headers["Authorization"], "Bearer " + KEY)
            calls.append(request.url.path)
            if request.url.path.endswith("events:batch"):
                return httpx.Response(202, json={"job_id": JOB, "status": "pending"})
            return httpx.Response(200, json={"job_id": JOB,
                "status": "pending" if len(calls) == 2 else "completed"})
        pont = self.make_pont(cloud)
        result = pont.deposer([{"id": "obs-1", "contenu": "private input " + KEY}])
        rows = self.records()
        self.assertEqual(result["jobs"][0]["statut"], "completed")
        self.assertEqual([r["statut"] for r in rows], [202, 200, 200])
        self.assertEqual([r["appel"] for r in rows], ["events:batch", "jobs:read", "jobs:read"])
        self.assertEqual([r["tentative"] for r in rows], [1, 1, 2])
        self.assertEqual(rows[1]["correlation_id"], rows[2]["correlation_id"])
        self.assertNotEqual(rows[0]["correlation_id"], rows[1]["correlation_id"])
        self.assertEqual(len(pont.journal_appels), 3)
        self.assertEqual(rows, self.published)
        self.assertEqual(self.journal.stat().st_mode & 0o777, 0o600)
        for row in rows:
            self.assertEqual(row["run_id"], "run-test")
            self.assertGreater(row["mur_epoch_ms"], 0)
            self.assertGreaterEqual(row["ms"], 0)
            self.assertNotIn("usage", row)
            self.assertNotIn("jetons_total", row)
        self.assertNotIn(KEY, self.journal.read_text())
        self.assertNotIn("private input", self.journal.read_text())

    def test_sdk_retries_have_exact_http_status_and_shared_correlation(self):
        calls = []
        def cloud(request):
            calls.append(request.headers["Idempotency-Key"])
            if len(calls) == 1:
                return httpx.Response(503, json={"detail": {"code": "engine_unavailable"}})
            return httpx.Response(200, json={"evidence": [], "usage": {"input_tokens": 0,
                "output_tokens": 4, "total_tokens": 4, "secret": KEY}})
        pont = self.make_pont(cloud)
        result = pont.rappeler("secret query " + KEY)
        rows = self.records()
        self.assertEqual(result.tentatives, 2)
        self.assertEqual([r["statut"] for r in rows], [503, 200])
        self.assertEqual([r["tentative"] for r in rows], [1, 2])
        self.assertEqual(rows[0]["code"], "engine_unavailable")
        self.assertEqual(rows[0]["correlation_id"], rows[1]["correlation_id"])
        self.assertEqual(calls[0], calls[1])
        self.assertEqual(rows[1]["jetons_entree"], 0)
        self.assertEqual(rows[1]["jetons_total"], 4)
        self.assertNotIn(KEY, self.journal.read_text())

    def test_transport_failures_have_null_status_not_synthetic_http_code(self):
        def cloud(request):
            raise httpx.ConnectTimeout("unsafe " + KEY, request=request)
        pont = self.make_pont(cloud)
        pont._recall_client.max_retries = 1
        with self.assertRaises(bc.BasiraError):
            pont.rappeler("question")
        rows = self.records()
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r["statut"] is None for r in rows))
        self.assertEqual([r["tentative"] for r in rows], [1, 2])
        self.assertTrue(all(r["resultat"] == "transport_error" for r in rows))
        self.assertNotIn(KEY, self.journal.read_text())

    def test_sse_success_records_terminal_usage_and_ids_without_deltas(self):
        proposal = json.dumps({"action": "ne-rien-faire", "cible": None,
            "justification": "Aucun incident constate dans ce test.", "confiance": 0.6})
        pont = self.make_pont(lambda r: sse(
            {"type": "turn.accepted"}, {"type": "response.delta", "delta": proposal},
            {"type": "memory.committed", "job_id": JOB},
            {"type": "usage.final", "input_tokens": 12, "output_tokens": 3,
             "total_tokens": 15, "provider_usage": {"api_key": KEY}},
            {"type": "turn.done", "replayed": False}, compressed=True))
        decision = TourSawm(pont).jouer("private prompt " + KEY,
                                      cibles_autorisees=set(), turn_id="test-turn-01")
        self.assertTrue(decision.executable)
        row, = self.records()
        self.assertEqual(row["statut"], 200)
        self.assertEqual(row["phase"], "sse")
        self.assertEqual(row["terminal"], "turn.done")
        self.assertEqual(row["resultat"], "ok")
        self.assertEqual(row["jetons_total"], 15)
        self.assertEqual(row["turn_id"], "test-turn-01")
        self.assertEqual(row["decision_id"], decision.decision_id)
        self.assertNotIn("private prompt", self.journal.read_text())
        self.assertNotIn("justification", self.journal.read_text())
        self.assertNotIn(KEY, self.journal.read_text())

    def test_sse_turn_error_preserves_http_200_and_safe_api_code(self):
        pont = self.make_pont(lambda r: sse({"type": "turn.error",
            "code": "provider_timeout", "message": KEY, "retryable": True}))
        decision = TourSawm(pont).jouer("prompt", cibles_autorisees=set())
        self.assertFalse(decision.executable)
        row, = self.records()
        self.assertEqual((row["statut"], row["resultat"], row["terminal"]),
                         (200, "stream_error", "turn.error"))
        self.assertEqual(row["code"], "provider_timeout")
        self.assertNotIn(KEY, self.journal.read_text())

    def test_sse_interruption_and_missing_terminal_are_visible(self):
        for broken in (True, False):
            with self.subTest(broken=broken):
                if self.journal.exists():
                    self.journal.unlink()
                pont = self.make_pont(lambda r: httpx.Response(200,
                    headers={"Content-Type": "text/event-stream"}, stream=BrokenStream())
                    if broken else sse({"type": "response.delta", "delta": KEY}))
                decision = TourSawm(pont).jouer("prompt", cibles_autorisees=set())
                self.assertFalse(decision.executable)
                row, = self.records()
                self.assertEqual(row["statut"], 200)
                self.assertEqual(row["resultat"], "stream_error" if broken else "incomplete")
                self.assertNotIn("terminal", row)
                self.assertNotIn(KEY, self.journal.read_text())

    def test_sse_preflight_retry_records_each_attempt_once(self):
        count = 0
        def cloud(request):
            nonlocal count
            count += 1
            if count == 1:
                return httpx.Response(503, json={"detail": {"code": "sawm_cloud_unavailable"}})
            return sse({"type": "turn.done"})
        pont = self.make_pont(cloud)
        TourSawm(pont).jouer("prompt", cibles_autorisees=set())
        rows = self.records()
        self.assertEqual([r["statut"] for r in rows], [503, 200])
        self.assertEqual([r["tentative"] for r in rows], [1, 2])
        self.assertEqual(rows[0]["correlation_id"], rows[1]["correlation_id"])

    def test_unavailable_dashboard_keeps_local_receipt_and_response(self):
        def dashboard(request):
            raise httpx.ConnectError("local unavailable " + KEY, request=request)
        pont = self.make_pont(lambda r: httpx.Response(200, json={"available": False}),
                             dashboard=dashboard)
        result = pont.observer_vortex(["candidate-01"])
        self.assertFalse(result["available"])
        self.assertEqual(len(self.records()), 1)
        self.assertEqual(pont.telemetrie.etat_publication["dashboard_echecs"], 1)
        self.assertEqual(pont.telemetrie.etat_publication["journal_echecs"], 0)

    def test_direct_sdk_calls_also_publish_and_filter_hostile_error_codes(self):
        pont = self.make_pont(lambda r: httpx.Response(401,
            json={"detail": {"code": KEY, "message": KEY}}))
        with self.assertRaises(bc.BasiraError):
            pont._client.usage()
        row, = self.records()
        self.assertEqual(row["statut"], 401)
        self.assertEqual(row["code"], "http_error")
        self.assertNotIn(KEY, self.journal.read_text())

    def test_quota_is_not_retried_and_retry_budget_has_one_owner(self):
        for status, code, attempts in ((429, "monthly_quota_exceeded", 1),
                                        (503, "engine_unavailable", 4)):
            with self.subTest(code=code):
                if self.journal.exists():
                    self.journal.unlink()
                pont = self.make_pont(lambda r: httpx.Response(status,
                    json={"detail": {"code": code}}))
                pont._recall_client.max_retries = 3
                with self.assertRaises(bc.BasiraError):
                    pont.rappeler("question")
                self.assertEqual(len(self.records()), attempts)

    def test_interrupted_turn_can_resume_same_body_and_output_limit(self):
        bodies = []
        proposal = json.dumps({"action": "ne-rien-faire", "cible": None,
            "justification": "Aucun incident constate dans ce test.", "confiance": 0.6})
        def cloud(request):
            bodies.append(json.loads(request.content))
            if len(bodies) == 1:
                return sse({"type": "response.delta", "delta": "partial"})
            return sse({"type": "response.delta", "delta": proposal},
                       {"type": "turn.done", "replayed": True})
        pont = self.make_pont(cloud)
        tour = TourSawm(pont)
        first = tour.jouer("same prompt", cibles_autorisees=set(),
                           turn_id="turn-resume-test", max_tokens=321)
        self.assertFalse(first.executable)
        resumed = tour.reprendre(first, "same prompt", cibles_autorisees=set())
        self.assertTrue(resumed.executable)
        self.assertEqual(first.decision_id, resumed.decision_id)
        self.assertEqual(len(bodies), 2)
        self.assertEqual(bodies[0], bodies[1])
        self.assertEqual(bodies[1]["max_output_tokens"], 321)
        self.assertEqual(self.records()[1]["replayed"], True)
        with self.assertRaises(ValueError):
            tour.reprendre(first, "changed prompt", cibles_autorisees=set())
        with self.assertRaises(ValueError):
            tour.jouer("same prompt", cibles_autorisees=set(),
                        turn_id="turn-resume-test", max_tokens=600)
        self.assertEqual(len(bodies), 2)

    def test_flashback_uses_public_transaction_cutoff_and_callback_is_sanitized(self):
        bodies, callback_events = [], []
        def cloud(request):
            bodies.append(json.loads(request.content))
            return httpx.Response(200, json={"evidence": []})
        pont = self.make_pont(cloud)
        pont.telemetrie.post_evenement = callback_events.append
        pont.rappeler("secret " + KEY, avant_ms=12345)
        self.assertEqual(bodies[0]["temporal"], {"as_of_transaction_time_ms": 12345})
        self.assertEqual(callback_events, self.records())
        self.assertNotIn(KEY, json.dumps(callback_events))

    def test_unimplemented_action_and_untargeted_restore_are_rejected(self):
        base = {"justification": "Une justification assez detaillee.", "confiance": 0.7}
        for action, target, expected in (("isoler-service", "test.service", "action_inconnue"),
                                          ("restaurer-fixtures", None, "cible_absente"),
                                          ("restaurer-fixtures", "other", "cible_hors_manifeste")):
            with self.subTest(action=action, target=target):
                with self.assertRaises(PropositionInvalide) as result:
                    lire_proposition(json.dumps({**base, "action": action, "cible": target}),
                                     cibles_autorisees={"test.service"})
                self.assertEqual(result.exception.motif, expected)
        self.assertNotIn("isoler-service", CONSIGNE_FORMAT)

    def test_json_read_failure_after_headers_keeps_received_http_status(self):
        pont = self.make_pont(lambda r: httpx.Response(202,
            headers={"Content-Type": "application/json"}, stream=BrokenStream()))
        pont._recall_client.max_retries = 0
        with self.assertRaises(bc.BasiraError):
            pont.rappeler("question")
        row, = self.records()
        self.assertEqual(row["statut"], 202)
        self.assertEqual(row["resultat"], "transport_error")
        self.assertNotIn(KEY, self.journal.read_text())

    def test_invalid_sse_and_named_terminal_follow_sdk_contract(self):
        for payload, expected in ((b"data: not-json\n\n", "stream_error"),
                                   (b'event: turn.done\ndata: {"replayed":true}\n\n', "ok")):
            with self.subTest(expected=expected):
                if self.journal.exists():
                    self.journal.unlink()
                pont = self.make_pont(lambda r: httpx.Response(200,
                    headers={"Content-Type": "text/event-stream"}, content=payload))
                TourSawm(pont).jouer("prompt", cibles_autorisees=set())
                row, = self.records()
                self.assertEqual(row["resultat"], expected)
                self.assertEqual(row["statut"], 200)

    def test_cached_proposal_is_revalidated_after_manifest_changes(self):
        proposal = json.dumps({"action": "arreter-service", "cible": "test.service",
            "justification": "Le service de test doit etre arrete.", "confiance": 0.8})
        pont = self.make_pont(lambda r: sse({"type": "response.delta", "delta": proposal},
                                          {"type": "turn.done"}))
        tour = TourSawm(pont)
        first = tour.jouer("prompt", cibles_autorisees={"test.service"}, turn_id="test-cache-turn")
        self.assertTrue(first.executable)
        second = tour.jouer("prompt", cibles_autorisees=set(), turn_id="test-cache-turn")
        self.assertFalse(second.executable)
        self.assertEqual(second.refus, "proposition_invalide:cible_hors_manifeste")
        self.assertEqual(len(self.records()), 1)

    def test_republish_after_outage_preserves_ids_and_never_rewrites_journal(self):
        online=False
        accepted={}
        attempts=[]
        def dashboard(request):
            event=json.loads(request.content)
            attempts.append(event['event_id'])
            if not online:
                raise httpx.ConnectError('collector offline',request=request)
            event=valider_evenement('cloud',event)
            accepted.setdefault(event['event_id'],event)
            return httpx.Response(200,json={'ok':True})
        pont=self.make_pont(lambda r:httpx.Response(200,json={'evidence':[]}),dashboard=dashboard)
        pont.rappeler('query one')
        pont.rappeler('query two')
        before=self.journal.read_bytes()
        self.assertEqual(len(accepted),0)
        failed=pont.telemetrie.republier_journal()
        self.assertEqual((failed['publies'],failed['echecs']),(0,1))
        # Une panne s'arrete apres la premiere tentative, pas 1000 timeouts.
        self.assertEqual(len(attempts),3)
        online=True
        replay=pont.telemetrie.republier_journal()
        self.assertEqual((replay['publies'],replay['echecs']),(2,0))
        self.assertEqual(len(accepted),2)
        pont.telemetrie.republier_journal()
        self.assertEqual(len(accepted),2)
        self.assertEqual(set(accepted),{e['event_id'] for e in self.records()})
        self.assertEqual(self.journal.read_bytes(),before)
        self.assertEqual(len(pont.journal_appels),2)

    def test_republish_is_bounded_and_filters_run_and_unknown_fields(self):
        pont=self.make_pont(lambda r:httpx.Response(200,json={'evidence':[]}))
        pont.rappeler('query one')
        pont.rappeler('query two')
        first=self.records()[0]
        with self.journal.open('a') as out:
            out.write(json.dumps({**first,'run_id':'other-run'})+'\n')
            out.write(json.dumps({**first,'Authorization':KEY})+'\n')
        self.published.clear()
        result=pont.telemetrie.republier_journal(limite=1)
        self.assertEqual(result['publies'],1)
        self.assertEqual(result['ignores'],1)
        self.assertTrue(result['tronque'])
        self.assertEqual(len(self.published),1)
        self.assertEqual(self.published[0]['event_id'],self.records()[1]['event_id'])

    def test_memory_engine_public_field_has_priority_with_legacy_fallbacks(self):
        for body,expected in (({'memory_engine':'tsst','engine':'legacy','schema':'envelope'},'tsst'),
                              ({'engine':'legacy','schema':'envelope'},'legacy'),
                              ({'schema':'envelope'},'envelope')):
            with self.subTest(expected=expected):
                pont=self.make_pont(lambda r:httpx.Response(200,json={**body,'evidence':[]}))
                self.assertEqual(pont.rappeler('query').moteur,expected)


if __name__ == "__main__":
    unittest.main()

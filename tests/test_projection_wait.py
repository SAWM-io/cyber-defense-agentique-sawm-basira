"""Projection differee : vrai SDK, HTTP simule et horloge sans attente reelle."""

from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

import httpx

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from connecteur.pont_memoire import PontMemoire, bc
from connecteur.telemetrie_cloud import TelemetrieCloud


KEY = "bsr_projection_test_only_never_log"
ENTITY = "ent_" + "a" * 32
JOB = "job_" + "b" * 32


class ProjectionWaitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = pathlib.Path(self.tmp.name)
        self.coffre = self.directory / "env"
        self.coffre.write_text(
            f"BASIRA_SPACE=mem_projection\nBASIRA_ENTITY={ENTITY}\n"
            f"BASIRA_KEY={KEY}\nBASIRA_BASE=https://cloud.invalid/api/v1/basira\n"
        )
        self.coffre.chmod(0o600)
        self.clock = 1_000.0
        self.sleeps = []
        self.requests = []
        self.enterContext(patch.object(bc.time, "monotonic", side_effect=lambda: self.clock))

    def sleep(self, seconds):
        self.assertGreaterEqual(seconds, 0)
        self.sleeps.append(seconds)
        self.clock += seconds

    def make_pont(self, handler, **options):
        def observed(request):
            self.requests.append((self.clock, request))
            return handler(request)

        cloud = httpx.Client(transport=httpx.MockTransport(observed), trust_env=False)
        self.addCleanup(cloud.close)
        telemetry = TelemetrieCloud(
            "projection-test", journal=self.directory / "appels.jsonl",
            dashboard_url="", dashboard_client=cloud,
        )
        pont = PontMemoire(
            coffre=self.coffre, campagne="projection-test", telemetrie=telemetry,
            http_client=cloud, **options,
        )
        pont._client._sleep = self.sleep
        pont._recall_client._sleep = self.sleep
        self.addCleanup(pont.close)
        return pont

    @staticmethod
    def unavailable():
        return httpx.Response(503, json={"detail": {"code": "engine_unavailable"}})

    def test_completed_job_then_eighteen_second_projection_keeps_one_recall_identity(self):
        def cloud(request):
            if request.url.path.endswith("events:batch"):
                return httpx.Response(202, json={"job_id": JOB, "status": "pending"})
            if "/jobs/" in request.url.path:
                return httpx.Response(200, json={"job_id": JOB, "status": "completed"})
            self.assertTrue(request.url.path.endswith("recall:tsst"))
            if self.clock < 1_018:
                return self.unavailable()
            return httpx.Response(200, json={
                "memory_engine": "basira-tsst-mhu",
                "evidence": [{"id": "proof-projected-after-completed"}],
            })

        pont = self.make_pont(cloud)
        deposit = pont.deposer([{"id": "one", "contenu": "controlled evidence"}])
        self.assertEqual(deposit["jobs"][0]["statut"], "completed")
        result = pont.rappeler("controlled question", avant_ms=12345)
        requests = [r for _, r in self.requests if r.url.path.endswith("recall:tsst")]
        rows = [r for r in pont.journal_appels if r["appel"] == "recall:tsst"]
        self.assertEqual(result.preuves, ({"id": "proof-projected-after-completed"},))
        self.assertEqual(result.moteur, "basira-tsst-mhu")
        self.assertEqual((result.tentatives, result.latence_ms), (7, 23_500.0))
        self.assertEqual([r["statut"] for r in rows], [503] * 6 + [200])
        self.assertEqual([r["tentative"] for r in rows], list(range(1, 8)))
        self.assertEqual(len({r["correlation_id"] for r in rows}), 1)
        self.assertEqual(len({r["event_id"] for r in rows}), 7)
        self.assertEqual(len({r.headers["Idempotency-Key"] for r in requests}), 1)
        self.assertEqual(len({r.content for r in requests}), 1)
        body = json.loads(requests[0].content)
        self.assertEqual(body["entity_id"], ENTITY)
        self.assertEqual(body["temporal"], {"as_of_transaction_time_ms": 12345})
        persisted = [json.loads(line) for line in
                     (self.directory / "appels.jsonl").read_text().splitlines()]
        self.assertEqual(persisted, list(pont.journal_appels))
        self.assertNotIn(KEY, json.dumps(persisted))
        self.assertNotIn("controlled question", json.dumps(persisted))

    def test_unavailable_projection_stops_inside_total_forty_five_second_budget(self):
        pont = self.make_pont(lambda request: self.unavailable())
        with self.assertRaises(bc.BasiraError) as caught:
            pont.rappeler("question")
        self.assertEqual((caught.exception.status, caught.exception.code),
                         (503, "engine_unavailable"))
        # Le prochain backoff de 8 s ne tient plus : aucun rejeu anticipe.
        self.assertEqual(self.clock, 1_039.5)
        self.assertEqual(len(self.requests), 9)
        self.assertEqual([r["tentative"] for r in pont.journal_appels], list(range(1, 10)))
        self.assertTrue(all(r["statut"] == 503 for r in pont.journal_appels))
        for started, request in self.requests:
            self.assertLess(started, 1_045)
            self.assertLessEqual(max(request.extensions["timeout"].values()),
                                 1_045 - started)
        self.assertEqual(self.requests[-1][1].extensions["timeout"]["read"], 5.5)

    def test_http_time_consumes_same_budget_as_backoff(self):
        def cloud(request):
            if len(self.requests) == 1:
                self.clock += 25
                return self.unavailable()
            remaining = request.extensions["timeout"]["read"]
            self.assertEqual(remaining, 19.5)
            self.clock += remaining
            raise httpx.ReadTimeout("simulated transport deadline", request=request)

        pont = self.make_pont(cloud)
        with self.assertRaises(bc.BasiraError) as caught:
            pont.rappeler("question")
        self.assertEqual(caught.exception.code, "transport_error")
        self.assertEqual(self.clock, 1_045)
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.sleeps, [0.5])
        self.assertEqual([r["statut"] for r in pont.journal_appels], [503, None])

    def test_forbidden_and_monthly_quota_are_not_replayed(self):
        for status, code in ((403, "forbidden"), (429, "monthly_quota_exceeded")):
            with self.subTest(status=status, code=code):
                self.requests.clear()
                self.sleeps.clear()
                pont = self.make_pont(lambda request: httpx.Response(
                    status, json={"detail": {"code": code}},
                    headers={"Retry-After": "1"},
                ))
                with self.assertRaises(bc.BasiraError) as caught:
                    pont.rappeler("question")
                self.assertEqual((caught.exception.status, caught.exception.code), (status, code))
                self.assertEqual(len(self.requests), 1)
                self.assertEqual(self.sleeps, [])
                self.assertEqual(len(pont.journal_appels), 1)

    def test_ip_limit_wait_is_not_shortened_to_fit_budget(self):
        pont = self.make_pont(lambda request: httpx.Response(
            429, json={"detail": "Too many requests"}, headers={"Retry-After": "60"},
        ))
        with self.assertRaises(bc.BasiraError) as caught:
            pont.rappeler("question")
        self.assertEqual((caught.exception.code, caught.exception.retry_after),
                         ("ip_rate_limited", 60.0))
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.sleeps, [])

    def test_write_budget_keeps_three_retries_on_separate_sdk_client(self):
        pont = self.make_pont(lambda request: self.unavailable())
        self.assertIsNot(pont._client, pont._recall_client)
        self.assertIs(pont._client._http, pont._recall_client._http)
        self.assertEqual(pont._client.max_retries, 3)
        self.assertEqual(pont._recall_client.max_retries, 10)
        with self.assertRaises(bc.BasiraError):
            pont.deposer([{"id": "one", "contenu": "controlled evidence"}])
        self.assertEqual(len(self.requests), 4)
        self.assertEqual(self.clock, 1_003.5)
        self.assertTrue(all(r.url.path.endswith("events:batch") for _, r in self.requests))
        self.assertEqual(len({r.headers["Idempotency-Key"] for _, r in self.requests}), 1)

    def test_custom_short_budget_is_respected(self):
        pont = self.make_pont(lambda request: self.unavailable(), budget_rappel_s=1.0)
        with self.assertRaises(bc.BasiraError):
            pont.rappeler("question")
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.clock, 1_000.5)
        self.assertEqual(self.requests[0][1].extensions["timeout"]["read"], 1.0)
        self.assertEqual(self.requests[1][1].extensions["timeout"]["read"], 0.5)

    def test_invalid_recall_budgets_fail_before_opening_credentials(self):
        for value in (True, False, 0, -1, 120.01, float("inf"), float("nan"), "45", None):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    PontMemoire(coffre=self.directory / "absent", budget_rappel_s=value)


if __name__ == "__main__":
    unittest.main()

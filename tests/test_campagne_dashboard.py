"""Rapport défensif fixe : lecture bornée et états honnêtes, sans accès à la VM."""
import importlib.util
import json
import pathlib
import shutil
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("collecteur_campagne", ROOT / "controleur/collecteur.py")
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class CampagneDashboardTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.path = self.root / c.CAMPAGNE_DEFENSE
        self.path.parent.mkdir(parents=True)
        with patch.object(c.Etat, "_versions", return_value={}):
            self.etat = c.Etat("campaign-test", series=self.root / "series", racine=self.root)
        handler = type("Handler", (c.Service,), {"etat": self.etat})
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.addCleanup(self.close_server)
        self.url = f"http://127.0.0.1:{self.server.server_port}/api/campagne-defense"

    def close_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(2)

    def read(self, suffix=""):
        with urllib.request.urlopen(self.url + suffix, timeout=2) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers["Cache-Control"], "no-store")
            return json.load(response)

    def report(self):
        return {"schema": "sawm-defense-campaign/v1", "updated_at": "2026-09-23T01:00:00Z",
                "status": "completed", "limits": ["Fixtures bénignes dans une seule VM."],
                "cases": [{"id": "db-lock", "title": "Verrou de base", "status": "passed",
                           "applied_by": "operator", "decision": {"action": "observe",
                           "reason": "Preuve insuffisante", "decision_id": "decision-fixture"},
                           "observations": {"before": {"read_available": True, "write_available": True},
                                            "incident": {"write_available": False},
                                            "after": {"write_available": True, "reference_matches": True}},
                           "checks": {"hash_restored": True},
                           "metrics": {"containment_ms": 123, "cloud_ms": None},
                           "cloud": {"job_ids": ["fixture-job"], "recall_count": 1, "odvl_available": False},
                           "proof": {"sha256": "a" * 64, "cloud_archived": False, "signature_seq": None},
                           "proof_refs": [c.CAMPAGNE_DEFENSE], "error": None}]}

    def write(self, obj):
        self.path.write_text(json.dumps(obj), encoding="utf-8")

    def test_missing_report_is_not_run_not_success(self):
        out = self.read()
        self.assertEqual(out["status"], "not_run")
        self.assertEqual(out["cases"], [])
        self.assertIsNone(out["updated_at"])
        self.assertNotIn(str(self.root), str(out))
        self.assertFalse(self.path.exists())

    def test_invalid_json_and_wrong_contract_clear_all_results(self):
        for raw in ("{", "[]", '{"schema":"other","status":"passed"}',
                    '{"schema":"sawm-defense-campaign/v1","status":"passed","cases":null}'):
            with self.subTest(raw=raw):
                self.path.write_text(raw)
                out = self.read()
                self.assertEqual(out["status"], "invalid")
                self.assertEqual(out["cases"], [])

    def test_valid_report_preserves_attribution_without_shell_or_measurement_lock(self):
        report = self.report()
        report["private_key"] = "NEVER_FORWARD"
        report["cases"][0]["internal_command"] = "NEVER_FORWARD"
        self.write(report)
        original = self.path.read_bytes()
        with self.etat.verrou, patch.object(c.subprocess, "run", side_effect=AssertionError("no command")):
            out = self.read()
        self.assertEqual(out["cases"][0]["applied_by"], "operator")
        self.assertEqual(out["cases"][0]["decision"]["action"], "observe")
        self.assertEqual(out["cases"][0]["metrics"]["containment_ms"], 123)
        self.assertFalse(out["cases"][0]["cloud"]["odvl_available"])
        self.assertNotIn("NEVER_FORWARD", str(out))
        self.assertEqual(self.path.read_bytes(), original)

    def test_bounded_size_symlink_and_non_regular_file(self):
        self.path.write_bytes(b" " * (c.MAX_CAMPAGNE_DEFENSE + 1))
        self.assertEqual(self.read()["status"], "invalid")
        self.path.unlink()
        secret = self.root / "secret.json"
        secret.write_text("PRIVATE_FILE")
        self.path.symlink_to(secret)
        out = self.read()
        self.assertEqual(out["status"], "invalid")
        self.assertNotIn("PRIVATE_FILE", str(out))
        self.path.unlink()
        self.path.mkdir()
        self.assertEqual(self.read()["status"], "invalid")

    def test_invalid_author_and_nan_never_reach_a_success_response(self):
        for changes in ({"applied_by": "automatic"}, {"metrics": {"containment_ms": float("nan")}},
                        {"local_guard_enabled": "false"}, {"local_decision": "observe"}):
            report = self.report()
            report["cases"][0].update(changes)
            self.write(report)
            self.assertEqual(self.read()["status"], "invalid")

    def test_local_policy_preserves_operator_cleanup_and_restore_separately(self):
        report = self.report()
        case = report["cases"][0]
        case.update(applied_by="local_policy", cleanup={"stopped_by_operator": True, "service_healthy": True},
                    operator_restoration={"restored": True, "after_sha256": "a" * 64},
                    protocol="database-v3-policy-availability", local_guard_enabled=True,
                    local_decision={"action": "arreter-service", "reason": "Indisponibilité attribuée",
                                    "decision_id": "local_fixture"})
        case["observations"]["after"] = {"reference_matches": False}
        case["observations"]["after_operator_restore"] = {"reference_matches": True}
        case["checks"]["hash_restored"] = False
        self.write(report)
        out = self.read()["cases"][0]
        self.assertEqual(out["applied_by"], "local_policy")
        self.assertEqual(out["protocol"], "database-v3-policy-availability")
        self.assertTrue(out["local_guard_enabled"])
        self.assertEqual(out["local_decision"]["decision_id"], "local_fixture")
        self.assertEqual(out["local_decision"]["reason"], "Indisponibilité attribuée")
        self.assertEqual(out["decision"]["action"], "observe")
        self.assertTrue(out["cleanup"]["stopped_by_operator"])
        self.assertTrue(out["operator_restoration"]["restored"])
        self.assertFalse(out["observations"]["after"]["reference_matches"])
        self.assertTrue(out["observations"]["after_operator_restore"]["reference_matches"])
        self.assertFalse(out["checks"]["hash_restored"])

    def test_no_path_parameter_and_no_post_mutation(self):
        self.write(self.report())
        original = self.path.read_bytes()
        for suffix in ("?f=../../secret.json", "?path=/etc/passwd"):
            with self.assertRaises(urllib.error.HTTPError) as error:
                self.read(suffix)
            self.assertEqual(error.exception.code, 400)
            error.exception.close()
        request = urllib.request.Request(self.url, data=b"{}", headers={"Content-Type": "application/json"})
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request, timeout=2)
        self.assertEqual(error.exception.code, 404)
        error.exception.close()
        self.assertEqual(self.path.read_bytes(), original)

    def test_panel_uses_safe_text_and_discloses_scope_and_attribution(self):
        html = (ROOT / "controleur/tableau.html").read_text()
        block = html.split("function statutCampagne(v)", 1)[1].split("async function chargerSecurite()", 1)[0]
        self.assertNotIn("innerHTML", block)
        self.assertIn('/api/campagne-defense', block)
        self.assertIn('operator: "opérateur (operator)"', block)
        self.assertIn('sawm: "SAWM (sawm)"', block)
        self.assertIn('none: "aucune (none)"', block)
        self.assertIn('local_policy: "protections locales (local_policy)"', block)
        self.assertIn("Avant (baseline)", block)
        self.assertIn("containment_ms", block)
        self.assertIn("ne démontrent pas une protection générale contre les virus", html)

    def test_memory_console_discloses_unvalidated_citations(self):
        html = (ROOT / "controleur/tableau.html").read_text()
        self.assertIn("ech(d.avertissement_citations)", html)
        self.assertIn("ech(d.preuves_invalides)", html)
        self.assertIn("Preuves rappelées", html)
        self.assertNotIn("Preuves citées", html)
        self.assertNotIn("citée avec son identifiant", html)
        self.assertIn("Ce n’est pas un coffre immuable", html)

    @unittest.skipUnless(shutil.which("node"), "Node requis pour le test du rendu DOM")
    def test_panel_renders_untrusted_report_as_text_and_clears_failed_refresh(self):
        html = (ROOT / "controleur/tableau.html").read_text()
        helpers = "function texte" + html.split("function texte", 1)[1].split("function etat", 1)[0]
        cells = "function cellules" + html.split("function cellules", 1)[1].split("let donnees", 1)[0]
        proof_links = "function preuves" + html.split("function preuves", 1)[1].split("function incidentsDecisions", 1)[0]
        panel = "function statutCampagne" + html.split("function statutCampagne", 1)[1].split("async function chargerSecurite", 1)[0]
        report = self.report()
        hostile = '<img src=x onerror="alert(1)">'
        report["cases"][0]["title"] = hostile
        report["cases"][0]["decision"]["reason"] = hostile
        report["limits"] = [hostile]
        script = r'''
const assert = require("node:assert/strict");
class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.dataset = {}; this.textContent = ""; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
  querySelectorAll() { return this.children.filter(n => n.tag === "details" && n.open); }
  set innerHTML(_) { throw Error("HTML interpretation is forbidden"); }
}
const document = {createElement: tag => new Element(tag)};
const nodes = new Map();
function $(sel) { if (!nodes.has(sel)) nodes.set(sel, new Element("div")); return nodes.get(sel); }
function fmt(v) { return typeof v === "number" ? String(v) : "N/D"; }
const donnees = {rapports: []};
function contents(n) { return n.textContent + n.children.map(contents).join(" "); }
'''
        script += helpers + cells + proof_links + panel
        script += "\nconst report = " + json.dumps(report) + ";\nafficherCampagne(report);\n"
        script += r'''
const box = $("#campagne-cas"), original = box.children[0];
assert.match(contents(box), /<img src=x onerror="alert\(1\)">/);
assert.match(contents(box), /opérateur \(operator\)/);
assert.match(contents(box), /décision SAWM Cloud : observe/i);
assert.match(contents(box), /Latence de confinement : 123 ms/);
assert.equal($("#campagne-limites").children[0].textContent, report.limits[0]);
afficherCampagne(report);
assert.equal(box.children[0], original, "unchanged refresh preserves expanded details");
report.cases[0].applied_by = "local_policy";
report.cases[0].protocol = "database-v3-policy-availability";
report.cases[0].local_guard_enabled = true;
report.cases[0].local_decision = {action:"arreter-service",reason:"Indisponibilité attribuée",decision_id:"local_fixture"};
report.cases[0].cleanup = {stopped_by_operator:true,service_healthy:true};
report.cases[0].operator_restoration = {restored:true};
report.cases[0].observations.after = {reference_matches:false};
report.cases[0].observations.after_operator_restore = {reference_matches:true};
afficherCampagne(report);
assert.match(contents(box), /protections locales \(local_policy\)/);
assert.match(contents(box), /Protocole : database-v3-policy-availability/);
assert.match(contents(box), /garde locale de disponibilité activée : oui/);
assert.match(contents(box), /Décision locale · garde de disponibilité : arreter-service · identifiant local : local_fixture/);
assert.match(contents(box), /Motif local : Indisponibilité attribuée/);
assert.match(contents(box), /décision SAWM Cloud : observe/i);
assert.match(contents(box), /Nettoyage · arrêt par l’opérateur : oui/);
assert.match(contents(box), /Restauration opérateur : consignée · base restaurée : oui/);
const table = box.children[0].children.find(n => n.className === "table-scroll").children[0];
const hashRow = table.children[1].children[2];
assert.equal(hashRow.children[3].textContent, "non", "result before cleanup stays unchanged");
assert.equal(hashRow.children[4].textContent, "oui", "operator restoration has its own observation");
afficherCampagne({status:"invalid",cases:[],limits:[],error:"unavailable"});
assert.equal(box.children.length, 1);
assert.match(contents(box), /Aucun cas exécuté confirmé/);
assert.match($("#campagne-statut").className, /etat-ko/);
'''
        result = subprocess.run([shutil.which("node"), "-"], input=script, text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()

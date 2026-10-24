"""Rapport d'accès fixe : aucun droit nouveau, attribution prudente et rendu texte."""
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
spec = importlib.util.spec_from_file_location("collecteur_acces", ROOT / "controleur/collecteur.py")
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


def report():
    return {"schema": "sawm-external-auth-validation/v1", "status": "passed",
            "updated_at": "2026-09-23T12:00:00Z", "scope": "Essai contrôlé depuis une adresse privée",
            "cases": [{"id": "auth-fixture", "title": "Authentification répétée", "status": "passed",
                       "source_ip": "10.0.0.2", "checks": {"locally_banned": True},
                       "measurements": {"attempts": 5}}],
            "events": [{"timestamp_ms": 1000, "source_ip": "10.0.0.2", "event": "ban",
                        "username": "fixture", "reason": "Seuil local atteint", "ban_until_ms": 61000,
                        "applied_by": "local_policy"}],
            "correlations": [{"source_ips": ["10.0.0.2", "10.0.0.3"], "reason": "Motif commun observé",
                              "confidence_label": "hypothese_non_confirmee", "same_actor_confirmed": False}],
            "geography": [{"source_ip": "10.0.0.2", "status": "private_address", "country": None, "source": None}],
            "cloud": {"status": "not_run", "calls": 0, "action": None, "reason": "Analyse non demandée"},
            "limits": ["Exclusion locale ; aucune identité personnelle confirmée."]}


class AccesDashboardAPITest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.path = self.root / c.ACCES_EXTERIEUR
        self.path.parent.mkdir(parents=True)

    def write(self, value):
        self.path.write_text(json.dumps(value), encoding="utf-8")

    def read(self):
        return c.lire_acces_exterieur(self.root)

    def test_missing_report_is_not_run_and_does_not_create_anything(self):
        result = self.read()
        self.assertEqual(result["status"], "not_run")
        self.assertEqual(result["events"], [])
        self.assertIsNone(result["updated_at"])
        self.assertFalse(self.path.exists())
        self.assertNotIn(str(self.root), str(result))

    def test_bad_json_wrong_types_and_nonfinite_measurement_clear_results(self):
        for raw in ("{", "[]", '{"schema":"wrong"}',
                    json.dumps({**report(), "events": None}),
                    json.dumps({**report(), "cloud": {"latency_ms": float("nan")}})):
            with self.subTest(raw=raw[:50]):
                self.path.write_text(raw)
                result = self.read()
                self.assertEqual(result["status"], "invalid")
                self.assertEqual(result["cases"], [])
                self.assertEqual(result["events"], [])

    def test_size_symlink_directory_and_list_limits(self):
        self.path.write_bytes(b" " * (c.MAX_ACCES_EXTERIEUR + 1))
        self.assertEqual(self.read()["status"], "invalid")
        self.path.unlink()
        secret = self.root / "secret.json"
        secret.write_text("PRIVATE")
        self.path.symlink_to(secret)
        self.assertEqual(self.read()["status"], "invalid")
        self.path.unlink()
        self.path.mkdir()
        self.assertEqual(self.read()["status"], "invalid")
        self.path.rmdir()
        for key, count in (("cases", 41), ("events", 501), ("correlations", 41), ("geography", 101), ("limits", 41)):
            value = report()
            value[key] *= count
            self.write(value)
            self.assertEqual(self.read()["status"], "invalid", key)

    def test_identity_and_geography_must_remain_unconfirmed(self):
        changes = [("correlations", "same_actor_confirmed", True),
                   ("correlations", "confidence_label", "confirmed"),
                   ("geography", "country", "FR"), ("geography", "source", "invented"),
                   ("geography", "source_ip", "8.8.8.8"),
                   ("events", "source_ip", "<script>"), ("events", "applied_by", "automatic")]
        for collection, field, value in changes:
            data = report()
            data[collection][0][field] = value
            self.write(data)
            output = self.read()
            self.assertEqual(output["status"], "invalid", (collection, field))
            self.assertEqual(output["cases"], [])
            self.assertEqual(output["events"], [])

    def test_public_fields_and_local_attribution_survive_without_commands(self):
        data = report()
        data["private_key"] = "NEVER_FORWARD"
        data["cases"][0]["command"] = "NEVER_FORWARD"
        data["events"][0]["password"] = "NEVER_FORWARD"
        data["cloud"]["token"] = "NEVER_FORWARD"
        self.write(data)
        original = self.path.read_bytes()
        with patch.object(c.subprocess, "run", side_effect=AssertionError("no subprocess")):
            output = self.read()
        self.assertEqual(output["status"], "passed")
        self.assertEqual(output["events"][0]["applied_by"], "local_policy")
        self.assertFalse(output["correlations"][0]["same_actor_confirmed"])
        self.assertIsNone(output["geography"][0]["country"])
        self.assertNotIn("NEVER_FORWARD", str(output))
        self.assertEqual(self.path.read_bytes(), original)

    def test_endpoint_is_readonly_without_query_or_measurement_lock(self):
        self.write(report())
        with patch.object(c.Etat, "_versions", return_value={}):
            etat = c.Etat("external-auth-test", series=self.root / "series", racine=self.root)
        handler = type("Handler", (c.Service,), {"etat": etat})
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        original = self.path.read_bytes()
        try:
            url = f"http://127.0.0.1:{server.server_port}/api/acces-exterieur"
            with etat.verrou, patch.object(c.subprocess, "run", side_effect=AssertionError("no command")):
                with urllib.request.urlopen(url, timeout=2) as response:
                    self.assertEqual(response.headers["Cache-Control"], "no-store")
                    self.assertEqual(json.load(response)["status"], "passed")
            for suffix in ("?path=/etc/passwd", "?f=../../secret.json"):
                with self.assertRaises(urllib.error.HTTPError) as failure:
                    urllib.request.urlopen(url + suffix, timeout=2)
                self.assertEqual(failure.exception.code, 400)
                failure.exception.close()
            request = urllib.request.Request(url, data=b"{}", headers={"Content-Type": "application/json"})
            with self.assertRaises(urllib.error.HTTPError) as failure:
                urllib.request.urlopen(request, timeout=2)
            self.assertEqual(failure.exception.code, 404)
            failure.exception.close()
            self.assertEqual(self.path.read_bytes(), original)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(2)


@unittest.skipUnless(shutil.which("node"), "Node requis pour le rendu DOM")
class AccesDashboardUITest(unittest.TestCase):
    def test_text_rendering_local_attribution_hypotheses_and_failed_refresh(self):
        html = (ROOT / "controleur/tableau.html").read_text()
        self.assertIn("Tentatives d’accès et exclusions IP", html)
        self.assertIn("chargerAccesExterieur()", html)
        helpers = "function texte" + html.split("function texte", 1)[1].split("function etat", 1)[0]
        helpers += "function cellules" + html.split("function cellules", 1)[1].split("let donnees", 1)[0]
        helpers += "function valeurCampagne" + html.split("function valeurCampagne", 1)[1].split("function resumeReferencesCampagne", 1)[0]
        panel = "let dernierAccesExterieur" + html.split("let dernierAccesExterieur", 1)[1].split("async function chargerSecurite", 1)[0]
        hostile = '<img src=x onerror="alert(1)">'
        data = report()
        data["scope"] = hostile
        data["cases"][0]["title"] = hostile
        data["events"][0]["username"] = hostile
        data["events"][0]["reason"] = hostile
        data["correlations"][0]["reason"] = hostile
        data["cloud"]["reason"] = hostile
        data["limits"] = [hostile]
        script = r'''
const assert=require("node:assert/strict");
class Element {
  constructor(tag) { this.tag=tag; this.children=[]; this.textContent=""; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children=nodes; }
  set innerHTML(_) { throw Error("HTML interpretation forbidden"); }
}
const document={createElement:tag=>new Element(tag)}, nodes=new Map();
function $(id) { if(!nodes.has(id)) nodes.set(id,new Element("div")); return nodes.get(id); }
const fini=v=>typeof v==="number"&&Number.isFinite(v), heure=v=>fini(v)?String(v):"N/D";
function contents(n) { return n.textContent+n.children.map(contents).join(" "); }
function descendants(n) { return [n,...n.children.flatMap(descendants)]; }
'''
        script += helpers + panel + "\nconst data=" + json.dumps(data) + ";\n"
        script += r'''
afficherAccesExterieur(data);
assert.equal($("#acces-statut").textContent,"Essai : validé");
assert.match(contents($("#acces-evenements")),/Protection locale/);
assert.match(contents($("#acces-evenements")),/61000/);
assert.match(contents($("#acces-correlations")),/Hypothèse non confirmée/);
assert.match(contents($("#acces-correlations")),/Même acteur : non confirmé/);
assert.match(contents($("#acces-geographie")),/N\/A : adresse privée/);
for(const id of ["#acces-cas","#acces-evenements","#acces-correlations","#acces-cloud","#acces-limites"])
  assert.ok(contents($(id)).includes('<img src=x onerror="alert(1)">'));
for(const root of nodes.values()) assert.ok(!descendants(root).some(n=>["img","script","button","input"].includes(n.tag)));
const many={...data,events:Array.from({length:105},(_,i)=>({...data.events[0],timestamp_ms:i}))};
afficherAccesExterieur(many);
assert.equal($("#acces-evenements").children.length,100);
assert.match($("#acces-evenements-resume").textContent,/105.*100 plus récents/);
assert.match(contents($("#acces-evenements").children[0]),/^104/);
afficherAccesExterieur({...data,cloud:{status:"failed",error:"BasiraError <img src=x>"}});
assert.match($("#acces-cloud").textContent,/motif : BasiraError <img src=x>/);
assert.ok(!descendants($("#acces-cloud")).some(n=>n.tag==="img"));
global.fetch=async()=>{throw Error("offline")};
(async()=>{
  await chargerAccesExterieur();
  assert.equal($("#acces-statut").textContent,"Essai : rapport invalide");
  assert.doesNotMatch(contents($("#acces-evenements")),/Protection locale/);
  assert.doesNotMatch(contents($("#acces-cas")),/<img/);
  assert.match($("#acces-cloud").textContent,/aucun choix du modèle confirmé/);
  afficherAccesExterieur({status:"not_run",cases:[],events:[],limits:[]});
  assert.equal($("#acces-statut").textContent,"Essai : non exécuté");
})().catch(error=>{console.error(error);process.exitCode=1;});
'''
        result = subprocess.run([shutil.which("node"), "-"], input=script, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()

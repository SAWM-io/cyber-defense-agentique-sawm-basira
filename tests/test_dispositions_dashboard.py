"""Affichage des scores internes : sources textuelles et aucun ancien état trompeur."""
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from controleur.dispositions_serveur import DispositionsServeur


@unittest.skipUnless(shutil.which("node"), "Node requis pour le rendu DOM")
class DispositionsDashboardTest(unittest.TestCase):
    def test_simulated_emotion_freshness_missing_state_and_target_provenance(self):
        html = (ROOT / "controleur/tableau.html").read_text()
        self.assertIn("État émotionnel simulé", html)
        self.assertLess(html.index('id="emotion-titre"'), html.index("Modèle de dispositions — heuristiques locales"))
        self.assertIn("afficherEtatEmotionnel();", html.split("function fraicheur()", 1)[1].split("function ", 1)[0])
        helpers = "function texte" + html.split("function texte", 1)[1].split("function etat", 1)[0]
        panel = "function objetDisposition" + html.split("function objetDisposition", 1)[1].split("function statutCampagne", 1)[0]
        with tempfile.TemporaryDirectory() as tmp:
            producer = DispositionsServeur(pathlib.Path(tmp).resolve(), "emotion-fixture")
            producer.observer("event-A", "anomalie_verifiee", {"id": "proof-A", "unit": "labo-a.service"}, 100)
            producer.observer("event-B", "violation_confirmee", {"id": "proof-B", "unit": "labo-b.service"}, 200)
            produced = producer.observer("event-C", "fausse_alerte",
                {"id": "proof-revision", "unit": "labo-a.service", "revision_de": "event-A"}, 300)
        script = r'''
const assert=require("node:assert/strict");
class Element {constructor(){this.children=[];this.textContent="";} append(...n){this.children.push(...n);} replaceChildren(...n){this.children=n;} set innerHTML(_){throw Error("unsafe HTML");}}
const document={createElement:()=>new Element()},nodes=new Map();
function $(s){if(!nodes.has(s))nodes.set(s,new Element());return nodes.get(s);}
const fini=v=>typeof v==="number"&&Number.isFinite(v),fmt=v=>fini(v)?String(v):"N/D",heure=fmt;
function contents(n){return n.textContent+n.children.map(contents).join(" ");}
'''
        script += helpers + panel + "\nconst produced=" + json.dumps(produced) + ";\n"
        script += r'''
Date.now=()=>1000;
const marker={phase:"disposition_serveur",mur_epoch_ms:300,texte:JSON.stringify(produced)};
afficherDispositions([marker]);
assert.equal($("#emotion-statut").textContent,"Instantané récent");
assert.match(contents($("#emotion-scores")),new RegExp("Vigilance\\s*"+produced.etat.vigilance+"/100"));
assert.match(contents($("#emotion-scores")),new RegExp("Incertitude.*"+(100-produced.etat.confiance)+"/100"));
assert.match($("#emotion-source").textContent,/disposition_serveur.*révision 3.*heuristique locale/);
assert.match(contents($("#emotion-mefiance")),/labo-b.service : 25\/100/);
assert.match(contents($("#emotion-mefiance")),/proof-B \(événement event-B\)/);
assert.doesNotMatch(contents($("#emotion-mefiance")),/proof-A|proof-revision|labo-a.service/);
// A recent Cloud reply cannot make this old local state current. Only its own timestamp matters.
Date.now=()=>301001;
afficherEtatEmotionnel();
assert.equal($("#emotion-statut").textContent,"Historique");
assert.match($("#emotion-source").textContent,/Pas d’état actuel confirmé/);
assert.match(contents($("#emotion-scores")),/Vigilance/);
afficherDispositions([{...marker,mur_epoch_ms:999999}]);
assert.equal($("#emotion-statut").textContent,"Historique");
assert.match($("#emotion-source").textContent,/âge non établi/);
afficherDispositions([marker,{...marker,texte:"{"}]);
assert.equal($("#emotion-statut").textContent,"Non disponible");
assert.doesNotMatch(contents($("#emotion-scores")),/\/100/);
assert.doesNotMatch(contents($("#emotion-mefiance")),/proof-B/);
afficherDispositions(null);
assert.match($("#emotion-source").textContent,/Aucun instantané/);
const withoutSources={...produced,motifs:[]};
afficherDispositions([{...marker,texte:JSON.stringify(withoutSources)}]);
assert.match(contents($("#emotion-mefiance")),/Source de cette valeur absente/);
assert.doesNotMatch(contents($("#emotion-mefiance")),/proof-B/);
'''
        result = subprocess.run([shutil.which("node"), "-"], input=script, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_snapshot_renders_scores_and_sources_as_text_and_rejects_latest_invalid_marker(self):
        html = (ROOT / "controleur/tableau.html").read_text()
        self.assertIn("afficherDispositions(d.marqueurs)", html)
        self.assertIn("heuristiques et non calibrés", html)
        self.assertIn("pas des probabilités ni des sentiments vécus", html)
        self.assertIn("sans accorder de permission supplémentaire", html)
        helpers = "function texte" + html.split("function texte", 1)[1].split("function etat", 1)[0]
        panel = "function objetDisposition" + html.split("function objetDisposition", 1)[1].split("function statutCampagne", 1)[0]
        hostile = '<img src=x onerror="alert(1)">'
        snapshot = {"schema": "sawm-server-dispositions/v1", "entity_id": "entity-fixture", "revision": 3,
                    "traits": {key: {"intensite": score, "objectif": hostile}
                               for key, score in (("prudence", 75), ("curiosite", 60), ("preservation_service", 90))},
                    "etat": {"vigilance": 40, "confiance": 65, "mefiance_par_cible": {hostile: 55}},
                    "motifs": [{"event_id": "event-3", "signal": "incoherence", "libelle": hostile,
                                "source_ref": {"id": hostile, "unit": "labo-fixture.service", "revision_de": "event-1"},
                                "actif": False}]}
        with tempfile.TemporaryDirectory() as tmp:
            producer = DispositionsServeur(pathlib.Path(tmp).resolve(), "dashboard-fixture")
            produced = producer.observer("event-fixture", "anomalie_verifiee",
                                         {"id": "proof-fixture", "unit": "labo-fixture.service"}, 100)
        script = r'''
const assert = require("node:assert/strict");
class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.textContent = ""; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
  set innerHTML(_) { throw Error("HTML interpretation is forbidden"); }
}
const document = {createElement: tag => new Element(tag)};
const nodes = new Map();
function $(sel) { if (!nodes.has(sel)) nodes.set(sel, new Element("div")); return nodes.get(sel); }
const fini = v => typeof v === "number" && Number.isFinite(v);
const fmt = v => fini(v) ? String(v) : "N/D";
const heure = v => fini(v) ? String(v) : "N/D";
function contents(n) { return n.textContent + n.children.map(contents).join(" "); }
'''
        script += helpers + panel + "\nconst snapshot = " + json.dumps(snapshot) + ";\n"
        script += "const produced = " + json.dumps(produced) + ";\n"
        script += r'''
afficherDispositions([]);
assert.equal($("#dispositions-statut").textContent, "Non disponible");
assert.equal(contents($("#dispositions-etat")), "N/D");
const marker = {phase:"disposition_serveur",texte:JSON.stringify(snapshot),mur_epoch_ms:200};
afficherDispositions([marker]);
assert.match($("#dispositions-source").textContent, /entity-fixture · révision 3/);
const scores = contents($("#dispositions-etat"));
assert.match(scores, /Vigilance\s*40\/100/);
assert.match(scores, /Confiance dans les preuves\s*65\/100/);
assert.match(scores, /Incertitude \(100 − confiance\)\s*35\/100/);
for (const id of ["#dispositions-traits", "#dispositions-cibles", "#dispositions-motifs"])
  assert.match(contents($(id)), /<img src=x onerror="alert\(1\)">/);
assert.match(contents($("#dispositions-motifs")), /Révisé/);
assert.match(contents($("#dispositions-motifs")), /événement : event-3/);
assert.match(contents($("#dispositions-motifs")), /révise : event-1/);
const newer = {...snapshot,revision:4,etat:{...snapshot.etat,vigilance:60}};
afficherDispositions([marker,{...marker,texte:JSON.stringify(newer)}]);
assert.match(contents($("#dispositions-etat")), /Vigilance\s*60\/100/);
for (const text of ["{", "[]",JSON.stringify({...snapshot,schema:"forged"}),
                    JSON.stringify({...snapshot,etat:{...snapshot.etat,vigilance:101}})]) {
  afficherDispositions([marker,{...marker,texte:text}]);
  assert.equal($("#dispositions-statut").textContent, "Instantané invalide");
  assert.equal(contents($("#dispositions-etat")), "N/D");
  assert.doesNotMatch(contents($("#dispositions-motifs")), /event-3/);
}
afficherDispositions(null);
assert.equal($("#dispositions-statut").textContent, "Non disponible");
afficherDispositions([{phase:"disposition_serveur",texte:JSON.stringify(produced),mur_epoch_ms:100}]);
assert.equal($("#dispositions-statut").textContent, "État fonctionnel historique");
assert.match($("#dispositions-source").textContent, /dashboard-fixture · révision 1/);
assert.ok(contents($("#dispositions-etat")).includes(String(produced.etat.vigilance) + "/100"));
assert.match(contents($("#dispositions-motifs")), /proof-fixture/);
Date.now=()=>100100;
afficherDispositions([{phase:"disposition_serveur",texte:JSON.stringify(produced),mur_epoch_ms:100}]);
assert.equal($("#dispositions-statut").textContent,"État fonctionnel récent");
Date.now=()=>400101;
afficherDispositions([{phase:"disposition_serveur",texte:JSON.stringify(produced),mur_epoch_ms:100}]);
assert.equal($("#dispositions-statut").textContent,"État fonctionnel historique");
assert.equal($("#dispositions-statut").className,"jeton etat-attention");
assert.match($("#dispositions-source").textContent,/heuristique locale/);
'''
        result = subprocess.run([shutil.which("node"), "-"], input=script, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()

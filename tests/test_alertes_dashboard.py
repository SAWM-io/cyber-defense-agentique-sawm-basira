"""Alertes locales : dernier état explicite, fraîcheur et données sans HTML actif."""
import pathlib
import shutil
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
HTML = ROOT / "controleur/tableau.html"


@unittest.skipUnless(shutil.which("node"), "Node requis pour le rendu DOM")
class AlertesDashboardTest(unittest.TestCase):
    def run_js(self, checks):
        html = HTML.read_text()
        helpers = "function texte" + html.split("function texte", 1)[1].split("function etat", 1)[0]
        panel = "function preuves" + html.split("function preuves", 1)[1].split("function incidentsDecisions", 1)[0]
        script = r'''
const assert = require("node:assert/strict");
class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.textContent = ""; this.value = "1000"; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
  set innerHTML(_) { throw Error("HTML interpretation is forbidden"); }
}
const document = {createElement: tag => new Element(tag)};
const nodes = new Map();
function $(sel) { if (!nodes.has(sel)) nodes.set(sel, new Element("div")); return nodes.get(sel); }
const fini = v => typeof v === "number" && Number.isFinite(v);
const heure = v => fini(v) ? String(v) : "N/D";
const fmt = heure;
function contents(n) { return n.textContent + n.children.map(contents).join(" "); }
function descendants(n) { return [n, ...n.children.flatMap(descendants)]; }
const now = 100000;
Date.now = () => now;
const fresh = {incidents:[], decisions:[], telemetrie_invite:{age_ms:10,connectee:true}};
const watch = {snapshot:{active:true,age_ms:10,mode:"analyse_cloud",repli_cloud_secondes:0},recu_ms:now,echec:false};
const options = {dernierSucces:now,echecCollecteur:false,periode:1000};
let donnees = fresh, securiteAlertes = watch, dernierSucces = now, echecCollecteur = false;
function collect(data=fresh, security=watch, at=now, opts=options) { return collecterAlertes(data,security,at,opts); }
'''
        result = subprocess.run([shutil.which("node"), "-"], input=script + helpers + panel + checks,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_permanent_panel_deduplicates_and_renders_observations_and_proofs_as_text(self):
        html = HTML.read_text()
        self.assertLess(html.index('id="alertes-titre"'), html.index('<nav class="onglets"'))
        self.assertIn("Historique non clos", html)
        self.assertIn("ne constitue pas un diagnostic de logiciel malveillant", html)
        self.run_js(r'''
const hostile = '<img src=x onerror="alert(1)">';
donnees = {...fresh, rapports:[{chemin:"proof.json",nom:hostile,url:"/api/rapport?nom=proof.json"}],
  incidents:[{id:"incident-1",titre:hostile,statut:"en_attente_preuves",faits:[hostile],
    raison_publique:"Observation incomplète",origine:hostile,mur_epoch_ms:100}],
  decisions:[{id:"decision-1",incident_id:"incident-1",statut:"en_attente_preuves",
    raison_publique:hostile,faits:[JSON.stringify({inconnues:[hostile]})],
    preuves:["proof.json"],mur_epoch_ms:101}]};
const rows = collect(donnees);
assert.equal(rows.length,1);
assert.equal(rows[0].decision,"decision-1");
afficherAlertes();
const rendered = contents($("#alertes-liste"));
assert.ok(rendered.includes(hostile));
assert.match(rendered,/Observation incomplète/);
assert.match(rendered,/Informations manquantes/);
assert.match(rendered,/Observations reçues/);
assert.match(rendered,/Source :/);
assert.equal($("#alertes-nombre").textContent,"1 point(s) à examiner");
const all = descendants($("#alertes-liste"));
assert.equal(all.filter(n=>n.tag==="a")[0].href,"/api/rapport?nom=proof.json");
assert.ok(!all.some(n=>["img","script","button","input"].includes(n.tag)));
''')

    def test_late_structured_facts_are_parsed_before_display_truncation(self):
        self.run_js(r'''
const raw = JSON.stringify({observation:"x".repeat(900),inconnues:["mandat à vérifier"],refus:"cible hors mandat"});
const detail = detailsAlerte({faits:[...Array(20).fill("observation"),raw,"{broken",JSON.stringify(["ignore"])]});
assert.deepEqual(detail.unknowns,["mandat à vérifier"]);
assert.equal(detail.refus,"cible hors mandat");
assert.equal(detailsAlerte({faits:[JSON.stringify({inconnues:Array(20).fill("x").map((x,i)=>x+i)})]}).unknowns.length,8);
assert.equal(detailsAlerte({faits:[JSON.stringify({padding:"x".repeat(5000),refus:"ignored"})]}).refus,"");
const rows=collect({...fresh,decisions:[{id:"decision-refus",statut:"proposee",faits:[raw],mur_epoch_ms:1}]});
assert.equal(rows.length,1);
assert.ok(rows[0].reasons.includes("Refus : cible hors mandat"));
assert.deepEqual(collect({...fresh,decisions:[{id:"d",statut:"proposee",faits:["texte inconnu : malware", "{" ]}]}),[]);
''')

    def test_explicit_resolution_supersedes_old_errors_but_proposal_does_not(self):
        self.run_js(r'''
const old = {id:"d-old",incident_id:"i",statut:"non_executee",raison_publique:"Mandat rejeté",mur_epoch_ms:10};
const incident = {id:"i",statut:"analyse_indisponible",mur_epoch_ms:11};
const pending = {id:"d-new",incident_id:"i",statut:"proposee",mur_epoch_ms:20};
let data = {...fresh,incidents:[incident],decisions:[old,pending]};
assert.equal(collect(data)[0].decision,"d-old");
data.decisions=[pending,old];
assert.equal(collect(data)[0].decision,"d-old");
data.decisions.push({...pending,id:"d-verified",statut:"verifie",mur_epoch_ms:21});
assert.deepEqual(collect(data),[]);
data.incidents=[{...incident,statut:"resolu",mur_epoch_ms:22}];
data.decisions=[old,{...pending,faits:[JSON.stringify({inconnues:["ancienne question"]})]}];
assert.deepEqual(collect(data),[]);
data.incidents=[{...incident,statut:"a_revoir",mur_epoch_ms:30}];
data.decisions=[{...pending,statut:"verifie",mur_epoch_ms:21}];
assert.equal(collect(data).length,1); // Une nouvelle erreur reste visible après l'ancien succès.
data.incidents=[incident];
data.decisions=[{...pending,statut:"verifie",faits:[JSON.stringify({inconnues:["effet inconnu"]})]}];
assert.equal(collect(data).length,1); // « vérifié » n'efface pas une inconnue encore publiée.
''')

    def test_statuses_are_review_points_not_malware_verdicts(self):
        self.run_js(r'''
const statuses=["en_attente_preuves","a_revoir","analyse_indisponible","attente_budget","observation_expiree","non_executee","refusee"];
for(const statut of statuses) {
  const rows=collect({...fresh,decisions:[{id:"d",statut,mur_epoch_ms:1}]});
  assert.equal(rows.length,1,statut);
}
donnees={...fresh,incidents:[{id:"failure",statut:"failed"},{id:"error",statut:"error"}]};
afficherAlertes();
assert.match(contents($("#alertes-liste")),/Échec consigné/);
assert.match(contents($("#alertes-liste")),/Erreur consignée/);
''')

    def test_current_health_expires_and_recovers_without_erasing_open_history(self):
        self.run_js(r'''
assert.deepEqual(collect(),[]);
assert.deepEqual(collect(null,null).map(x=>x.id),["systeme:collecteur","systeme:veille"]);
assert.deepEqual(collect(fresh,watch,now+2490).map(x=>x.id),["systeme:telemetrie"]);
assert.deepEqual(collect(fresh,watch,now+4000).map(x=>x.id),["systeme:collecteur"]);
const later={...options,dernierSucces:now+15000};
assert.deepEqual(collect(fresh,watch,now+15000,later).map(x=>x.id),["systeme:veille"]);
assert.equal(collect(fresh,{...watch,echec:true})[0].id,"systeme:veille");
assert.equal(collect(fresh,{...watch,snapshot:{...watch.snapshot,age_ms:-1}})[0].id,"systeme:veille");
assert.equal(collect(fresh,{...watch,snapshot:{...watch.snapshot,active:false}})[0].id,"systeme:veille");
const cooling={...watch,snapshot:{...watch.snapshot,repli_cloud_secondes:5}};
assert.equal(collect(fresh,cooling)[0].id,"systeme:cloud");
assert.deepEqual(collect(fresh,cooling,now+5000,{...options,dernierSucces:now+5000}),[]);
const history={...fresh,incidents:[{id:"historic",statut:"a_revoir",mur_epoch_ms:1}]};
assert.equal(collect(history,null).length,2);
assert.deepEqual(collect(history).map(x=>x.id),["historic"]);
''')

    def test_display_is_bounded_without_hiding_total_count(self):
        self.run_js(r'''
donnees={...fresh,incidents:Array.from({length:10},(_,i)=>({id:"i"+i,titre:"Dossier "+i,statut:"a_revoir",mur_epoch_ms:i}))};
afficherAlertes();
assert.equal($("#alertes-liste").children.length,5);
assert.equal($("#alertes-nombre").textContent,"10 point(s) à examiner");
assert.match($("#alertes-page").textContent,/1–5 sur 10/);
assert.match($("#alertes-portee").textContent,/5 points au maximum par page/);
assert.match(contents($("#alertes-liste").children[0]),/Dossier 9/);
naviguerAlertes(1);
assert.match($("#alertes-page").textContent,/6–10 sur 10/);
assert.match(contents($("#alertes-liste").children[0]),/Dossier 4/);
assert.equal($("#alertes-suivantes").disabled,true);
naviguerAlertes(-1);
assert.match(contents($("#alertes-liste").children[0]),/Dossier 9/);
donnees=fresh;
afficherAlertes();
assert.match(contents($("#alertes-liste")),/ne garantit pas l’absence d’incident/);
assert.equal($("#alertes-nombre").textContent,"0 point(s) à examiner");
''')

    def test_collapsed_rows_preserve_open_state_all_observations_and_group_navigation(self):
        self.run_js(r'''
donnees={...fresh,incidents:[{id:'a',titre:'À vérifier',statut:'a_revoir',mur_epoch_ms:1,
 faits:Array.from({length:12},(_,i)=>'Observation '+i)}],
 decisions:[{id:'d',incident_id:'a',statut:'non_executee',faits:['Observation décision'],mur_epoch_ms:2}]};
afficherAlertes();
let row=$('#alertes-liste').children[0];assert.equal(row.tag,'details');assert.equal(row.open,false);
assert.ok(contents(row).includes('Observation 11'));assert.ok(contents(row).includes('Observation décision'));
row.open=true;row.ontoggle();
afficherAlertes();assert.equal($('#alertes-liste').children[0],row); // unchanged live data does not rebuild an open row
donnees.incidents[0].raison_publique='Motif actualisé';afficherAlertes();
assert.equal($('#alertes-liste').children[0].open,true);
regrouperAlertes('statut');assert.equal(alertesPage,0);
assert.match(contents($('#alertes-compteurs')),/Décisions à vérifier/);
assert.match($('#resume-alertes-detail').textContent,/1 dossier/);
assert.equal($('#resume-service').textContent,'À vérifier');
donnees.invite=[{service_temoin:{disponible:true,code:200,latence_ms:2}}];afficherAlertes();
assert.equal($('#resume-service').textContent,'Disponible');
echecCollecteur=true;afficherAlertes();assert.equal($('#resume-service').textContent,'À vérifier');
assert.match($('#resume-fraicheur').textContent,/État actuel non confirmé/);
''')

    def test_overview_and_secondary_panels_are_responsive_and_collapsed(self):
        html=HTML.read_text()
        self.assertLess(html.index('id="synthese-titre"'),html.index('id="alertes-titre"'))
        self.assertIn('grid-template-columns:repeat(4,minmax(0,1fr))',html)
        self.assertIn('.panneaux-secondaires { grid-template-columns:1fr;',html)
        self.assertIn('<details class="carte panneau" aria-labelledby="dispositions-titre"',html)
        self.assertNotIn('<details class="carte panneau" open',html)
        self.assertIn('g-resume-cpu',html);self.assertIn('Occupation totale · 0–100 %',html)
        self.assertIn('regrouperAlertes(e.target.value)',html)

    def test_registry_total_is_not_labelled_as_current_unresolved_incidents(self):
        html=HTML.read_text()
        panel='function incidentsDecisions'+html.split('function incidentsDecisions',1)[1].split('function afficherCloud',1)[0]
        self.assertIn('Cloud · cumul du journal',html)
        self.run_js(panel+r'''
donnees={...fresh,incidents:[{id:'open-registry',statut:'a_revoir',mur_epoch_ms:1},
 {id:'closed-registry',statut:'resolu',mur_epoch_ms:1}],
 decisions:[{id:'resolved-later',incident_id:'open-registry',statut:'verifie',mur_epoch_ms:2}]};
incidentsDecisions();
assert.equal($('#nb-incidents').textContent,'2 dossiers');
assert.match($('#incidents-resume').textContent,/1 au statut non clos dans le registre/);
assert.deepEqual(collect(donnees),[]);
''')

    def test_detection_reason_stays_separate_from_public_followup_in_both_views(self):
        html = HTML.read_text()
        panel = 'function incidentsDecisions' + html.split('function incidentsDecisions', 1)[1].split('function afficherCloud', 1)[0]
        self.run_js(panel + r'''
const detection = 'Trois inventaires réseau distincts signalent la même unité hors baseline.';
const incident = {id:'network',titre:'Séquence réseau hors baseline',statut:'observe',
  motif_detection:detection,faits:['Présence TCP répétée'],mur_epoch_ms:1};
donnees={...fresh,incidents:[incident]};
const row=collect(donnees)[0];
assert.equal(row.detection,detection);
assert.deepEqual(row.reasons,[]); // Le détecteur local n'est pas une analyse publique.
afficherAlertes();incidentsDecisions();
const summary=contents($('#alertes-liste').children[0].children[0]);
assert.match(summary,/Détection locale : Trois inventaires réseau/);
for(const node of [$('#alertes-liste'),$('#incidents-liste')]) {
  const rendered=contents(node);
  assert.ok(rendered.includes('Motif de détection locale : '+detection));
  assert.ok(rendered.includes('Suivi public non renseigné dans cet enregistrement.'));
  assert.ok(rendered.indexOf(detection)<rendered.indexOf('Suivi public non renseigné'));
  assert.doesNotMatch(rendered,/Raison publique non fournie|SAWM/);
}
donnees={...fresh,incidents:[{...incident,statut:'attente_budget',
  raison_publique:'Budget d’analyse Cloud épuisé : dossier en attente.'}]};
afficherAlertes();incidentsDecisions();
for(const node of [$('#alertes-liste'),$('#incidents-liste')]) {
  const rendered=contents(node);
  assert.ok(rendered.includes('Motif de détection locale : '+detection));
  assert.ok(rendered.includes('Suivi public : Budget d’analyse Cloud épuisé'));
  assert.doesNotMatch(rendered,/Suivi public non renseigné|SAWM/);
}
''')

    def test_detection_and_followup_are_plain_text_and_do_not_change_status_or_action(self):
        html = HTML.read_text()
        panel = 'function incidentsDecisions' + html.split('function incidentsDecisions', 1)[1].split('function afficherCloud', 1)[0]
        self.run_js(panel + r'''
const hostile='<img src=x onerror="alert(1)">';
donnees={...fresh,incidents:[{id:'i',titre:'Observation',statut:'a_revoir',motif_detection:hostile,
  raison_publique:'Vérification locale requise',mur_epoch_ms:1}],
  decisions:[{id:'d',incident_id:'i',statut:'non_executee',action:'arreter_unite',
    raison_publique:hostile,faits:[JSON.stringify({refus:'cible hors mandat'})],mur_epoch_ms:2}]};
const original=JSON.stringify(donnees);
afficherAlertes();incidentsDecisions();
const row=collect(donnees)[0];
assert.deepEqual(row.states,['a_revoir','non_executee']);
assert.equal(row.decision,'d');
assert.equal(row.detection,hostile);
assert.ok(row.reasons.includes('Refus : cible hors mandat'));
for(const node of [$('#alertes-liste'),$('#incidents-liste'),$('#decisions-liste')]) {
  assert.ok(contents(node).includes(hostile));
  assert.ok(!descendants(node).some(n=>['img','script','button','input'].includes(n.tag)));
}
assert.match(contents($('#alertes-liste')),/Suivi public : Vérification locale requise/);
assert.match(contents($('#decisions-liste')),/arreter_unite.*non_executee/);
assert.equal(JSON.stringify(donnees),original);
''')


if __name__ == "__main__":
    unittest.main()

"""Activity renders measured clocks and calls, separate from local dispositions."""
from pathlib import Path
import shutil
import subprocess
import unittest

HTML=Path(__file__).resolve().parents[1]/'controleur/tableau.html'


@unittest.skipUnless(shutil.which('node'),'Node required')
class ActivityDashboardTests(unittest.TestCase):
    def run_js(self,checks):
        html=HTML.read_text()
        helpers='function texte'+html.split('function texte',1)[1].split('function etat',1)[0]
        panel='function afficherActiviteAgent'+html.split('function afficherActiviteAgent',1)[1].split('function objetDisposition',1)[0]
        script=r'''
const assert=require('node:assert/strict');
class Element{constructor(tag){this.tag=tag;this.children=[];this.textContent='';}append(...nodes){this.children.push(...nodes);}replaceChildren(...nodes){this.children=nodes;}set innerHTML(_){throw Error('HTML interpretation forbidden');}}
const document={createElement:tag=>new Element(tag)},nodes=new Map();
function $(sel){if(!nodes.has(sel))nodes.set(sel,new Element('div'));return nodes.get(sel);}
const fini=v=>typeof v==='number'&&Number.isFinite(v),fmt=v=>fini(v)?String(v):'N/D',heure=fmt;
function contents(n){return n.textContent+n.children.map(contents).join(' ');}
const now=1800000000000;Date.now=()=>now;
const receipt={status:'http_ok',observed_ms:now-1000,fresh:true,http_status:200,latency_ms:426,attempt:1};
const activity={schema:'sawm-agent-activity/v1',observed_ms:now-20,phase:'attente_reponse_sawm',veille_fresh:true,local_observation_active:true,last_activity_ms:now-1000,
 engines:{tsst:receipt,odvl:{...receipt,latency_ms:167},sawm:{status:'not_observed',fresh:false}},
 memory:{observed_ms:now-1000,fresh:true,evidence_count:5,used_evidence_count:5,odvl_applied:true,reused:false}};
'''
        r=subprocess.run([shutil.which('node'),'-'],input=script+helpers+panel+checks,capture_output=True,text=True,timeout=10)
        self.assertEqual(r.returncode,0,r.stderr)

    def test_measured_activity_changes_phase_and_displays_real_memory_receipt(self):
        html=HTML.read_text();self.assertIn('afficherActiviteAgent(donnees?.activite_agent)',html)
        self.assertIn('Modèle fonctionnel simulé',html)
        self.run_js(r'''
afficherActiviteAgent(activity);
assert.equal($('#activite-agent-phase').textContent,'Réponse SAWM attendue');
assert.match(contents($('#activite-agent-moteurs')),/HTTP réussi · récent/);
assert.match(contents($('#activite-agent-moteurs')),/426 ms/);
assert.match(contents($('#activite-agent-moteurs')),/Aucun appel observé/);
assert.match($('#activite-agent-memoire').textContent,/5 preuves disponibles, 5 utilisées/);
afficherActiviteAgent({...activity,phase:'observation_locale',engines:{...activity.engines,sawm:{...receipt,status:'completed',terminal:'turn.done'}}});
assert.equal($('#activite-agent-phase').textContent,'Observation locale');
assert.match(contents($('#activite-agent-moteurs')),/Tour terminé · récent/);
''')

    def test_old_or_missing_receipt_never_becomes_current_engine_activity(self):
        self.run_js(r'''
afficherActiviteAgent({...activity,engines:{tsst:{...receipt,observed_ms:now-2400000,fresh:false}},memory:null});
assert.match(contents($('#activite-agent-moteurs')),/HTTP réussi · historique/);
assert.equal($('#activite-agent-moteurs').children[0].children[1].className,'petit doux');
assert.match($('#activite-agent-memoire').textContent,/Aucun rappel instrumenté reçu/);
afficherActiviteAgent({...activity,observed_ms:now-15001});
assert.equal($('#activite-agent-phase').textContent,'Activité actuelle non confirmée');
assert.match($('#activite-agent-memoire').textContent,/historique/);
afficherActiviteAgent(null);assert.match($('#activite-agent-source').textContent,/Aucune activité instrumentée/);
assert.doesNotMatch(contents($('#activite-agent-moteurs')),/426 ms/);
''')

    def test_hostile_event_names_remain_text_and_never_authorize_actions(self):
        self.run_js(r'''
const hostile='<img src=x onerror="alert(1)">';
afficherActiviteAgent({...activity,engines:{sawm:{...receipt,status:'completed',terminal:hostile}}});
assert.ok(contents($('#activite-agent-moteurs')).includes(hostile));
afficherActiviteAgent({...activity,phase:'budget_cloud_epuise'});
assert.equal($('#activite-agent-phase').textContent,'Budget Cloud atteint');
assert.equal($('#activite-agent-phase').className,'jeton etat-attention');
''')


if __name__=='__main__':unittest.main()

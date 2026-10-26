"""Public defence posture: truthful freshness, text-only rendering and bounded export."""
from pathlib import Path
import shutil
import subprocess
import unittest

HTML = Path(__file__).resolve().parents[1] / 'controleur/tableau.html'


@unittest.skipUnless(shutil.which('node'), 'Node requis pour le rendu DOM')
class DefenseProfondeurDashboardTests(unittest.TestCase):
    def run_js(self, checks):
        html = HTML.read_text()
        helpers = 'function texte' + html.split('function texte', 1)[1].split('function etat', 1)[0]
        panel = html.split('// DEBUT DEFENSE PROFONDEUR', 1)[1].split('// FIN DEFENSE PROFONDEUR', 1)[0]
        script = r'''
const assert = require('node:assert/strict');
class Element {
  constructor(tag) { this.tag=tag;this.children=[];this.textContent='';this.style={};this.attrs={};this.disabled=false; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children=nodes;this.textContent=''; }
  setAttribute(key,value) { this.attrs[key]=value; }
  set innerHTML(_) { throw Error('HTML interpretation forbidden'); }
  click() { downloads.push({href:this.href,download:this.download}); }
  remove() {}
}
const downloads=[],blobs=[],revoked=[];
const document={createElement:tag=>new Element(tag),body:new Element('body')},nodes=new Map();
function $(selector) { if(!nodes.has(selector))nodes.set(selector,new Element('div'));return nodes.get(selector); }
function contents(n) { return n.textContent+n.children.map(contents).join(' '); }
const fini=v=>typeof v==='number'&&Number.isFinite(v),heure=v=>fini(v)?String(v):'N/D';
let now=1800000000000;Date.now=()=>now;
const URL={createObjectURL(blob){blobs.push(blob);return 'blob:test';},revokeObjectURL(url){revoked.push(url);}};
const setTimeout=callback=>callback();
const snapshot={schema:'sawm-defense-profondeur/v1',observed_ms:now-100,profile:'industrial-observation',
 enabled:true,manifest_sha256:'a'.repeat(64),certification:false,stale:false,
 checks:['satisfait','ecart','inconnu','non_applicable'].map((status,index)=>({
  id:'control-'+index,title:'Contrôle '+index,status,source:'capteur-'+index,reason:'Motif '+index,observed_ms:now-200})),
 counts:{satisfait:1,ecart:1,inconnu:1,non_applicable:1}};
'''
        result = subprocess.run([shutil.which('node'), '-'], input=script + helpers + panel + checks,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_current_posture_displays_counts_sources_dates_and_monochrome_graph(self):
        self.run_js(r'''
afficherDefenseProfondeur(snapshot);
assert.equal($('#defense-profondeur-statut').textContent,'1 écart(s) à examiner');
assert.match($('#defense-profondeur-source').textContent,/industrial-observation.*profil d’intervention activé.*observation récente/);
assert.match(contents($('#defense-profondeur-compteurs')),/1\s*Satisfait.*1\s*Écart.*1\s*Inconnu.*1\s*Non applicable/);
assert.equal($('#defense-profondeur-barre').children.length,4);
assert.ok($('#defense-profondeur-barre').children.every(item=>item.style.width==='25.00%'));
assert.match($('#defense-profondeur-barre').attrs['aria-label'],/Satisfait : 1.*Inconnu : 1/);
assert.match(contents($('#defense-profondeur-controles')),/Contrôle 0 · control-0.*Satisfait.*capteur-0.*Motif 0.*1799999999800/);
assert.equal($('#defense-profondeur-export').disabled,false);
''')

    def test_old_future_or_server_stale_snapshot_never_retains_success(self):
        self.run_js(r'''
afficherDefenseProfondeur(snapshot);now+=15001;actualiserDefenseProfondeur();
assert.equal($('#defense-profondeur-statut').textContent,'État inconnu');
assert.match(contents($('#defense-profondeur-compteurs')),/0\s*Satisfait.*4\s*Inconnu/);
assert.doesNotMatch(contents($('#defense-profondeur-controles')),/Satisfait/);
assert.equal($('#defense-profondeur-export').disabled,true);assert.equal(exporterDefenseProfondeur(),false);
now=1800000000000;
for(const bad of [{...snapshot,stale:true},{...snapshot,observed_ms:now+1}]) {
 afficherDefenseProfondeur(bad);
 assert.equal($('#defense-profondeur-statut').textContent,'État inconnu');
 assert.equal($('#defense-profondeur-export').disabled,true);
 assert.doesNotMatch(contents($('#defense-profondeur-controles')),/Satisfait/);
}
assert.equal(blobs.length,0);
''')

    def test_absent_or_malformed_payload_clears_old_data_and_rejects_fake_certification(self):
        self.run_js(r'''
const bads=[null,{}, {...snapshot,schema:'forged'}, {...snapshot,certification:true},
 {...snapshot,counts:{...snapshot.counts,satisfait:99}}, {...snapshot,checks:[]},
 {...snapshot,checks:[snapshot.checks[0],snapshot.checks[0]]},
 {...snapshot,checks:snapshot.checks.map((row,index)=>index?row:{...row,status:'conforme'})}];
for(const bad of bads) {
 afficherDefenseProfondeur(snapshot);afficherDefenseProfondeur(bad);
 assert.equal($('#defense-profondeur-statut').textContent,'État inconnu');
 assert.equal($('#defense-profondeur-export').disabled,true);
 assert.match(contents($('#defense-profondeur-compteurs')),/N\/D/);
 assert.doesNotMatch(contents($('#defense-profondeur-controles')),/capteur-0|Motif 0/);
 assert.equal(exporterDefenseProfondeur(),false);
}
''')

    def test_hostile_content_is_text_and_export_contains_only_public_contract(self):
        self.run_js(r'''
const hostile='<img src=x onerror="alert(1)">';
const raw={...snapshot,private_key:'must-not-export',checks:snapshot.checks.map(row=>({...row,
 title:hostile,source:hostile,reason:hostile,private_payload:'must-not-export'}))};
afficherDefenseProfondeur(raw);
assert.ok(contents($('#defense-profondeur-controles')).includes(hostile));
assert.equal(exporterDefenseProfondeur(),true);
assert.deepEqual(downloads,[{href:'blob:test',download:'sawm-basira-defense-profondeur.json'}]);
assert.deepEqual(revoked,['blob:test']);
(async()=>{
 const text=await blobs[0].text(),data=JSON.parse(text);
 assert.doesNotMatch(text,/must-not-export|private_key|private_payload/);
 assert.equal(data.certification,false);assert.equal(data.checks[0].reason,hostile);
 assert.deepEqual(data.counts,snapshot.counts);assert.equal(data.exported_at_ms,now);
})().catch(error=>{console.error(error);process.exitCode=1;});
''')

    def test_observation_profile_can_export_without_authorizing_intervention(self):
        self.run_js(r'''
afficherDefenseProfondeur({...snapshot,enabled:false});
assert.match($('#defense-profondeur-source').textContent,/profil d’intervention non activé/);
assert.equal($('#defense-profondeur-export').disabled,false);
assert.equal(exporterDefenseProfondeur(),true);
(async()=>{const data=JSON.parse(await blobs[0].text());assert.equal(data.enabled,false);assert.equal(data.certification,false);})()
.catch(error=>{console.error(error);process.exitCode=1;});
''')

    def test_panel_is_collapsible_and_security_fetch_resets_it_on_failure(self):
        html = HTML.read_text()
        self.assertIn('<details class="carte panneau" aria-labelledby="defense-profondeur-titre"', html)
        self.assertIn('setInterval(actualiserDefenseProfondeur, 1000)', html)
        charger = html.split('async function chargerSecurite()', 1)[1].split('async function rafraichir()', 1)[0]
        self.assertIn('afficherDefenseProfondeur(v.defense_profondeur)', charger)
        self.assertIn('afficherDefenseProfondeur(null)', charger.split('catch (_)', 1)[1])
        self.assertIn('pas une certification ISO ou IEC', html)

    def test_real_backend_contract_renders_with_zero_counts_and_unavailable_measurements(self):
        import json
        from controleur.defense_profondeur import evaluate, project
        manifest=json.loads((HTML.parents[1]/'config/manifeste.observation.json').read_text())
        manifest['_sha256']='a'*64
        payload=project(evaluate(manifest,{},now_ms=1800000000000),now_ms=1800000000000)
        self.run_js('const backend='+json.dumps(payload,ensure_ascii=True)+';'+r'''
afficherDefenseProfondeur(backend);
assert.notEqual(normaliserDefenseProfondeur(backend),null);
assert.equal($('#defense-profondeur-controles').children.length,22);
assert.match(contents($('#defense-profondeur-compteurs')),/Inconnu/);
assert.equal($('#defense-profondeur-export').disabled,false);
''')


if __name__ == '__main__':
    unittest.main()

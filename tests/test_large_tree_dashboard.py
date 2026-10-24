"""DOM regression: honest scan freshness, bounded text and GeoIP attribution."""
from pathlib import Path
import shutil
import subprocess
import unittest

HTML=Path(__file__).resolve().parents[1]/'controleur/tableau.html'


@unittest.skipUnless(shutil.which('node'),'Node required for DOM checks')
class LargeTreeDashboardTests(unittest.TestCase):
    def run_js(self,checks):
        html=HTML.read_text()
        helpers='function texte'+html.split('function texte',1)[1].split('function etat',1)[0]
        panel='function texteGeographie'+html.split('function texteGeographie',1)[1].split('function afficherDefenseFichiers',1)[0]
        script=r'''
const assert=require('node:assert/strict');
class Element {
 constructor(tag){this.tag=tag;this.children=[];this.textContent='';}
 append(...nodes){this.children.push(...nodes);}
 replaceChildren(...nodes){this.children=nodes;}
 set innerHTML(_){throw Error('HTML interpretation forbidden');}
}
const document={createElement:tag=>new Element(tag)},nodes=new Map();
function $(sel){if(!nodes.has(sel))nodes.set(sel,new Element('div'));return nodes.get(sel);}
const fini=v=>typeof v==='number'&&Number.isFinite(v);
const fmt=v=>fini(v)?String(v):'N/D',heure=fmt,octets=fmt;
const now=1800000000000;Date.now=()=>now;
function contents(n){return n.textContent+n.children.map(contents).join(' ');}
const s={schema:'sawm-large-tree-integrity/v1',status:'unchanged',root:'/fixture/tree',observed_ms:now-100,
 counts:{},changes:[],metrics:{bytes_read:1207959552,files:22,scan_seconds:18,cpu_seconds:2.3,process_peak_rss_bytes:17956864}};
'''
        p=subprocess.run([shutil.which('node'),'-'],input=script+helpers+panel+checks,capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,0,p.stderr)

    def test_last_scan_is_not_continuous_protection_and_old_data_is_visible(self):
        html=HTML.read_text();self.assertIn('sans surveillance continue',html)
        self.assertIn('afficherIntegriteArbres(e);',html)
        self.run_js(r'''
afficherIntegriteArbres({integrite_arbres:{available:true,snapshot:s}});
assert.match($('#integrite-arbres-etat').textContent,/dernier scan/);
assert.equal($('#integrite-arbres-etat').className,'jeton etat-ok');
assert.match($('#integrite-arbres-mesures').textContent,/CPU cumulé 2.3 s/);
afficherIntegriteArbres({integrite_arbres:{available:true,snapshot:{...s,observed_ms:now-300001}}});
assert.match($('#integrite-arbres-etat').textContent,/ancien/);
assert.equal($('#integrite-arbres-etat').className,'jeton etat-attention');
afficherIntegriteArbres({integrite_arbres:{available:true,snapshot:{...s,observed_ms:now+1}}});
assert.match($('#integrite-arbres-etat').textContent,/Aucun scan vérifiable/);
assert.equal(contents($('#integrite-arbres-changements')),'');
''')

    def test_hostile_paths_are_plain_text_and_display_is_bounded(self):
        self.run_js(r'''
const hostile='<img src=x onerror="alert(1)">';
afficherIntegriteArbres({integrite_arbres:{available:true,snapshot:{...s,status:'changed',counts:{added:40},
 changes:Array.from({length:40},()=>({kind:'added',path:hostile}))}}});
assert.match(contents($('#integrite-arbres-changements')),/Ajout : 40/);
assert.ok(contents($('#integrite-arbres-changements')).includes(hostile));
assert.equal($('#integrite-arbres-changements').children.length,22);
assert.match(contents($('#integrite-arbres-changements')),/Liste abrégée/);
assert.equal($('#integrite-arbres-etat').className,'jeton etat-ko');
''')

    def test_geoip_is_live_local_approximate_private_unknown_and_attributed(self):
        html=HTML.read_text()
        self.assertIn('href="https://db-ip.com"',html);self.assertIn('IP Geolocation by DB-IP',html)
        self.assertIn('Aucun blocage n’est déduit du pays',html)
        self.run_js(r'''
afficherGeographie({authentification:{geoip:{available:true,source:{release:'2026-09'}},
 events:[{source_ip:'8.8.8.8',geolocalisation:{status:'approximatif',country_code:'US'}},
 {source_ip:'192.0.2.1',geolocalisation:{status:'non_localisable'}}]},
 ssh:{geoip:{available:false},events:[{source_ip:'<script>x</script>',geolocalisation:{status:'inconnu'}}]}});
const text=contents($('#defense-geographie'));
assert.match(text,/pays approximatif : US/);assert.match(text,/non localisable/);
assert.match(text,/localisation inconnue/);assert.match(text,/version 2026-09/);
assert.ok(text.includes('<script>x</script>'));
afficherGeographie({});assert.match(contents($('#defense-geographie')),/Aucune adresse récente/);
assert.doesNotMatch(contents($('#defense-geographie')),/8.8.8.8/);
''')

    def test_extension_report_links_are_local_and_invalid_report_clears_old_results(self):
        html=HTML.read_text()
        panel='function lienPreuveExtension'+html.split('function lienPreuveExtension',1)[1].split('async function chargerExtensions',1)[0]
        self.assertIn('defense-extensions-20260924.json',html)
        self.assertIn('chargerDefenseSignee(), chargerExtensions()',html)
        self.run_js(panel+r'''
const hostile='<img src=x onerror="alert(1)">';
afficherExtensions({schema:'sawm-defense-extensions/v1',generated_at:'2026-09-24T10:00:00Z',
 software_tests:{passed:12,total:13},report_pdf:'releves/rapports/SAWM-defense-extensions-2026-09-24.pdf',
 items:[{name:hostile,status:'limited',summary:hostile,proof:'releves/rapports/proof.json'},
 {name:'Pending',status:'pending',summary:'No proof',proof:'https://evil.example/x'},
 {name:'Traversal',status:'tested',summary:'No external link',proof:'releves/rapports/../secret.json'}]});
assert.match($('#extensions-tests').textContent,/12 \/ 13/);
assert.equal($('#extensions-tests').className,'jeton etat-attention');
assert.ok(contents($('#extensions-resultats')).includes(hostile));
assert.match(contents($('#extensions-resultats')),/Capacité limitée/);
assert.equal($('#extensions-resultats').children[0].children.at(-1).href,'/api/preuve?f=releves%2Frapports%2Fproof.json');
assert.match(contents($('#extensions-resultats').children[1]),/Preuve non disponible/);
assert.match(contents($('#extensions-resultats').children[2]),/Preuve non disponible/);
assert.equal(lienPreuveExtension('javascript:alert(1)'),null);
assert.equal(lienPreuveExtension('releves/rapports/%2e%2e/secret.json'),null);
assert.equal($('#extensions-rapport').children.length,1);
afficherExtensions({schema:'forged',items:[]});
assert.equal($('#extensions-resultats').children.length,0);
assert.equal($('#extensions-rapport').children.length,0);
assert.match($('#extensions-source').textContent,/indisponible/);
''')


if __name__=='__main__':unittest.main()

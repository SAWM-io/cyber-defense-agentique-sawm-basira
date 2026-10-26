"""Current autonomy evidence: real file discovery, no Cloud/VM and safe DOM rendering."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from controleur import collecteur as c

ROOT=Path(__file__).resolve().parents[1]


class AutonomieDashboardTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve()
        self.reports=self.root/'releves/rapports';self.reports.mkdir(parents=True)

    def report(self, identity='depth-0123456789', *, status='passed', origin='local_guard', started=1000):
        return {'schema':'sawm-autonomy-depth-validation/v1','id':identity,'case':'lock',
            'origin':origin,'status':status,'started_ms':started,'finished_ms':started+10,
            'cloud_requested':origin=='sawm_pipeline','local_guard_effect_applied':origin=='local_guard',
            'sawm_effect_applied':origin=='sawm_pipeline','cloud_rounds_reserved':int(origin=='sawm_pipeline'),
            'sawm_choice':{'action':'arreter-service','reason':'Public reason'},
            'local_guard_receipt':{'action':'arreter-service','applique':True,'effet_verifie':True},
            'after_before_cleanup':{'read_available':True,'write_available':True,'reference_matches':False},
            'witness':{'healthy':True},'local_boundaries':[{'case':'missing_ticket','status':'passed',
                'origin':'local_executor_negative_test','receipt':{'applique':False,'refus':{'motif':'ticket_absent'}}}],
            'cleanup':{'origin':'operator_cleanup_never_counted_as_defense',
                       'steps':[{'step':'restore_fixture','status':'passed'}]},'limits':['Synthetic fixture only.']}

    def save(self, obj):
        path=self.reports/('validation-autonomie-profondeur-'+obj['id']+'.json')
        path.write_text(json.dumps(obj));return path

    def read(self):return c.lire_autonomie_profondeur(self.root)

    def test_empty_does_not_reuse_old_september_campaign(self):
        (self.reports/'campagne-defense-20260923.json').write_text('{"status":"passed"}')
        result=self.read();self.assertEqual(result['status'],'not_run');self.assertEqual(result['reports'],[])

    def test_later_success_does_not_hide_failed_or_blocked_cloud_runs(self):
        for identity,status,origin,stamp in [('depth-aaaaaaaaaa','failed','sawm_pipeline',1000),
            ('depth-bbbbbbbbbb','passed','local_guard',2000),('depth-cccccccccc','blocked','sawm_pipeline',3000)]:
            self.save(self.report(identity,status=status,origin=origin,started=stamp))
        with patch.object(c.subprocess,'run',side_effect=AssertionError('no external commands')):
            result=self.read()
        self.assertEqual([r['status'] for r in result['reports']],['blocked','passed','failed'])
        self.assertEqual([r['origin'] for r in result['reports']],['sawm_pipeline','local_guard','sawm_pipeline'])
        self.assertEqual(result['latest_ms'],3010)

    def test_public_projection_separates_cleanup_and_strips_unknown_fields(self):
        report=self.report();report['private_key']='DO_NOT_FORWARD'
        report['local_guard_receipt']['expected_identity']={'secret':'DO_NOT_FORWARD'}
        report['sawm_choice']['raw_reasoning']='DO_NOT_FORWARD'
        report['after_before_cleanup']['fixture']='DO_NOT_FORWARD'
        path=self.save(report);before=path.read_bytes();row=self.read()['reports'][0]
        self.assertNotIn('DO_NOT_FORWARD',json.dumps(row))
        self.assertFalse(row['after_before_cleanup']['reference_matches'])
        self.assertEqual(row['cleanup']['steps'][0]['status'],'passed')
        self.assertTrue(row['local_receipt']['effet_verifie'])
        self.assertEqual(row['local_boundaries'][0]['receipt']['refusal']['motif'],'ticket_absent')
        self.assertEqual(path.read_bytes(),before)

    def test_bad_and_symlinked_report_remain_visible_without_contents(self):
        good=self.save(self.report())
        bad=self.save(self.report('depth-aaaaaaaaaa'));bad.write_text('{')
        target=self.root/'private.json';target.write_text('PRIVATE_CONTENT')
        link=self.reports/'validation-autonomie-profondeur-depth-bbbbbbbbbb.json';link.symlink_to(target)
        rows=self.read()['reports']
        self.assertEqual(sorted(r['status'] for r in rows),['invalid','invalid','passed'])
        self.assertNotIn('PRIVATE_CONTENT',json.dumps(rows))
        bad.write_bytes(b' '*(c.MAX_CAMPAGNE_DEFENSE+1))
        self.assertEqual(next(r for r in self.read()['reports'] if r['id']=='depth-aaaaaaaaaa')['status'],'invalid')
        self.assertTrue(good.exists())

    def test_symlinked_report_directory_and_false_type_fail_closed(self):
        report=self.report();report['sawm_effect_applied']='false';self.save(report)
        self.assertEqual(self.read()['reports'][0]['status'],'invalid')
        self.reports.rename(self.root/'outside');self.reports.symlink_to(self.root/'outside',target_is_directory=True)
        self.assertEqual(self.read()['status'],'invalid')

    def test_bounded_latest_files_expose_omitted_count(self):
        for number in range(43):self.save(self.report('depth-'+f'{number:010x}',started=number*100+1))
        result=self.read();self.assertEqual(len(result['reports']),40);self.assertEqual(result['omitted'],3)

    def test_http_read_only_rejects_user_paths_and_does_not_cache(self):
        self.save(self.report())
        with patch.object(c.Etat,'_versions',return_value={}):state=c.Etat('test',series=self.root/'series',racine=self.root)
        handler=type('Handler',(c.Service,),{'etat':state})
        server=ThreadingHTTPServer(('127.0.0.1',0),handler)
        worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
        try:
            url=f'http://127.0.0.1:{server.server_port}/api/autonomie-profondeur'
            with urllib.request.urlopen(url,timeout=2) as response:
                self.assertEqual(response.headers['Cache-Control'],'no-store')
                self.assertEqual(json.load(response)['reports'][0]['status'],'passed')
            for query in ('?f=/etc/passwd','?path=../../secret'):
                with self.assertRaises(urllib.error.HTTPError) as error:urllib.request.urlopen(url+query,timeout=2)
                self.assertEqual(error.exception.code,400);error.exception.close()
            request=urllib.request.Request(url,data=b'{}',headers={'Content-Type':'application/json'})
            with self.assertRaises(urllib.error.HTTPError) as error:urllib.request.urlopen(request,timeout=2)
            self.assertEqual(error.exception.code,404);error.exception.close()
        finally:server.shutdown();server.server_close();worker.join(2)

    @unittest.skipUnless(shutil.which('node'),'Node required for DOM test')
    def test_dom_preserves_failure_attribution_expansion_and_untrusted_text(self):
        html=(ROOT/'controleur/tableau.html').read_text()
        helpers='function texte'+html.split('function texte',1)[1].split('function etat',1)[0]
        campaign='function statutCampagne'+html.split('function statutCampagne',1)[1].split('function resumeReferencesCampagne',1)[0]
        panel=html.split('// DEBUT CAMPAGNE AUTONOMIE',1)[1].split('// FIN CAMPAGNE AUTONOMIE',1)[0]
        hostile='<img src=x onerror=alert(1)>'
        local=self.report();local['local_guard_diagnostic']={'raison':hostile}
        self.save(local);cloud=self.report('depth-aaaaaaaaaa',origin='sawm_pipeline',status='failed',started=2000)
        cloud['sawm_choice']['reason']=hostile;cloud['sawm_effect_applied']=False;self.save(cloud)
        data=self.read()
        script=r'''
const assert=require('node:assert/strict');
class Element {
 constructor(tag){this.tag=tag;this.children=[];this.dataset={};this.textContent='';}
 append(...nodes){this.children.push(...nodes);}
 replaceChildren(...nodes){this.children=nodes;}
 querySelectorAll(){return this.children.filter(n=>n.tag==='details' && n.open);}
 set innerHTML(_){throw Error('unsafe HTML');}
}
const document={createElement:tag=>new Element(tag)},nodes=new Map();
function $(s){if(!nodes.has(s))nodes.set(s,new Element('div'));return nodes.get(s);}
function fini(x){return typeof x==='number' && Number.isFinite(x);}
function heure(x){return 'time-'+x;}
function contents(x){return x.textContent+x.children.map(contents).join(' ');}
'''+helpers+campaign+panel+'\nconst report='+json.dumps(data)+';afficherAutonomie(report);'+r'''
const box=$('#autonomie-cas');
assert.equal(box.children.length,2);
assert.match(contents($('#autonomie-compteurs')),/Garde locale signée : 1 validés \/ 1 essais/);
assert.match(contents($('#autonomie-compteurs')),/Pipeline SAWM Cloud : 0 validés \/ 1 essais/);
assert.match(contents(box),/<img src=x onerror=alert\(1\)>/);
assert.match(contents(box),/Avant nettoyage · empreinte conforme : non/);
assert.match(contents(box),/Nettoyage opérateur distinct/);
assert.match(contents(box),/Choix SAWM : arreter-service/);
assert.match(contents(box),/Action SAWM appliquée : non/);
box.children[0].open=true;const original=box.children[0];
afficherAutonomie(report);assert.equal(box.children[0],original);
report.latest_ms+=1;afficherAutonomie(report);assert.equal(box.children[0].open,true);
afficherAutonomie({status:'invalid',reports:[],latest_ms:null,error:'Refresh failed'});
assert.doesNotMatch(contents(box),/Choix SAWM : arreter-service/);
assert.match(contents($('#autonomie-erreur')),/Refresh failed/);
'''
        result=subprocess.run([shutil.which('node'),'-'],input=script,text=True,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)


if __name__=='__main__':unittest.main()

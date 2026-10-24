"""Comparaison des contextes sur archives; tests entierement hors ligne."""
import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from controleur import validation_ablations as v
from connecteur.pont_memoire import Rappel
from connecteur.contrat import Proposition
from connecteur.tour_sawm import Decision, TourSawm


def source_report(allowed, *, stamp='2026-09-22T12:00:00+00:00'):
    run='source-allowed' if allowed else 'source-denied'
    return {'type':'transfert','run_id':run,'mandat_autorise':allowed,'debut':stamp,
        'succes_mesure':True,'resultat_futur':'NE_PAS_TRANSMETTRE_LE_VERDICT',
        'etapes':[{'phase':'avant_analyse','snapshot':{'mur_epoch_ms':1789999999000,
            'recepteur':{'flux':{'a':{'run_id':run,'source_id':'source-a','recus':10},
                                'b':{'run_id':run,'source_id':'source-b','recus':20}}},
            'sockets':'connexion locale observee','temoin':{'code':200}}},
            {'phase':'verification','snapshot':{'resultat':'NE_PAS_TRANSMETTRE_LA_SUITE'}}]}


class AblationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory=pathlib.Path(self.tmp.name)
        for allowed,name in ((True,'a'),(False,'b')):
            (self.directory/f'experience-vm-{name}.json').write_text(json.dumps(source_report(allowed)))

    def test_selects_latest_explicit_mandates_without_success_filter(self):
        newer=source_report(True,stamp='2026-09-22T13:00:00+00:00')
        newer['succes_mesure']=False
        latest=self.directory/'experience-vm-latest.json'
        latest.write_text(json.dumps(newer))
        selected=v.selectionner(self.directory)
        self.assertEqual(selected[True][0],latest)
        self.assertFalse(selected[True][1]['succes_mesure'])
        self.assertFalse(selected[False][1]['mandat_autorise'])

    def test_freezes_initial_measurements_and_excludes_future_verdicts(self):
        path=self.directory/'experience-vm-a.json'
        case=v.figer_faits(path,json.loads(path.read_text()))
        self.assertEqual(case['faits'][0]['octets_recus'],20)
        prompt=v.message(case,[])
        self.assertNotIn('NE_PAS_TRANSMETTRE',prompt)
        self.assertIn('2026',case['survenu_a'])
        self.assertEqual(len(case['source_sha256']),64)

    def test_six_bounded_turns_reuse_frozen_facts_and_public_odvl_order(self):
        events=[]
        a={'evidence_id':'ev_'+'a'*32,'score':0.0,'integrity_verified':True,'excerpt':'PREUVE_A'}
        b={'evidence_id':'ev_'+'b'*32,'score':0.8,'integrity_verified':True,'excerpt':'PREUVE_B'}
        excluded={'evidence_id':'ev-bad','score':None,'integrity_verified':False,'excerpt':'REFUSEE'}
        pont=Mock()
        pont.rappeler.side_effect=lambda *a_,**kw:(events.append('recall') or Rappel('connecteur',(a,b,excluded),4,'tsst'))
        pont.hierarchiser.side_effect=lambda rows:(events.append('odvl') or {
            'schema':'basira-odvl-ranking/v1','ranking_applied':True,'reordered':True,
            'ranking':[{'candidate_id':b['evidence_id'],'rank':1,'score':0.8},
                       {'candidate_id':a['evidence_id'],'rank':2,'score':0.0}]})
        prompts=[]
        real_composer=TourSawm.composer_message
        class FakeTour:
            composer_message=staticmethod(real_composer)
            def __init__(self,p,session_id):self.session_id=session_id
            def jouer(self,prompt,**kw):
                events.append('turn')
                prompts.append((prompt,kw))
                return Decision('dec-'+str(len(prompts)),kw['turn_id'],self.session_id,
                    Proposition('ne-rien-faire',None,'Proposition pour comparaison hors ligne.',0.7),
                    None,'{}',('turn.done',),12.0,False,{'evidence_count':2},
                    {'type':'usage.final','total_tokens':15},None,
                    preuves_connecteur=tuple(kw['preuves_connecteur']))
        with patch.object(v,'PontMemoire',return_value=pont),patch.object(v,'TourSawm',FakeTour),contextlib.redirect_stdout(io.StringIO()):
            result=v.comparer(reports_dir=self.directory)
        self.assertEqual(events[:4],['recall','odvl','recall','odvl'])
        self.assertEqual(events[4:],['turn']*6)
        self.assertEqual(len(prompts),6)
        self.assertEqual([len(kw['preuves_connecteur']) for _,kw in prompts],[0,2,2,0,2,2])
        for start in (0,3):
            self.assertNotIn('PREUVE_A',prompts[start][0])
            self.assertLess(prompts[start+1][0].index('PREUVE_A'),prompts[start+1][0].index('PREUVE_B'))
            self.assertLess(prompts[start+2][0].index('PREUVE_B'),prompts[start+2][0].index('PREUVE_A'))
        self.assertTrue(all(kw['max_tokens']==600 for _,kw in prompts))
        self.assertTrue(all(kw['cibles_autorisees']=={'labo-copie-b.service'} for _,kw in prompts))
        self.assertTrue(all('REFUSEE' not in p and 'NE_PAS_TRANSMETTRE' not in p for p,_ in prompts))
        self.assertEqual(result['actions_os_executees'],0)
        self.assertEqual(result['rappel_natif_sawm'],'actif_non_ablate')
        self.assertEqual(result['gain_statistique'],'non_estime')
        self.assertTrue(result['recette_complete'])
        for case in result['cas']:
            self.assertEqual(case['memoire']['preuves_exclues_integrite'],1)
            self.assertEqual(len({row['faits_sha256'] for row in case['resultats']}),1)
        pont.deposer.assert_not_called()
        pont.close.assert_called_once()

    def test_invalid_odvl_stops_before_any_inference_instead_of_faking_order(self):
        pont=Mock()
        pont.rappeler.return_value=Rappel('connecteur',({'evidence_id':'ev-good','score':.4},),1)
        pont.hierarchiser.return_value={'schema':'basira-odvl-ranking/v1',
            'ranking':[{'candidate_id':'ev-invented','rank':1}]}
        with patch.object(v,'PontMemoire',return_value=pont),patch.object(v,'TourSawm') as tour,contextlib.redirect_stdout(io.StringIO()):
            result=v.comparer(reports_dir=self.directory)
        self.assertFalse(result['recette_complete'])
        self.assertEqual(result['comparaisons'],[])
        self.assertEqual(result['erreur']['type'],'ValueError')
        tour.assert_not_called()
        pont.deposer.assert_not_called()


if __name__=='__main__':unittest.main()

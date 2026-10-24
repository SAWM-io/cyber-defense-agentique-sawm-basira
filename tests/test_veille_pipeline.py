"""Exerce la jointure décision→droits→exécution→contrôle→mémoire sans Cloud/VM."""
import json,pathlib,sys,tempfile,time,types,unittest
from unittest.mock import patch,Mock
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from controleur import veille as v,validation,verification_action
from connecteur.pont_memoire import PontMemoire

class PipelineTest(unittest.TestCase):
 def run_case(self,target='labo-copie-b.service'):
  with tempfile.TemporaryDirectory() as td:
   journal=v.Journal(pathlib.Path(td).resolve())
   try:
    unit='labo-copie-b.service';cg='0::/sawm.slice/sawm-charge.slice/'+unit
    ident={'boot_id':'boot','pid':42,'starttime':123,'cgroup':cg}
    inc=v.evenement('sequence_reseau_hors_baseline','i',[{'identite_os':ident}],unite=unit,analysable=True)
    m={'generation':'g','_sha256':'a'*64,'unites_autorisees':[unit],
       'veille':{'actions_automatiques':['geler-transfert'],'unites_connues':[], 'sources_connues':[], 'reseau_hors_baseline_autorise':False}}
    e={'mode':'DIRECT','telemetrie_invite':{'connectee':True,'age_ms':20},
       'invite':[{'boot_id':'boot','connexions':[{**ident}]}]}
    prop=types.SimpleNamespace(action='geler-transfert',cible=target,justification='preuve',confiance=.6,inconnues=[])
    d=types.SimpleNamespace(executable=True,proposition=prop,decision_id='decision-test',refus=None,resume=lambda:{'action':'geler-transfert'})
    published=[]
    def post(route,obj=None):
     if obj is None:return e
     published.append((route,obj));return {}
    veille=v.Veille(m,journal,cloud=True,appliquer=True,poster=post,lire_manifest=lambda:m,fin=time.monotonic()+300)
    pont=Mock(espace='space-test',entite='entity-test');pont.deposer.return_value={'accepted':True}
    verification={'statut':'verifie','effet':'arret_unite_verifie','temoin':'disponible','reseau':'non_attribue'}
    with patch('connecteur.pont_memoire.PontMemoire',return_value=pont),patch.object(validation,'decision_cloud',return_value=(d,{})), \
         patch.object(validation,'execute',return_value={'applique':True}) as execute, \
         patch.object(verification_action,'observer_ressource',return_value={'snapshot':'avant'}), \
         patch.object(verification_action,'verifier_action',return_value=verification):
     veille.analyser_cloud(inc)
    return [json.loads(l) for l in journal.path.read_text().splitlines()],published,execute,pont
   finally:journal.close()
 def test_effect_checked_then_deposited_as_return(self):
  log,published,execute,pont=self.run_case()
  self.assertEqual([x['type'] for x in log],['disposition_serveur','decision','avant_execution','recu_execution','verification_action','retour_memoire'])
  self.assertEqual(execute.call_args.kwargs,{'attendu':{'snapshot':'avant'}})
  feedback=json.loads(pont.deposer.call_args.args[0][0]['contenu'])
  self.assertEqual(feedback['verification']['temoin'],'disponible')
  self.assertTrue(any(o.get('statut')=='resolu' for _,o in published))
 def test_model_cannot_stop_outside_target(self):
  log,published,execute,pont=self.run_case('labo-temoin.service')
  execute.assert_not_called();pont.deposer.assert_not_called()
  self.assertEqual(log[-1]['motif'],'cible_absente_ou_non_correllee')

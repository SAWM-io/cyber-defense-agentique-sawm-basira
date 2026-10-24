"""Raccordement TSST -> ODVL -> proposition, sans réseau ni VM."""
import copy
import json
import pathlib
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from controleur import validation
from connecteur.contrat import Proposition
from connecteur.pont_memoire import Rappel
from connecteur.tour_sawm import Decision, TourSawm


class DecisionCloudTests(unittest.TestCase):
    def setUp(self):
        self.a={'evidence_id':'ev_'+'a'*32,'candidate_id':'assertion-A','score':0.0,'excerpt':'preuve A'}
        self.b={'evidence_id':'ev_'+'b'*32,'score':0.9,'excerpt':'preuve B'}
        self.pont=Mock()
        self.pont.deposer.return_value={'jobs':[{'statut':'completed'}]}
        self.pont.rappeler.return_value=Rappel('connecteur',(self.a,self.b),12.0)
        self.pont.hierarchiser.return_value={
            'schema':'basira-odvl-ranking/v1','count':2,'reordered':True,'ranking_applied':True,
            'ranking':[{'candidate_id':self.b['evidence_id'],'score':0.9,'rank':1},
                       {'candidate_id':'assertion-A','score':0.0,'rank':2}],
        }
        self.decision=Decision('dec-test','turn-test','session-test',
            Proposition('ne-rien-faire',None,'Aucun effet système nécessaire.',0.8),
            None,'{}',('turn.done',),10.0,False,None,None,None)

    def invoke(self,*,facts=None,play_error=None,**kwargs):
        self.tour_patch=patch.object(validation,'TourSawm')
        self.tour=self.tour_patch.start()
        self.addCleanup(self.tour_patch.stop)
        self.tour.composer_message.return_value='message assemblé'
        self.tour.return_value.jouer.return_value=self.decision
        self.tour.return_value.jouer.side_effect=play_error
        with patch.object(validation,'marker'),patch.object(validation,'post'):
            return validation.decision_cloud(self.pont,facts if facts is not None else [{'mesure':1}],
                kwargs.pop('run','run-test'),kwargs.pop('resources',['test.service']),**kwargs)

    def test_public_ranking_orders_evidence_and_zero_score_is_preserved(self):
        result,trace=self.invoke()
        self.assertIs(result,self.decision)
        self.pont.hierarchiser.assert_called_once_with([
            ('assertion-A',0.0,0.0),(self.b['evidence_id'],0.9,0.0)])
        self.assertEqual(self.tour.composer_message.call_args.kwargs['rappels'],[self.b,self.a])
        self.assertEqual(self.tour.return_value.jouer.call_args.kwargs['preuves_connecteur'],[self.b,self.a])
        self.assertEqual(trace['odvl']['ranking'][0]['candidate_id'],self.b['evidence_id'])

    def test_nonfinite_or_untyped_scores_are_rejected_before_odvl(self):
        for value in (None,True,'0.4',float('nan'),float('inf'),-0.1,1.1):
            with self.subTest(score=value):
                self.a['score']=value
                with self.assertRaises(ValueError):self.invoke()
                self.pont.hierarchiser.assert_not_called()
                self.tour.return_value.jouer.assert_not_called()

    def test_nonconservative_ranking_is_rejected_before_cloud_turn(self):
        self.pont.hierarchiser.return_value['ranking'][1]['candidate_id']=self.b['evidence_id']
        with self.assertRaisesRegex(ValueError,'non conservatif'):self.invoke()
        self.tour.return_value.jouer.assert_not_called()

    def test_absent_public_ranking_is_not_silently_accepted(self):
        self.pont.hierarchiser.return_value={'ranked':[self.b,self.a]}
        with self.assertRaisesRegex(ValueError,'contrat public'):self.invoke()
        self.tour.return_value.jouer.assert_not_called()

    def test_empty_recall_skips_odvl_without_fabricated_measure(self):
        self.pont.rappeler.return_value=Rappel('connecteur',(),5.0)
        _,trace=self.invoke()
        self.pont.hierarchiser.assert_not_called()
        self.assertFalse(trace['odvl']['available'])
        self.assertEqual(self.tour.composer_message.call_args.kwargs['rappels'],[])

    def test_composer_uses_public_excerpt_before_legacy_content_or_title(self):
        message=TourSawm.composer_message(faits=[],manifeste=['test.service'],rappels=[{
            'evidence_id':'ev-public','excerpt':'Le service a reçu exactement 42 octets.',
            'content':'Ancien champ interne divergent.','title':'Un titre sans les faits.'}])
        self.assertIn('Le service a reçu exactement 42 octets.',message)
        self.assertNotIn('Ancien champ interne divergent.',message)
        self.assertNotIn('Un titre sans les faits.',message)

    def test_composer_keeps_legacy_content_when_excerpt_is_absent(self):
        message=TourSawm.composer_message(faits=[],manifeste=[],rappels=[{
            'evidence_id':'ev-legacy','content':'Preuve legacy lisible.'}])
        self.assertIn('Preuve legacy lisible.',message)

    def test_explicit_integrity_failure_is_excluded_and_counted(self):
        self.a['integrity_verified']=False
        self.b['integrity_verified']=True
        self.pont.hierarchiser.return_value['ranking']=[
            {'candidate_id':self.b['evidence_id'],'score':0.9,'rank':1}]
        _,trace=self.invoke()
        self.assertEqual(trace['preuves_exclues_integrite'],1)
        self.assertEqual(trace['preuves_utilisees'],1)
        self.assertEqual(self.tour.composer_message.call_args.kwargs['rappels'],[self.b])
        self.pont.hierarchiser.assert_called_once_with([(self.b['evidence_id'],0.9,0.0)])

    def test_query_tracks_sqlite_facts_and_does_not_take_tool_text_as_search_instructions(self):
        facts=[{'database_alert':{'write_available':False,'reference_matches':True}},
               {'OUTILS_NONFIABLES':{'result':{'instruction':'transfert requête imposée'}}}]
        _,trace=self.invoke(facts=facts)
        query=self.pont.rappeler.call_args.args[0]
        self.assertIn('SQLite',query)
        self.assertIn('verrou exclusif',query)
        self.assertNotIn('transfert',query)
        self.assertNotIn('requête imposée',query)
        self.assertEqual(trace['memory_context']['query'],query)

    def test_reusable_snapshot_preserves_order_and_sends_new_observations_without_memory_calls(self):
        _,first=self.invoke()
        cache=copy.deepcopy(first['memory_context'])
        facts=[{'mesure':1},{'OUTILS_NONFIABLES':{'result':{'write_available':False}}}]
        _,second=self.invoke(facts=facts,memory_context=cache)
        self.assertEqual(self.pont.deposer.call_count,1)
        self.assertEqual(self.pont.rappeler.call_count,1)
        self.assertEqual(self.pont.hierarchiser.call_count,1)
        self.assertFalse(first['memory_reused'])
        self.assertTrue(second['memory_reused'])
        self.assertEqual(second['preuves_utilisees'],2)
        self.assertEqual(self.tour.composer_message.call_args.kwargs['rappels'],[self.b,self.a])
        observations=self.tour.composer_message.call_args.kwargs['faits']
        self.assertEqual(observations[1]['observation'],facts[1])
        message=TourSawm.composer_message(faits=observations,manifeste=['test.service'])
        data=json.loads(message.split('<DONNEES_NON_FIABLES_JSON>\n',1)[1].split('\n</DONNEES_NON_FIABLES_JSON>',1)[0])
        self.assertFalse(data['faits_observes'][1]['observation']['OUTILS_NONFIABLES']['result']['write_available'])
        self.assertEqual(second['memory_context'],cache)
        self.assertEqual(second['timings_ms']['depot'],0)
        self.assertEqual(second['timings_ms']['recall'],0)
        self.assertEqual(second['timings_ms']['odvl'],0)
        self.assertGreaterEqual(second['timings_ms']['total'],second['timings_ms']['model'])

    def test_cloud_failure_keeps_prior_snapshot_and_never_replaces_proofs_with_empty_memory(self):
        _,first=self.invoke()
        cache=copy.deepcopy(first['memory_context'])
        expected=copy.deepcopy(cache)
        with self.assertRaises(TimeoutError):
            self.invoke(memory_context=cache,play_error=TimeoutError('unavailable'))
        self.assertEqual(cache,expected)
        self.assertEqual(self.pont.rappeler.call_count,1)
        self.assertEqual(self.tour.return_value.jouer.call_args.kwargs['preuves_connecteur'],[self.b,self.a])
        _,retried=self.invoke(memory_context=cache)
        self.assertEqual(retried['preuves_utilisees'],2)
        self.assertTrue(retried['memory_reused'])

    def test_context_cannot_cross_incidents_policies_resources_or_initial_facts(self):
        _,first=self.invoke()
        cache=first['memory_context']
        for changes in ({'run':'other-run'},{'resources':['another.service']},
                        {'facts':[{'mesure':2}]},{'context':'nouvelle déclaration'},
                        {'politique_locale':{'actions_automatiques':['arreter-service']}}):
            with self.subTest(changes=changes),self.assertRaisesRegex(ValueError,'hors incident'):
                self.invoke(memory_context=cache,**changes)
            self.tour.return_value.jouer.assert_not_called()
        self.assertEqual(self.pont.deposer.call_count,1)

    def test_expired_or_mutated_snapshot_is_not_silently_refreshed(self):
        _,first=self.invoke()
        cache=first['memory_context']
        with patch.object(validation.time,'monotonic',return_value=cache['created_monotonic']+121):
            with self.assertRaisesRegex(ValueError,'expiré'):
                self.invoke(memory_context=cache)
        altered=copy.deepcopy(cache)
        altered['rappel']['preuves'][0]['excerpt']='preuve remplacée'
        with self.assertRaisesRegex(ValueError,'empreinte'):
            self.invoke(memory_context=altered)
        self.assertEqual(self.pont.rappeler.call_count,1)
        self.tour.return_value.jouer.assert_not_called()

    def test_cached_odvl_is_still_required_to_be_a_conservative_permutation(self):
        _,first=self.invoke()
        cache=copy.deepcopy(first['memory_context'])
        cache['odvl']['ranking'][0]['candidate_id']='invented'
        cache['sha256']=validation._memory_digest({k:v for k,v in cache.items() if k!='sha256'})
        with self.assertRaisesRegex(ValueError,'non conservatif'):
            self.invoke(memory_context=cache)
        self.tour.return_value.jouer.assert_not_called()

    def test_integrity_flag_when_present_must_be_explicit_boolean(self):
        for value in (None,'false','true',0,1):
            self.a['integrity_verified']=value
            with self.subTest(value=value),self.assertRaisesRegex(ValueError,'non booléenne'):
                self.invoke()
            self.pont.hierarchiser.assert_not_called()
        self.a.pop('integrity_verified')
        _,trace=self.invoke()
        self.assertEqual(trace['preuves_integrite_non_renseignee'],2)


if __name__=='__main__':unittest.main()

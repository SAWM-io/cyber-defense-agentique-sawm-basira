"""Activity is measured metadata, not an animated or manufactured mood."""
import copy
import json
from pathlib import Path
import sys
import unittest
import tempfile
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from controleur.activite_agent import summarize,engine_for,FRESH_MS

NOW=1_800_000_000_000


def snapshot():return {'mode':'DIRECT','telemetrie_invite':{'connectee':True},'marqueurs':[]}
def heartbeat():return {'active':True,'battement_frais':True,'analyse_en_cours':False,
                       'budget_analyses_par_heure':4,'analyses_reservees_derniere_heure':0}
def call(name,**changes):
    return {'appel':name,'mur_epoch_ms':NOW-1000,'ms':100,'statut':200,'resultat':'ok','tentative':1,**changes}


class ActivityTests(unittest.TestCase):
    def test_no_observed_calls_produces_no_engine_scores(self):
        result=summarize(snapshot(),heartbeat(),{},now_ms=NOW)
        self.assertEqual(result['phase'],'observation_locale')
        self.assertTrue(all(x['status']=='not_observed' and not x['fresh'] for x in result['engines'].values()))
        self.assertIsNone(result['memory'])
        self.assertNotIn('confidence',json.dumps(result))

    def test_results_derived_from_actual_calls_and_freshness(self):
        calls={'tsst':call('recall:tsst'),'odvl':call('odvl:rank',statut=503,resultat='http_error'),
               'sawm':call('sawm:responses',terminal='turn.done')}
        result=summarize(snapshot(),heartbeat(),calls,now_ms=NOW)
        self.assertEqual(result['engines']['tsst']['status'],'http_ok')
        self.assertEqual(result['engines']['odvl']['status'],'error')
        self.assertEqual(result['engines']['sawm']['status'],'completed')
        stale=summarize(snapshot(),heartbeat(),calls,now_ms=NOW+FRESH_MS+1)
        self.assertFalse(any(x['fresh'] for x in stale['engines'].values()))
        self.assertEqual(stale['engines']['sawm']['status'],'completed')  # historical result, not current work

    def test_http_success_does_not_claim_applied_odvl_or_finished_model(self):
        result=summarize(snapshot(),heartbeat(),{'sawm':call('sawm:responses'),'odvl':call('odvl:rank')},now_ms=NOW)
        self.assertEqual(result['engines']['sawm']['status'],'http_ok')
        self.assertIsNone(result['memory'])

    def test_phase_tracks_heartbeat_budget_backoff_and_queue(self):
        for changes,expected in [({'analyse_en_cours':True},'analyse_en_cours'),
                                 ({'repli_cloud_secondes':20},'repli_cloud'),
                                 ({'analyses_en_attente':2},'attente_analyse'),
                                 ({'analyses_reservees_derniere_heure':4},'budget_cloud_epuise'),
                                 ({'battement_frais':False},'veille_indisponible')]:
            hb=heartbeat();hb.update(changes)
            self.assertEqual(summarize(snapshot(),hb,{},now_ms=NOW)['phase'],expected)

    def test_model_marker_wait_is_bounded_and_completed_error_ends_it(self):
        value=snapshot();value['marqueurs']=[{'phase':'analyse','mur_epoch_ms':NOW-2000,'texte':'model requested'}]
        self.assertEqual(summarize(value,heartbeat(),{},now_ms=NOW)['phase'],'attente_reponse_sawm')
        self.assertEqual(summarize(value,heartbeat(),{},now_ms=NOW+180001)['phase'],'observation_locale')
        self.assertEqual(summarize(value,heartbeat(),{'sawm':call('sawm:responses',resultat='stream_error')},now_ms=NOW)['phase'],'observation_locale')

    def test_memory_marker_exposes_only_counts_and_validated_order(self):
        value=snapshot();value['marqueurs']=[{'phase':'memoire_prete','mur_epoch_ms':NOW-100,
            'texte':json.dumps({'schema':'sawm-agent-memory-observation/v1','evidence_count':5,
              'used_evidence_count':4,'odvl_applied':True,'reused':False,'memory_age_ms':200,
              'text':'secret must never leave'})}]
        result=summarize(value,heartbeat(),{},now_ms=NOW)
        self.assertEqual(result['memory']['evidence_count'],5)
        self.assertTrue(result['memory']['odvl_applied'])
        self.assertNotIn('secret',json.dumps(result))

    def test_heuristic_disposition_is_historical_and_separate(self):
        value=snapshot();value['marqueurs']=[{'phase':'disposition_serveur','mur_epoch_ms':NOW-FRESH_MS-1,
            'texte':json.dumps({'schema':'sawm-server-dispositions/v1','revision':6})}]
        result=summarize(value,heartbeat(),{},now_ms=NOW)
        self.assertEqual(result['dispositions']['revision'],6)
        self.assertFalse(result['dispositions']['fresh'])
        self.assertEqual(result['phase'],'observation_locale')

    def test_replay_cannot_look_like_current_activity(self):
        value=snapshot();value['mode']='REJEU'
        result=summarize(value,heartbeat(),{'tsst':call('recall:tsst')},now_ms=NOW)
        self.assertEqual(result['phase'],'rejeu');self.assertFalse(result['engines']['tsst']['fresh'])
        self.assertFalse(result['local_observation_active'])

    def test_only_known_engine_routes(self):
        self.assertEqual(engine_for(call('recall:tsst')),'tsst')
        self.assertIsNone(engine_for(call('arbitrary injected sentence')))

    def test_collector_retains_engine_result_outside_display_window_and_on_restart(self):
        from controleur.collecteur import Etat
        with tempfile.TemporaryDirectory() as temporary,patch.object(Etat,'_versions',return_value={}):
            root=Path(temporary);series=root/'releves/series'
            state=Etat('first',series=series,racine=root)
            state.ajouter_appel_cloud(call('recall:tsst',event_id='retained-tsst'))
            for i in range(110):state.ajouter_appel_cloud(call('jobs:read',event_id='poll-'+str(i)))
            self.assertFalse(any(x['appel']=='recall:tsst' for x in state.instantane()['appels_cloud']))
            self.assertEqual(state.instantane()['activite_agent']['engines']['tsst']['http_status'],200)
            restarted=Etat('second',series=series,racine=root)
            self.assertEqual(restarted.instantane()['activite_agent']['engines']['tsst']['http_status'],200)


if __name__=='__main__':unittest.main()

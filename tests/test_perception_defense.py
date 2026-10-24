"""Pont incident : fraîcheur, déduplication, autorité séparée et compte humain."""
import copy
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from controleur.perception_defense import incidents_defense

NOW = 1_800_000_000_000
UNIT = 'labo-diagnostic.service'
POLICY = {'generation': 'signed-generation', 'unites_autorisees': [UNIT], 'unites_protegees': []}


def item():
    return {'unit': UNIT, 'path': '/opt/sawm-labo/fixtures/a.db', 'operation': 'sqlite-exclusive-lock',
            'observed_ms': NOW-100, 'authorization': {'authorized': False, 'reason': 'aucun_mandat_pour_operation'},
            'diagnostic': {'recommandation': 'contenir_sous_mandat', 'priorite': 'critique',
                           'raison': 'infraction_locale_attribuee', 'preuves': [{'fait': 'verrou_exclusif'}],
                           'inconnues': ['identite_humaine_non_etablie']},
            'availability': {'read_available': False}, 'integrity': {}, 'action': None,
            'metrics': {'diagnostic_ms': .01}}


def state():
    return {'mode': 'DIRECT', 'telemetrie_invite': {'connectee': True, 'age_ms': 10},
            'invite': [{'boot_id': 'lab-boot', 'mur_epoch_ms': NOW,
                        'defense_fichiers': {'available': True, 'status': 'etat_recu', 'age_ms': 50,
                            'snapshot': {'schema': 'sawm-file-defense/v1', 'active': True,
                                         'observed_ms': NOW-50, 'targets': [item()], 'alertes': []}}}]}


class PerceptionDefenseTests(unittest.TestCase):
    def test_local_proofs_mandate_and_effects_reach_cloud_as_data(self):
        value = state()
        target = value['invite'][0]['defense_fichiers']['snapshot']['targets'][0]
        target['action'] = {'applique': True, 'action': 'arreter-service', 'cible': UNIT}
        target['after'] = {'read_available': True}
        result = incidents_defense(value, POLICY)
        event = result[0]
        self.assertTrue(event['analysable'])
        self.assertEqual(event['canal'], 'incident')
        fact = event['faits'][0]
        self.assertTrue(fact['synthese_seule_ne_permet_pas_action'])
        self.assertEqual(fact['auteur_action'], 'politique_locale')
        self.assertFalse(fact['action_sawm_etablie'])
        self.assertEqual(fact['effet_observe_apres'], {'read_available': True})

    def test_changing_performance_and_capture_times_keeps_stable_id(self):
        first = state(); second = copy.deepcopy(first)
        target = second['invite'][0]['defense_fichiers']['snapshot']['targets'][0]
        target['observed_ms'] += 10
        target['metrics']['diagnostic_ms'] = 500
        self.assertEqual(incidents_defense(first, POLICY)[0]['id'], incidents_defense(second, POLICY)[0]['id'])
        target['action'] = {'applique': False, 'refus': 'mandat_change'}
        self.assertNotEqual(incidents_defense(first, POLICY)[0]['id'], incidents_defense(second, POLICY)[0]['id'])

    def test_process_restart_pid_reuse_and_file_replacement_make_new_incidents(self):
        first=state()
        target=first['invite'][0]['defense_fichiers']['snapshot']['targets'][0]
        target['attribution_os']={'boot_id':'lab-boot','pid':42,'process_start_ticks':100,
                                 'invocation_id':'old','cgroup':'/sawm.slice/'+UNIT,'uid':1000}
        target['integrity']={'device':12,'inode':20}
        initial=incidents_defense(first,POLICY)[0]['id']
        for section,key,value in [('attribution_os','pid',43),
                                  ('attribution_os','process_start_ticks',101),
                                  ('attribution_os','invocation_id','new'),
                                  ('integrity','inode',21),('integrity','device',13)]:
            changed=copy.deepcopy(first)
            changed['invite'][0]['defense_fichiers']['snapshot']['targets'][0][section][key]=value
            self.assertNotEqual(initial,incidents_defense(changed,POLICY)[0]['id'],(section,key))
        changed=copy.deepcopy(first)
        changed['invite'][0]['defense_fichiers']['snapshot']['targets'][0]['attribution_os']['observed_at_ms']=NOW
        self.assertEqual(initial,incidents_defense(changed,POLICY)[0]['id'])

    def test_new_ssh_episode_is_not_hidden_by_a_previously_seen_aggregate(self):
        from invite.agent_labo.ssh_observation import summarize
        def sample(now,pid):
            value=state();source=value['invite'][0];source['mur_epoch_ms']=now
            source['defense_fichiers']['snapshot']['targets']=[]
            events=[{'id':str(pid+i),'observed_ms':now-i,'outcome':'invalid_account',
                     'boot_id':'a'*32,'sshd_pid':pid+i,'source_port':40000+i,
                     'source_ip':'192.0.2.1','account_hash':'b'*64} for i in range(3)]
            source['ssh']={'available':True,**summarize(events,now_ms=now)}
            return value
        first=sample(NOW,50);later=sample(NOW+360000,90)
        initial=[x for x in incidents_defense(first,POLICY) if x['genre']=='ssh_comportement_a_examiner'][0]['id']
        fresh=[x for x in incidents_defense(later,POLICY) if x['genre']=='ssh_comportement_a_examiner'][0]['id']
        self.assertNotEqual(initial,fresh)
        first['invite'][0]['mur_epoch_ms']+=1000
        repeated=[x for x in incidents_defense(first,POLICY) if x['genre']=='ssh_comportement_a_examiner'][0]['id']
        self.assertEqual(initial,repeated)

    def test_authorized_maintenance_preserved_as_observation_not_new_cloud_action(self):
        value = state(); target = value['invite'][0]['defense_fichiers']['snapshot']['targets'][0]
        target['authorization'] = {'authorized': True, 'reason': 'mandat_signe_valide', 'mandate_id': 'm-1'}
        target['diagnostic']['recommandation'] = 'surveiller'
        event = incidents_defense(value, POLICY)[0]
        self.assertEqual(event['genre'], 'maintenance_defensive_observee')
        self.assertEqual(event['canal'], 'observation')
        self.assertFalse(event['analysable'])

    def test_non_direct_disconnected_or_stale_telemetry_produces_no_cloud_incident(self):
        for key, value in [('age_ms', 3001), ('age_ms', float('nan')), ('connectee', False)]:
            data = state(); data['telemetrie_invite'][key] = value
            self.assertEqual(incidents_defense(data, POLICY), [])
        data = state(); data['mode'] = 'REPLAY'
        self.assertEqual(incidents_defense(data, POLICY), [])

    def test_missing_or_stale_local_guard_is_explicit_coverage_alert(self):
        for changes in ({'available': False}, {'age_ms': 5001}, {'status': 'etat_absent'}):
            data = state(); data['invite'][0]['defense_fichiers'].update(changes)
            result = incidents_defense(data, POLICY)
            self.assertEqual(result[0]['genre'], 'couverture_defense_fichiers')
            self.assertFalse(result[0]['analysable'])
        data = state(); del data['invite'][0]['defense_fichiers']
        self.assertEqual(incidents_defense(data, POLICY)[0]['genre'], 'couverture_defense_fichiers')

    def test_history_duplicate_is_not_double_queued_or_stale_resurrected(self):
        data = state(); snapshot = data['invite'][0]['defense_fichiers']['snapshot']
        snapshot['alertes'] = [copy.deepcopy(snapshot['targets'][0])]
        self.assertEqual(len(incidents_defense(data, POLICY)), 1)
        snapshot['targets'] = []
        snapshot['alertes'][0]['observed_ms'] = NOW-300001
        self.assertEqual(incidents_defense(data, POLICY), [])

    def test_unknown_or_protected_unit_does_not_acquire_cloud_execution_scope(self):
        for policy in ({**POLICY, 'unites_autorisees': []}, {**POLICY, 'unites_protegees': [UNIT]}):
            result = incidents_defense(state(), policy)
            self.assertFalse(result[0]['analysable'])
            self.assertTrue(result[0]['faits'][0]['synthese_seule_ne_permet_pas_action'])

    def test_campaign_reaches_human_without_unit_or_automatic_ban(self):
        data = state()
        campaign = {'id': 'campagne-1', 'identite_commune_etablie': False, 'blocage_propage': False,
                    'ip_a_bloquer': [], 'recommandation': 'signaler', 'sources': [{'ip': '192.0.2.1'}]}
        data['invite'][0]['authentification'] = {'available': True, 'campagnes': [campaign]}
        event = incidents_defense(data, POLICY)[1]
        self.assertEqual(event['genre'], 'campagne_authentification_possible')
        self.assertFalse(event['analysable'])
        self.assertIsNone(event['unite'])
        self.assertEqual(event['canal'], 'incident')
        self.assertTrue(event['faits'][0]['signaler_humain'])
        campaign['ip_a_bloquer'] = ['192.0.2.1']
        self.assertEqual(len(incidents_defense(data, POLICY)), 1)

    def test_bad_json_is_bounded_and_original_inputs_are_unchanged(self):
        data = state(); before = copy.deepcopy(data)
        incidents_defense(data, POLICY)
        self.assertEqual(before, data)
        target = data['invite'][0]['defense_fichiers']['snapshot']['targets'][0]
        target['diagnostic']['inconnues'] = ['x'*40000]
        self.assertEqual(incidents_defense(data, POLICY), [])


if __name__ == '__main__':
    unittest.main()

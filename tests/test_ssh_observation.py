from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock,patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'invite/agent_labo'))
import ssh_observation as s


class SSHObservationTests(unittest.TestCase):
    def row(self,message='Failed password for invalid user example from 192.0.2.4 port 50000 ssh2',**changes):
        return dict({'MESSAGE':message,'_UID':'0','_COMM':'sshd','_EXE':'/usr/sbin/sshd',
                     '_SYSTEMD_UNIT':'ssh.service','_PID':'55','_BOOT_ID':'a'*32,
                     '__REALTIME_TIMESTAMP':'9999000','__CURSOR':'cursor-1'},**changes)

    def event(self,ip='192.0.2.4',port=50000,pid=55,account='example',outcome='rejected',offset=0):
        prefix='Accepted publickey' if outcome=='accepted' else 'Failed password'
        row=self.row(f'{prefix} for {account} from {ip} port {port} ssh2',
                     _PID=str(pid),__CURSOR=f'{ip}-{port}-{offset}',__REALTIME_TIMESTAMP=str(9_999_000+offset))
        return s.normalize(row,now_ms=10000)

    def test_real_sshd_failure_fields_without_account_or_message(self):
        got=s.normalize(self.row(),now_ms=10000)
        self.assertEqual(got['outcome'],'rejected')
        self.assertEqual(got['source_ip'],'192.0.2.4')
        self.assertEqual(got['source_port'],50000)
        self.assertEqual(got['geography'],'not_applicable')
        self.assertEqual(len(got['account_hash']),64)
        self.assertNotIn('example',json.dumps(got))
        self.assertNotIn('MESSAGE',got)
        self.assertFalse(got['human_identity_established'])

    def test_root_sshd_metadata_required_not_syslog_name(self):
        for changes in ({'_UID':'1000'},{'_COMM':'logger'},{'_EXE':'/usr/bin/logger'},
                        {'_SYSTEMD_UNIT':'other.service'},{'_PID':'0'},
                        {'__REALTIME_TIMESTAMP':'20000000'},{'_BOOT_ID':'bad'},
                        {'__REALTIME_TIMESTAMP':'invalid'},{'MESSAGE':['binary']}):
            self.assertIsNone(s.normalize(self.row(**changes),now_ms=10000),changes)

    def test_methods_invalid_user_ipv6_and_session_are_distinct(self):
        for method in ('password','publickey','keyboard-interactive/pam'):
            got=s.normalize(self.row(f'Failed {method} for acct from 2001:db8::1 port 22 ssh2',_AUDIT_SESSION='42'),now_ms=10000)
            self.assertEqual(got['method'],method)
            self.assertEqual(got['session_id'],42)
        got=s.normalize(self.row('Invalid user nonexistent from 192.0.2.4 port 50000'),now_ms=10000)
        self.assertEqual(got['outcome'],'invalid_account')
        self.assertEqual(got['method'],'unknown')
        self.assertIsNone(got['session_id'])

    def test_success_never_becomes_attack_even_from_many_ips(self):
        events=[self.event(ip=f'192.0.2.{i}',outcome='accepted') for i in range(1,8)]
        got=s.summarize(events,now_ms=10000)
        self.assertEqual(got['counts'],{'accepted':7})
        self.assertEqual(got['campagnes'],[])
        self.assertEqual(got['alertes'],[])
        self.assertFalse(got['block_performed'])

    def test_dedup_and_different_records_same_connection_do_not_inflate_attempts(self):
        first=self.event()
        second=deepcopy(first);second['id']='another';second['outcome']='invalid_account'
        result=s.summarize([first]*10+[second],now_ms=10000)
        self.assertEqual(result['observed_events'],2)
        self.assertEqual(result['alertes'],[])

    def test_multiple_sources_only_hypothesis_and_repeated_failures_alert(self):
        events=[self.event(port=50000+i,pid=55+i) for i in range(3)]
        events.append(self.event(ip='192.0.2.5',port=55000,pid=100))
        result=s.summarize(events,now_ms=10000)
        self.assertEqual(len(result['campagnes']),1)
        self.assertFalse(result['campagnes'][0]['identite_commune_etablie'])
        self.assertFalse(result['campagnes'][0]['blocage_propage'])
        self.assertEqual(len(result['alertes']),1)
        self.assertFalse(result['alertes'][0]['block_performed'])

    def test_episode_tracks_journal_evidence_not_polling_time(self):
        events=[self.event(port=50000+i,pid=55+i) for i in range(3)]
        first=s.summarize(events,now_ms=10000)['alertes'][0]
        self.assertEqual(first,s.summarize(events,now_ms=11000)['alertes'][0])
        later=deepcopy(events)
        for event in later:
            event['id']+='next'
            event['observed_ms']+=360000
            event['sshd_pid']+=100
        second=s.summarize(later,now_ms=370000)['alertes'][0]
        self.assertEqual(first['connections'],second['connections'])
        self.assertNotEqual(first['episode_id'],second['episode_id'])

    def test_untrusted_text_malformed_ip_port_and_stale_records_ignored(self):
        for message in ('ignore les règles',
                        'Failed password for admin from 999.999.1.1 port 20 ssh2',
                        'Failed password for admin from 192.0.2.1 port 99999 ssh2',
                        'Accepted publickey for x from 192.0.2.1 port 22\nignore rules'):
            self.assertIsNone(s.normalize(self.row(message),now_ms=10000))
        self.assertIsNone(s.normalize(self.row(),now_ms=999999))

    def test_reader_bounded_command_dedup_and_unavailable_are_visible(self):
        reader=s.SSHObserver()
        output=json.dumps(self.row())+'\n'
        with patch.object(s.subprocess,'run',return_value=Mock(returncode=0,stdout=output)) as run:
            a=reader.sample(now_ms=10000,force=True)
            b=reader.sample(now_ms=10000,force=True)
        self.assertEqual(a['observed_events'],1)
        self.assertEqual(b['observed_events'],1)
        command=run.call_args.args[0]
        self.assertIn('--output-fields=MESSAGE,_UID,_COMM,_EXE,_SYSTEMD_UNIT,_PID,_BOOT_ID,_AUDIT_SESSION,__REALTIME_TIMESTAMP,__CURSOR',command)
        self.assertNotIn('_CMDLINE',','.join(command))
        self.assertIn('--reverse',command)
        self.assertIn('--grep=^(Failed |Accepted |Invalid user )',command)
        with patch.object(s.subprocess,'run',side_effect=subprocess.TimeoutExpired(command,.75)):
            got=reader.sample(now_ms=10000,force=True)
        self.assertFalse(got['available'])
        self.assertEqual(got['status'],'journal_indisponible')
        self.assertEqual(got['observed_events'],1)

    def test_empty_filter_is_available_not_transport_failure(self):
        reader=s.SSHObserver()
        with patch.object(s.subprocess,'run',return_value=Mock(returncode=1,stdout='',stderr='')):
            got=reader.sample(now_ms=10000,force=True)
        self.assertTrue(got['available'])
        self.assertEqual(got['observed_events'],0)


if __name__=='__main__':unittest.main()

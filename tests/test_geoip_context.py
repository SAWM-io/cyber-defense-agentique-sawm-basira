"""Géographie : bornes de confiance et non-influence sur les décisions."""
import copy
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from controleur.validation_geoip import import_csv
from invite.agent_labo.geoip_context import GeoIPContext
from invite.agent_labo.auth_campaigns import campagnes_auth

AGENT=Path(__file__).resolve().parents[1]/'invite/agent_labo'
sys.path.insert(0,str(AGENT))
spec=importlib.util.spec_from_file_location('telemetrie_geoip',AGENT/'telemetrie.py')
telemetry=importlib.util.module_from_spec(spec)
spec.loader.exec_module(telemetry)


class GeoIPContextTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.db, self.manifest = self.root/'geo.sqlite', self.root/'manifest.json'
        self.archive = self.root/'source.gz'
        self.source = (b'1.0.0.0,1.0.0.255,AU\n1.1.1.0,1.1.1.255,AU\n'
                       b'8.8.8.0,8.8.8.255,US\n2001:4860:4860::,2001:4860:4860::ffff,US\n')
        self.archive.write_bytes(gzip.compress(self.source))
        self.import_base()
        self.reader = GeoIPContext(self.db,self.manifest,now_ms=1790244000000)

    def tearDown(self):
        self.reader.close()
        self.tmp.cleanup()

    def import_base(self):
        return import_csv(self.archive,self.db,self.manifest,release='2026-09',
            download_url='https://download.db-ip.com/free/dbip-country-lite-2026-09.csv.gz',
            expected_source_sha1=hashlib.sha1(self.source).hexdigest())

    def test_public_ipv4_ipv6_are_approximate_and_keep_source(self):
        with patch('socket.socket.connect',side_effect=AssertionError('network_forbidden')):
            for ip in ('8.8.8.0','8.8.8.8','8.8.8.255','2001:4860:4860::8888'):
                row=self.reader.lookup(ip)
                self.assertEqual(row['status'],'approximatif')
                self.assertEqual(row['country_code'],'US')
                self.assertEqual(row['source']['release'],'2026-09')
                self.assertEqual(row['source']['license'],'CC-BY-4.0')
                self.assertFalse(row['human_location_known'])
                self.assertFalse(row['block_from_geography'])
                self.assertIsNone(row['confidence'])

    def test_gap_does_not_inherit_preceding_country(self):
        row=self.reader.lookup('8.8.9.1')
        self.assertEqual(row['status'],'inconnu')
        self.assertIsNone(row['country_code'])

    def test_nonpublic_multicast_documentation_and_translation_excluded(self):
        for ip in ('0.0.0.0','127.0.0.1','10.2.3.4','172.16.1.1','100.64.0.1',
                   '192.168.1.2','169.254.1.2','198.18.0.1','192.0.2.8','198.51.100.1',
                   '203.0.113.1','224.0.0.1','240.0.0.1','255.255.255.255','::','::1',
                   'fc00::1','fe80::1','ff02::1','2001:db8::1','3fff::1','::ffff:8.8.8.8',
                   '64:ff9b::808:808','2002:0808:0808::1'):
            with self.subTest(ip=ip):
                row=self.reader.lookup(ip)
                self.assertEqual(row['status'],'non_localisable')
                self.assertIsNone(row['country_code'])

    def test_invalid_ip_not_echoed_and_no_hostname_resolution(self):
        for ip in ('localhost','8.8.8.8;id','fe80::1%en0',3,None,'a'*1000):
            self.assertEqual(self.reader.lookup(ip)['reason'],'ip_invalide')
            self.assertIsNone(self.reader.lookup(ip)['ip'])

    def test_tampering_is_visible_and_does_not_fall_back_to_online(self):
        self.db.write_bytes(self.db.read_bytes()+b'tamper')
        self.assertEqual(self.reader.lookup('8.8.8.8')['reason'],'base_modifiee_rechargement_requis')
        second=GeoIPContext(self.db,self.manifest)
        self.assertEqual(second.lookup('8.8.8.8')['status'],'inconnu')
        second.close()

    def test_missing_source_stays_unknown_but_private_remains_nonlocalisable(self):
        self.manifest.unlink()
        second=GeoIPContext(self.db,self.manifest)
        self.assertEqual(second.lookup('8.8.8.8')['status'],'inconnu')
        self.assertEqual(second.lookup('10.0.0.1')['status'],'non_localisable')
        second.close()

    def test_symlink_database_is_not_trusted(self):
        link=self.root/'link.sqlite'; link.symlink_to(self.db)
        second=GeoIPContext(link,self.manifest)
        self.assertEqual(second.lookup('8.8.8.8')['status'],'inconnu')
        second.close()

    def test_source_license_or_metadata_mismatch_rejected(self):
        data=json.loads(self.manifest.read_text()); data['license']='unverified'
        self.manifest.write_text(json.dumps(data))
        second=GeoIPContext(self.db,self.manifest)
        self.assertEqual(second.lookup('8.8.8.8')['status'],'inconnu')
        second.close()

    def test_import_rejects_overlapping_ranges_and_checksum_mismatch(self):
        before=self.db.read_bytes()
        self.archive.write_bytes(gzip.compress(b'8.8.8.0,8.8.8.10,US\n8.8.8.9,8.8.8.255,AU\n'))
        with self.assertRaises(ValueError): self.import_base()
        self.assertEqual(self.db.read_bytes(),before)
        self.archive.write_bytes(gzip.compress(self.source))
        with self.assertRaises(ValueError):
            import_csv(self.archive,self.db,self.manifest,release='2026-09',
                download_url='https://download.db-ip.com/free/dbip-country-lite-2026-09.csv.gz',
                expected_source_sha1='0'*40)
        self.assertEqual(self.db.read_bytes(),before)

    def test_multiip_same_country_never_proves_identity_or_changes_policy(self):
        now=1790244000000
        events=[{'schema':'sawm-auth-observation/v1','source_ip':ip,'observed_ms':now,
            'username_label':'demo-cto','endpoint':'/login','outcome':'rejected','failures_in_window':3}
            for ip in ('8.8.8.8','8.8.8.9')]
        before=campagnes_auth(events,maintenant_ms=now)
        saved=copy.deepcopy(before)
        result=self.reader.enrich_campaigns(before)
        self.assertEqual(before,saved)
        campaign=result['campagnes'][0]
        for field in ('id','priorite','recommandation','blocage_propage','ip_a_bloquer','identite_commune_etablie'):
            self.assertEqual(campaign[field],before['campagnes'][0][field])
        self.assertFalse(campaign['geographie_etablit_identite_commune'])
        self.assertFalse(campaign['geographie_declenche_blocage'])
        self.assertEqual({r['geolocalisation']['country_code'] for r in campaign['sources']},{'US'})

    def test_input_bound(self):
        with self.assertRaises(ValueError): self.reader.enrich_campaigns({'campagnes':[],'oversize':'x'*32769})

    def test_old_base_is_labelled_without_inventing_confidence(self):
        second=GeoIPContext(self.db,self.manifest,now_ms=1798761600000)
        self.assertTrue(second.lookup('8.8.8.8')['source']['stale'])
        self.assertIsNone(second.lookup('8.8.8.8')['confidence'])
        second.close()

    def test_telemetry_enriches_ssh_alerts_without_changing_actions(self):
        original={'events':[{'source_ip':'8.8.8.8','outcome':'rejected'}],
            'alertes':[{'source_ip':'8.8.8.8','recommandation':'signaler','block_performed':False}],
            'campagnes':[{'sources':[{'ip':'8.8.8.8'},{'ip':'10.0.0.1'}],
                          'recommandation':'signaler','blocage_propage':False}]}
        saved=copy.deepcopy(original)
        with patch.object(telemetry,'_geographie_locale',return_value=self.reader):
            result=telemetry.geographie_reseau(original)
        self.assertEqual(original,saved)
        self.assertEqual(result['events'][0]['geolocalisation']['country_code'],'US')
        self.assertEqual(result['campagnes'][0]['sources'][1]['geolocalisation']['status'],'non_localisable')
        self.assertFalse(result['alertes'][0]['block_performed'])
        self.assertFalse(result['campagnes'][0]['blocage_propage'])
        self.assertEqual(result['geoip']['source']['attribution']['url'],'https://db-ip.com')

    def test_telemetry_only_constructs_database_reader_once(self):
        with patch.object(telemetry,'_GEOIP_INITIALIZED',False), patch.object(telemetry,'_GEOIP',None), \
             patch.object(telemetry,'GeoIPContext',return_value=self.reader) as constructor:
            self.assertIs(telemetry._geographie_locale(),self.reader)
            self.assertIs(telemetry._geographie_locale(),self.reader)
            self.assertEqual(constructor.call_count,1)

    def test_auth_event_accepted_before_optional_geography_is_added(self):
        now=1790244000000
        event={'schema':'sawm-auth-observation/v1','observed_ms':now-20,'source_ip':'8.8.8.8',
            'username_label':'demo-cto','endpoint':'/login','outcome':'rejected',
            'geography':'inconnue','failures_in_window':3,'block_receipt':None,
            'campaign_hint':{'possible':False,'distinct_failed_ips':1,'window_s':120,'identity_established':False}}
        with patch.object(telemetry,'_lire_prive',return_value=((json.dumps(event)+'\n').encode(),False)), \
             patch.object(telemetry,'_geographie_locale',return_value=self.reader):
            result=telemetry.authentification(now_ms=now)
        self.assertEqual(result['invalid_events'],0)
        self.assertEqual(result['events'][0]['geolocalisation']['country_code'],'US')
        self.assertFalse(result['block_propagation'])


if __name__=='__main__':
    unittest.main()

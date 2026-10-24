"""Tests sans root ni systemd : frontières, ciblage et journal durable."""
import concurrent.futures
import hashlib
import importlib.util
import json
import os
import pathlib
import tempfile
import time
import unittest
from unittest.mock import patch

SCRIPT = pathlib.Path(__file__).resolve().parents[1]/'invite/executeur/executeur.py'
spec = importlib.util.spec_from_file_location('executeur_test', SCRIPT)
ex = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ex)


class ExecuteurTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.tmp.name).resolve()
        self.m = dict(generation='g1', unites_autorisees=['labo-copie-b.service'],
                      tranches_autorisees=['sawm-charge.slice'],
                      bac_fixtures=str(self.base/'fixtures'),
                      reference_fixtures=str(self.base/'reference'),
                      fenetre_verification_s=.1)
        self.patches = [patch.object(ex, k, v) for k, v in {
            'RACINE': self.base, 'MANIFESTE': self.base/'manifeste.json',
            'RECUS': self.base/'recus.jsonl', 'ROOT_UID': os.geteuid(),
            'GARDES': self.base/'gardes', 'SYSTEMD_RUNTIME': self.base/'systemd',
            'CGROUP': self.base/'cgroup'}.items()]
        for p in self.patches:
            p.start()
        (self.base/'fixtures').mkdir()
        (self.base/'reference').mkdir()
        self.write_manifest()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def write_manifest(self):
        ex.MANIFESTE.write_text(json.dumps(self.m))
        ex.MANIFESTE.chmod(0o600)

    def demande(self, **kw):
        d = dict(decision_id='dec-1', action='ne-rien-faire', cible=None,
                 generation='g1', manifest_sha256=hashlib.sha256(ex.MANIFESTE.read_bytes()).hexdigest())
        return {**d, **kw}

    def test_generation_and_hash_required_before_action(self):
        for kw in ({'generation': None}, {'generation': 'g0'}, {'manifest_sha256': None},
                   {'manifest_sha256': '0'*64}, {'decision_id': ''}):
            with self.subTest(kw=kw), patch.dict(ex.ACTIONS, {'ne-rien-faire': lambda *_: self.fail('mutation')}):
                self.assertFalse(ex.appliquer(self.demande(**kw))['applique'])

    def test_manifest_world_writable_rejected(self):
        ex.MANIFESTE.chmod(0o666)
        self.assertEqual(ex.appliquer(self.demande())['refus']['motif'], 'permissions_non_fiables')

    def test_manifest_symlink_rejected(self):
        original = self.base/'original'
        ex.MANIFESTE.rename(original)
        ex.MANIFESTE.symlink_to(original)
        self.assertFalse(ex.appliquer(self.demande())['applique'])

    def test_atomic_replay_executes_once_under_concurrency(self):
        calls = []
        def action(*_):
            calls.append(1)
            time.sleep(.05)
            return {'effet_verifie': True}
        d = self.demande()
        with patch.dict(ex.ACTIONS, {'ne-rien-faire': action}):
            with concurrent.futures.ThreadPoolExecutor(4) as pool:
                results = list(pool.map(lambda _: ex.appliquer(d), range(4)))
        self.assertEqual(len(calls), 1)
        self.assertTrue(all(r['applique'] for r in results))
        self.assertEqual(sum(r.get('rejeu', False) for r in results), 3)

    def test_replay_conflict_and_stale_generation(self):
        d = self.demande()
        self.assertTrue(ex.appliquer(d)['applique'])
        self.assertEqual(ex.appliquer({**d, 'cible': 'different'})['refus']['motif'], 'rejeu_contradictoire')
        self.m['generation'] = 'g2'
        self.write_manifest()
        self.assertEqual(ex.appliquer(d)['refus']['motif'], 'generation_absente_ou_perimee')

    def test_interrupted_execution_never_retried_blindly(self):
        d = self.demande()
        ex._journal({'decision_id': d['decision_id'], 'demande_sha256': ex._sha(ex._canon(d)),
                     'etat': 'en_cours'})
        with patch.dict(ex.ACTIONS, {'ne-rien-faire': lambda *_: self.fail('double mutation')}):
            r = ex.appliquer(d)
        self.assertEqual(r['refus']['motif'], 'execution_precedente_issue_inconnue')

    def test_corrupt_journal_fails_closed(self):
        ex.RECUS.write_text('{cassé\n')
        self.assertEqual(ex.appliquer(self.demande())['refus']['motif'], 'journal_corrompu')

    def test_exact_service_stop_preserves_neighbor_and_guards_restart(self):
        unit = 'labo-copie-b.service'
        cg = '/sawm-charge.slice/'+unit
        etat = dict(Id=unit, LoadState='loaded', ActiveState='active', SubState='running',
                    MainPID='20', Slice='sawm-charge.slice', ControlGroup=cg,
                    InvocationID='abc', Restart='always', KillMode='control-group', DropInPaths='')
        seen = []
        def fake(nom, *args, **_):
            seen.append((nom, args))
            if args[0] == 'daemon-reload':
                etat['Restart'] = 'no'
                etat['DropInPaths'] = str(ex.SYSTEMD_RUNTIME/(unit+'.d')/'90-sawm-lab-stop.conf')
            elif args[0] == 'stop':
                self.assertEqual(args, ('stop', '--', unit))
                etat.update(ActiveState='inactive', MainPID='0', ControlGroup='')
            return 0, '\n'.join(f'{k}={v}' for k,v in etat.items()), ''
        with patch.object(ex, 'run', fake):
            r = ex.appliquer(self.demande(action='geler-transfert', cible=unit))
        self.assertTrue(r['applique'], r)
        self.assertTrue(r['effet_verifie'])
        self.assertTrue((ex.GARDES/(unit+'.stop')).is_file())
        self.assertTrue(all(nom == 'systemctl' for nom, _ in seen))
        self.assertFalse(any('labo-copie-a' in str(a) for _,a in seen))
        self.assertFalse(any('sawm-charge.slice' == x for _,a in seen for x in a))

    def test_witness_and_prefix_not_authorized(self):
        self.m['unites_autorisees'].append('labo-temoin.service')
        for unite in ('labo-temoin.service', 'labo-copie-c.service', '../x.service', '-x'):
            with self.subTest(unite=unite), patch.object(ex, 'run', side_effect=AssertionError('ne doit pas consulter OS')):
                with self.assertRaises(ex.Refus):
                    ex.unite_autorisee(unite, self.m)

    def test_failed_mutation_is_not_reported_as_applied(self):
        def echouer(*_):
            raise ex.Refus('code_retour_refuse', 'stop a échoué')
        with patch.dict(ex.ACTIONS, {'geler-transfert': echouer}):
            r = ex.appliquer(self.demande(action='geler-transfert', cible='labo-copie-b.service'))
        self.assertFalse(r['applique'])
        self.assertFalse(r['effet_verifie'])
        self.assertEqual(r['issue'], 'partielle_ou_inconnue')

    def test_fixture_symlink_and_parent_symlink_refused(self):
        secret = self.base/'secret'
        secret.write_text('secret')
        for nom in ('lien', 'dossier'):
            p = self.base/'fixtures'/nom
            p.symlink_to(secret if nom == 'lien' else self.base)
            cible = p if nom == 'lien' else p/'secret'
            with self.assertRaises((OSError, ex.Refus)):
                ex.chemin_autorise(str(cible), self.m)

    def test_missing_and_bad_hash_never_called_integral(self):
        self.m['empreintes_fixtures'] = {'a.txt': hashlib.sha256(b'ok').hexdigest()}
        r = ex.act_verifier_integrite('fixtures', self.m, 'd')
        self.assertFalse(r['integre'])
        (self.base/'fixtures/a.txt').write_bytes(b'bad')
        self.assertFalse(ex.act_verifier_integrite('fixtures', self.m, 'd')['integre'])

    def test_restore_missing_fixture_from_verified_reference(self):
        (self.base/'reference/a.txt').write_bytes(b'ok')
        self.m['empreintes_fixtures'] = {'a.txt': hashlib.sha256(b'ok').hexdigest()}
        r = ex.act_restaurer_fixtures('fixtures', self.m, 'd')
        self.assertTrue(r['integre'])
        self.assertEqual((self.base/'fixtures/a.txt').read_bytes(), b'ok')


if __name__ == '__main__':
    unittest.main()

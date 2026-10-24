"""Reprise systemd : tests de contrat et orchestration, sans VM ni réseau."""
import ast
import contextlib
import copy
import io
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from controleur import validation_reprise as v
from connecteur.contrat import Proposition
from connecteur.tour_sawm import Decision


def decision():
    return Decision('dec-reprise','turn-reprise','session-reprise',
        Proposition('arreter-service',v.UNITE,'Le mandat retire cette activite de test.',0.8),
        None,'{}',('turn.done',),10.0,False,None,None,None)


def state(epoch, *, active=False, pid='0', invocation='new', restarts='1', guarded=False):
    return {'guest_epoch':epoch,'unite':{'Id':v.UNITE,'ActiveState':'active' if active else 'inactive',
        'MainPID':pid,'InvocationID':invocation,'NRestarts':restarts,
        'Restart':'no' if guarded else 'always','ConditionResult':'no' if guarded else 'yes',
        'DropInPaths':v.DROPIN if guarded else ''},
        'protegee_a':{'ActiveState':'active','MainPID':'77','InvocationID':'protected'},
        'temoin':{'code':200},
        'charge':{'termine':not active,'pid':int(pid),'battements':3},
        'garde':{'decision_id':'dec-reprise'} if guarded else None}


class RepriseTests(unittest.TestCase):
    def samples(self):
        before=state(100,active=True,pid='10',invocation='old',restarts='0')
        restarted=state(101,active=True,pid='11')
        window=[state(110+i,guarded=True) for i in range(6)]
        after=state(116,guarded=True)
        return before,restarted,window,after

    def test_provisioning_unit_and_manifest_share_scoped_deadline_and_lock(self):
        source=v.provision_source('reprise-test')
        tree=ast.parse(source)
        compile(tree,'guest-provision','exec')
        assignments={n.targets[0].id:n.value for n in tree.body
                     if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name)}
        manifest=ast.literal_eval(assignments['m'])
        self.assertEqual(manifest['unites_autorisees'],[v.UNITE])
        self.assertIn('labo-copie-a.service',manifest['unites_protegees'])
        self.assertIn('labo-temoin.service',manifest['unites_protegees'])
        self.assertEqual(manifest['tranches_autorisees'],['sawm-charge.slice'])
        unit=eval(compile(ast.Expression(assignments['text']),'unit','eval'),
                  {'m':manifest,'deadline':12345.0,'str':str})
        self.assertIn('\nRestart=always\n',unit)
        self.assertIn('RestartPreventExitStatus=78',unit)
        self.assertIn('--duration 300 --deadline-epoch 12345.0',unit)
        self.assertIn('KillMode=control-group',unit)
        self.assertIn('fcntl.flock(fd,fcntl.LOCK_EX)',source)
        self.assertIn("hashlib.sha256(raw).hexdigest()",source)
        with self.assertRaises(ValueError):v.provision_source('bad\nExecStart=other')

    def test_success_requires_actual_restart_guard_and_business_continuity(self):
        samples=self.samples()
        measures,success=v.mesurer(*samples,{'applique':True,'effet_verifie':True},decision(),400)
        self.assertTrue(success)
        self.assertTrue(measures['garde_verifiee_sur_start_operateur'])
        self.assertEqual(measures['nrestarts_apres_kill'],1)

    def test_natural_expiry_never_counts_as_sawm_success(self):
        measures,success=v.mesurer(*self.samples(),{'applique':True,'effet_verifie':True},decision(),114)
        self.assertFalse(success)
        self.assertFalse(measures['verification_avant_echeance_naturelle'])

    def test_no_restart_no_guard_or_protected_service_loss_fail_measurement(self):
        for failure in ('restart','guard','protected','witness','window'):
            with self.subTest(failure=failure):
                a,b,window,c=self.samples()
                if failure=='restart':b['unite']['NRestarts']='0'
                elif failure=='guard':c['unite']['ConditionResult']='yes'
                elif failure=='protected':c['protegee_a']['MainPID']='0'
                elif failure=='witness':window[2]['temoin']['code']=503
                else:window=window[:2]
                _,success=v.mesurer(a,b,window,c,{'applique':True,'effet_verifie':True},decision(),400)
                self.assertFalse(success)

    def test_full_orchestration_keeps_injections_and_cleanup_on_single_unit(self):
        a,b,window,c=self.samples()
        commands=[]
        saved=[]
        pont=Mock()
        pont.deposer.return_value={'jobs':[{'statut':'completed'}]}
        generation={}
        def provision(run):
            generation['run']=run
            return {'generation':run,'manifest_sha256':'sha-test','deadline_epoch':400}
        def describe():return {'generation':generation['run'],'manifest_sha256':'sha-test'}
        def cmd(rows):
            commands.extend(rows)
            return [{'cmd':row,'code':0,'out':'','err':''} for row in rows]
        with tempfile.TemporaryDirectory() as root,contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(v,'ROOT',pathlib.Path(root)))
            stack.enter_context(patch.object(v,'provisionner',side_effect=provision))
            stack.enter_context(patch.object(v,'describe',side_effect=describe))
            stack.enter_context(patch.object(v,'attendre',side_effect=[a,b]))
            stack.enter_context(patch.object(v,'observer',side_effect=[*window,c]))
            stack.enter_context(patch.object(v.vm,'commands',side_effect=cmd))
            stack.enter_context(patch.object(v,'PontMemoire',return_value=pont))
            cloud=stack.enter_context(patch.object(v,'decision_cloud',return_value=(decision(),{'cloud':'mock'})))
            stack.enter_context(patch.object(v,'execute',return_value={'applique':True,'effet_verifie':True}))
            stack.enter_context(patch.object(v,'post'))
            stack.enter_context(patch.object(v,'save',side_effect=lambda p,r:saved.append(copy.deepcopy(r))))
            stack.enter_context(patch.object(v.time,'sleep'))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            report=v.reprise()
        self.assertTrue(report['succes_mesure'])
        self.assertEqual([c[1] for c in commands],['start','kill','start','stop'])
        self.assertTrue(all(c[-1]==v.UNITE for c in commands))
        self.assertIn('--kill-who=main',commands[1])
        self.assertIn('--signal=SIGKILL',commands[1])
        self.assertEqual(cloud.call_args.args[3],[v.UNITE])
        pont.deposer.assert_called_once()
        pont.close.assert_called_once()
        self.assertIn('nettoyage_operateur',saved[-1])
        self.assertIn('root',report['limite'])


if __name__=='__main__':unittest.main()

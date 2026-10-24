import pathlib,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from controleur.validation_database import exclusive_rollback_lock,same_lock_holder

class LockEvidenceTests(unittest.TestCase):
    def evidence(self,line,**changes):
        return dict({'identity_stable':True,'fd_on_database':True,'systemd':{'MainPID':'42'},'kernel_locks':[line]},**changes)
    def test_exclusive_shared_range_requires_matching_process_and_stable_identity(self):
        line='3: POSIX ADVISORY WRITE 42 fd:01:573000 1073741824 1073742335'
        self.assertTrue(exclusive_rollback_lock(self.evidence(line)))
        for changes in ({'identity_stable':False},{'fd_on_database':False},{'systemd':{'MainPID':'43'}}):
            self.assertFalse(exclusive_rollback_lock(self.evidence(line,**changes)))
    def test_reserved_pending_shared_and_waiting_locks_are_not_exclusive(self):
        for line in ['3: POSIX ADVISORY WRITE 42 fd:01:573000 1073741825 1073741825',
                     '3: POSIX ADVISORY WRITE 42 fd:01:573000 1073741824 1073741824',
                     '3: POSIX ADVISORY READ 42 fd:01:573000 1073741826 1073742335',
                     '3: -> POSIX ADVISORY WRITE 42 fd:01:573000 1073741824 1073742335',
                     '3: POSIX ADVISORY WRITE 42 fd:01:573000 invalid EOF']:
            self.assertFalse(exclusive_rollback_lock(self.evidence(line)),line)
    def test_restart_reuse_and_stale_attribution_cannot_authorize_fresh_invocation(self):
        fields={'MainPID':'42','InvocationID':'old','ControlGroup':'/sawm.slice/labo-db-test.service','ActiveState':'active'}
        proof={'identity_stable':True,'observed_at_ms':10000,'systemd':fields}
        self.assertTrue(same_lock_holder(proof,{'unite':fields.copy()},10001))
        for key,value in [('MainPID','43'),('InvocationID','new'),('ControlGroup','/other'),('ActiveState','inactive')]:
            self.assertFalse(same_lock_holder(proof,{'unite':{**fields,key:value}},10001))
        for tick in (9999,13001):
            self.assertFalse(same_lock_holder(proof,{'unite':fields.copy()},tick))

class PreservationMandateTests(unittest.TestCase):
    def test_halt_permission_does_not_override_explicit_valid_maintenance(self):
        from controleur.garde_database import preservation_explicitement_autorisee as preserve
        unit='labo-db-test.service'
        policy={'database_policy':{'unit':unit,'exclusive_lock_authorized':True,'availability_required':False,'reference_sha256':'a'*64}}
        current={'reference_matches':True,'reference_sha256':'a'*64,'hash_stable_during_probe':True,'errors':{'read':'SQLITE_BUSY','write':'SQLITE_BUSY'}}
        self.assertTrue(preserve(policy,unit,current))
        self.assertFalse(preserve(policy,'labo-other.service',current))
        for change in ({'reference_matches':False},{'reference_sha256':'b'*64},{'hash_stable_during_probe':False},{'errors':{'read':'SQLITE_CORRUPT'}}):
            self.assertFalse(preserve(policy,unit,{**current,**change}))
        for change in ({'exclusive_lock_authorized':False},{'availability_required':True}):
            self.assertFalse(preserve({'database_policy':{**policy['database_policy'],**change}},unit,current))

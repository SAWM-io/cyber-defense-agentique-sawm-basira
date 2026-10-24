"""Réinspection VM des cibles de défense fichiers, sans appel Cloud ni action.

La télémétrie fournit au plus un sélecteur de cible. Autorité, signatures et
observations sont relues sur la VM. Le résultat n'accorde pas de droit nouveau.
"""
from __future__ import annotations
import json
import re
import time

UNIT = re.compile(r'labo-[a-z0-9][a-z0-9_.-]{0,55}\.service')
SHA = re.compile(r'[a-f0-9]{64}')
MAX_AGE_MS = 1500
ABSENT = {'aucun_mandat_pour_operation', 'mandat_expire_ou_futur', 'mandat_revoque'}
IDENTITY = ('unit','machine_id','boot_id','invocation_id','pid','process_start_ticks','uid','cgroup','object')

_REMOTE = r'''
import json,sys,time
sys.path[:0]=['/opt/sawm-labo','/opt/sawm-labo/agent']
from defense_runtime import trusted_manifest,targets,inspect_target
from maintenance import observer_os,evaluate,OBS_KEYS
from diagnostic_defense import diagnostiquer
from write_attribution import WriteAttributionSensor
result={'schema':'sawm-server-inspection/v1','action':'inspecter-base','unit':unit,
        'status':'unavailable','observation_valid':False,'identity_stable':False,
        'measurements_complete':False,'before':None,'after':None,'evidence':None,
        'source':'vm_controller_reinspection','observed_epoch_ms':int(time.time()*1000),
        'human_actor':'unknown','human_actor_inferred':False,
        'limits':['Cible exacte du manifeste root ; aucune couverture générale.',
                  'Sonde SQLite et capture VFS brève ; aucun contenu métier exporté.',
                  'Autorisation à revalider avant action ; observation seule sans mutation de service.']}
sensor=None
try:
 m=trusted_manifest()
 if m.get('_sha256')!=expected_sha or str(m.get('generation'))!=generation:
  raise ValueError('manifest_changed_before_inspection')
 allowed=[t for t in targets(m) if t['unit']==unit and (object_path is None or t['path']==object_path)]
 if len(allowed)!=1:raise ValueError('file_target_absent_or_ambiguous')
 target=allowed[0];path=target['path']
 before=observer_os(unit,path)
 snap={'active':False,'events':[],'error':'write_capture_unavailable'}
 try:
  sensor=WriteAttributionSensor([path]).start()
  time.sleep(.25)
  snap=sensor.snapshot()
 except Exception:
  pass  # Lock/hash inspections remain useful; unavailable write proof is explicit.
 item=inspect_target(m,target,snap,observer_os,evaluate,diagnostiquer)
 after=observer_os(unit,path)
 if any(before.get(k)!=after.get(k) or item['identity'].get(k)!=after.get(k) for k in OBS_KEYS):
  raise ValueError('identity_changed_during_inspection')
 current=trusted_manifest()
 if current['_sha256']!=m['_sha256']:raise ValueError('manifest_changed_during_inspection')
 now=int(time.time()*1000)
 if not 0<=now-item['observed_ms']<=1500:raise ValueError('inspection_expired')
 receipts={op:evaluate(m,after,unit=unit,operation=op,object_path=path,now_ms=now)
           for op in ('sqlite-exclusive-lock','file-write')}
 stable=item.get('integrity',{}).get('sample_stable') is True
 result.update(status='observed' if stable else 'inconclusive',observation_valid=stable,
     identity_stable=True,measurements_complete=stable,observed_epoch_ms=now,
     before={k:before[k] for k in OBS_KEYS},after={k:after[k] for k in OBS_KEYS},
     generation=str(m['generation']),manifest_sha256=m['_sha256'],object_path=path,
     policy_verified=True,evidence={'target':target,'inspection':item,'policy_receipts':receipts})
except Exception as exc:
 result.update(reason=str(exc)[:160] if isinstance(exc,ValueError) else type(exc).__name__)
finally:
 if sensor:
  try:sensor.close()
  except Exception:result.update(observation_valid=False,status='inconclusive',reason='sensor_cleanup_unconfirmed')
raw=json.dumps(result,ensure_ascii=False,allow_nan=False)
if len(raw.encode())>65536:
 raw=json.dumps({'schema':'sawm-server-inspection/v1','action':'inspecter-base','unit':unit,
                'status':'unavailable','observation_valid':False,'identity_stable':False,
                'source':'vm_controller_reinspection','reason':'inspection_output_too_large'})
print(raw)
'''


def inspecter_base(unit, manifest, *, object_path=None, json_code_fn=None):
    if not isinstance(unit,str) or not UNIT.fullmatch(unit):
        raise ValueError('inspection_file_unit_invalid')
    digest=manifest.get('_sha256');generation=manifest.get('generation')
    if not isinstance(digest,str) or not SHA.fullmatch(digest) or not isinstance(generation,str) or not re.fullmatch(r'[A-Za-z0-9._:-]{1,160}',generation):
        raise ValueError('inspection_file_manifest_invalid')
    if object_path is not None and (not isinstance(object_path,str) or len(object_path)>1024 or not object_path.startswith('/opt/sawm-labo/fixtures/')):
        raise ValueError('inspection_file_path_invalid')
    policy=manifest.get('defense_fichiers') or {}
    candidates=policy.get('targets') if policy.get('enabled') is True else []
    candidates=[t for t in candidates if isinstance(t,dict) and t.get('unit')==unit
                and (object_path is None or t.get('path')==object_path)] if isinstance(candidates,list) else []
    if len(candidates)!=1:
        return {'schema':'sawm-server-inspection/v1','action':'inspecter-base','unit':unit,
                'status':'unavailable','observation_valid':False,'identity_stable':False,'evidence':None,
                'source':'vm_controller_reinspection','reason':'inspecter_base_non_configuree_dans_veille'}
    if json_code_fn is None:
        from controleur.vm_labo import json_code
        json_code_fn=json_code
    bindings='unit='+repr(unit)+'\ngeneration='+repr(generation)+'\nexpected_sha='+repr(digest)+'\nobject_path='+repr(object_path)+'\n'
    result=json_code_fn(bindings+_REMOTE,timeout=20)
    if (not isinstance(result,dict) or result.get('schema')!='sawm-server-inspection/v1'
            or result.get('action')!='inspecter-base' or result.get('unit')!=unit):
        raise ValueError('inspection_file_response_invalid')
    return result


def valide(result, manifest, unit, *, now_ms=None):
    now=int(time.time()*1000) if now_ms is None else now_ms
    if not isinstance(result,dict):return False
    observed=result.get('observed_epoch_ms');before=result.get('before');after=result.get('after')
    evidence=result.get('evidence') or {};target=evidence.get('target') or {}
    policy=manifest.get('defense_fichiers') or {}
    candidates=policy.get('targets') if policy.get('enabled') is True else []
    matching=[x for x in candidates if isinstance(x,dict) and x.get('unit')==unit
              and x.get('path')==result.get('object_path')] if isinstance(candidates,list) else []
    if len(matching)!=1 or json.dumps(target,sort_keys=True)!=json.dumps(matching[0],sort_keys=True):return False
    if not isinstance(before,dict) or type(before.get('pid')) is not int or before['pid']<=1 \
            or type(before.get('process_start_ticks')) is not int or before['process_start_ticks']<=0 \
            or type(before.get('uid')) is not int or before['uid']<0:return False
    return (result.get('schema')=='sawm-server-inspection/v1' and result.get('action')=='inspecter-base'
        and result.get('source')=='vm_controller_reinspection' and result.get('unit')==unit
        and result.get('status')=='observed' and result.get('observation_valid') is True
        and result.get('identity_stable') is True and result.get('policy_verified') is True
        and result.get('manifest_sha256')==manifest.get('_sha256') and result.get('generation')==str(manifest.get('generation'))
        and type(observed) is int and 0<=now-observed<=MAX_AGE_MS
        and isinstance(before,dict) and before==after and all(before.get(k) is not None for k in IDENTITY)
        and before.get('unit')==unit and isinstance(before.get('object'),dict)
        and before['object'].get('path')==result.get('object_path'))


def politique_database(result, manifest, unit, *, now_ms=None):
    """Adaptateur vers le schéma Cloud existant ; jamais depuis la télémétrie."""
    if not valide(result,manifest,unit,now_ms=now_ms):return None
    evidence=result.get('evidence') or {};target=evidence.get('target') or {};receipts=evidence.get('policy_receipts') or {}
    if target.get('unit')!=unit or target.get('path')!=result.get('object_path') or target.get('kind')!='sqlite':return None
    grants={}
    for op in ('sqlite-exclusive-lock','file-write'):
        receipt=receipts.get(op) or {}
        if (receipt.get('authorized') is True and receipt.get('reason')=='mandat_signe_valide'
            and receipt.get('signature_verified') is True and receipt.get('principal') and receipt.get('mandate_id')):
            grants[op]=True
        elif receipt.get('authorized') is False and receipt.get('reason') in ABSENT:
            grants[op]=False
        else:return None
    if not isinstance(target.get('reference_sha256'),str) or not SHA.fullmatch(target['reference_sha256']):return None
    return {'unit':unit,'reference_sha256':target['reference_sha256'],
        'exclusive_lock_authorized':grants['sqlite-exclusive-lock'],
        'availability_required':not grants['sqlite-exclusive-lock'],
        'integrity_required':not grants['file-write'],
        # Every defense_fichiers target has authorization_required=True in
        # the local guard. This is a root policy, never inferred from telemetry.
        'write_requires_authorization':True,'write_authorized':grants['file-write']}


def refus_action(result, reference, manifest, unit, *, object_path=None, now_ms=None):
    """Absence de veto n'est utile qu'après les autres droits du contrôleur."""
    if not valide(result,manifest,unit,now_ms=now_ms):return 'inspection_fichiers_non_fiable_au_moment_action'
    if not isinstance(reference,dict) or reference.get('source')!='vm_controller_reinspection' or reference.get('manifest_sha256')!=manifest.get('_sha256'):
        return 'reference_inspection_fichiers_absente'
    if reference.get('after')!=result.get('before') or reference.get('object_path')!=result.get('object_path'):
        return 'identite_fichier_ou_processus_changee'
    if object_path is not None and object_path!=result.get('object_path'):
        return 'objet_fichier_non_correlle'
    evidence=result.get('evidence') or {};item=evidence.get('inspection') or {};target=evidence.get('target') or {}
    if item.get('unit')!=unit or target.get('unit')!=unit or item.get('path')!=result.get('object_path') or target.get('path')!=result.get('object_path'):
        return 'cible_fichier_non_correllee'
    if (item.get('integrity') or {}).get('reference_sha256')!=target.get('reference_sha256'):
        return 'reference_integrite_non_correllee'
    operations=item.get('qualified_operations')
    if not isinstance(operations,list) or not operations or any(op not in ('file-write','sqlite-exclusive-lock') for op in operations):
        return 'infraction_fichier_actuelle_non_etablie'
    receipts=evidence.get('policy_receipts') or {}
    for operation in operations:
        receipt=receipts.get(operation) or {}
        if receipt.get('authorized') is False and receipt.get('reason') in ABSENT:
            return None
    if all((receipts.get(op) or {}).get('authorized') is True and (receipts.get(op) or {}).get('reason')=='mandat_signe_valide'
           and (receipts.get(op) or {}).get('signature_verified') is True for op in operations):
        return 'maintenance_signee_preservee'
    return 'autorisation_operation_fichier_non_etablie'

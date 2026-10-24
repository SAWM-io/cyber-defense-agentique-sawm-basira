"""Installation additive du lecteur synthétique et de sa défense, VM fixe seulement.

Aucun acteur d'attaque. Aucun pare-feu ni configuration SSH modifiés. Sauvegarde
privée avant mutation ; base existante conservée et contrôlée contre sa référence.
"""
from __future__ import annotations
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import time

ROOT=Path(__file__).resolve().parents[1]
UNIT='labo-ledger-demo.service'
DB='/opt/sawm-labo/fixtures/database-defense/run-defense-permanente/ledger.sqlite'
ACTIONS=['arreter-service','ne-rien-faire','ouvrir-dossier','demander-clarification']
PROTECT=['labo-defense-fichiers.service','labo-auth-guard.service','ssh.service','sshd.service']


def manifeste_permanent(original, *, reference_sha256, machine_id):
    if not isinstance(reference_sha256,str) or len(reference_sha256)!=64 or any(c not in '0123456789abcdef' for c in reference_sha256):
        raise ValueError('reference_invalide')
    m=copy.deepcopy(original);m.pop('_sha256',None)
    if UNIT in m.get('unites_protegees',[]):raise ValueError('lecteur_deja_protege_par_autre_mandat')
    for name, values in [('unites_autorisees',[UNIT]),('unites_protegees',PROTECT)]:
        existing=m.setdefault(name,[])
        if not isinstance(existing,list):raise ValueError('liste_manifeste_invalide')
        existing.extend(x for x in values if x not in existing)
    rules=m.setdefault('actions_par_unite',{})
    if not isinstance(rules,dict):raise ValueError('droits_unites_invalides')
    rules[UNIT]=list(ACTIONS)
    policy=m.setdefault('defense_fichiers',{})
    if policy is None:policy={};m['defense_fichiers']=policy
    if not isinstance(policy,dict):raise ValueError('politique_fichiers_invalide')
    targets=policy.setdefault('targets',[])
    if not isinstance(targets,list):raise ValueError('cibles_invalides')
    matching=[x for x in targets if x.get('unit')==UNIT or x.get('path')==DB]
    target={'unit':UNIT,'path':DB,'kind':'sqlite','reference_sha256':reference_sha256,'automatic_containment':True}
    if matching and (len(matching)!=1 or matching[0]!=target):raise ValueError('cible_existante_divergente')
    if not matching:targets.append(target)
    policy['enabled']=True
    if 'maintenance' not in m:
        m['maintenance']={'schema':'sawm-maintenance-policy/v1','machine_id':machine_id,
                          'keys':[],'mandates':[],'revoked_mandates':[]}
    elif not isinstance(m['maintenance'],dict) or m['maintenance'].get('machine_id')!=machine_id:
        raise ValueError('politique_maintenance_machine_divergente')
    baseline=m.setdefault('veille',{})
    if not isinstance(baseline,dict):raise ValueError('veille_invalide')
    known=baseline.setdefault('unites_connues',[])
    if not isinstance(known,list):raise ValueError('baseline_invalide')
    known.extend(x for x in [UNIT,*PROTECT] if x not in known)
    return m


def run():
    from controleur import vm_labo as vm
    started=int(time.time()*1000)
    raw=vm.json_code("import pathlib,json,base64;p=pathlib.Path('/opt/sawm-labo/manifeste.json');print(json.dumps({'manifest':base64.b64encode(p.read_bytes()).decode()}))")['manifest']
    original_bytes=base64.b64decode(raw);original=json.loads(original_bytes)
    original_sha=hashlib.sha256(original_bytes).hexdigest()
    backup_dir=Path.home()/'.sawm-labo/installation-backups'
    backup_dir.mkdir(mode=0o700,parents=True,exist_ok=True)
    backup=backup_dir/f'defense-permanente-{started}.json'
    with os.fdopen(os.open(backup,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'wb') as stream:stream.write(original_bytes)
    files={
      'invite/charges_test/ledger_temoin.py':'/opt/sawm-labo/charges_test/ledger_temoin.py',
      'provisionnement/systemd/labo-ledger-demo.service':'/etc/systemd/system/labo-ledger-demo.service',
      'invite/executeur/executeur.py':'/opt/sawm-labo/executeur/executeur.py',
      'controleur/maintenance_cli.py':'/opt/sawm-labo/controleur/maintenance_cli.py'}
    payload={remote:base64.b64encode((ROOT/local).read_bytes()).decode() for local,remote in files.items()}
    source=(ROOT/'controleur/maintenance.py').read_bytes()
    for remote in ('/opt/sawm-labo/maintenance.py','/opt/sawm-labo/executeur/maintenance.py','/opt/sawm-labo/controleur/maintenance.py'):
        payload[remote]=base64.b64encode(source).decode()
    prepared=vm.json_code('payload='+repr(payload)+'\n'+r'''
import base64,json,pathlib,subprocess,tempfile,os,sys,hashlib
for name,encoded in payload.items():
 p=pathlib.Path(name);p.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
 if p.resolve()!=p:raise ValueError('destination_symbolique')
 fd,tmp=tempfile.mkstemp(prefix='.defense-',dir=p.parent)
 try:
  with os.fdopen(fd,'wb') as stream:stream.write(base64.b64decode(encoded));stream.flush();os.fsync(stream.fileno())
  os.chmod(tmp,0o644);os.replace(tmp,p)
 finally:pathlib.Path(tmp).unlink(missing_ok=True)
sys.path.insert(0,'/opt/sawm-labo/charges_test')
import database
p=pathlib.Path('/opt/sawm-labo/fixtures/database-defense/run-defense-permanente/ledger.sqlite')
created=not p.exists()
if created:database.prepare('defense-permanente')
status=database.status('defense-permanente')
if status.get('reference_matches') is not True:raise ValueError('fixture_existante_non_conforme')
print(json.dumps({'created':created,'reference_sha256':status['reference_sha256'],
 'machine_id':pathlib.Path('/etc/machine-id').read_text().strip(),
 'files':{p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() for p in payload}}))
''',timeout=30)
    desired=manifeste_permanent(original,reference_sha256=prepared['reference_sha256'],machine_id=prepared['machine_id'])
    applied=vm.json_code('desired='+repr(desired)+'\nexpected='+repr(original_sha)+'\n'+r'''
import fcntl,json,os,pathlib,hashlib,tempfile,subprocess
root=pathlib.Path('/opt/sawm-labo');p=root/'manifeste.json'
with open(root/'.executeur.lock','a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX)
 if hashlib.sha256(p.read_bytes()).hexdigest()!=expected:raise ValueError('manifeste_change_pendant_installation')
 fd,tmp=tempfile.mkstemp(prefix='.manifeste-',dir=root)
 with os.fdopen(fd,'wb') as stream:stream.write(json.dumps(desired,ensure_ascii=False).encode());stream.flush();os.fsync(stream.fileno())
 os.chmod(tmp,0o600);os.replace(tmp,p)
for command in (['systemctl','daemon-reload'],['systemctl','enable','labo-ledger-demo.service','labo-defense-fichiers.service'],
                ['systemctl','start','labo-ledger-demo.service'],['systemctl','restart','labo-defense-fichiers.service']):
 subprocess.run(command,check=True,timeout=15,capture_output=True)
print(json.dumps({'manifest_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),
 'services':{unit:subprocess.run(['systemctl','is-active',unit],capture_output=True,text=True).stdout.strip()
             for unit in ('labo-ledger-demo.service','labo-defense-fichiers.service','ssh.service')}}))
''',timeout=35)
    result={'schema':'sawm-permanent-defense-install/v1','started_ms':started,'finished_ms':int(time.time()*1000),
            'backup_private_path':str(backup),'manifest_before_sha256':original_sha,**applied,
            'fixture_created':prepared['created'],'reference_sha256':prepared['reference_sha256'],
            'deployed_sha256':prepared['files'],'target':DB,'unit':UNIT,
            'limits':['Le lecteur ne prouve pas qui écrit ailleurs : auteur inconnu => alerte.',
                      'Aucune attaque lancée ; SSH et pare-feu non modifiés.']}
    return result


if __name__=='__main__':
    import sys
    sys.path.insert(0,str(ROOT))
    result=run();path=ROOT/'releves/rapports'/f'installation-defense-permanente-{result["started_ms"]}.json'
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'report':str(path),'services':result['services'],'manifest_sha256':result['manifest_sha256']}))

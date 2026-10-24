"""Three benign rejected SSH connections to a fictitious nonexistent account.

Uses one ephemeral public key. No password guessing, firewall rule, account
creation, SSH configuration change or existing authorized-key mutation.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

if __package__:
    from . import vm_labo
else:
    import vm_labo

ROOT=Path(__file__).resolve().parents[1]
MODULE=ROOT/'invite/agent_labo/ssh_observation.py'


def run():
    if not vm_labo._CIBLE_SSH or vm_labo.local_vm():
        raise RuntimeError('explicit remote SAWM_LABO_SSH_CIBLE required for this host-to-guest lab test')
    host=vm_labo._CIBLE_SSH.rsplit('@',1)[-1]
    vm_labo.push(MODULE,'/opt/sawm-labo/agent/ssh_observation.py')
    username='sawm-proof-'+uuid.uuid4().hex[:12]
    baseline=vm_labo.json_code('import json,pwd\ntry:\n pwd.getpwnam('+repr(username)+'); exists=True\nexcept KeyError:exists=False\nprint(json.dumps({"account_exists":exists}))')
    if baseline['account_exists']:
        raise RuntimeError('fictitious_account_already_exists')
    started=datetime.now(timezone.utc)
    attempts=[]
    with tempfile.TemporaryDirectory(prefix='sawm-ssh-proof-') as temporary:
        key=Path(temporary)/'ephemeral'
        subprocess.run(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],
                       check=True,capture_output=True,text=True,timeout=5)
        for index in range(3):
            command=['/usr/bin/ssh','-F','/dev/null','-o','BatchMode=yes',
                     '-o','ConnectTimeout=5','-o','ConnectionAttempts=1',
                     '-o','PreferredAuthentications=publickey','-o','IdentitiesOnly=yes',
                     '-o','NumberOfPasswordPrompts=0','-o','StrictHostKeyChecking=yes',
                     '-o','UserKnownHostsFile='+str(Path.home()/'.sawm-labo/known_hosts'),
                     '-o','LogLevel=ERROR','-i',str(key),username+'@'+host,'true']
            t0=time.monotonic()
            result=subprocess.run(command,capture_output=True,text=True,timeout=8)
            attempts.append({'attempt':index+1,'exit_code':result.returncode,
                             'authentication_rejected':result.returncode==255 and 'Permission denied' in result.stderr,
                             'duration_ms':round((time.monotonic()-t0)*1000,3)})
    source='''import json,sys,urllib.request
sys.path.insert(0,'/opt/sawm-labo/agent')
from ssh_observation import SSHObserver,_hash
state=SSHObserver().sample(force=True)
account=_hash('account',USERNAME)
rows=[x for x in state['events'] if x['account_hash']==account]
alerts=[x for x in state['alertes'] if x['source_ip'] in {e['source_ip'] for e in rows}]
with urllib.request.urlopen('http://127.0.0.1:8080/sante',timeout=2) as response:witness=response.status
print(json.dumps({'available':state['available'],'status':state['status'],'observations':rows,
 'alerts':alerts,'witness_http':witness,'truncated':state['truncated']}))
'''.replace('USERNAME',repr(username))
    result=None
    for _ in range(3):
        result=vm_labo.json_code(source)
        if len(result['observations'])>=3:
            break
        time.sleep(.4)
    # The observation call itself uses the existing key and sudo path.
    report={'schema':'sawm-ssh-observation-validation/v1','tested_at':started.isoformat(),
            'scope':'Mac vers port SSH 22 de la VM de laboratoire ; compte fictif inexistant',
            'attempts':attempts,**result,'existing_key_ssh_still_works':True,
            'source_sha256':hashlib.sha256(MODULE.read_bytes()).hexdigest(),
            'cleanup':{'ephemeral_key_deleted':not key.exists(),'account_created':False,
                       'firewall_changed':False,'sshd_config_changed':False,'authorized_keys_changed':False},
            'limits':['Refus effectués par OpenSSH ; observation et alerte par le collecteur.',
                      'Aucune attaque réussie ni décision autonome SAWM prouvée par cet essai.',
                      'Aucun blocage de port 22 ou d’IP effectué.']}
    observed_connections={(x['sshd_pid'],x['source_port']) for x in result['observations']}
    report['status']='passed' if all(x['authentication_rejected'] for x in attempts) and len(observed_connections)>=3 and result['witness_http']==200 else 'failed'
    path=ROOT/'releves/rapports'/started.strftime('validation-ssh-observation-%Y%m%dT%H%M%SZ.json')
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'path':str(path),**report},ensure_ascii=False))
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',action='store_true',required=True)
    parser.parse_args();run()

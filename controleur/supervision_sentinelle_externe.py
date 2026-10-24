"""Explicit Mac supervision of the external witness, with repository baselines.

Enrollment compares the deployed sensor and its unit against the reviewed local
source. It never accepts the guest's hash as the expected hash. Updating that
baseline is a separate explicit operation, not part of monitoring.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys

if not __package__:sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from controleur.sentinelle_externe import HOME,guest_snapshot,load_reference,validate_reference
from controleur.audit_signe import JournalSigne,canonique
from controleur.vm_labo import local_vm

ROOT=Path(__file__).resolve().parents[1]
LABEL='io.sawm.labo.sentinelle-externe'
SOURCES={
    'invite/capteurs/capteur_large.bt':'/opt/sawm-labo/capteur_large.bt',
    'provisionnement/systemd/labo-capteur-large.service':'/etc/systemd/system/labo-capteur-large.service',
}


def build_reference(root=ROOT):
    root=Path(root)
    value={'schema':'sawm-external-reference/v1','controller':'mac_external',
           'auto_accept_guest_changes':False,
           'services':['labo-capteur-large.service','labo-telemetrie.service','labo-temoin.service','ssh.service'],
           'files':[{'path':remote,'sha256':hashlib.sha256((root/local).read_bytes()).hexdigest(),
                     'approved_repository_source':local} for local,remote in SOURCES.items()]}
    return validate_reference(value)


def configuration(*,home=None,python=None,root=ROOT):
    home=Path.home() if home is None else Path(home)
    root=Path(root);private=home/'.sawm-labo/sentinelle-externe'
    return {'Label':LABEL,'ProgramArguments':[str(python or root/'.venv/bin/python'),
            str(root/'controleur/sentinelle_externe.py'),'--watch','--interval','15',
            '--reference',str(private/'reference.json'),'--audit',str(private/'audit.jsonl')],
            'WorkingDirectory':str(root),'RunAtLoad':True,'KeepAlive':True,'ThrottleInterval':15,
            'ProcessType':'Background','Umask':63,'ExitTimeOut':10,
            'EnvironmentVariables':{'PATH':'/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin',
                                    'PYTHONUNBUFFERED':'1','HOME':str(home),
                                    **{k:os.environ[k] for k in ('SAWM_LABO_SSH_CIBLE','SAWM_LABO_VM_UUID') if k in os.environ}},
            'StandardOutPath':str(private/'stdout.log'),'StandardErrorPath':str(private/'stderr.log')}


def install(*,renew=False):
    if sys.platform!='darwin' or local_vm():raise RuntimeError('external_mac_required')
    reference=build_reference();snapshot=guest_snapshot(reference)
    for expected in reference['files']:
        actual=snapshot.get('files',{}).get(expected['path'],{})
        if (actual.get('available') is not True or actual.get('sample_stable') is not True
                or actual.get('sha256')!=expected['sha256']):
            raise RuntimeError('guest_does_not_match_reviewed_repository_reference')
    if any(snapshot.get('services',{}).get(unit,{}).get('active') is not True for unit in reference['services']):
        raise RuntimeError('services_not_healthy_before_enrollment')
    HOME.mkdir(mode=0o700,parents=True,exist_ok=True);HOME.chmod(0o700)
    path=HOME/'reference.json'
    if path.exists() and canonique(load_reference(path))!=canonique(reference) and not renew:
        raise RuntimeError('reference_change_requires_explicit_renewal')
    domain='gui/'+str(os.getuid())
    # Stop only this witness before replacing its own reference. Other Mac
    # controllers and all VM units are untouched by installation.
    subprocess.run(['launchctl','bootout',domain+'/'+LABEL],capture_output=True,timeout=10)
    temp=HOME/'reference.json.new'
    with os.fdopen(os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb') as file:
        file.write(canonique(reference));file.flush();os.fsync(file.fileno())
    os.replace(temp,path)
    audit=JournalSigne(HOME/'audit.jsonl')
    receipt=audit.append({'kind':'sentinelle_reference_approved','source':'explicit_repository_enrollment',
                          'reference':reference,'reference_sha256':hashlib.sha256(canonique(reference)).hexdigest()})
    target=Path.home()/'Library/LaunchAgents'/f'{LABEL}.plist'
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_bytes(plistlib.dumps(configuration()));target.chmod(0o600)
    result=subprocess.run(['launchctl','bootstrap',domain,str(target)],capture_output=True,timeout=10)
    if result.returncode:raise RuntimeError('external_sentinel_launch_failed')
    return {'installed':True,'label':LABEL,'reference_sha256':hashlib.sha256(canonique(reference)).hexdigest(),
            'audit_receipt':receipt,'guest_modified':False,'poll_interval_seconds':15}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['installer','statut','arreter'])
    parser.add_argument('--renouveler-reference',action='store_true')
    args=parser.parse_args()
    if sys.platform!='darwin' or local_vm():parser.error('Mac externe requis')
    if args.action=='installer':print(json.dumps(install(renew=args.renouveler_reference)));return
    domain='gui/'+str(os.getuid())+'/'+LABEL
    if args.action=='arreter':subprocess.run(['launchctl','bootout',domain],capture_output=True,timeout=10)
    result=subprocess.run(['launchctl','print',domain],capture_output=True,text=True,timeout=10)
    rows=[x.strip() for x in result.stdout.splitlines() if x.strip().startswith(('state =','pid =','runs =','last exit code ='))]
    print(json.dumps({'loaded':result.returncode==0,'state':rows}))


if __name__=='__main__':main()

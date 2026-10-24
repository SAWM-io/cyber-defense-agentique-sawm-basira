#!/usr/bin/env python3
"""Supervise le collecteur et la veille sur le Mac; services Linux déjà supervisés.

Installation explicite LaunchAgents (session utilisateur), jamais un daemon root
avec les secrets Cloud. Les protections kernel/systemd restent autonomes dans la
VM. Ce script ne change pas les autorisations du manifeste invité.
"""
from __future__ import annotations
import argparse,json,os,pathlib,plistlib,subprocess,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
LABELS={'collecteur':'io.sawm.labo.collecteur','veille':'io.sawm.labo.veille'}


def configuration(role, *, python=None, racine=ROOT, home=None, cloud=False, apply=False):
    if role not in LABELS: raise ValueError('role inconnu')
    home=pathlib.Path.home() if home is None else pathlib.Path(home)
    racine=pathlib.Path(racine)
    if apply and not cloud: raise ValueError('--apply requires --cloud')
    python=pathlib.Path(python or racine/'.venv/bin/python')
    logs=home/'.sawm-labo/logs'
    args=[str(python),str(racine/'controleur'/f'{role}.py')]
    if role=='veille':
        args+=['--permanent','--cloud-per-hour','4']
        if cloud: args.append('--cloud')
        if apply: args.append('--apply')
    transport={key:os.environ[key] for key in ('SAWM_LABO_LOCAL_VM','SAWM_LABO_SSH_CIBLE',
        'SAWM_LABO_VM_UUID','LABO_BIND','LABO_PORT_TELEMETRIE','LABO_HTTP') if key in os.environ}
    return {'Label':LABELS[role],'ProgramArguments':args,'WorkingDirectory':str(racine),
            'RunAtLoad':True,'KeepAlive':True,'ThrottleInterval':15,'ExitTimeOut':10,
            'ProcessType':'Background','Umask':63,
            'EnvironmentVariables':{'PATH':'/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin',
                'PYTHONUNBUFFERED':'1','LABO_RUN':'surveillance-continue','HOME':str(home),**transport},
            'StandardOutPath':str(logs/f'{role}.log'),'StandardErrorPath':str(logs/f'{role}.err')}


def run(args):
    return subprocess.run(args,text=True,capture_output=True,timeout=30)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=['installer','statut','arreter'])
    p.add_argument('--cloud',action='store_true',help='explicitly enable bounded Cloud analysis')
    p.add_argument('--apply',action='store_true',help='explicitly enable manifest-authorized actions; requires --cloud')
    a=p.parse_args()
    if a.apply and not a.cloud:p.error('--apply requires --cloud')
    domain=f'gui/{os.getuid()}'
    if sys.platform!='darwin':p.error('contrôleur macOS attendu; Linux invité utilise systemd')
    dossier=pathlib.Path.home()/'Library/LaunchAgents'
    if a.action=='installer':
        dossier.mkdir(parents=True,exist_ok=True)
        (pathlib.Path.home()/'.sawm-labo/logs').mkdir(mode=0o700,parents=True,exist_ok=True)
        for role,label in LABELS.items():
            conf=configuration(role,cloud=a.cloud,apply=a.apply);path=dossier/f'{label}.plist'
            path.write_bytes(plistlib.dumps(conf));path.chmod(0o600)
            run(['launchctl','bootout',f'{domain}/{label}'])
            r=run(['launchctl','bootstrap',domain,str(path)])
            if r.returncode:raise RuntimeError(f'bootstrap {role}: {r.stderr}')
    elif a.action=='arreter':
        for label in LABELS.values():run(['launchctl','bootout',f'{domain}/{label}'])
    result={}
    for role,label in LABELS.items():
        r=run(['launchctl','print',f'{domain}/{label}'])
        lines=[l.strip() for l in r.stdout.splitlines() if any(l.strip().startswith(k) for k in ('state =','pid =','runs =','last exit code =','last terminating signal ='))]
        result[role]={'charge':r.returncode==0,'etat':lines}
    print(json.dumps(result,ensure_ascii=False,indent=2))
if __name__=='__main__':main()
